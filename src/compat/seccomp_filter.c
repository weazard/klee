/*
 * Klee - Userspace bwrap translation layer
 * Child seccomp filter interception implementation
 *
 * When a child installs a seccomp filter under the ptrace backend,
 * we prepend instructions that convert Klee's intercepted syscalls
 * to SECCOMP_RET_TRACE (which generates a ptrace stop), then fall
 * through to the child's original filter for everything else.
 */
#include "compat/seccomp_filter.h"
#include "syscall/sysnum.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

/* BPF instruction macros */
#undef BPF_STMT
#undef BPF_JUMP
#define BPF_STMT(code, k) \
    ((struct sock_filter){ (unsigned short)(code), 0, 0, (unsigned int)(k) })
#define BPF_JUMP(code, k, jt, jf) \
    ((struct sock_filter){ (unsigned short)(code), (unsigned char)(jt), (unsigned char)(jf), (unsigned int)(k) })

/*
 * Build a rewritten BPF filter that prepends SECCOMP_RET_TRACE checks
 * for Klee's intercepted syscalls before the child's original filter.
 *
 * orig_insns: the child's original BPF instructions (already read into
 *             klee's memory from the tracee).
 * orig_len:   number of instructions in the child's original filter.
 *
 * Returns a malloc'd sock_fprog on success, NULL on failure.
 * Caller must free both result->filter and result.
 */
static struct sock_fprog *rewrite_child_filter(const struct sock_filter *orig_insns,
                                                unsigned short orig_len)
{
    /* Get the list of intercepted syscalls */
    int syscalls[KLEE_INTERCEPTED_SYSCALL_COUNT];
    int count = klee_get_intercepted_syscalls(syscalls,
                                               KLEE_INTERCEPTED_SYSCALL_COUNT);
    if (count <= 0) {
        KLEE_WARN("seccomp rewrite: no intercepted syscalls");
        return NULL;
    }

    /*
     * Prefix layout:
     *   [0]       LD syscall_nr
     *   [1..cnt]  JEQ syscall_i, goto ret_trace, next
     *   [cnt+1]   JA to child filter (skip over RET_TRACE)
     *   [cnt+2]   RET SECCOMP_RET_TRACE
     *   [cnt+3..] child's original filter
     */
    size_t prefix_len = 1 + (size_t)count + 2; /* load + compares + jump + ret_trace */
    size_t total_len = prefix_len + orig_len;

    if (total_len > 4096) { /* BPF_MAXINSNS */
        KLEE_WARN("seccomp rewrite: combined filter too large (%zu > %d)",
                   total_len, BPF_MAXINSNS);
        return NULL;
    }

    struct sock_filter *combined = calloc(total_len, sizeof(struct sock_filter));
    if (!combined)
        return NULL;

    size_t n = 0;

    /* Load syscall number */
    combined[n++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                              offsetof(struct seccomp_data, nr));

    /* For each intercepted syscall: jump to RET_TRACE on match */
    size_t ret_trace_idx = 1 + (size_t)count + 1; /* index of RET_TRACE instruction */
    for (int i = 0; i < count; i++) {
        size_t cur_idx = n;
        uint8_t jt = (uint8_t)(ret_trace_idx - cur_idx - 1);
        combined[n++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                  (uint32_t)syscalls[i], jt, 0);
    }

    /* Jump over RET_TRACE to child's filter */
    combined[n++] = BPF_STMT(BPF_JMP | BPF_JA, 1);

    /* RET_TRACE */
    combined[n++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE);

    /* Append child's original filter */
    memcpy(combined + n, orig_insns, orig_len * sizeof(struct sock_filter));

    struct sock_fprog *result = calloc(1, sizeof(struct sock_fprog));
    if (!result) {
        free(combined);
        return NULL;
    }
    result->len = (unsigned short)total_len;
    result->filter = combined;

    KLEE_DEBUG("seccomp rewrite: prepended %zu instructions before %d child instructions",
               prefix_len, orig_len);
    return result;
}

int klee_compat_handle_seccomp_filter(KleeInterceptor *ic, pid_t pid,
                                       struct sock_fprog *fprog_local,
                                       void *fprog_remote,
                                       uint64_t tracee_rsp)
{
    if (!fprog_local || !fprog_local->filter || fprog_local->len == 0) {
        KLEE_WARN("child seccomp filter: empty program");
        return 0;
    }

    KLEE_DEBUG("child seccomp filter: %d instructions from pid %d",
               fprog_local->len, pid);

    /*
     * For seccomp_unotify backend: child filters don't interfere with
     * the supervisor's notification mechanism, as USER_NOTIF takes priority
     * over other actions in the filter chain.
     */
    if (ic->backend == INTERCEPT_SECCOMP_UNOTIFY)
        return 0; /* Allow as-is */

    /*
     * For ptrace backend: child filters could potentially KILL syscalls
     * before ptrace sees them. Rewrite the child's BPF to exempt klee's
     * intercepted syscalls by prepending SECCOMP_RET_TRACE instructions.
     */
    if (ic->backend == INTERCEPT_PTRACE) {
        /* First, read the child's original BPF instructions from tracee memory.
         * fprog_local->filter is a TRACEE-SIDE pointer, not valid in our space. */
        size_t orig_filter_size = fprog_local->len * sizeof(struct sock_filter);
        struct sock_filter *orig_insns = malloc(orig_filter_size);
        if (!orig_insns)
            return 0;

        int rc = ic->read_mem(ic, pid, orig_insns,
                               fprog_local->filter, orig_filter_size);
        if (rc < 0) {
            KLEE_WARN("seccomp rewrite: failed to read %d BPF instructions from tracee",
                       fprog_local->len);
            free(orig_insns);
            return 0;
        }

        struct sock_fprog *rewritten = rewrite_child_filter(orig_insns,
                                                             fprog_local->len);
        free(orig_insns);

        if (!rewritten) {
            KLEE_WARN("child installing seccomp filter under ptrace - "
                       "rewrite failed, allowing original filter");
            return 0;
        }

        /* The rewritten filter is LARGER than the original (prefix added).
         * Write the new filter to a scratch area below the tracee's stack
         * and update the sock_fprog struct in the tracee to point there. */
        size_t filter_size = rewritten->len * sizeof(struct sock_filter);
        /* Place below tracee's stack (past 128-byte red zone on x86_64) */
        uint64_t scratch = (tracee_rsp - 128 - filter_size) & ~7ULL;

        rc = ic->write_mem(ic, pid, (void *)(uintptr_t)scratch,
                            rewritten->filter, filter_size);
        if (rc < 0) {
            KLEE_WARN("seccomp rewrite: failed to write filter to tracee: %d", rc);
            free(rewritten->filter);
            free(rewritten);
            return 0;
        }

        /* Update the tracee's sock_fprog: new length and new filter pointer.
         * fprog_remote is the tracee-side address of the sock_fprog struct. */
        struct sock_fprog new_fprog;
        new_fprog.len = rewritten->len;
        new_fprog.filter = (struct sock_filter *)(uintptr_t)scratch;
        rc = ic->write_mem(ic, pid, fprog_remote, &new_fprog, sizeof(new_fprog));
        if (rc < 0)
            KLEE_WARN("seccomp rewrite: failed to update fprog: %d", rc);

        KLEE_INFO("seccomp rewrite: successfully rewrote child filter for pid %d "
                   "(%d -> %d instructions)", pid, fprog_local->len, new_fprog.len);
        free(rewritten->filter);
        free(rewritten);
        return 0;
    }

    return 0; /* Allow */
}
