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
 * Rewrite a child's BPF filter to exempt Klee's intercepted syscalls.
 * Prepends a prefix that checks each intercepted syscall number and
 * returns SECCOMP_RET_TRACE on match. Non-matching syscalls fall
 * through to the child's original filter.
 *
 * The prefix is self-contained with absolute jumps, so appending the
 * child's filter (which uses relative jumps) doesn't break anything.
 */
static struct sock_fprog *rewrite_child_filter(const struct sock_fprog *orig)
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
     * Prefix structure:
     *   [0]   Load syscall number
     *   [1..N] For each intercepted syscall: JEQ nr -> RET_TRACE
     *   [N+1] Fall through to child's original filter
     *
     * Total prefix size: 1 (load) + count (compares) + 1 (RET_TRACE target)
     * But we need the RET_TRACE return at the end of prefix.
     *
     * Layout:
     *   [0]       LD syscall_nr
     *   [1..cnt]  JEQ syscall_i, goto ret_trace, next
     *   [cnt+1]   JA to child filter (skip over RET_TRACE)
     *   [cnt+2]   RET SECCOMP_RET_TRACE
     *   [cnt+3..] child's original filter
     */
    size_t prefix_len = 1 + (size_t)count + 2; /* load + compares + jump + ret_trace */
    size_t total_len = prefix_len + orig->len;

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
    memcpy(combined + n, orig->filter, orig->len * sizeof(struct sock_filter));

    struct sock_fprog *result = calloc(1, sizeof(struct sock_fprog));
    if (!result) {
        free(combined);
        return NULL;
    }
    result->len = (unsigned short)total_len;
    result->filter = combined;

    KLEE_DEBUG("seccomp rewrite: prepended %zu instructions before %d child instructions",
               prefix_len, orig->len);
    return result;
}

int klee_compat_handle_seccomp_filter(KleeInterceptor *ic, pid_t pid,
                                       struct sock_fprog *prog)
{
    if (!prog || !prog->filter || prog->len == 0) {
        KLEE_WARN("child seccomp filter: empty program");
        return 0;
    }

    KLEE_DEBUG("child seccomp filter: %d instructions from pid %d",
               prog->len, pid);

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
        struct sock_fprog *rewritten = rewrite_child_filter(prog);
        if (!rewritten) {
            KLEE_WARN("child installing seccomp filter under ptrace - "
                       "rewrite failed, allowing original filter");
            return 0;
        }

        /* Write the rewritten filter back to tracee memory.
         * We overwrite the original sock_fprog structure that the child
         * passed to the seccomp syscall. The child's memory at prog->filter
         * is reused if large enough, otherwise we write to a new location. */

        /* Write the new filter instructions to tracee */
        size_t filter_size = rewritten->len * sizeof(struct sock_filter);
        int rc = ic->write_mem(ic, pid, prog->filter, rewritten->filter,
                                filter_size);
        if (rc < 0) {
            KLEE_WARN("seccomp rewrite: failed to write filter to tracee: %d", rc);
            free(rewritten->filter);
            free(rewritten);
            return 0;
        }

        /* Update the filter length in the tracee's sock_fprog */
        unsigned short new_len = rewritten->len;
        rc = ic->write_mem(ic, pid, &prog->len, &new_len, sizeof(new_len));
        if (rc < 0)
            KLEE_WARN("seccomp rewrite: failed to update filter len: %d", rc);

        free(rewritten->filter);
        free(rewritten);
        KLEE_INFO("seccomp rewrite: successfully rewrote child filter for pid %d", pid);
        return 0;
    }

    return 0; /* Allow */
}
