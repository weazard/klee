/*
 * Klee - Userspace bwrap translation layer
 * Raw BPF filter generation
 */
#include "filter.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

/* BPF helper macros - undef system ones and use compound literal form */
#undef BPF_STMT
#undef BPF_JUMP
#define BPF_STMT(code, k) \
    ((struct sock_filter){ (unsigned short)(code), 0, 0, (unsigned int)(k) })
#define BPF_JUMP(code, k, jt, jf) \
    ((struct sock_filter){ (unsigned short)(code), (unsigned char)(jt), (unsigned char)(jf), (unsigned int)(k) })

/*
 * Generate a BPF filter for seccomp.
 * The filter checks the architecture (x86_64 only), then uses a linear
 * scan of syscall numbers. For small syscall lists this is fine;
 * a binary search tree could be used for very large lists.
 */
static KleeBpfProg generate_filter(const int *syscall_nrs, size_t count,
                                    uint32_t match_action)
{
    KleeBpfProg prog = { NULL, 0 };

    /*
     * Filter structure:
     *   [0]     Load architecture
     *   [1]     Jump if x86_64
     *   [2]     ALLOW (non-x86_64 fallthrough)
     *   [3]     Load syscall number
     *   [4..N]  Compare against each intercepted syscall
     *   [N+1]   Default: ALLOW
     *   [N+2]   Match action (TRACE or USER_NOTIF)
     */
    size_t max_len = 6 + count;
    struct sock_filter *f = calloc(max_len, sizeof(struct sock_filter));
    if (!f)
        return prog;

    size_t n = 0;

    /* Load arch */
    f[n++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                       offsetof(struct seccomp_data, arch));

    /* Verify x86_64 */
    f[n++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
    f[n++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    /* Load syscall number */
    f[n++] = BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                       offsetof(struct seccomp_data, nr));

    /* Compare against each intercepted syscall */
    for (size_t i = 0; i < count; i++) {
        /* Jump to match_action (which is at n + (count - i) instructions ahead) */
        size_t remaining = count - i - 1;
        f[n++] = BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)syscall_nrs[i],
                          (uint8_t)(remaining + 1), 0);
    }

    /* Default: allow */
    f[n++] = BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    /* Match action */
    f[n++] = BPF_STMT(BPF_RET | BPF_K, match_action);

    prog.filter = f;
    prog.len = n;
    return prog;
}

KleeBpfProg klee_bpf_generate_notif_filter(const int *syscall_nrs, size_t count)
{
#ifdef SECCOMP_RET_USER_NOTIF
    return generate_filter(syscall_nrs, count, SECCOMP_RET_USER_NOTIF);
#else
    (void)syscall_nrs;
    (void)count;
    KLEE_ERROR("SECCOMP_RET_USER_NOTIF not available");
    return (KleeBpfProg){ NULL, 0 };
#endif
}

KleeBpfProg klee_bpf_generate_trace_filter(const int *syscall_nrs, size_t count)
{
    return generate_filter(syscall_nrs, count, SECCOMP_RET_TRACE);
}

void klee_bpf_free(KleeBpfProg *prog)
{
    if (prog) {
        free(prog->filter);
        prog->filter = NULL;
        prog->len = 0;
    }
}
