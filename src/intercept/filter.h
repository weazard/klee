/*
 * Klee - Userspace bwrap translation layer
 * Raw BPF filter generation for seccomp
 */
#ifndef KLEE_FILTER_H
#define KLEE_FILTER_H

#include <linux/filter.h>
#include <stddef.h>

/* Maximum number of syscalls we intercept */
#define KLEE_MAX_INTERCEPTED_SYSCALLS 128

typedef struct {
    struct sock_filter *filter;
    size_t len;
} KleeBpfProg;

/* Generate a BPF filter that returns SECCOMP_RET_USER_NOTIF for the
 * given syscall numbers and SECCOMP_RET_ALLOW for everything else.
 * Caller must free the returned filter with klee_bpf_free(). */
KleeBpfProg klee_bpf_generate_notif_filter(const int *syscall_nrs, size_t count);

/* Generate a BPF filter that returns SECCOMP_RET_TRACE for the given
 * syscall numbers (for ptrace-based interception). */
KleeBpfProg klee_bpf_generate_trace_filter(const int *syscall_nrs, size_t count);

/* Free a BPF program */
void klee_bpf_free(KleeBpfProg *prog);

#endif /* KLEE_FILTER_H */
