/*
 * Klee - Userspace bwrap translation layer
 * Child seccomp filter interception
 */
#ifndef KLEE_SECCOMP_FILTER_H
#define KLEE_SECCOMP_FILTER_H

#include "intercept/intercept.h"
#include <linux/filter.h>

/* Handle a child process attempting to install a seccomp filter.
 * Analyzes the BPF program for conflicts with klee's interception.
 * fprog_remote is the tracee-side address of the sock_fprog struct.
 * fprog_local is a copy of that struct read into klee's memory.
 * tracee_rsp is the tracee's current stack pointer (for scratch space).
 * Returns 0 to allow, negative to deny. */
int klee_compat_handle_seccomp_filter(KleeInterceptor *ic, pid_t pid,
                                       struct sock_fprog *fprog_local,
                                       void *fprog_remote,
                                       uint64_t tracee_rsp);

#endif /* KLEE_SECCOMP_FILTER_H */
