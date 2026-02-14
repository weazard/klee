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
 * Returns 0 to allow, negative to deny. */
int klee_compat_handle_seccomp_filter(KleeInterceptor *ic, pid_t pid,
                                       struct sock_fprog *prog);

#endif /* KLEE_SECCOMP_FILTER_H */
