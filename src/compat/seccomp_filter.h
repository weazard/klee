/*
 * Klee - Userspace bwrap translation layer
 * Child seccomp filter interception
 */
#ifndef KLEE_SECCOMP_FILTER_H
#define KLEE_SECCOMP_FILTER_H

#include "intercept/intercept.h"
#include "process/process.h"
#include <linux/filter.h>

/* Handle a child process attempting to install a seccomp filter.
 * Under the ptrace backend, rewrites the filter (in tracee scratch
 * memory) so klee's intercepted syscalls keep generating ptrace stops.
 * prog is the tracee's sock_fprog already copied to klee memory;
 * prog->filter still points into tracee memory and is read here.
 * Returns 0 to allow the (possibly rewritten) syscall to proceed. */
int klee_compat_handle_seccomp_filter(KleeProcess *proc, KleeInterceptor *ic,
                                       KleeEvent *ev,
                                       const struct sock_fprog *prog);

#endif /* KLEE_SECCOMP_FILTER_H */
