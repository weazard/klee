/*
 * Klee - Userspace bwrap translation layer
 * Per-syscall handler registration
 */
#ifndef KLEE_HANDLERS_H
#define KLEE_HANDLERS_H

#include "syscall/sysnum.h"

/* Get the list of all syscall numbers to intercept */
int klee_get_intercepted_syscalls(int *out, size_t max_count);

#endif /* KLEE_HANDLERS_H */
