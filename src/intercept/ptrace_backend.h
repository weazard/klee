/*
 * Klee - Userspace bwrap translation layer
 * ptrace fallback backend
 */
#ifndef KLEE_PTRACE_BACKEND_H
#define KLEE_PTRACE_BACKEND_H

#include "intercept.h"

/* Create a ptrace backend interceptor */
KleeInterceptor *klee_ptrace_create(void);

#endif /* KLEE_PTRACE_BACKEND_H */
