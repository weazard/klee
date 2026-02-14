/*
 * Klee - Userspace bwrap translation layer
 * Nested bwrap invocation handling
 */
#ifndef KLEE_NESTED_H
#define KLEE_NESTED_H

#include "process/process.h"
#include "intercept/intercept.h"
#include <stdbool.h>

/* Check if an execve target is bwrap or klee (for nested invocation handling) */
bool klee_nested_is_bwrap(const char *exe_path);

/* Handle nested bwrap: parse args inline, apply mounts to parent's table,
 * and rewrite execve to run the target command directly (skipping bwrap). */
int klee_nested_handle_exec(KleeProcess *proc, KleeInterceptor *ic,
                             KleeEvent *ev);

#endif /* KLEE_NESTED_H */
