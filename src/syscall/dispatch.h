/*
 * Klee - Userspace bwrap translation layer
 * Table-driven syscall dispatch
 */
#ifndef KLEE_DISPATCH_H
#define KLEE_DISPATCH_H

#include "process/process.h"
#include "intercept/intercept.h"

/* Syscall handler function types */
typedef int (*klee_syscall_enter_fn)(KleeProcess *proc, KleeInterceptor *ic,
                                      KleeEvent *event);
typedef int (*klee_syscall_exit_fn)(KleeProcess *proc, KleeInterceptor *ic,
                                     KleeEvent *event);

typedef struct {
    int syscall_nr;
    const char *name;
    klee_syscall_enter_fn enter;
    klee_syscall_exit_fn exit;
} KleeSyscallHandler;

/* Initialize the syscall dispatch table */
void klee_dispatch_init(void);

/* Dispatch a syscall event (enter or exit) to the appropriate handler.
 * Returns: 0 to continue syscall, negative errno to deny,
 * positive to indicate the syscall was handled. */
int klee_dispatch_enter(KleeProcess *proc, KleeInterceptor *ic,
                         KleeEvent *event);
int klee_dispatch_exit(KleeProcess *proc, KleeInterceptor *ic,
                        KleeEvent *event);

/* Get handler for a syscall number */
const KleeSyscallHandler *klee_dispatch_get(int syscall_nr);

#endif /* KLEE_DISPATCH_H */
