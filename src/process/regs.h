/*
 * Klee - Userspace bwrap translation layer
 * Register access abstraction
 */
#ifndef KLEE_REGS_H
#define KLEE_REGS_H

#include "process/process.h"
#include "intercept/intercept.h"
#include <sys/user.h>
#include <stdint.h>

/* Fetch current registers from tracee */
int klee_regs_fetch(KleeInterceptor *ic, KleeProcess *proc);

/* Push modified registers to tracee */
int klee_regs_push(KleeInterceptor *ic, KleeProcess *proc);

/* Save original registers (call at syscall enter) */
void klee_regs_save_original(KleeProcess *proc);

/* Restore original registers */
void klee_regs_restore_original(KleeProcess *proc);

/* Get/set syscall number */
int klee_regs_get_sysnum(const KleeProcess *proc);
void klee_regs_set_sysnum(KleeProcess *proc, int sysnum);

/* Get/set syscall arguments (0-5) */
uint64_t klee_regs_get_arg(const KleeProcess *proc, int n);
void klee_regs_set_arg(KleeProcess *proc, int n, uint64_t value);

/* Get/set syscall return value */
long klee_regs_get_result(const KleeProcess *proc);
void klee_regs_set_result(KleeProcess *proc, long value);

/* Get instruction pointer */
uint64_t klee_regs_get_ip(const KleeProcess *proc);

/* Get stack pointer */
uint64_t klee_regs_get_sp(const KleeProcess *proc);

#endif /* KLEE_REGS_H */
