/*
 * Klee - Userspace bwrap translation layer
 * Register access implementation (x86_64)
 */
#include "process/regs.h"
#include "util/log.h"

#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <linux/elf.h>

int klee_regs_fetch(KleeInterceptor *ic, KleeProcess *proc)
{
    if (ic->backend == INTERCEPT_PTRACE) {
        struct iovec iov = {
            &proc->regs[REG_CURRENT],
            sizeof(struct user_regs_struct)
        };
        if (ptrace(PTRACE_GETREGSET, proc->real_pid, NT_PRSTATUS, &iov) < 0)
            return -errno;
    }
    /* For seccomp_unotify, registers come from the notification struct */
    return 0;
}

int klee_regs_push(KleeInterceptor *ic, KleeProcess *proc)
{
    if (ic->backend == INTERCEPT_PTRACE) {
        struct iovec iov = {
            &proc->regs[REG_CURRENT],
            sizeof(struct user_regs_struct)
        };
        if (ptrace(PTRACE_SETREGSET, proc->real_pid, NT_PRSTATUS, &iov) < 0)
            return -errno;
    }
    return 0;
}

void klee_regs_save_original(KleeProcess *proc)
{
    memcpy(&proc->regs[REG_ORIGINAL], &proc->regs[REG_CURRENT],
           sizeof(struct user_regs_struct));
}

void klee_regs_restore_original(KleeProcess *proc)
{
    memcpy(&proc->regs[REG_CURRENT], &proc->regs[REG_ORIGINAL],
           sizeof(struct user_regs_struct));
}

/* x86_64 register mapping for syscall arguments:
 * arg0 = rdi, arg1 = rsi, arg2 = rdx, arg3 = r10, arg4 = r8, arg5 = r9
 * syscall number = orig_rax
 * return value = rax
 */

int klee_regs_get_sysnum(const KleeProcess *proc)
{
    return (int)proc->regs[REG_CURRENT].orig_rax;
}

void klee_regs_set_sysnum(KleeProcess *proc, int sysnum)
{
    proc->regs[REG_CURRENT].orig_rax = (unsigned long long)sysnum;
}

uint64_t klee_regs_get_arg(const KleeProcess *proc, int n)
{
    const struct user_regs_struct *r = &proc->regs[REG_CURRENT];
    switch (n) {
    case 0: return r->rdi;
    case 1: return r->rsi;
    case 2: return r->rdx;
    case 3: return r->r10;
    case 4: return r->r8;
    case 5: return r->r9;
    default: return 0;
    }
}

void klee_regs_set_arg(KleeProcess *proc, int n, uint64_t value)
{
    struct user_regs_struct *r = &proc->regs[REG_CURRENT];
    switch (n) {
    case 0: r->rdi = value; break;
    case 1: r->rsi = value; break;
    case 2: r->rdx = value; break;
    case 3: r->r10 = value; break;
    case 4: r->r8 = value; break;
    case 5: r->r9 = value; break;
    }
}

long klee_regs_get_result(const KleeProcess *proc)
{
    return (long)proc->regs[REG_CURRENT].rax;
}

void klee_regs_set_result(KleeProcess *proc, long value)
{
    proc->regs[REG_CURRENT].rax = (unsigned long long)value;
}

uint64_t klee_regs_get_ip(const KleeProcess *proc)
{
    return proc->regs[REG_CURRENT].rip;
}

uint64_t klee_regs_get_sp(const KleeProcess *proc)
{
    return proc->regs[REG_CURRENT].rsp;
}
