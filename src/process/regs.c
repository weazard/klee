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
        /* PTRACE_GETREGS: the 64-bit register view for every tracee.
         * GETREGSET would return the i386 layout for a 32-bit one. */
        if (ptrace(PTRACE_GETREGS, proc->real_pid, NULL,
                   &proc->regs[REG_CURRENT]) < 0)
            return -errno;
    }
    /* For seccomp_unotify, registers come from the notification struct */
    return 0;
}

int klee_regs_push(KleeInterceptor *ic, KleeProcess *proc)
{
    if (ic->backend == INTERCEPT_PTRACE) {
        if (ptrace(PTRACE_SETREGS, proc->real_pid, NULL,
                   &proc->regs[REG_CURRENT]) < 0)
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

/* Register mapping for syscall arguments:
 *   x86_64: arg0 = rdi, arg1 = rsi, arg2 = rdx, arg3 = r10, arg4 = r8, arg5 = r9
 *   i386:   arg0 = ebx, arg1 = ecx, arg2 = edx, arg3 = esi, arg4 = edi, arg5 = ebp
 * syscall number = orig_rax, return value = rax in both.
 */

static uint64_t get_reg_arg(const KleeProcess *proc, int n)
{
    const struct user_regs_struct *r = &proc->regs[REG_CURRENT];
    if (proc->abi == KLEE_ABI_I386) {
        switch (n) {
        case 0: return (uint32_t)r->rbx;
        case 1: return (uint32_t)r->rcx;
        case 2: return (uint32_t)r->rdx;
        case 3: return (uint32_t)r->rsi;
        case 4: return (uint32_t)r->rdi;
        case 5: return (uint32_t)r->rbp;
        default: return 0;
        }
    }
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

static unsigned long long *reg_arg(KleeProcess *proc, int n)
{
    struct user_regs_struct *r = &proc->regs[REG_CURRENT];
    if (proc->abi == KLEE_ABI_I386) {
        switch (n) {
        case 0: return &r->rbx;
        case 1: return &r->rcx;
        case 2: return &r->rdx;
        case 3: return &r->rsi;
        case 4: return &r->rdi;
        case 5: return &r->rbp;
        default: return NULL;
        }
    }
    switch (n) {
    case 0: return &r->rdi;
    case 1: return &r->rsi;
    case 2: return &r->rdx;
    case 3: return &r->r10;
    case 4: return &r->r8;
    case 5: return &r->r9;
    default: return NULL;
    }
}

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
    if (n < 0 || n > 5)
        return 0;
    if (proc->demux_mem)
        return proc->demux_args[n];
    return get_reg_arg(proc, n + proc->arg_shift);
}

void klee_regs_set_arg(KleeProcess *proc, int n, uint64_t value)
{
    if (n < 0 || n > 5)
        return;
    if (proc->demux_mem) {
        proc->demux_args[n] = value;
        proc->demux_dirty = true;
        return;
    }
    klee_regs_set_arg_raw(proc, n + proc->arg_shift, value);
}

void klee_regs_set_arg_raw(KleeProcess *proc, int n, uint64_t value)
{
    unsigned long long *reg = reg_arg(proc, n);
    if (!reg)
        return;
    if (proc->abi == KLEE_ABI_I386)
        value = (*reg & ~(uint64_t)UINT32_MAX) | (uint32_t)value;
    if (*reg == value)
        return;
    unsigned bit = 1u << n;
    if (!(proc->changed_args & bit))
        proc->original_regs[n] = *reg;
    proc->changed_args |= bit;
    *reg = value;
}

void klee_regs_restore_args(KleeProcess *proc)
{
    for (int n = 0; n < 6; n++) {
        if (proc->changed_args & (1u << n))
            *reg_arg(proc, n) = proc->original_regs[n];
    }
    proc->changed_args = 0;
}

void klee_regs_repeat_syscall(KleeProcess *proc)
{
    /* x86 syscall restart returns to the two-byte syscall/int80 instruction. */
    struct user_regs_struct *regs = &proc->regs[REG_CURRENT];
    regs->rip -= 2;
    regs->rax = (unsigned long long)proc->raw_nr;
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
