/*
 * Klee - seccomp filter test: both ABIs must be trapped.
 *
 * Installs klee's SECCOMP_RET_TRACE filter in this process.  With no
 * tracer attached the kernel fails a trapped syscall with ENOSYS, so an
 * intercepted syscall returning ENOSYS proves the filter matched it and a
 * non-intercepted one succeeding proves it did not.  The i386 ABI is
 * exercised with int $0x80, which x86_64 kernels route through the compat
 * syscall table (seccomp sees AUDIT_ARCH_I386).
 */
#include "intercept/filter.h"
#include "syscall/sysnum.h"
#include "syscall/sysnum32.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

static long sys32(int nr, long a0)
{
    long ret;
    __asm__ volatile ("int $0x80" : "=a"(ret) : "a"(nr), "b"(a0) : "memory");
    return ret;
}

static int failed;
#define CHECK(name, cond) do { \
    printf("  %s... %s\n", name, (cond) ? "OK" : "FAIL"); \
    if (!(cond)) failed++; \
} while (0)

int main(void)
{
    printf("=== seccomp filter (x86_64 + i386) ===\n");

    int nrs[256];
    CHECK("i386 open maps to x86_64 open", klee_sysnum_i386_to_x64(5, NULL) == SYS_open);
    CHECK("i386 stat64 maps to x86_64 stat", klee_sysnum_i386_to_x64(195, NULL) == SYS_stat);
    unsigned flags = 0;
    klee_sysnum_i386_to_x64(102, &flags);
    CHECK("socketcall flagged as demux", flags & KLEE_SYS32_DEMUX);
    klee_sysnum_i386_to_x64(165, &flags);
    CHECK("legacy i386 getresuid uses 16-bit IDs", flags & KLEE_SYS32_UID16);
    CHECK("i386 time64 sched_rr_get_interval is mapped",
          klee_sysnum_i386_to_x64(423, NULL) == SYS_sched_rr_get_interval);
    size_t n = klee_sysnum_x64_to_i386(SYS_stat, nrs, 256);
    CHECK("stat has several i386 spellings", n >= 2);

    int syscalls[KLEE_INTERCEPTED_SYSCALL_COUNT];
    int count = klee_get_intercepted_syscalls(syscalls, KLEE_INTERCEPTED_SYSCALL_COUNT);
    KleeBpfProg prog = klee_bpf_generate_trace_filter(syscalls, (size_t)count);
    CHECK("filter generated", prog.filter != NULL && prog.len > 0);

    struct sock_fprog fprog = { (unsigned short)prog.len, prog.filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
        syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fprog) < 0) {
        printf("  install filter... FAIL (%s)\n", strerror(errno));
        return 1;
    }

    errno = 0;
    long r = syscall(SYS_getpid);
    CHECK("x86_64 getpid trapped", r == -1 && errno == ENOSYS);
    errno = 0;
    r = syscall(SYS_getpgrp);
    CHECK("x86_64 getpgrp trapped", r == -1 && errno == ENOSYS);
    r = syscall(SYS_gettimeofday, 0, 0);
    CHECK("x86_64 gettimeofday allowed", r == 0);
    errno = 0;
    r = syscall(SYS_sendto, -1, NULL, 0, 0, NULL, 0);
    CHECK("connected sendto is passed through", r == -1 && errno == EBADF);

    CHECK("i386 getpid (20) trapped", sys32(20, 0) == -ENOSYS);
    CHECK("i386 open (5) trapped", sys32(5, 0) == -ENOSYS);
    CHECK("i386 stat64 (195) trapped", sys32(195, 0) == -ENOSYS);
    CHECK("i386 socketcall (102) trapped", sys32(102, 0) == -ENOSYS);
    CHECK("i386 time (13) allowed", sys32(13, 0) > 0);

    klee_bpf_free(&prog);
    if (failed)
        printf("%d check(s) failed\n", failed);
    else
        printf("All filter tests passed!\n");
    return failed ? 1 : 0;
}
