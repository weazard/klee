/*
 * Klee - Userspace bwrap translation layer
 * Unified interception API implementation
 */
#include "intercept.h"
#include "seccomp_notif.h"
#include "ptrace_backend.h"
#include "filter.h"
#include "util/log.h"
#include "syscall/sysnum.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

KleeInterceptor *klee_interceptor_create(void)
{
    /* Path and syscall argument translation requires ptrace register access. */
    return klee_ptrace_create();
}

int klee_interceptor_get_seccomp_fd(KleeInterceptor *interceptor)
{
    if (interceptor->backend == INTERCEPT_SECCOMP_UNOTIFY)
        return interceptor->seccomp.notif_fd;
    return -1;
}

int klee_interceptor_install_child(KleeInterceptor *interceptor)
{
    if (interceptor->backend == INTERCEPT_SECCOMP_UNOTIFY) {
#ifdef HAVE_SECCOMP_UNOTIFY
        /* Generate BPF filter for USER_NOTIF */
        int syscalls[KLEE_INTERCEPTED_SYSCALL_COUNT];
        int count = klee_get_intercepted_syscalls(syscalls, KLEE_INTERCEPTED_SYSCALL_COUNT);
        if (count <= 0) {
            KLEE_ERROR("no syscalls to intercept");
            return -EINVAL;
        }

        KleeBpfProg prog = klee_bpf_generate_notif_filter(syscalls, (size_t)count);
        if (!prog.filter)
            return -ENOMEM;

        /* Set no-new-privs (required for seccomp) */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            klee_bpf_free(&prog);
            return -errno;
        }

        /* Install filter and get listener fd */
        struct sock_fprog fprog = {
            .len = (unsigned short)prog.len,
            .filter = prog.filter,
        };

        int fd = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                              SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog);
        if (fd < 0) {
            int err = errno;
            klee_bpf_free(&prog);
            KLEE_ERROR("seccomp(NEW_LISTENER) failed: %s", strerror(err));
            return -err;
        }

        interceptor->seccomp.listener_fd = fd;
        klee_bpf_free(&prog);
        return 0;
#else
        return -ENOTSUP;
#endif
    } else {
        close(interceptor->ptrace.startup_fd[0]);
        interceptor->ptrace.startup_fd[0] = -1;
        int fd = interceptor->ptrace.startup_fd[1];
        char ready;
        ssize_t n;
        do {
            n = read(fd, &ready, 1);
        } while (n < 0 && errno == EINTR);
        if (n != 1)
            return n < 0 ? -errno : -EPIPE;

        /* Parent has set PTRACE_O_TRACESECCOMP and resumed us.
         * Now install the BPF filter. */
        char filter_ok = 0;
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0) {
            int syscalls[KLEE_MAX_INTERCEPTED_SYSCALLS];
            int count = klee_get_intercepted_syscalls(syscalls,
                                                       KLEE_MAX_INTERCEPTED_SYSCALLS);
            if (count > 0) {
                KleeBpfProg prog = klee_bpf_generate_trace_filter(
                    syscalls, (size_t)count);
                if (prog.filter) {
                    struct sock_fprog fprog = {
                        .len = (unsigned short)prog.len,
                        .filter = prog.filter,
                    };
                    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                                0, &fprog) == 0)
                        filter_ok = 1;
                    klee_bpf_free(&prog);
                }
            }
        }

        do {
            n = write(fd, &filter_ok, 1);
        } while (n < 0 && errno == EINTR);
        if (n != 1)
            return n < 0 ? -errno : -EIO;

        /* Stop before any guest setup. A breakpoint gives a ptrace stop
         * without issuing a syscall through the filter we just installed. */
        __asm__ volatile("int3" ::: "memory");
        close(fd);
        interceptor->ptrace.startup_fd[1] = -1;
        return 0;
    }
}

int klee_interceptor_setup_parent(KleeInterceptor *interceptor, pid_t child_pid)
{
    if (interceptor->backend == INTERCEPT_SECCOMP_UNOTIFY) {
        /* The listener fd was obtained in install_child, but it's in the child
         * process. We need to receive it via SCM_RIGHTS or pidfd_getfd.
         * For simplicity, we use the listener_fd directly since it was set
         * before the fork. */
        interceptor->seccomp.notif_fd = interceptor->seccomp.listener_fd;
        return 0;
    } else {
        close(interceptor->ptrace.startup_fd[1]);
        interceptor->ptrace.startup_fd[1] = -1;
        int fd = interceptor->ptrace.startup_fd[0];
        if (ptrace(PTRACE_SEIZE, child_pid, NULL, interceptor->ptrace.options) < 0)
            return -errno;

        const char ready = 1;
        if (send(fd, &ready, 1, MSG_NOSIGNAL) != 1)
            return -errno;

        int status;
        pid_t p;
        do {
            p = waitpid(child_pid, &status, __WALL);
        } while (p < 0 && errno == EINTR);
        if (p < 0)
            return -errno;
        if (!WIFSTOPPED(status))
            return -ECHILD;
        if (WSTOPSIG(status) != SIGTRAP || status >> 16)
            return -EIO;

        char filter_status = 0;
        if (recv(fd, &filter_status, 1, MSG_DONTWAIT) != 1)
            return -EIO;
        close(fd);
        interceptor->ptrace.startup_fd[0] = -1;

        if (filter_status) {
            interceptor->ptrace.seccomp_filter = true;
            KLEE_INFO("seccomp pre-filter active (SECCOMP_RET_TRACE)");
        } else {
            KLEE_INFO("seccomp pre-filter not available, using PTRACE_SYSCALL");
        }

        return 0;
    }
}
