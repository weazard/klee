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
#include <sys/wait.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif

KleeInterceptor *klee_interceptor_create(void)
{
#ifdef HAVE_SECCOMP_UNOTIFY
    if (klee_seccomp_notif_available()) {
        KLEE_INFO("using seccomp_unotify interception backend");
        return klee_seccomp_notif_create();
    }
    KLEE_INFO("seccomp_unotify not available, falling back to ptrace");
#else
    KLEE_INFO("seccomp_unotify not compiled in, using ptrace backend");
#endif
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
        int syscalls[KLEE_MAX_INTERCEPTED_SYSCALLS];
        int count = klee_get_intercepted_syscalls(syscalls, KLEE_MAX_INTERCEPTED_SYSCALLS);
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
        klee_bpf_free(&prog);

        interceptor->seccomp.listener_fd = fd;

        /* Publish the fd NUMBER to the parent, which fetches its own
         * copy via pidfd_getfd.  SCM_RIGHTS can't be used here: sendmsg
         * is itself an intercepted syscall and would block until the
         * supervisor services it — which it can't before it has the
         * listener fd. */
        if (interceptor->seccomp.fd_pipe[1] >= 0) {
            if (write(interceptor->seccomp.fd_pipe[1], &fd, sizeof(fd))
                    != (ssize_t)sizeof(fd))
                return -EIO;
            close(interceptor->seccomp.fd_pipe[1]);
            interceptor->seccomp.fd_pipe[1] = -1;
        }
        if (interceptor->seccomp.fd_pipe[0] >= 0) {
            close(interceptor->seccomp.fd_pipe[0]);
            interceptor->seccomp.fd_pipe[0] = -1;
        }
        return 0;
#else
        return -ENOTSUP;
#endif
    } else {
        /* ptrace: TRACEME + SIGSTOP, then install seccomp pre-filter.
         *
         * Sequence: child does TRACEME + SIGSTOP → parent catches the stop,
         * sets PTRACE_O_TRACESECCOMP, and resumes us → we install the BPF
         * filter (SECCOMP_RET_TRACE for intercepted syscalls) → write status
         * to pipe so parent knows whether the filter is active. */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
            return -errno;
        raise(SIGSTOP);

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

        /* Signal status to parent via pipe */
        if (interceptor->ptrace.status_pipe[1] >= 0) {
            (void)!write(interceptor->ptrace.status_pipe[1], &filter_ok, 1);
            close(interceptor->ptrace.status_pipe[1]);
            interceptor->ptrace.status_pipe[1] = -1;
        }
        if (interceptor->ptrace.status_pipe[0] >= 0) {
            close(interceptor->ptrace.status_pipe[0]);
            interceptor->ptrace.status_pipe[0] = -1;
        }
        return 0;
    }
}

int klee_interceptor_setup_parent(KleeInterceptor *interceptor, pid_t child_pid)
{
    if (interceptor->backend == INTERCEPT_SECCOMP_UNOTIFY) {
        /* The listener fd exists only in the child (the filter has to be
         * installed there).  Read its fd number from the pipe and fetch
         * our own copy with pidfd_getfd. */
        if (interceptor->seccomp.fd_pipe[1] >= 0) {
            close(interceptor->seccomp.fd_pipe[1]);
            interceptor->seccomp.fd_pipe[1] = -1;
        }

        int child_fd = -1;
        ssize_t n = -1;
        if (interceptor->seccomp.fd_pipe[0] >= 0) {
            do {
                n = read(interceptor->seccomp.fd_pipe[0],
                         &child_fd, sizeof(child_fd));
            } while (n < 0 && errno == EINTR);
            close(interceptor->seccomp.fd_pipe[0]);
            interceptor->seccomp.fd_pipe[0] = -1;
        }
        if (n != (ssize_t)sizeof(child_fd) || child_fd < 0) {
            KLEE_ERROR("child did not publish seccomp listener fd");
            return -EIO;
        }

        int pidfd = (int)syscall(SYS_pidfd_open, child_pid, 0);
        if (pidfd < 0) {
            int err = errno;
            KLEE_ERROR("pidfd_open(%d) failed: %s",
                       child_pid, strerror(err));
            return -err;
        }
        int fd = (int)syscall(SYS_pidfd_getfd, pidfd, child_fd, 0);
        int err = errno;
        close(pidfd);
        if (fd < 0) {
            KLEE_ERROR("pidfd_getfd failed: %s", strerror(err));
            return -err;
        }

        interceptor->seccomp.notif_fd = fd;
        return 0;
    } else {
        /* ptrace: wait for child's SIGSTOP, set options (including
         * TRACESECCOMP), resume child so it can install the BPF filter,
         * then drain ptrace stops until we read the status from the pipe. */
        int status;
        pid_t p = waitpid(child_pid, &status, 0);
        if (p < 0)
            return -errno;

        if (ptrace(PTRACE_SETOPTIONS, child_pid, NULL,
                   (void *)(unsigned long)interceptor->ptrace.options) < 0)
            return -errno;

        /* Resume child — it will install the BPF filter and write to the pipe */
        if (ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL) < 0)
            return -errno;

        /* Close our copy of the write end */
        if (interceptor->ptrace.status_pipe[1] >= 0) {
            close(interceptor->ptrace.status_pipe[1]);
            interceptor->ptrace.status_pipe[1] = -1;
        }

        /* Drain ptrace stops from the child (it makes syscalls to
         * install the filter: prctl, seccomp, write, close).
         * We do NOT dispatch these through the event loop — handling
         * them here avoids the compat seccomp rewriter seeing klee's
         * own seccomp() call. */
        char filter_status = 0;
        bool got_status = false;

        if (interceptor->ptrace.status_pipe[0] < 0) {
            /* No pipe — can't use seccomp pre-filter */
            got_status = true;
        }

        while (!got_status) {
            p = waitpid(child_pid, &status, 0);
            if (p < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }

            KLEE_TRACE("drain: status=%#x stopped=%d sig=%d event=%d",
                        status, WIFSTOPPED(status),
                        WIFSTOPPED(status) ? WSTOPSIG(status) : -1,
                        (status >> 16) & 0xffff);

            /* Try to read filter status from pipe */
            if (interceptor->ptrace.status_pipe[0] >= 0) {
                ssize_t n = read(interceptor->ptrace.status_pipe[0],
                                  &filter_status, 1);
                if (n == 1) {
                    KLEE_TRACE("drain: got pipe status=%d, breaking", filter_status);
                    got_status = true;
                    /* Continue the child past its current stop */
                    if (WIFSTOPPED(status))
                        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
                    break;
                }
            }

            /* Child hasn't finished yet — continue past this stop */
            if (WIFSTOPPED(status)) {
                ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
            } else {
                /* Child exited/signaled during setup */
                break;
            }
        }

        /* Close read end of status pipe */
        if (interceptor->ptrace.status_pipe[0] >= 0) {
            close(interceptor->ptrace.status_pipe[0]);
            interceptor->ptrace.status_pipe[0] = -1;
        }

        if (filter_status) {
            interceptor->ptrace.seccomp_filter = true;
            KLEE_INFO("seccomp pre-filter active (SECCOMP_RET_TRACE)");
        } else {
            KLEE_INFO("seccomp pre-filter not available, using PTRACE_SYSCALL");
        }

        return 0;
    }
}
