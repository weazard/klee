/*
 * Klee - Userspace bwrap translation layer
 * ptrace fallback backend implementation
 */
#include "ptrace_backend.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <linux/elf.h>
#include <linux/ptrace.h>
#include <sys/syscall.h>
#include <fcntl.h>

#ifndef PTRACE_EVENT_SECCOMP
#define PTRACE_EVENT_SECCOMP 7
#endif
#ifndef PTRACE_O_TRACESECCOMP
#define PTRACE_O_TRACESECCOMP (1 << PTRACE_EVENT_SECCOMP)
#endif

#define PTRACE_OPTIONS (PTRACE_O_TRACESYSGOOD | \
                        PTRACE_O_TRACEFORK    | \
                        PTRACE_O_TRACEVFORK   | \
                        PTRACE_O_TRACECLONE   | \
                        PTRACE_O_TRACEEXEC    | \
                        PTRACE_O_TRACEEXIT    | \
                        PTRACE_O_TRACESECCOMP | \
                        PTRACE_O_EXITKILL)

/* Read memory using process_vm_readv (fast path) or PTRACE_PEEKDATA (fallback) */
static int ptrace_read_mem(KleeInterceptor *self, pid_t pid,
                           void *local, const void *remote, size_t len)
{
    (void)self;
#ifdef HAVE_PROCESS_VM
    struct iovec local_iov = { local, len };
    struct iovec remote_iov = { (void *)remote, len };
    ssize_t n = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (n == (ssize_t)len)
        return 0;
    /* Fall through to ptrace on failure or partial read (the latter
     * happens when the requested range spans a mapped/unmapped page
     * boundary — common during string reads near the end of a region). */
    KLEE_TRACE("process_vm_readv %s for pid %d, falling back to ptrace",
               n < 0 ? "failed" : "partial", pid);
#endif

    /* Fallback: PTRACE_PEEKDATA, word by word */
    size_t off = 0;
    unsigned char *dst = local;
    const unsigned char *src = remote;

    while (off < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, src + off, NULL);
        if (errno != 0) {
            KLEE_TRACE("PEEKDATA failed: pid=%d addr=%p errno=%d",
                        pid, (void *)(src + off), errno);
            return -errno;
        }

        size_t chunk = len - off;
        if (chunk > sizeof(long))
            chunk = sizeof(long);
        memcpy(dst + off, &word, chunk);
        off += sizeof(long);
    }
    return 0;
}

/* Write memory using process_vm_writev (fast path) or PTRACE_POKEDATA (fallback) */
static int ptrace_write_mem(KleeInterceptor *self, pid_t pid,
                            const void *remote, const void *local, size_t len)
{
    (void)self;

#ifdef HAVE_PROCESS_VM
    struct iovec local_iov = { (void *)local, len };
    struct iovec remote_iov = { (void *)remote, len };
    ssize_t n = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (n == (ssize_t)len)
        return 0;
    if (n >= 0)
        return -EIO;
    KLEE_TRACE("process_vm_writev failed for pid %d, falling back to ptrace", pid);
#endif

    size_t off = 0;
    const unsigned char *src = local;
    const unsigned char *dst = remote;

    while (off < len) {
        long word = 0;
        size_t chunk = len - off;
        if (chunk < sizeof(long)) {
            /* Partial word: read-modify-write */
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid, dst + off, NULL);
            if (errno != 0)
                return -errno;
        }
        if (chunk > sizeof(long))
            chunk = sizeof(long);
        memcpy(&word, src + off, chunk);

        if (ptrace(PTRACE_POKEDATA, pid, dst + off, (void *)word) < 0)
            return -errno;
        off += sizeof(long);
    }
    return 0;
}

/* Wait for next ptrace event */
static int ptrace_wait_event(KleeInterceptor *self, KleeEvent *out)
{
    (void)self;
    int status;
    pid_t pid;

    memset(out, 0, sizeof(*out));

    pid = waitpid(-1, &status, __WALL);
    if (pid < 0) {
        if (errno == ECHILD)
            return -ECHILD;
        return -errno;
    }

    out->pid = pid;

    if (WIFEXITED(status)) {
        out->type = KLEE_EVENT_EXIT;
        out->retval = WEXITSTATUS(status);
        return 0;
    }

    if (WIFSIGNALED(status)) {
        out->type = KLEE_EVENT_EXIT;
        out->signal = WTERMSIG(status);
        out->retval = 128 + out->signal;
        return 0;
    }

    if (!WIFSTOPPED(status))
        return -EINVAL;

    int sig = WSTOPSIG(status);
    int event = (status >> 16) & 0xffff;

    /* Syscall stop: SIGTRAP | 0x80 */
    if (sig == (SIGTRAP | 0x80)) {
        /* Read registers to determine syscall number and args */
        struct user_regs_struct regs;
        struct iovec iov = { &regs, sizeof(regs) };
        if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
            return -errno;

        out->syscall_nr = (int)regs.orig_rax;
        out->args[0] = regs.rdi;
        out->args[1] = regs.rsi;
        out->args[2] = regs.rdx;
        out->args[3] = regs.r10;
        out->args[4] = regs.r8;
        out->args[5] = regs.r9;

        /* Determine if this is enter or exit by checking rax.
         * On enter, rax == -ENOSYS. On exit, rax has the return value. */
        if ((long)regs.rax == -ENOSYS)
            out->type = KLEE_EVENT_SYSCALL_ENTER;
        else {
            out->type = KLEE_EVENT_SYSCALL_EXIT;
            out->retval = (long)regs.rax;
        }
        return 0;
    }

    /* ptrace events */
    switch (event) {
    case PTRACE_EVENT_FORK:
    case PTRACE_EVENT_VFORK:
        out->type = KLEE_EVENT_FORK;
        ptrace(PTRACE_GETEVENTMSG, pid, 0, &out->new_child_pid);
        break;
    case PTRACE_EVENT_CLONE:
        out->type = KLEE_EVENT_CLONE;
        ptrace(PTRACE_GETEVENTMSG, pid, 0, &out->new_child_pid);
        break;
    case PTRACE_EVENT_EXEC:
        out->type = KLEE_EVENT_EXEC;
        break;
    case PTRACE_EVENT_EXIT:
        out->type = KLEE_EVENT_EXIT;
        ptrace(PTRACE_GETEVENTMSG, pid, 0, &out->retval);
        break;
    case PTRACE_EVENT_SECCOMP: {
        /* Seccomp pre-filter fired SECCOMP_RET_TRACE — this is a
         * syscall-enter stop for a syscall klee needs to intercept. */
        struct user_regs_struct seccomp_regs;
        struct iovec seccomp_iov = { &seccomp_regs, sizeof(seccomp_regs) };
        if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &seccomp_iov) < 0)
            return -errno;
        out->type = KLEE_EVENT_SYSCALL_ENTER;
        out->syscall_nr = (int)seccomp_regs.orig_rax;
        out->args[0] = seccomp_regs.rdi;
        out->args[1] = seccomp_regs.rsi;
        out->args[2] = seccomp_regs.rdx;
        out->args[3] = seccomp_regs.r10;
        out->args[4] = seccomp_regs.r8;
        out->args[5] = seccomp_regs.r9;
        break;
    }
    default:
        /* Regular signal delivery */
        out->type = KLEE_EVENT_SIGNAL;
        out->signal = sig;
        break;
    }

    return 0;
}

/* Continue a traced process */
static int ptrace_continue(KleeInterceptor *self, pid_t pid, int signal)
{
    (void)self;
    if (ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(long)signal) < 0)
        return -errno;
    return 0;
}

/* Continue a traced process after a non-enter event.
 * With seccomp pre-filter: PTRACE_CONT (only intercepted syscalls will stop).
 * Without: PTRACE_SYSCALL (same as continue_syscall — stop at every syscall). */
static int ptrace_continue_running(KleeInterceptor *self, pid_t pid, int signal)
{
    int req = self->ptrace.seccomp_filter ? PTRACE_CONT : PTRACE_SYSCALL;
    if (ptrace(req, pid, NULL, (void *)(long)signal) < 0)
        return -errno;
    return 0;
}

/* Skip a syscall by replacing orig_rax with -1 (invalid).
 * The kernel will return -ENOSYS; the caller must override the return
 * value on the subsequent syscall-exit stop via deny_errno. */
static int ptrace_skip_syscall(KleeInterceptor *self, pid_t pid, long retval)
{
    (void)self;
    (void)retval;
    struct user_regs_struct regs;
    struct iovec iov = { &regs, sizeof(regs) };

    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
        return -errno;

    /* Replace with invalid syscall -1 so kernel returns ENOSYS.
     * The event loop overrides the return value at syscall-exit. */
    regs.orig_rax = -1;

    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0)
        return -errno;

    return 0;
}

/* Respond to an event (ptrace: skip + continue) */
static int ptrace_respond(KleeInterceptor *self, KleeEvent *event,
                          long retval, int err)
{
    (void)retval;
    if (err) {
        ptrace_skip_syscall(self, event->pid, -err);
    }
    return ptrace_continue(self, event->pid, 0);
}

static void ptrace_destroy(KleeInterceptor *self)
{
    if (self->ptrace.status_pipe[0] >= 0)
        close(self->ptrace.status_pipe[0]);
    if (self->ptrace.status_pipe[1] >= 0)
        close(self->ptrace.status_pipe[1]);
    free(self);
}

KleeInterceptor *klee_ptrace_create(void)
{
    KleeInterceptor *ic = calloc(1, sizeof(KleeInterceptor));
    if (!ic)
        return NULL;

    ic->backend = INTERCEPT_PTRACE;
    ic->ptrace.options = PTRACE_OPTIONS;
    ic->ptrace.seccomp_filter = false;
    ic->ptrace.status_pipe[0] = -1;
    ic->ptrace.status_pipe[1] = -1;

    /* Create pipe for child→parent seccomp filter status notification */
    int pfd[2];
    if (pipe2(pfd, O_CLOEXEC | O_NONBLOCK) == 0) {
        ic->ptrace.status_pipe[0] = pfd[0];
        ic->ptrace.status_pipe[1] = pfd[1];
    } else {
        KLEE_WARN("pipe2 for seccomp status failed: %s (seccomp pre-filter disabled)",
                   strerror(errno));
    }

    ic->wait_event = ptrace_wait_event;
    ic->respond = ptrace_respond;
    ic->continue_syscall = ptrace_continue;
    ic->continue_running = ptrace_continue_running;
    ic->skip_syscall = ptrace_skip_syscall;
    ic->read_mem = ptrace_read_mem;
    ic->write_mem = ptrace_write_mem;
    ic->destroy = ptrace_destroy;

    return ic;
}
