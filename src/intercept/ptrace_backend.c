/*
 * Klee - Userspace bwrap translation layer
 * ptrace fallback backend implementation
 */
#include "ptrace_backend.h"
#include "syscall/sysnum32.h"
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
#include <linux/audit.h>
#include <linux/ptrace.h>
#include <sys/syscall.h>
#include <sys/socket.h>

#ifndef PTRACE_EVENT_SECCOMP
#define PTRACE_EVENT_SECCOMP 7
#endif
#ifndef PTRACE_O_TRACESECCOMP
#define PTRACE_O_TRACESECCOMP (1 << PTRACE_EVENT_SECCOMP)
#endif

#ifndef PTRACE_SYSCALL_INFO_ENTRY
#define PTRACE_SYSCALL_INFO_ENTRY   1
#define PTRACE_SYSCALL_INFO_EXIT    2
#define PTRACE_SYSCALL_INFO_SECCOMP 3
struct ptrace_syscall_info {
    uint8_t op, pad[3];
    uint32_t arch;
    uint64_t instruction_pointer, stack_pointer;
    union {
        struct { uint64_t nr, args[6]; } entry;
        struct { int64_t rval; uint8_t is_error; } exit;
        struct { uint64_t nr, args[6]; uint32_t ret_data; } seccomp;
    };
};
#endif
#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif

static void decode_syscall(KleeEvent *out, bool i386, int nr, const uint64_t args[6])
{
    out->raw_nr = nr;
    if (i386) {
        out->abi = KLEE_ABI_I386;
        out->syscall_nr = klee_sysnum_i386_to_x64(nr, &out->abi_flags);
        for (size_t i = 0; i < 6; i++)
            out->args[i] = (uint32_t)args[i];
    } else {
        out->abi = KLEE_ABI_X86_64;
        out->syscall_nr = nr;
        memcpy(out->args, args, sizeof(out->args));
    }
}

#define PTRACE_OPTIONS (PTRACE_O_TRACESYSGOOD | \
                        PTRACE_O_TRACEFORK    | \
                        PTRACE_O_TRACEVFORK   | \
                        PTRACE_O_TRACECLONE   | \
                        PTRACE_O_TRACEEXEC    | \
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
    if (n >= 0 || errno == EFAULT)
        return -EFAULT;
#endif

    /* Fallback: PTRACE_PEEKDATA, word by word */
    size_t off = 0;
    unsigned char *dst = local;
    while (off < len) {
        uintptr_t addr = (uintptr_t)remote + off;
        size_t start = addr % sizeof(long);
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(addr - start), NULL);
        if (errno != 0)
            return -errno;

        size_t chunk = len - off;
        if (chunk > sizeof(long) - start)
            chunk = sizeof(long) - start;
        memcpy(dst + off, (unsigned char *)&word + start, chunk);
        off += chunk;
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
    if (n >= 0 || errno == EFAULT)
        return -EFAULT;
#endif

    size_t off = 0;
    const unsigned char *src = local;
    while (off < len) {
        uintptr_t addr = (uintptr_t)remote + off;
        size_t start = addr % sizeof(long);
        void *word_addr = (void *)(addr - start);
        long word = 0;
        size_t chunk = len - off;
        if (chunk > sizeof(long) - start)
            chunk = sizeof(long) - start;
        if (chunk < sizeof(long)) {
            /* Partial word: read-modify-write */
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid, word_addr, NULL);
            if (errno != 0)
                return -errno;
        }
        memcpy((unsigned char *)&word + start, src + off, chunk);

        if (ptrace(PTRACE_POKEDATA, pid, word_addr, (void *)word) < 0)
            return -errno;
        off += chunk;
    }
    return 0;
}

struct klee_wait_status {
    pid_t pid;
    int status;
};

/* Capture the ready stops before resuming any tracee. A hot thread cannot
 * fill the front of the queue again while its peers are waiting. */
static int next_wait_status(KleeInterceptor *self, struct klee_wait_status *out)
{
    if (self->ptrace.wait_next < self->ptrace.wait_count) {
        *out = self->ptrace.wait_statuses[self->ptrace.wait_next++];
        return 0;
    }
    self->ptrace.wait_next = 0;
    self->ptrace.wait_count = 0;

    out->pid = waitpid(-1, &out->status, __WALL);
    if (out->pid < 0)
        return -errno;

    if (self->ptrace.batch_wait) {
        struct klee_wait_status ready;
        while ((ready.pid = waitpid(-1, &ready.status, __WALL | WNOHANG)) > 0) {
            if (self->ptrace.wait_count == self->ptrace.wait_capacity) {
                size_t capacity = self->ptrace.wait_capacity ?
                                  self->ptrace.wait_capacity * 2 : 16;
                void *statuses = realloc(self->ptrace.wait_statuses,
                                         capacity * sizeof(ready));
                if (!statuses)
                    return -ENOMEM;
                self->ptrace.wait_statuses = statuses;
                self->ptrace.wait_capacity = capacity;
            }
            self->ptrace.wait_statuses[self->ptrace.wait_count++] = ready;
        }
    }
    return 0;
}

static int decode_syscall_stop(KleeInterceptor *self, KleeEvent *out,
                               bool seccomp)
{
    if (!self->ptrace.no_syscall_info) {
        struct ptrace_syscall_info info;
        if (ptrace(PTRACE_GET_SYSCALL_INFO, out->pid, sizeof(info), &info) >= 0) {
            if (info.op == PTRACE_SYSCALL_INFO_EXIT) {
                out->type = KLEE_EVENT_SYSCALL_EXIT;
                out->retval = info.exit.rval;
            } else if (info.op == PTRACE_SYSCALL_INFO_ENTRY ||
                       info.op == PTRACE_SYSCALL_INFO_SECCOMP) {
                uint64_t args[6];
                bool is_seccomp = info.op == PTRACE_SYSCALL_INFO_SECCOMP;
                memcpy(args, is_seccomp ? info.seccomp.args : info.entry.args,
                       sizeof(args));
                out->type = KLEE_EVENT_SYSCALL_ENTER;
                decode_syscall(out, info.arch == AUDIT_ARCH_I386,
                               (int)(is_seccomp ? info.seccomp.nr : info.entry.nr),
                               args);
            } else {
                return -EIO;
            }
            return 0;
        }
        if (errno != EINVAL && errno != EIO && errno != ENOSYS)
            return -errno;
        self->ptrace.no_syscall_info = true;
    }

    /* Older kernels lack syscall info. The pending entry in the event
     * loop disambiguates an exit whose result happens to be -ENOSYS. */
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, out->pid, NULL, &r) < 0)
        return -errno;
    out->retval = (long)r.rax;
    out->unclassified_stop = !seccomp;
    if (!seccomp && out->retval != -ENOSYS) {
        out->type = KLEE_EVENT_SYSCALL_EXIT;
        return 0;
    }

    /* The interrupt instruction can also be issued from 64-bit code. */
    bool i386 = r.cs == 0x23;
    if (!i386 && r.rip >= 2) {
        unsigned char op[2];
        if (ptrace_read_mem(self, out->pid, op, (void *)(uintptr_t)(r.rip - 2),
                            sizeof(op)) == 0)
            i386 = op[0] == 0xcd && op[1] == 0x80;
    }
    uint64_t args64[] = {r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9};
    uint64_t args32[] = {r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.rbp};
    out->type = KLEE_EVENT_SYSCALL_ENTER;
    decode_syscall(out, i386, (int)r.orig_rax, i386 ? args32 : args64);
    return 0;
}

static int ptrace_wait_event(KleeInterceptor *self, KleeEvent *out)
{
    struct klee_wait_status ready;
    int rc = next_wait_status(self, &ready);
    if (rc < 0)
        return rc;
    pid_t pid = ready.pid;
    int status = ready.status;

    memset(out, 0, sizeof(*out));
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

    if (sig == (SIGTRAP | 0x80) || event == PTRACE_EVENT_SECCOMP)
        return decode_syscall_stop(self, out, event == PTRACE_EVENT_SECCOMP);

    unsigned long event_msg;
    switch (event) {
    case PTRACE_EVENT_FORK:
    case PTRACE_EVENT_VFORK:
    case PTRACE_EVENT_CLONE:
        if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &event_msg) < 0)
            return -errno;
        out->type = event == PTRACE_EVENT_CLONE ? KLEE_EVENT_CLONE : KLEE_EVENT_FORK;
        out->new_child_pid = (pid_t)event_msg;
        break;
    case PTRACE_EVENT_EXEC:
        if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &event_msg) < 0)
            return -errno;
        out->type = KLEE_EVENT_EXEC;
        out->former_tid = (pid_t)event_msg;
        break;
    case PTRACE_EVENT_STOP:
        out->type = KLEE_EVENT_STOP;
        out->signal = sig;
        break;
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
 * value on the subsequent syscall-exit stop. */
static int ptrace_skip_syscall(KleeInterceptor *self, pid_t pid, long retval)
{
    (void)self;
    (void)retval;
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0)
        return -errno;

    /* Replace with invalid syscall -1 so kernel returns ENOSYS.
     * The event loop overrides the return value at syscall-exit. */
    regs.orig_rax = -1;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0)
        return -errno;

    return 0;
}

/* Respond to an event (ptrace: skip + continue) */
static int ptrace_respond(KleeInterceptor *self, KleeEvent *event,
                          long retval, int err)
{
    if (err || event->emulated) {
        int rc = ptrace_skip_syscall(self, event->pid, retval);
        if (rc < 0)
            return rc;
    }
    return ptrace_continue(self, event->pid, 0);
}

static void ptrace_destroy(KleeInterceptor *self)
{
    if (self->ptrace.startup_fd[0] >= 0)
        close(self->ptrace.startup_fd[0]);
    if (self->ptrace.startup_fd[1] >= 0)
        close(self->ptrace.startup_fd[1]);
    free(self->ptrace.wait_statuses);
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
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
                   ic->ptrace.startup_fd) < 0) {
        KLEE_ERROR("cannot create ptrace startup socket: %s", strerror(errno));
        free(ic);
        return NULL;
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
