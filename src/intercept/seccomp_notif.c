/*
 * Klee - Userspace bwrap translation layer
 * seccomp_unotify backend implementation
 */
#include "seccomp_notif.h"
#include "filter.h"
#include "util/log.h"
#include "syscall/sysnum.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>

#ifdef HAVE_SECCOMP_UNOTIFY

#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_RECV       _IOWR('!', 0, struct seccomp_notif)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_SEND
#define SECCOMP_IOCTL_NOTIF_SEND       _IOWR('!', 1, struct seccomp_notif_resp)
#endif
#ifndef SECCOMP_IOCTL_NOTIF_ID_VALID
#define SECCOMP_IOCTL_NOTIF_ID_VALID   _IOW('!', 2, __u64)
#endif
#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES        3
#endif

#ifndef SECCOMP_ADDFD_FLAG_SETFD
#define SECCOMP_ADDFD_FLAG_SETFD (1UL << 0)
#endif


/* Read memory from tracee using /proc/pid/mem */
static int seccomp_read_mem(KleeInterceptor *self, pid_t pid,
                            void *local, const void *remote, size_t len)
{
    (void)self;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        KLEE_DEBUG("failed to open %s: %s", path, strerror(errno));
        return -errno;
    }

    ssize_t n = pread(fd, local, len, (off_t)(uintptr_t)remote);
    close(fd);

    if (n < 0)
        return -errno;
    if ((size_t)n != len)
        return -EIO;
    return 0;
}

/* Write memory to tracee using /proc/pid/mem */
static int seccomp_write_mem(KleeInterceptor *self, pid_t pid,
                             const void *remote, const void *local, size_t len)
{
    (void)self;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        KLEE_DEBUG("failed to open %s for write: %s", path, strerror(errno));
        return -errno;
    }

    ssize_t n = pwrite(fd, local, len, (off_t)(uintptr_t)remote);
    close(fd);

    if (n < 0)
        return -errno;
    if ((size_t)n != len)
        return -EIO;
    return 0;
}

/* Wait for a seccomp notification event */
static int seccomp_wait_event(KleeInterceptor *self, KleeEvent *out)
{
    struct seccomp_notif *notif;
    struct seccomp_notif_sizes sizes;

    memset(out, 0, sizeof(*out));

    /* Get notification sizes */
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0) {
        /* Fallback to compile-time size */
        sizes.seccomp_notif = sizeof(struct seccomp_notif);
    }

    notif = calloc(1, sizes.seccomp_notif);
    if (!notif)
        return -ENOMEM;

    if (ioctl(self->seccomp.notif_fd, SECCOMP_IOCTL_NOTIF_RECV, notif) < 0) {
        int err = errno;
        free(notif);
        if (err == EINTR)
            return -EINTR;
        if (err == EAGAIN || err == EWOULDBLOCK)
            return -EAGAIN;
        return -err;
    }

    out->type = KLEE_EVENT_SYSCALL_ENTER;
    out->pid = notif->pid;
    out->syscall_nr = notif->data.nr;
    out->notif_id = notif->id;
    for (int i = 0; i < 6; i++)
        out->args[i] = notif->data.args[i];

    free(notif);
    return 0;
}

/* Respond to a seccomp notification: CONTINUE or return error.
 *
 * Convention:
 *   err == 0:  CONTINUE — let the kernel execute the syscall as-is
 *              (path translation has already been written in-place to
 *              tracee memory, so the kernel picks up the new path).
 *   err != 0:  Return -err to the tracee (skip the real syscall).
 */
static int seccomp_respond(KleeInterceptor *self, KleeEvent *event,
                           long retval, int err)
{
    (void)retval;
    struct seccomp_notif_resp resp;
    memset(&resp, 0, sizeof(resp));

    resp.id = event->notif_id;

    if (err) {
        /* Deny: return error to the tracee */
        resp.val = 0;
        resp.error = -err;
        resp.flags = 0;
    } else {
        /* Allow: let the kernel execute the syscall */
        resp.val = 0;
        resp.error = 0;
        resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    }

    if (ioctl(self->seccomp.notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
        if (errno == ENOENT) {
            KLEE_DEBUG("target process %d died before response", event->pid);
            return -ESRCH;
        }
        KLEE_DEBUG("NOTIF_SEND failed: %s (pid=%d id=%llu flags=0x%x err=%d)",
                    strerror(errno), event->pid,
                    (unsigned long long)resp.id, resp.flags, resp.error);
        return -errno;
    }
    return 0;
}

/* Continue syscall — for unotify this is a no-op because all continuation
 * is done through respond().  The event loop calls respond() directly
 * for the unotify backend; continue_syscall is only called for ptrace. */
static int seccomp_continue(KleeInterceptor *self, pid_t pid, int signal)
{
    (void)self;
    (void)pid;
    (void)signal;
    return 0;
}

/* Continue running (after non-enter events like fork, exec, exit, signal).
 * For unotify, these events come from signalfd/waitpid, not from seccomp
 * notifications, so there's nothing to "continue". */
static int seccomp_continue_running(KleeInterceptor *self, pid_t pid, int signal)
{
    (void)self;
    (void)pid;
    (void)signal;
    return 0;
}

/* Skip syscall — for unotify, skipping is done via respond_value().
 * This stub exists for vtable completeness. */
static int seccomp_skip(KleeInterceptor *self, pid_t pid, long retval)
{
    (void)self;
    (void)pid;
    (void)retval;
    return 0;
}

static void seccomp_destroy(KleeInterceptor *self)
{
    if (self->seccomp.notif_fd >= 0)
        close(self->seccomp.notif_fd);
    if (self->seccomp.listener_fd >= 0)
        close(self->seccomp.listener_fd);
    if (self->seccomp.setup_pipe[0] >= 0)
        close(self->seccomp.setup_pipe[0]);
    if (self->seccomp.setup_pipe[1] >= 0)
        close(self->seccomp.setup_pipe[1]);
    free(self);
}

int klee_seccomp_notif_available(void)
{
    struct seccomp_notif_sizes sizes;
    return syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == 0;
}

/* Respond by returning a specific value to the tracee WITHOUT executing
 * the real syscall.  Used when an enter handler fully handles the syscall
 * (e.g., getpid returning a virtual PID, getcwd returning a virtual CWD). */
int klee_seccomp_notif_respond_value(KleeInterceptor *ic, KleeEvent *event,
                                      long retval)
{
    struct seccomp_notif_resp resp;
    memset(&resp, 0, sizeof(resp));

    resp.id = event->notif_id;
    resp.val = retval;
    resp.error = 0;
    resp.flags = 0; /* Don't CONTINUE — return our value instead */

    if (ioctl(ic->seccomp.notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
        if (errno == ENOENT) {
            KLEE_DEBUG("target process %d died before respond_value", event->pid);
            return -ESRCH;
        }
        return -errno;
    }
    return 0;
}

/* Send the seccomp listener FD number from the child to the parent via
 * a pipe.  Uses write() which is NOT in the intercepted syscall list,
 * so it works even after the seccomp USER_NOTIF filter is installed.
 * (sendmsg IS intercepted, which is why the old SCM_RIGHTS approach
 * deadlocked — the filter trapped sendmsg before anyone was listening.) */
/* NOTE: with CLONE_FILES, close() here affects the parent too.
 * We must not close pipe FDs until after unshare(CLONE_FILES). */
int klee_seccomp_notif_send_fd(KleeInterceptor *ic, int listener_fd)
{
    if (ic->seccomp.setup_pipe[1] < 0)
        return -EINVAL;

    ssize_t n = write(ic->seccomp.setup_pipe[1], &listener_fd, sizeof(listener_fd));
    if (n != sizeof(listener_fd))
        return -errno;
    return 0;
}

/* Receive the seccomp listener FD from the child.  The child writes the
 * FD number over a pipe.  Since we forked with CLONE_FILES (shared FD
 * table), the FD is directly accessible in the parent's table.
 *
 * IMPORTANT: we must NOT close the pipe write end before reading — with
 * CLONE_FILES the FD table is shared, so closing the write end here
 * would also close it in the child (preventing it from writing). */
int klee_seccomp_notif_recv_fd(KleeInterceptor *ic)
{
    if (ic->seccomp.setup_pipe[0] < 0)
        return -EINVAL;

    /* Poll for data with a timeout (can't close write end to get EOF
     * because CLONE_FILES means it's shared with the child). */
    struct pollfd pfd = { .fd = ic->seccomp.setup_pipe[0], .events = POLLIN };
    int ret = poll(&pfd, 1, 10000);  /* 10s timeout */
    if (ret <= 0) {
        KLEE_ERROR("timed out waiting for seccomp listener fd from child");
        return -ETIMEDOUT;
    }

    int fd;
    ssize_t n = read(ic->seccomp.setup_pipe[0], &fd, sizeof(fd));

    if (n == 0)
        return -ECONNRESET;
    if (n != sizeof(fd))
        return -EIO;

    return fd;
}

KleeInterceptor *klee_seccomp_notif_create(void)
{
    KleeInterceptor *ic = calloc(1, sizeof(KleeInterceptor));
    if (!ic)
        return NULL;

    ic->backend = INTERCEPT_SECCOMP_UNOTIFY;
    ic->seccomp.notif_fd = -1;
    ic->seccomp.listener_fd = -1;
    ic->seccomp.setup_pipe[0] = -1;
    ic->seccomp.setup_pipe[1] = -1;

    /* Create pipe for child→parent listener FD number transfer.
     * We use a pipe + pidfd_getfd() instead of a socketpair + SCM_RIGHTS
     * because sendmsg is in our intercepted syscall list.  After the child
     * installs the seccomp USER_NOTIF filter, sendmsg would be trapped
     * with no listener yet, causing a deadlock.  write() is not intercepted. */
    int pfd[2];
    if (pipe2(pfd, O_CLOEXEC) < 0) {
        KLEE_ERROR("pipe for unotify FD transfer failed: %s",
                    strerror(errno));
        free(ic);
        return NULL;
    }
    ic->seccomp.setup_pipe[0] = pfd[0];
    ic->seccomp.setup_pipe[1] = pfd[1];

    ic->wait_event = seccomp_wait_event;
    ic->respond = seccomp_respond;
    ic->continue_syscall = seccomp_continue;
    ic->continue_running = seccomp_continue_running;
    ic->skip_syscall = seccomp_skip;
    ic->read_mem = seccomp_read_mem;
    ic->write_mem = seccomp_write_mem;
    ic->destroy = seccomp_destroy;

    return ic;
}

#else /* !HAVE_SECCOMP_UNOTIFY */

int klee_seccomp_notif_available(void)
{
    return 0;
}

KleeInterceptor *klee_seccomp_notif_create(void)
{
    KLEE_ERROR("seccomp_unotify not available (compiled without support)");
    return NULL;
}

int klee_seccomp_notif_respond_value(KleeInterceptor *ic, KleeEvent *event,
                                      long retval)
{
    (void)ic; (void)event; (void)retval;
    return -ENOTSUP;
}

int klee_seccomp_notif_send_fd(KleeInterceptor *ic, int listener_fd)
{
    (void)ic; (void)listener_fd;
    return -ENOTSUP;
}

int klee_seccomp_notif_recv_fd(KleeInterceptor *ic)
{
    (void)ic;
    return -ENOTSUP;
}

#endif /* HAVE_SECCOMP_UNOTIFY */
