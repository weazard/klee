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

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif

/*
 * Confirm the notification being serviced is still alive.  If the target
 * died, its PID may have been recycled and /proc/<pid>/mem could belong
 * to an unrelated process (see seccomp_unotify(2) "Caveats").
 */
static int notif_still_valid(KleeInterceptor *self)
{
    uint64_t id = self->seccomp.cur_notif_id;
    if (ioctl(self->seccomp.notif_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) < 0)
        return -ESRCH;
    return 0;
}

/* Read memory from tracee using /proc/pid/mem */
static int seccomp_read_mem(KleeInterceptor *self, pid_t pid,
                            void *local, const void *remote, size_t len)
{
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
    return notif_still_valid(self);
}

/* Write memory to tracee using /proc/pid/mem */
static int seccomp_write_mem(KleeInterceptor *self, pid_t pid,
                             const void *remote, const void *local, size_t len)
{
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
    return notif_still_valid(self);
}

/* Wait for a seccomp notification event */
static int seccomp_wait_event(KleeInterceptor *self, KleeEvent *out)
{
    memset(out, 0, sizeof(*out));

    /* Allocate the kernel-sized notification buffer once and reuse it */
    if (!self->seccomp.notif_buf) {
        struct seccomp_notif_sizes sizes;
        if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) < 0)
            sizes.seccomp_notif = sizeof(struct seccomp_notif);
        if (sizes.seccomp_notif < sizeof(struct seccomp_notif))
            sizes.seccomp_notif = sizeof(struct seccomp_notif);
        self->seccomp.notif_buf = calloc(1, sizes.seccomp_notif);
        if (!self->seccomp.notif_buf)
            return -ENOMEM;
        self->seccomp.notif_buf_size = sizes.seccomp_notif;
    }

    struct seccomp_notif *notif = self->seccomp.notif_buf;
    memset(notif, 0, self->seccomp.notif_buf_size);

    if (ioctl(self->seccomp.notif_fd, SECCOMP_IOCTL_NOTIF_RECV, notif) < 0)
        return -errno;

    out->type = KLEE_EVENT_SYSCALL_ENTER;
    out->pid = notif->pid;
    out->syscall_nr = notif->data.nr;
    out->notif_id = notif->id;
    for (int i = 0; i < 6; i++)
        out->args[i] = notif->data.args[i];

    self->seccomp.cur_notif_id = notif->id;
    return 0;
}

/* Respond to a seccomp notification */
static int seccomp_respond(KleeInterceptor *self, KleeEvent *event,
                           long retval, int err)
{
    struct seccomp_notif_resp resp;
    memset(&resp, 0, sizeof(resp));

    resp.id = event->notif_id;
    resp.val = retval;
    resp.error = err ? -err : 0;
    resp.flags = (err == 0 && retval == 0 && !event->emulated)
                     ? SECCOMP_USER_NOTIF_FLAG_CONTINUE : 0;

    if (ioctl(self->seccomp.notif_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) < 0) {
        if (errno == ENOENT) {
            KLEE_DEBUG("target process %d died before response", event->pid);
            return -ESRCH;
        }
        return -errno;
    }
    return 0;
}

/*
 * No-op continuation hooks.  Unlike ptrace, seccomp_unotify has no
 * per-stop resume step: everything goes through respond() with the
 * notification id.  These exist only to satisfy the backend interface.
 */
static int seccomp_continue(KleeInterceptor *self, pid_t pid, int signal)
{
    (void)self; (void)pid; (void)signal;
    return 0;
}

static int seccomp_skip(KleeInterceptor *self, pid_t pid, long retval)
{
    (void)self; (void)pid; (void)retval;
    return 0;
}

static void seccomp_destroy(KleeInterceptor *self)
{
    if (self->seccomp.notif_fd >= 0)
        close(self->seccomp.notif_fd);
    if (self->seccomp.listener_fd >= 0)
        close(self->seccomp.listener_fd);
    if (self->seccomp.fd_pipe[0] >= 0)
        close(self->seccomp.fd_pipe[0]);
    if (self->seccomp.fd_pipe[1] >= 0)
        close(self->seccomp.fd_pipe[1]);
    free(self->seccomp.notif_buf);
    free(self);
}

int klee_seccomp_notif_available(void)
{
    struct seccomp_notif_sizes sizes;
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0)
        return 0;

    /* The parent fetches the child's listener fd with pidfd_getfd
     * (kernel 5.6+); without it we must fall back to ptrace.
     * Probe by duplicating one of our own fds. */
    int pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (pidfd < 0)
        return 0;
    int fd = (int)syscall(SYS_pidfd_getfd, pidfd, 0, 0);
    close(pidfd);
    if (fd < 0)
        return 0;
    close(fd);
    return 1;
}

KleeInterceptor *klee_seccomp_notif_create(void)
{
    KleeInterceptor *ic = calloc(1, sizeof(KleeInterceptor));
    if (!ic)
        return NULL;

    ic->backend = INTERCEPT_SECCOMP_UNOTIFY;
    ic->seccomp.notif_fd = -1;
    ic->seccomp.listener_fd = -1;

    /* Channel for the child to publish its listener fd number */
    if (pipe2(ic->seccomp.fd_pipe, O_CLOEXEC) < 0) {
        free(ic);
        return NULL;
    }

    ic->wait_event = seccomp_wait_event;
    ic->respond = seccomp_respond;
    ic->continue_syscall = seccomp_continue;
    ic->continue_running = seccomp_continue;
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

#endif /* HAVE_SECCOMP_UNOTIFY */
