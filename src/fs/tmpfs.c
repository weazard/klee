/*
 * Klee - Userspace bwrap translation layer
 * tmpfs backing directory management
 */
#include "fs/tmpfs.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ftw.h>
#include <linux/limits.h>

static char backing_root[sizeof("/tmp/klee-tmp.XXXXXX")];
static pid_t backing_owner;
static unsigned long next_backing;

char *klee_tmpfs_create(const char *guest_dest)
{
    pid_t own_pid = getpid();
    if (backing_owner != own_pid) {
        strcpy(backing_root, "/tmp/klee-tmp.XXXXXX");
        if (!mkdtemp(backing_root))
            return NULL;
        /* A guest can change its real UID. Keep the mount's permissions
         * authoritative while restricting writes to the session root. */
        if (chmod(backing_root, 0711) < 0) {
            int error = errno;
            rmdir(backing_root);
            errno = error;
            return NULL;
        }
        backing_owner = own_pid;
        next_backing = 0;
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%lu", backing_root, next_backing++);
    if (mkdir(path, 0755) < 0)
        return NULL;

    KLEE_DEBUG("tmpfs: created %s for guest %s", path, guest_dest);
    return strdup(path);
}

char *klee_tmpfs_create_file(const char *guest_dest, int fd, mode_t mode)
{
    char *dir = klee_tmpfs_create(guest_dest);
    if (!dir)
        return NULL;

    const char *base = strrchr(guest_dest, '/');
    base = base ? base + 1 : guest_dest;
    if (!*base || strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
        base = "data";

    char path[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s/%s", dir, base);
    free(dir);
    if (length < 0 || (size_t)length >= sizeof(path)) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    int out = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (out < 0)
        return NULL;

    int error = 0;
    char buf[8192];
    ssize_t nread;
    while ((nread = read(fd, buf, sizeof(buf))) > 0) {
        size_t written = 0;
        while (written < (size_t)nread) {
            ssize_t n = write(out, buf + written, (size_t)nread - written);
            if (n <= 0) {
                error = n < 0 ? errno : EIO;
                break;
            }
            written += (size_t)n;
        }
        if (error)
            break;
    }
    if (nread < 0)
        error = errno;
    if (!error && fchmod(out, mode) < 0)
        error = errno;
    if (close(out) < 0 && !error)
        error = errno;
    if (error) {
        unlink(path);
        errno = error;
        return NULL;
    }

    KLEE_DEBUG("tmpfs file: created %s for guest %s", path, guest_dest);
    return strdup(path);
}

static int remove_backing(const char *path, const struct stat *st, int type,
                          struct FTW *info)
{
    (void)st;
    (void)type;
    (void)info;
    if (remove(path) < 0 && errno != ENOENT) {
        KLEE_WARN("cannot remove backing path %s: %s", path, strerror(errno));
        return 1;
    }
    return 0;
}

void klee_tmpfs_cleanup(void)
{
    if (backing_owner != getpid())
        return;
    if (nftw(backing_root, remove_backing, 16, FTW_DEPTH | FTW_PHYS | FTW_MOUNT) < 0 &&
        errno != ENOENT)
        KLEE_WARN("cannot clean up %s: %s", backing_root, strerror(errno));
    backing_owner = 0;
}
