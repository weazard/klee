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
#include <sys/types.h>
#include <fcntl.h>
#include <ftw.h>
#include <linux/limits.h>

static char **tmpfs_dirs;
static int tmpfs_count;
static int tmpfs_capacity;
static pid_t tmpfs_pid;

static int register_tmpfs(const char *path)
{
    if (tmpfs_count == tmpfs_capacity) {
        int cap = tmpfs_capacity ? tmpfs_capacity * 2 : 16;
        char **dirs = realloc(tmpfs_dirs, (size_t)cap * sizeof(char *));
        if (!dirs)
            return -ENOMEM;
        tmpfs_dirs = dirs;
        tmpfs_capacity = cap;
    }
    tmpfs_dirs[tmpfs_count] = strdup(path);
    if (!tmpfs_dirs[tmpfs_count])
        return -ENOMEM;
    tmpfs_count++;
    if (tmpfs_pid == 0)
        tmpfs_pid = getpid();
    return 0;
}

/* Create a unique private backing directory.  mkdtemp() guarantees the
 * directory is newly created with mode 0700, so a pre-existing entry
 * planted in /tmp can never become our backing store. */
static char *make_backing_dir(void)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/tmp/klee-%d-XXXXXX", getpid());

    if (!mkdtemp(path)) {
        KLEE_WARN("failed to create tmpfs dir %s: %s", path, strerror(errno));
        return NULL;
    }
    if (chmod(path, 0755) < 0)
        KLEE_WARN("chmod %s failed: %s", path, strerror(errno));

    if (register_tmpfs(path) < 0) {
        rmdir(path);
        return NULL;
    }
    return strdup(path);
}

char *klee_tmpfs_create(const char *guest_dest)
{
    char *path = make_backing_dir();
    if (path)
        KLEE_DEBUG("tmpfs: created %s for guest %s", path, guest_dest);
    return path;
}

char *klee_tmpfs_create_file(const char *guest_dest, int fd)
{
    char *dir_path = make_backing_dir();
    if (!dir_path)
        return NULL;

    /* Use basename of guest_dest */
    const char *base = strrchr(guest_dest, '/');
    base = base ? base + 1 : guest_dest;
    if (!*base)
        base = "data";

    char file_path[PATH_MAX];
    int n = snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, base);
    if (n < 0 || (size_t)n >= sizeof(file_path)) {
        KLEE_WARN("file path too long: %s/%s", dir_path, base);
        free(dir_path);
        return NULL;
    }
    free(dir_path);

    int out_fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        KLEE_WARN("failed to create file %s: %s", file_path, strerror(errno));
        return NULL;
    }

    /* Copy fd contents into the backing file */
    if (fd >= 0) {
        char buf[4096];
        ssize_t r;
        for (;;) {
            r = read(fd, buf, sizeof(buf));
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                KLEE_WARN("read for %s failed: %s", file_path,
                          strerror(errno));
                close(out_fd);
                return NULL;
            }
            if (r == 0)
                break;
            ssize_t written = 0;
            while (written < r) {
                ssize_t w = write(out_fd, buf + written,
                                  (size_t)(r - written));
                if (w < 0) {
                    if (errno == EINTR)
                        continue;
                    KLEE_WARN("write to %s failed: %s", file_path,
                              strerror(errno));
                    close(out_fd);
                    return NULL;
                }
                written += w;
            }
        }
    }

    close(out_fd);
    KLEE_DEBUG("tmpfs file: created %s for guest %s", file_path, guest_dest);
    return strdup(file_path);
}

static int rm_rf_visit(const char *fpath, const struct stat *sb,
                       int typeflag, struct FTW *ftwbuf)
{
    (void)sb;
    (void)ftwbuf;
    if (typeflag == FTW_DP || typeflag == FTW_D)
        return rmdir(fpath);
    return unlink(fpath);
}

static void rm_rf(const char *path)
{
    /* FTW_DEPTH visits children before their directory; FTW_PHYS does
     * not follow symlinks, so only the link itself is removed. */
    if (nftw(path, rm_rf_visit, 32, FTW_DEPTH | FTW_PHYS) < 0)
        KLEE_WARN("cleanup of %s failed: %s", path, strerror(errno));
}

void klee_tmpfs_cleanup(void)
{
    /* Only clean up from the process that created them */
    if (tmpfs_pid != 0 && tmpfs_pid != getpid())
        return;

    for (int i = 0; i < tmpfs_count; i++) {
        if (tmpfs_dirs[i]) {
            KLEE_DEBUG("tmpfs cleanup: %s", tmpfs_dirs[i]);
            rm_rf(tmpfs_dirs[i]);
            free(tmpfs_dirs[i]);
            tmpfs_dirs[i] = NULL;
        }
    }
    free(tmpfs_dirs);
    tmpfs_dirs = NULL;
    tmpfs_count = 0;
    tmpfs_capacity = 0;
}
