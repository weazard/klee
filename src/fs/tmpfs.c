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
#include <linux/limits.h>

#define MAX_TMPFS_DIRS 256

static char *tmpfs_dirs[MAX_TMPFS_DIRS];
static int tmpfs_count = 0;
static pid_t tmpfs_pid = 0;

static void register_tmpfs(const char *path)
{
    if (tmpfs_count < MAX_TMPFS_DIRS) {
        tmpfs_dirs[tmpfs_count++] = strdup(path);
        if (tmpfs_pid == 0)
            tmpfs_pid = getpid();
    }
}

char *klee_tmpfs_create(const char *guest_dest)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/tmp/klee-%d-%d", getpid(), tmpfs_count);

    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        KLEE_WARN("failed to create tmpfs dir %s: %s", path, strerror(errno));
        return NULL;
    }

    register_tmpfs(path);
    KLEE_DEBUG("tmpfs: created %s for guest %s", path, guest_dest);
    return strdup(path);
}

char *klee_tmpfs_create_file(const char *guest_dest, int fd)
{
    char dir_path[PATH_MAX];
    snprintf(dir_path, sizeof(dir_path), "/tmp/klee-%d-%d", getpid(), tmpfs_count);

    if (mkdir(dir_path, 0755) < 0 && errno != EEXIST) {
        KLEE_WARN("failed to create tmpfs dir: %s", strerror(errno));
        return NULL;
    }

    char file_path[PATH_MAX];
    /* Use basename of guest_dest */
    const char *base = strrchr(guest_dest, '/');
    base = base ? base + 1 : guest_dest;
    if (!*base)
        base = "data";
    int n = snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, base);
    if (n < 0 || (size_t)n >= sizeof(file_path)) {
        KLEE_WARN("file path too long: %s/%s", dir_path, base);
        return NULL;
    }

    /* Read from fd and write to file */
    int out_fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        KLEE_WARN("failed to create file %s: %s", file_path, strerror(errno));
        return NULL;
    }

    if (fd >= 0) {
        char buf[4096];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            ssize_t written = 0;
            while (written < n) {
                ssize_t w = write(out_fd, buf + written, (size_t)(n - written));
                if (w < 0) {
                    close(out_fd);
                    return NULL;
                }
                written += w;
            }
        }
    }

    close(out_fd);
    register_tmpfs(dir_path);
    KLEE_DEBUG("tmpfs file: created %s for guest %s", file_path, guest_dest);
    return strdup(file_path);
}

static int rm_rf(const char *path)
{
    /* Simple recursive delete using system rm */
    char cmd[PATH_MAX + 16];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    return system(cmd);
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
    tmpfs_count = 0;
}
