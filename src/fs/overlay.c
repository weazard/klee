/*
 * Klee - Userspace bwrap translation layer
 * Userspace overlay mount implementation
 *
 * Creates a merged view of multiple directory layers using symlinks
 * in a tmpfs-backed directory. Higher layers shadow lower ones.
 * Writable overlays get a separate upper directory for writes.
 *
 * Key behavioral guarantees matching kernel overlayfs:
 * - overlay_resolve returns real file paths (not symlink paths)
 * - Whiteout tracking hides deleted files from lower layers
 * - Copy-on-write copies file from lower to upper on first write
 */
#include "fs/overlay.h"
#include "fs/tmpfs.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/limits.h>

/* FNV-1a hash for whiteout path keys */
static uint64_t hash_path(const char *path)
{
    uint64_t h = 14695981039346656037ULL;
    for (const char *p = path; *p; p++) {
        h ^= (unsigned char)*p;
        h *= 1099511628211ULL;
    }
    return h;
}

/* Recursively merge a source directory into merged_dir.
 * Files from src_dir are symlinked into merged_dir.
 * Higher layers overwrite existing symlinks (shadowing). */
static int merge_layer(const char *src_dir, const char *merged_dir,
                        const char *rel_prefix)
{
    char src_path[PATH_MAX];
    char dst_path[PATH_MAX];
    char child_prefix[PATH_MAX];
    char full_src[PATH_MAX];

    int n = snprintf(src_path, sizeof(src_path), "%s%s%s",
                     src_dir, rel_prefix[0] ? "/" : "", rel_prefix);
    if (n < 0 || (size_t)n >= sizeof(src_path))
        return -ENAMETOOLONG;

    DIR *dp = opendir(src_path);
    if (!dp)
        return 0; /* Silently skip non-existent layers */

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        n = snprintf(full_src, sizeof(full_src), "%s/%s", src_path, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(full_src))
            continue;

        if (rel_prefix[0])
            n = snprintf(child_prefix, sizeof(child_prefix), "%s/%s",
                         rel_prefix, de->d_name);
        else
            n = snprintf(child_prefix, sizeof(child_prefix), "%s", de->d_name);
        if (n < 0 || (size_t)n >= sizeof(child_prefix))
            continue;

        n = snprintf(dst_path, sizeof(dst_path), "%s/%s", merged_dir, child_prefix);
        if (n < 0 || (size_t)n >= sizeof(dst_path))
            continue;

        struct stat st;
        if (lstat(full_src, &st) < 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            /* Create directory in merged view and recurse */
            mkdir(dst_path, st.st_mode & 07777);
            merge_layer(src_dir, merged_dir, child_prefix);
        } else {
            /* Remove existing symlink (higher layer shadows lower) */
            unlink(dst_path);
            /* Create symlink to the source file */
            if (symlink(full_src, dst_path) < 0)
                KLEE_DEBUG("overlay: symlink %s -> %s failed: %s",
                           dst_path, full_src, strerror(errno));
        }
    }
    closedir(dp);
    return 0;
}

/* Ensure parent directories exist for a path within the upper dir */
static void ensure_parents(const char *base_dir, const char *remainder)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s", remainder);
    if (n < 0 || (size_t)n >= sizeof(path))
        return;

    char full[PATH_MAX];
    char *p = path;
    while (*p == '/')
        p++;

    char *slash;
    while ((slash = strchr(p, '/')) != NULL) {
        *slash = '\0';
        n = snprintf(full, sizeof(full), "%s/%s", base_dir, path);
        if (n >= 0 && (size_t)n < sizeof(full))
            mkdir(full, 0755);
        *slash = '/';
        p = slash + 1;
    }
}

/* Copy a file from source to destination (copy-on-write).
 * Preserves mode and ownership as much as possible. */
static int copy_file(const char *src, const char *dst)
{
    struct stat st;
    if (stat(src, &st) < 0)
        return -errno;

    int src_fd = open(src, O_RDONLY);
    if (src_fd < 0)
        return -errno;

    int dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 07777);
    if (dst_fd < 0) {
        close(src_fd);
        return -errno;
    }

    char buf[8192];
    ssize_t nread;
    while ((nread = read(src_fd, buf, sizeof(buf))) > 0) {
        ssize_t written = 0;
        while (written < nread) {
            ssize_t w = write(dst_fd, buf + written, (size_t)(nread - written));
            if (w < 0) {
                close(src_fd);
                close(dst_fd);
                return -errno;
            }
            written += w;
        }
    }

    close(src_fd);
    close(dst_fd);
    return nread < 0 ? -errno : 0;
}

/* Find a file in lower layers, returning the real path.
 * Checks from top-most lower layer (highest index) to bottom. */
static int find_in_lowers(const KleeOverlayMount *ov, const char *remainder,
                           char *found_path, size_t found_size)
{
    for (int i = ov->lower_count - 1; i >= 0; i--) {
        int n = snprintf(found_path, found_size, "%s/%s",
                         ov->lower_dirs[i], remainder);
        if (n < 0 || (size_t)n >= found_size)
            continue;
        struct stat st;
        if (lstat(found_path, &st) == 0)
            return 0;
    }
    return -ENOENT;
}

KleeOverlayMount *klee_overlay_create(const char *dest, const char *upper,
                                        char **lowers, int lower_count, bool ro)
{
    KleeOverlayMount *ov = calloc(1, sizeof(KleeOverlayMount));
    if (!ov)
        return NULL;

    ov->readonly = ro;
    ov->lower_count = lower_count;

    ov->whiteouts = klee_ht_create();
    if (!ov->whiteouts) {
        free(ov);
        return NULL;
    }

    /* Copy lower layer paths */
    if (lower_count > 0) {
        ov->lower_dirs = calloc((size_t)lower_count, sizeof(char *));
        if (!ov->lower_dirs) {
            klee_ht_destroy(ov->whiteouts);
            free(ov);
            return NULL;
        }
        for (int i = 0; i < lower_count; i++)
            ov->lower_dirs[i] = strdup(lowers[i]);
    }

    /* Create merged tmpfs directory */
    char merged_name[PATH_MAX];
    snprintf(merged_name, sizeof(merged_name), "%s/.merged", dest);
    ov->merged_dir = klee_tmpfs_create(merged_name);
    if (!ov->merged_dir) {
        KLEE_WARN("overlay: failed to create merged dir for %s", dest);
        klee_overlay_destroy(ov);
        return NULL;
    }

    /* Create upper tmpfs directory for writable overlays */
    if (!ro) {
        if (upper) {
            ov->upper_dir = strdup(upper);
        } else {
            char upper_name[PATH_MAX];
            snprintf(upper_name, sizeof(upper_name), "%s/.upper", dest);
            ov->upper_dir = klee_tmpfs_create(upper_name);
        }
        if (!ov->upper_dir) {
            KLEE_WARN("overlay: failed to create upper dir for %s", dest);
            klee_overlay_destroy(ov);
            return NULL;
        }
    }

    /* Merge lower layers bottom-to-top into merged view */
    for (int i = 0; i < lower_count; i++)
        merge_layer(lowers[i], ov->merged_dir, "");

    /* If there's an upper dir with existing content, merge it on top */
    if (ov->upper_dir)
        merge_layer(ov->upper_dir, ov->merged_dir, "");

    KLEE_DEBUG("overlay: created for %s (%d lowers, %s)",
               dest, lower_count, ro ? "ro" : "rw");
    return ov;
}

int klee_overlay_resolve(const KleeOverlayMount *ov, const char *remainder,
                          char *host_path_out, size_t out_size, bool for_write)
{
    if (!ov || !remainder || !host_path_out)
        return -EINVAL;

    /* Skip leading slashes */
    while (*remainder == '/')
        remainder++;

    /* Check whiteout - if path was deleted, return ENOENT */
    if (*remainder && ov->whiteouts) {
        uint64_t h = hash_path(remainder);
        if (klee_ht_contains(ov->whiteouts, h))
            return -ENOENT;
    }

    if (for_write) {
        if (ov->readonly)
            return -EROFS;

        if (ov->upper_dir) {
            ensure_parents(ov->upper_dir, remainder);
            char upper_path[PATH_MAX];
            if (*remainder)
                snprintf(upper_path, sizeof(upper_path), "%s/%s",
                         ov->upper_dir, remainder);
            else
                snprintf(upper_path, sizeof(upper_path), "%s", ov->upper_dir);

            /* Copy-on-write: if file doesn't exist in upper but exists
             * in a lower layer, copy it to upper before returning. */
            struct stat st;
            if (*remainder && lstat(upper_path, &st) < 0) {
                char lower_path[PATH_MAX];
                if (find_in_lowers(ov, remainder, lower_path,
                                    sizeof(lower_path)) == 0) {
                    if (lstat(lower_path, &st) == 0 && S_ISREG(st.st_mode)) {
                        if (copy_file(lower_path, upper_path) == 0)
                            KLEE_DEBUG("overlay: copy-up %s -> %s",
                                       lower_path, upper_path);
                    }
                }
            }

            snprintf(host_path_out, out_size, "%s", upper_path);
            return 0;
        }
    }

    /* For reads: check upper first, then merged view */
    if (ov->upper_dir) {
        char upper_path[PATH_MAX];
        if (*remainder)
            snprintf(upper_path, sizeof(upper_path), "%s/%s",
                     ov->upper_dir, remainder);
        else
            snprintf(upper_path, sizeof(upper_path), "%s", ov->upper_dir);

        struct stat st;
        if (lstat(upper_path, &st) == 0) {
            snprintf(host_path_out, out_size, "%s", upper_path);
            return 0;
        }
    }

    /* Fall through to merged view.
     * The merged dir contains symlinks to actual files in lower layers.
     * Resolve symlinks so callers see the real file, not the symlink -
     * this matches kernel overlayfs behavior where the overlay presents
     * regular files, not symlinks. */
    {
        char merged_path[PATH_MAX];
        if (*remainder)
            snprintf(merged_path, sizeof(merged_path), "%s/%s",
                     ov->merged_dir, remainder);
        else
            snprintf(merged_path, sizeof(merged_path), "%s", ov->merged_dir);

        /* If it's a symlink in merged_dir, resolve to the actual target */
        char resolved[PATH_MAX];
        ssize_t link_len = readlink(merged_path, resolved, sizeof(resolved) - 1);
        if (link_len > 0) {
            resolved[link_len] = '\0';
            snprintf(host_path_out, out_size, "%s", resolved);
        } else {
            /* Not a symlink (directory or doesn't exist) - use merged path */
            snprintf(host_path_out, out_size, "%s", merged_path);
        }
    }
    return 0;
}

void klee_overlay_whiteout(KleeOverlayMount *ov, const char *remainder)
{
    if (!ov || !remainder || !ov->whiteouts)
        return;

    while (*remainder == '/')
        remainder++;
    if (!*remainder)
        return;

    uint64_t h = hash_path(remainder);
    klee_ht_put(ov->whiteouts, h, (void *)1);

    /* Also remove from merged dir so readdir won't show it */
    char merged_path[PATH_MAX];
    int n = snprintf(merged_path, sizeof(merged_path), "%s/%s",
                     ov->merged_dir, remainder);
    if (n >= 0 && (size_t)n < sizeof(merged_path))
        unlink(merged_path);

    KLEE_DEBUG("overlay: whiteout %s", remainder);
}

bool klee_overlay_is_whiteout(const KleeOverlayMount *ov, const char *remainder)
{
    if (!ov || !remainder || !ov->whiteouts)
        return false;

    while (*remainder == '/')
        remainder++;
    if (!*remainder)
        return false;

    uint64_t h = hash_path(remainder);
    return klee_ht_contains(ov->whiteouts, h);
}

void klee_overlay_destroy(KleeOverlayMount *ov)
{
    if (!ov)
        return;

    /* lower_dirs are just path copies; tmpfs cleanup handles actual dirs */
    if (ov->lower_dirs) {
        for (int i = 0; i < ov->lower_count; i++)
            free(ov->lower_dirs[i]);
        free(ov->lower_dirs);
    }
    if (ov->whiteouts)
        klee_ht_destroy(ov->whiteouts);
    free(ov->upper_dir);
    /* merged_dir is managed by tmpfs subsystem */
    free(ov->merged_dir);
    free(ov);
}
