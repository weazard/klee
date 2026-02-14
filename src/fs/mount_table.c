/*
 * Klee - Userspace bwrap translation layer
 * Virtual mount table implementation
 */
#include "fs/mount_table.h"
#include "fs/overlay.h"
#include "fs/tmpfs.h"
#include "fuse/fuse_mountinfo.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <linux/limits.h>

KleeMountTable *klee_mount_table_create(void)
{
    KleeMountTable *mt = calloc(1, sizeof(KleeMountTable));
    if (!mt)
        return NULL;

    mt->arena = klee_arena_create(8192);
    if (!mt->arena) {
        free(mt);
        return NULL;
    }

    mt->tree = klee_radix_create(mt->arena);
    if (!mt->tree) {
        klee_arena_destroy(mt->arena);
        free(mt);
        return NULL;
    }

    mt->virtual_root = klee_arena_strdup(mt->arena, "/");
    return mt;
}

void klee_mount_table_destroy(KleeMountTable *mt)
{
    if (!mt)
        return;
    /* Arena owns all nodes and mount entries */
    klee_arena_destroy(mt->arena);
    free(mt);
}

int klee_mount_table_add(KleeMountTable *mt, MountType type,
                          const char *source, const char *dest,
                          bool readonly, int perms)
{
    KleeMount *mount = klee_arena_calloc(mt->arena, 1, sizeof(KleeMount));
    if (!mount)
        return -ENOMEM;

    mount->type = type;
    mount->source = source ? klee_arena_strdup(mt->arena, source) : NULL;
    mount->dest = dest ? klee_arena_strdup(mt->arena, dest) : NULL;
    mount->is_readonly = readonly;
    mount->perms = perms;

    RadixNode *node = klee_radix_insert(mt->tree, dest, mount);
    if (!node)
        return -ENOMEM;

    mt->num_mounts++;
    KLEE_DEBUG("mount: type=%d src=%s dest=%s ro=%d",
               type, source ? source : "(null)", dest, readonly);
    return 0;
}

int klee_mount_table_populate(KleeMountTable *mt, const KleeConfig *cfg)
{
    for (KleeMountOp *op = cfg->mount_ops; op; op = op->next) {
        bool readonly = false;
        const char *source = op->source;
        const char *dest = op->dest;

        switch (op->type) {
        case MOUNT_BIND_RW:
        case MOUNT_BIND_TRY:
        case MOUNT_DEV_BIND:
        case MOUNT_DEV_BIND_TRY:
            readonly = false;
            break;

        case MOUNT_BIND_RO:
        case MOUNT_BIND_RO_TRY:
            readonly = true;
            break;

        case MOUNT_TMPFS: {
            char *tmpfs_path = klee_tmpfs_create(dest);
            if (!tmpfs_path) {
                KLEE_WARN("failed to create tmpfs backing for %s", dest);
                continue;
            }
            int rc = klee_mount_table_add(mt, MOUNT_TMPFS, tmpfs_path, dest,
                                           false, op->perms);
            if (rc < 0)
                return rc;
            continue;
        }

        case MOUNT_PROC:
            /* /proc is special - backed by real /proc or FUSE */
            klee_mount_table_add(mt, MOUNT_PROC, "/proc", dest, false, 0755);
            continue;

        case MOUNT_DEV:
        {
            /* Create a curated /dev matching bwrap's behavior:
             * tmpfs-backed dir with only specific device nodes and symlinks */
            char *dev_path = klee_tmpfs_create(dest);
            if (!dev_path) {
                KLEE_WARN("failed to create /dev backing for %s", dest);
                continue;
            }
            klee_mount_table_add(mt, MOUNT_DEV, dev_path, dest, false, 0755);

            /* Bind-mount device nodes from host /dev */
            static const char *dev_nodes[] = {
                "null", "zero", "full", "random", "urandom", "tty"
            };
            for (size_t d = 0; d < sizeof(dev_nodes)/sizeof(dev_nodes[0]); d++) {
                char host_dev[PATH_MAX], guest_dev[PATH_MAX];
                snprintf(host_dev, sizeof(host_dev), "/dev/%s", dev_nodes[d]);
                snprintf(guest_dev, sizeof(guest_dev), "%s/%s", dest, dev_nodes[d]);
                klee_mount_table_add(mt, MOUNT_DEV_BIND, host_dev, guest_dev,
                                      false, 0666);
            }

            /* Create stdio symlinks */
            char sl_path[PATH_MAX];
            snprintf(sl_path, sizeof(sl_path), "%s/stdin", dest);
            klee_mount_table_add(mt, MOUNT_SYMLINK, "/proc/self/fd/0", sl_path,
                                  false, 0777);
            snprintf(sl_path, sizeof(sl_path), "%s/stdout", dest);
            klee_mount_table_add(mt, MOUNT_SYMLINK, "/proc/self/fd/1", sl_path,
                                  false, 0777);
            snprintf(sl_path, sizeof(sl_path), "%s/stderr", dest);
            klee_mount_table_add(mt, MOUNT_SYMLINK, "/proc/self/fd/2", sl_path,
                                  false, 0777);
            /* Legacy symlinks */
            snprintf(sl_path, sizeof(sl_path), "%s/fd", dest);
            klee_mount_table_add(mt, MOUNT_SYMLINK, "/proc/self/fd", sl_path,
                                  false, 0777);
            snprintf(sl_path, sizeof(sl_path), "%s/core", dest);
            klee_mount_table_add(mt, MOUNT_SYMLINK, "/proc/kcore", sl_path,
                                  false, 0777);

            /* Create /dev/shm and /dev/pts directories */
            char sub_path[PATH_MAX];
            snprintf(sub_path, sizeof(sub_path), "%s/shm", dev_path);
            mkdir(sub_path, 0755);
            snprintf(sub_path, sizeof(sub_path), "%s/pts", dev_path);
            mkdir(sub_path, 0755);

            /* ptmx -> pts/ptmx symlink */
            snprintf(sl_path, sizeof(sl_path), "%s/ptmx", dest);
            klee_mount_table_add(mt, MOUNT_SYMLINK, "pts/ptmx", sl_path,
                                  false, 0777);
            continue;
        }

        case MOUNT_DIR:
            /* Create empty directory backed by tmpfs */
        {
            char *dir_path = klee_tmpfs_create(dest);
            if (dir_path)
                klee_mount_table_add(mt, MOUNT_DIR, dir_path, dest,
                                      false, op->perms);
            continue;
        }

        case MOUNT_SYMLINK:
            klee_mount_table_add(mt, MOUNT_SYMLINK, source, dest, false, 0777);
            continue;

        case MOUNT_FILE:
        case MOUNT_BIND_DATA:
        case MOUNT_RO_BIND_DATA:
        {
            char *file_path = klee_tmpfs_create_file(dest, op->fd);
            if (file_path) {
                bool ro = (op->type == MOUNT_RO_BIND_DATA);
                klee_mount_table_add(mt, op->type, file_path, dest,
                                      ro, op->perms);
            }
            continue;
        }

        case MOUNT_REMOUNT_RO:
        {
            /* Find existing mount and set readonly */
            KleeMount *existing = klee_mount_table_resolve(mt, dest);
            if (existing)
                existing->is_readonly = true;
            else
                KLEE_WARN("remount-ro: no mount at %s", dest);
            continue;
        }

        case MOUNT_CHMOD:
        {
            /* Change permissions on existing mount */
            KleeMount *existing = klee_mount_table_resolve(mt, dest);
            if (existing)
                existing->perms = op->perms;
            continue;
        }

        case MOUNT_OVERLAY_SRC:
            /* Overlay source is just collected for later use by --overlay */
            continue;

        case MOUNT_OVERLAY:
        {
            /* --overlay: upper=source, lowers=overlay_srcs */
            KleeOverlayMount *ov = klee_overlay_create(
                dest, source, op->overlay_srcs, op->overlay_src_count, false);
            if (!ov) {
                KLEE_WARN("overlay: failed to create overlay for %s", dest);
                continue;
            }
            int rc = klee_mount_table_add(mt, MOUNT_OVERLAY,
                                           ov->merged_dir, dest, false, op->perms);
            if (rc < 0) return rc;
            KleeMount *m = klee_mount_table_resolve(mt, dest);
            if (m) m->overlay = ov;
            continue;
        }

        case MOUNT_TMP_OVERLAY:
        {
            /* --tmp-overlay: tmpfs upper, lowers=overlay_srcs */
            KleeOverlayMount *ov = klee_overlay_create(
                dest, NULL, op->overlay_srcs, op->overlay_src_count, false);
            if (!ov) {
                KLEE_WARN("overlay: failed to create tmp-overlay for %s", dest);
                continue;
            }
            int rc = klee_mount_table_add(mt, MOUNT_TMP_OVERLAY,
                                           ov->merged_dir, dest, false, op->perms);
            if (rc < 0) return rc;
            KleeMount *m = klee_mount_table_resolve(mt, dest);
            if (m) m->overlay = ov;
            continue;
        }

        case MOUNT_RO_OVERLAY:
        {
            /* --ro-overlay: no upper, lowers=overlay_srcs, readonly */
            KleeOverlayMount *ov = klee_overlay_create(
                dest, NULL, op->overlay_srcs, op->overlay_src_count, true);
            if (!ov) {
                KLEE_WARN("overlay: failed to create ro-overlay for %s", dest);
                continue;
            }
            int rc = klee_mount_table_add(mt, MOUNT_RO_OVERLAY,
                                           ov->merged_dir, dest, true, op->perms);
            if (rc < 0) return rc;
            KleeMount *m = klee_mount_table_resolve(mt, dest);
            if (m) m->overlay = ov;
            continue;
        }

        case MOUNT_MQUEUE:
            /* Mount mqueue backed by tmpfs for now */
        {
            char *mq_path = klee_tmpfs_create(dest);
            if (mq_path)
                klee_mount_table_add(mt, MOUNT_MQUEUE, mq_path, dest,
                                      false, op->perms);
            continue;
        }

        case MOUNT_BIND_FD:
        case MOUNT_RO_BIND_FD:
        {
            /* FD-based bind mount - read path from /proc/self/fd/N */
            char fd_path[64];
            char resolved[PATH_MAX];
            snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", op->fd);
            ssize_t len = readlink(fd_path, resolved, sizeof(resolved) - 1);
            if (len > 0) {
                resolved[len] = '\0';
                bool ro = (op->type == MOUNT_RO_BIND_FD);
                klee_mount_table_add(mt, op->type, resolved, dest,
                                      ro, op->perms);
            } else {
                KLEE_WARN("bind-fd: cannot resolve fd %d", op->fd);
            }
            continue;
        }
        }

        int rc = klee_mount_table_add(mt, op->type, source, dest,
                                       readonly, op->perms);
        if (rc < 0 && op->type != MOUNT_BIND_TRY &&
            op->type != MOUNT_BIND_RO_TRY &&
            op->type != MOUNT_DEV_BIND_TRY) {
            return rc;
        }
    }

    return 0;
}

KleeMount *klee_mount_table_resolve(const KleeMountTable *mt,
                                     const char *guest_path)
{
    if (!mt || !guest_path)
        return NULL;

    size_t match_len;
    RadixNode *node = klee_radix_lookup(mt->tree, guest_path,
                                         &match_len, NULL);
    if (!node)
        return NULL;

    return node->mount;
}

static int translate_depth(const KleeMountTable *mt,
                            const char *guest_path,
                            char *host_path_out, size_t out_size,
                            int depth)
{
    if (!mt || !guest_path || !host_path_out)
        return -EINVAL;

    size_t match_len;
    const char *remainder;
    RadixNode *node = klee_radix_lookup(mt->tree, guest_path,
                                         &match_len, &remainder);
    if (!node || !node->mount) {
        /* No mount covers this path - pass through */
        snprintf(host_path_out, out_size, "%s", guest_path);
        return 0;
    }

    KleeMount *mount = node->mount;

    switch (mount->type) {
    case MOUNT_BIND_RW:
    case MOUNT_BIND_RO:
    case MOUNT_BIND_TRY:
    case MOUNT_BIND_RO_TRY:
    case MOUNT_DEV_BIND:
    case MOUNT_DEV_BIND_TRY:
    case MOUNT_BIND_DATA:
    case MOUNT_RO_BIND_DATA:
    case MOUNT_BIND_FD:
    case MOUNT_RO_BIND_FD:
        /* Prefix substitution: replace mount dest with mount source */
        if (mount->source) {
            /* Skip over matched prefix, append remainder to source */
            while (*remainder == '/')
                remainder++;
            if (*remainder) {
                /* Avoid double slashes when source ends with / */
                size_t slen = strlen(mount->source);
                if (slen > 0 && mount->source[slen - 1] == '/')
                    snprintf(host_path_out, out_size, "%s%s",
                             mount->source, remainder);
                else
                    snprintf(host_path_out, out_size, "%s/%s",
                             mount->source, remainder);
            } else {
                snprintf(host_path_out, out_size, "%s", mount->source);
            }
        } else {
            snprintf(host_path_out, out_size, "%s", guest_path);
        }
        break;

    case MOUNT_TMPFS:
    case MOUNT_DIR:
    case MOUNT_FILE:
    case MOUNT_PROC:
    case MOUNT_DEV:
    case MOUNT_MQUEUE:
        /* Backed by a tmpfs directory or special mount */
        if (mount->source) {
            while (*remainder == '/')
                remainder++;
            if (*remainder) {
                size_t slen = strlen(mount->source);
                if (slen > 0 && mount->source[slen - 1] == '/')
                    snprintf(host_path_out, out_size, "%s%s",
                             mount->source, remainder);
                else
                    snprintf(host_path_out, out_size, "%s/%s",
                             mount->source, remainder);
            } else {
                snprintf(host_path_out, out_size, "%s", mount->source);
            }
        } else {
            snprintf(host_path_out, out_size, "%s", guest_path);
        }
        break;

    case MOUNT_SYMLINK: {
        /* Symlinks: source is a guest-path target; append remainder and
         * recursively re-translate since the result is still a guest path.
         * Relative targets are resolved against the parent of dest,
         * matching kernel symlink semantics. */
        if (depth >= 40)
            return -ELOOP;
        char new_guest[PATH_MAX];
        const char *target = mount->source;
        char resolved[PATH_MAX];
        if (target[0] != '/') {
            /* Relative symlink — prepend parent directory of dest */
            char parent[PATH_MAX];
            snprintf(parent, PATH_MAX, "%s", mount->dest);
            char *slash = strrchr(parent, '/');
            if (slash && slash != parent)
                *slash = '\0';
            else if (slash)
                parent[1] = '\0';  /* parent is "/" */
            snprintf(resolved, PATH_MAX, "%s/%s", parent, target);
            target = resolved;
        }
        while (*remainder == '/')
            remainder++;
        if (*remainder)
            snprintf(new_guest, PATH_MAX, "%s/%s", target, remainder);
        else
            snprintf(new_guest, PATH_MAX, "%s", target);
        return translate_depth(mt, new_guest, host_path_out, out_size,
                               depth + 1);
    }

    case MOUNT_OVERLAY:
    case MOUNT_TMP_OVERLAY:
    case MOUNT_RO_OVERLAY:
        if (mount->overlay) {
            bool for_write = false; /* translate is read-only lookup */
            return klee_overlay_resolve(mount->overlay, remainder,
                                         host_path_out, out_size, for_write);
        }
        /* Fallback: use source as merged dir */
        if (mount->source) {
            while (*remainder == '/')
                remainder++;
            if (*remainder)
                snprintf(host_path_out, out_size, "%s/%s",
                         mount->source, remainder);
            else
                snprintf(host_path_out, out_size, "%s", mount->source);
        } else {
            snprintf(host_path_out, out_size, "%s", guest_path);
        }
        break;

    case MOUNT_REMOUNT_RO:
    case MOUNT_CHMOD:
    case MOUNT_OVERLAY_SRC:
    default:
        snprintf(host_path_out, out_size, "%s", guest_path);
        break;
    }

    return 0;
}

int klee_mount_table_translate(const KleeMountTable *mt,
                                const char *guest_path,
                                char *host_path_out, size_t out_size)
{
    return translate_depth(mt, guest_path, host_path_out, out_size, 0);
}

bool klee_mount_table_is_readonly(const KleeMountTable *mt,
                                   const char *guest_path)
{
    KleeMount *mount = klee_mount_table_resolve(mt, guest_path);
    return mount && mount->is_readonly;
}

void klee_mount_table_set_root(KleeMountTable *mt, const char *root)
{
    if (mt && root)
        mt->virtual_root = klee_arena_strdup(mt->arena, root);
}

const char *klee_mount_table_get_root(const KleeMountTable *mt)
{
    return mt ? mt->virtual_root : "/";
}

int klee_mount_table_gen_mountinfo(const KleeMountTable *mt,
                                    char *buf, size_t buf_size)
{
    if (!mt || !buf)
        return -EINVAL;

    /* Delegate to the full mountinfo generator which walks the radix tree */
    return klee_gen_mountinfo(mt, buf, buf_size);
}

/*
 * Create host-side mirrors for mounts under /run/host.
 *
 * Pressure-vessel's runtime overlay contains host-side symlinks that
 * point to guest paths like /run/host/usr/lib/...  Since klee uses
 * ptrace-based path translation, the kernel follows these symlinks on
 * the host filesystem directly.  Without matching host-side paths the
 * symlinks dangle and libraries fail to load.
 *
 * For bind mounts:  mkdir -p <dest>   (or symlink source if trivial)
 * For symlinks:     ln -sfn <source> <dest>
 */
static void mirror_run_host_mount(const char *path, KleeMount *mount, void *ctx)
{
    (void)ctx;

    /* Only care about mounts under /run/host */
    if (strncmp(path, "/run/host", 9) != 0)
        return;
    /* Must be exactly /run/host or /run/host/... */
    if (path[9] != '\0' && path[9] != '/')
        return;

    struct stat st;

    if (mount->type == MOUNT_SYMLINK) {
        /* Create parent directory, then symlink */
        char parent[PATH_MAX];
        snprintf(parent, sizeof(parent), "%s", path);
        char *slash = strrchr(parent, '/');
        if (slash && slash != parent) {
            *slash = '\0';
            /* mkdir -p parent (simple one-level since /run/host exists) */
            if (stat(parent, &st) < 0)
                mkdir(parent, 0755);
        }
        /* Don't overwrite existing non-symlink entries */
        if (lstat(path, &st) == 0 && !S_ISLNK(st.st_mode))
            return;
        /* Create or update the symlink */
        unlink(path);
        if (symlink(mount->source, path) == 0)
            KLEE_DEBUG("host mirror: symlink %s -> %s", path, mount->source);
    } else if (mount->type == MOUNT_BIND_RW || mount->type == MOUNT_BIND_RO ||
               mount->type == MOUNT_BIND_TRY || mount->type == MOUNT_BIND_RO_TRY) {
        /* For bind mounts, create a host-side symlink to the source path
         * so the kernel can follow /run/host/... references */
        if (lstat(path, &st) == 0)
            return;  /* already exists, don't touch */
        char parent[PATH_MAX];
        snprintf(parent, sizeof(parent), "%s", path);
        char *slash = strrchr(parent, '/');
        if (slash && slash != parent) {
            *slash = '\0';
            if (stat(parent, &st) < 0)
                mkdir(parent, 0755);
        }
        if (symlink(mount->source, path) == 0)
            KLEE_DEBUG("host mirror: symlink %s -> %s", path, mount->source);
    }
}

void klee_mount_table_create_host_mirrors(const KleeMountTable *mt)
{
    if (!mt)
        return;

    /* Only act if there are mounts under /run/host */
    KleeMount *probe = klee_mount_table_resolve(mt, "/run/host");
    if (!probe)
        return;

    /* Ensure /run/host directory exists.
     * /run is typically root-owned; if we can't create /run/host,
     * log a warning so the admin can pre-create it:
     *   mkdir -p /run/host && chmod 1777 /run/host */
    struct stat st;
    if (stat("/run/host", &st) < 0) {
        if (mkdir("/run/host", 0777) < 0 && errno != EEXIST) {
            KLEE_WARN("cannot create /run/host (run: mkdir -p /run/host && chmod 1777 /run/host)");
            return;
        }
    }

    klee_radix_walk(mt->tree, mirror_run_host_mount, NULL);
}

/*
 * Apply pressure-vessel overrides as explicit mount entries.
 *
 * In a real bwrap container, pressure-vessel uses overlayfs to merge the
 * overrides directory on top of the runtime's /usr.  Since klee can't do
 * overlayfs, we pre-scan the overrides and add individual mount entries
 * for each file.  These entries are more specific than the general /usr
 * bind mount, so they take precedence in the radix tree.
 *
 * Override symlinks (e.g. libdl.so.2 -> /run/host/usr/lib/...)  become
 * MOUNT_SYMLINK entries; regular files become MOUNT_BIND_RO entries.
 */
static void scan_overrides_dir(KleeMountTable *mt,
                                const char *host_dir,
                                const char *guest_prefix)
{
    DIR *dp = opendir(host_dir);
    if (!dp)
        return;

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (de->d_name[0] == '.')
            continue;

        char host_path[PATH_MAX];
        char guest_path[PATH_MAX];

        snprintf(host_path, sizeof(host_path), "%s/%s", host_dir, de->d_name);
        snprintf(guest_path, sizeof(guest_path), "%s/%s", guest_prefix, de->d_name);

        struct stat st;
        if (lstat(host_path, &st) < 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            scan_overrides_dir(mt, host_path, guest_path);
        } else if (S_ISLNK(st.st_mode)) {
            /* Read symlink target — this is a guest-side path like
             * /run/host/usr/lib/x86_64-linux-gnu/libdl.so.2 */
            char target[PATH_MAX];
            ssize_t len = readlink(host_path, target, sizeof(target) - 1);
            if (len > 0) {
                target[len] = '\0';
                klee_mount_table_add(mt, MOUNT_SYMLINK, target, guest_path,
                                      false, 0777);
            }
        } else if (S_ISREG(st.st_mode)) {
            klee_mount_table_add(mt, MOUNT_BIND_RO, host_path, guest_path,
                                  true, 0644);
        }
    }
    closedir(dp);
}

void klee_mount_table_apply_pv_overrides(KleeMountTable *mt)
{
    if (!mt)
        return;

    /* Look for the /overrides symlink mount — pressure-vessel convention */
    KleeMount *ov_mount = klee_mount_table_resolve(mt, "/overrides");
    if (!ov_mount || ov_mount->type != MOUNT_SYMLINK) {
        KLEE_DEBUG("pv-overrides: no /overrides symlink (mount=%p type=%d)",
                   (void *)ov_mount, ov_mount ? (int)ov_mount->type : -1);
        return;
    }

    KLEE_DEBUG("pv-overrides: found /overrides -> %s", ov_mount->source);

    /* The symlink target is typically "usr/lib/pressure-vessel/overrides".
     * We need to find the /usr bind mount to construct the host path. */
    KleeMount *usr_mount = klee_mount_table_resolve(mt, "/usr");
    if (!usr_mount || !usr_mount->source) {
        KLEE_DEBUG("pv-overrides: no /usr mount found");
        return;
    }

    /* Only proceed if /usr is a real bind mount (not a symlink etc.) */
    if (usr_mount->type != MOUNT_BIND_RO && usr_mount->type != MOUNT_BIND_RW &&
        usr_mount->type != MOUNT_BIND_TRY && usr_mount->type != MOUNT_BIND_RO_TRY) {
        KLEE_DEBUG("pv-overrides: /usr is type=%d, not a bind mount",
                   usr_mount->type);
        return;
    }

    /* Construct overrides host path.
     * Symlink target "usr/lib/pressure-vessel/overrides" relative to /usr
     * means: strip "usr/" prefix and append to /usr source.
     * Or more simply: <usr_source>/lib/pressure-vessel/overrides */
    const char *ov_target = ov_mount->source;
    const char *rel = ov_target;
    /* Strip leading "usr/" if present */
    if (strncmp(rel, "usr/", 4) == 0)
        rel = rel + 4;
    else if (rel[0] == '/')
        rel = rel + 1;  /* absolute — shouldn't happen but handle it */

    char overrides_host[PATH_MAX];
    snprintf(overrides_host, sizeof(overrides_host), "%s/%s",
             usr_mount->source, rel);

    struct stat st;
    if (stat(overrides_host, &st) < 0 || !S_ISDIR(st.st_mode)) {
        KLEE_DEBUG("pv-overrides: no overrides dir at %s", overrides_host);
        return;
    }

    KLEE_INFO("pv-overrides: applying overrides from %s", overrides_host);

    /* Scan and add entries.  Override files map to /usr/<relative_path>
     * because in the real container, overlayfs merges overrides onto /usr. */
    scan_overrides_dir(mt, overrides_host, "/usr");
}

/*
 * Apply Flatpak GL extension library symlinks and content merging.
 *
 * Flatpak GL extensions (e.g. org.freedesktop.Platform.GL.default) are
 * bind-mounted at /usr/lib/<triplet>/GL/<vendor>/.  These extensions
 * contain shared libraries in lib/ that the dynamic linker needs
 * (libGLX_mesa.so.0, libEGL_mesa.so.0, libgbm.so.1, etc.), plus
 * Vulkan ICD manifests, EGL vendor configs, and other content.
 *
 * In a real bwrap container, Flatpak creates a tmpfs at the GL/
 * directory and populates it with symlinks that merge content from
 * all vendor extensions into a unified view.  Under klee, the tmpfs
 * exists but remains empty — only the vendor bind mounts are present.
 *
 * This function does two things:
 * 1. Adds MOUNT_SYMLINK entries at the parent library directory so
 *    GL shared libraries are discoverable at the standard search path.
 * 2. Creates real symlinks in the GL tmpfs backing store to merge
 *    vendor content (Vulkan ICDs, EGL vendors, etc.) so that loaders
 *    like the Vulkan loader can discover drivers via directory listing.
 */

/* Subdirectories within GL extensions that need merging into the
 * GL tmpfs.  Each is scanned per vendor and symlinked into the
 * tmpfs backing store at the same relative path. */
static const char *gl_merge_subdirs[] = {
    "vulkan/icd.d",
    "vulkan/implicit_layer.d",
    "share/vulkan/implicit_layer.d",
    "share/vulkan/explicit_layer.d",
    "glvnd/egl_vendor.d",
    "share/glvnd/egl_vendor.d",
    "egl/egl_external_platform.d",
    NULL
};

/* Recursively create directories (like mkdir -p) */
static void mkdirs(const char *path, mode_t mode)
{
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, mode);
            *p = '/';
        }
    }
    mkdir(tmp, mode);
}

/* Merge files from a vendor's subdirectory into the GL tmpfs backing
 * store by creating real host-side symlinks. */
static void gl_merge_subdir(const char *backing_store, const char *host_source,
                             const char *subdir)
{
    char src_dir[PATH_MAX];
    snprintf(src_dir, sizeof(src_dir), "%s/%s", host_source, subdir);

    DIR *dp = opendir(src_dir);
    if (!dp)
        return;

    /* Create the target directory in the tmpfs backing store */
    char dst_dir[PATH_MAX];
    snprintf(dst_dir, sizeof(dst_dir), "%s/%s", backing_store, subdir);
    mkdirs(dst_dir, 0755);

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (de->d_name[0] == '.')
            continue;

        char src_file[PATH_MAX];
        snprintf(src_file, sizeof(src_file), "%s/%s", src_dir, de->d_name);

        struct stat st;
        if (lstat(src_file, &st) < 0)
            continue;
        if (S_ISDIR(st.st_mode))
            continue;

        /* Resolve the source to an absolute path for the symlink target.
         * If it's already a symlink, follow it to the real file. */
        char real_src[PATH_MAX];
        if (realpath(src_file, real_src) == NULL)
            continue;

        char dst_link[PATH_MAX];
        snprintf(dst_link, sizeof(dst_link), "%s/%s", dst_dir, de->d_name);

        /* Don't overwrite existing symlinks (another vendor may have
         * already provided this file) */
        if (lstat(dst_link, &st) == 0)
            continue;

        if (symlink(real_src, dst_link) == 0) {
            KLEE_DEBUG("gl-ext: merged %s/%s -> %s",
                       subdir, de->d_name, real_src);
        }
    }
    closedir(dp);
}

struct gl_ext_ctx {
    KleeMountTable *mt;
};

static void gl_extension_walker(const char *path, KleeMount *mount, void *ctx)
{
    struct gl_ext_ctx *gc = ctx;

    /* Match paths like /usr/lib/<triplet>/GL/<vendor> */
    if (strncmp(path, "/usr/lib/", 9) != 0)
        return;

    const char *gl_pos = strstr(path, "/GL/");
    if (!gl_pos)
        return;

    /* vendor name must be the last component (no further slashes) */
    const char *vendor = gl_pos + 4;
    if (!*vendor || strchr(vendor, '/') != NULL)
        return;

    /* Must be a bind mount (the GL extension directory) */
    if (mount->type != MOUNT_BIND_RO && mount->type != MOUNT_BIND_RW &&
        mount->type != MOUNT_BIND_TRY && mount->type != MOUNT_BIND_RO_TRY)
        return;

    if (!mount->source)
        return;

    /* Compute guest GL directory path (up to and including /GL) */
    char gl_path[PATH_MAX];
    size_t gl_path_len = (size_t)(gl_pos - path) + 3; /* include "/GL" */
    if (gl_path_len >= PATH_MAX)
        return;
    memcpy(gl_path, path, gl_path_len);
    gl_path[gl_path_len] = '\0';

    /* Compute guest parent libdir (everything before /GL/) */
    char libdir[PATH_MAX];
    size_t libdir_len = (size_t)(gl_pos - path);
    if (libdir_len == 0 || libdir_len >= PATH_MAX)
        return;
    memcpy(libdir, path, libdir_len);
    libdir[libdir_len] = '\0';

    /* --- Phase 1: shared library symlinks (existing behavior) --- */

    char host_lib_dir[PATH_MAX];
    snprintf(host_lib_dir, sizeof(host_lib_dir), "%s/lib", mount->source);

    DIR *dp = opendir(host_lib_dir);
    if (dp) {
        KLEE_DEBUG("gl-ext: scanning %s (vendor=%s) for %s",
                   host_lib_dir, vendor, libdir);

        struct dirent *de;
        while ((de = readdir(dp)) != NULL) {
            if (de->d_name[0] == '.')
                continue;

            /* Only shared library files (name contains ".so") */
            if (!strstr(de->d_name, ".so"))
                continue;

            char host_file[PATH_MAX];
            snprintf(host_file, sizeof(host_file), "%s/%s",
                     host_lib_dir, de->d_name);

            struct stat st;
            if (lstat(host_file, &st) < 0)
                continue;

            /* Skip directories (e.g. dri/, which has its own symlinks) */
            if (S_ISDIR(st.st_mode))
                continue;

            /* guest symlink source: the GL extension lib path */
            char guest_src[PATH_MAX];
            snprintf(guest_src, sizeof(guest_src), "%s/GL/%s/lib/%s",
                     libdir, vendor, de->d_name);

            /* guest symlink dest: the standard library search path */
            char guest_dest[PATH_MAX];
            snprintf(guest_dest, sizeof(guest_dest), "%s/%s",
                     libdir, de->d_name);

            klee_mount_table_add(gc->mt, MOUNT_SYMLINK,
                                 guest_src, guest_dest, false, 0777);
        }
        closedir(dp);
    }

    /* --- Phase 2: merge vendor content into GL tmpfs backing store --- */

    /* Look up the GL tmpfs mount to find its backing store path */
    KleeMount *gl_mount = klee_mount_table_resolve(gc->mt, gl_path);
    if (!gl_mount || gl_mount->type != MOUNT_TMPFS || !gl_mount->source)
        return;

    KLEE_DEBUG("gl-ext: merging vendor %s content into %s",
               vendor, gl_mount->source);

    for (int i = 0; gl_merge_subdirs[i] != NULL; i++)
        gl_merge_subdir(gl_mount->source, mount->source, gl_merge_subdirs[i]);
}

void klee_mount_table_apply_gl_extensions(KleeMountTable *mt)
{
    if (!mt)
        return;

    struct gl_ext_ctx ctx = { .mt = mt };
    klee_radix_walk(mt->tree, gl_extension_walker, &ctx);
}

void klee_mount_table_dump(const KleeMountTable *mt)
{
    if (!mt)
        return;
    fprintf(stderr, "=== Mount Table (%zu mounts, root=%s) ===\n",
            mt->num_mounts, mt->virtual_root);
    klee_radix_dump(mt->tree);
}
