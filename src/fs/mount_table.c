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

static uint64_t next_mount_id = 1;

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

static void release_mounts(const char *path, KleeMount *mount, void *data)
{
    (void)path;
    (void)data;
    for (; mount; mount = mount->stacked)
        klee_overlay_destroy(mount->overlay);
}

void klee_mount_table_destroy(KleeMountTable *mt)
{
    if (!mt)
        return;
    klee_radix_walk(mt->tree, release_mounts, NULL);
    klee_arena_destroy(mt->arena);
    free(mt);
}

typedef struct {
    KleeMountTable *copy;
    bool failed;
} MountClone;

static void clone_mounts(const char *path, KleeMount *mount, void *data)
{
    MountClone *clone = data;
    if (clone->failed)
        return;
    KleeMountTable *copy = clone->copy;
    RadixNode *node = klee_radix_insert(copy->tree, path, NULL);
    if (!node) {
        clone->failed = true;
        return;
    }
    KleeMount **tail = &node->mount;
    for (; mount; mount = mount->stacked) {
        KleeMount *entry = klee_arena_alloc(copy->arena, sizeof(*entry));
        if (!entry) {
            clone->failed = true;
            return;
        }
        *entry = *mount;
        entry->stacked = NULL;
        entry->source = mount->source ? klee_arena_strdup(copy->arena, mount->source) : NULL;
        entry->dest = klee_arena_strdup(copy->arena, mount->dest);
        entry->link_path = mount->link_path ?
            klee_arena_strdup(copy->arena, mount->link_path) : NULL;
        entry->overlay_prefix = mount->overlay_prefix
            ? klee_arena_strdup(copy->arena, mount->overlay_prefix) : NULL;
        if (!entry->dest || (mount->source && !entry->source) ||
            (mount->link_path && !entry->link_path) ||
            (mount->overlay_prefix && !entry->overlay_prefix)) {
            clone->failed = true;
            return;
        }
        klee_overlay_ref(entry->overlay);
        *tail = entry;
        tail = &entry->stacked;
        copy->num_mounts++;
    }
}

KleeMountTable *klee_mount_table_clone(const KleeMountTable *mt)
{
    KleeMountTable *copy = klee_mount_table_create();
    if (!copy)
        return NULL;
    copy->virtual_root = klee_arena_strdup(copy->arena, mt->virtual_root);
    MountClone clone = { .copy = copy, .failed = !copy->virtual_root };
    klee_radix_walk(mt->tree, clone_mounts, &clone);
    if (clone.failed) {
        klee_mount_table_destroy(copy);
        return NULL;
    }
    return copy;
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
    if (!mount->dest || (source && !mount->source))
        return -ENOMEM;
    mount->is_readonly = readonly;
    mount->perms = perms;
    mount->id = next_mount_id++;

    if (type == MOUNT_SYMLINK) {
        if (!mt->link_dir) {
            char *dir = klee_tmpfs_create("virtual symlinks");
            if (!dir)
                return -errno;
            mt->link_dir = klee_arena_strdup(mt->arena, dir);
            free(dir);
            if (!mt->link_dir)
                return -ENOMEM;
        }
        char backing[PATH_MAX];
        int n = snprintf(backing, sizeof(backing), "%s/%llu", mt->link_dir,
                         (unsigned long long)mount->id);
        if (n < 0 || (size_t)n >= sizeof(backing))
            return -ENAMETOOLONG;
        mount->link_path = klee_arena_strdup(mt->arena, backing);
        if (!mount->link_path)
            return -ENOMEM;
        if (symlink(source, backing) < 0)
            return -errno;
    }

    RadixNode *node = klee_radix_insert(mt->tree, dest, mount);
    if (!node)
        return -ENOMEM;

    mt->num_mounts++;
    KLEE_DEBUG("mount: type=%d src=%s dest=%s ro=%d",
               type, source ? source : "(null)", dest, readonly);
    return 0;
}

static void clear_submounts(KleeMountTable *mt, RadixNode *node)
{
    for (; node; node = node->sibling) {
        for (KleeMount *mount = node->mount; mount; mount = mount->stacked) {
            klee_overlay_destroy(mount->overlay);
            mt->num_mounts--;
        }
        node->mount = NULL;
        clear_submounts(mt, node->children);
    }
}

static int add_config_mount(KleeMountTable *mt, MountType type,
                             const char *source, const char *dest, bool ro, int perms)
{
    int rc = klee_mount_table_add(mt, type, source, dest, ro, perms);
    if (rc == 0)
        clear_submounts(mt, klee_radix_find_exact(mt->tree, dest)->children);
    return rc;
}

static int create_backed_mount(KleeMountTable *mt, MountType type,
                               const char *dest, int perms)
{
    char *path = klee_tmpfs_create(dest);
    if (!path)
        return -errno;
    int rc = chmod(path, perms) < 0 ? -errno :
             add_config_mount(mt, type, path, dest, false, perms);
    free(path);
    return rc;
}

static int ensure_directory(KleeMountTable *mt, const char *dest, mode_t mode)
{
    char guest[PATH_MAX];
    if (snprintf(guest, sizeof(guest), "%s", dest) >= (int)sizeof(guest))
        return -ENAMETOOLONG;
    for (char *end = guest + 1; ; end++) {
        if (*end && *end != '/')
            continue;
        char saved = *end;
        *end = '\0';

        char host[PATH_MAX];
        int rc = klee_mount_table_translate(mt, guest, host, sizeof(host));
        if (rc < 0)
            return rc;
        struct stat st;
        if (stat(host, &st) == 0) {
            if (!S_ISDIR(st.st_mode))
                return -ENOTDIR;
        } else {
            if (errno != ENOENT)
                return -errno;
            if (klee_mount_table_is_readonly(mt, guest))
                return -EROFS;

            mode_t perms = saved ? 0755 : mode;
            if (!klee_mount_table_resolve(mt, guest)) {
                char *backing = klee_tmpfs_create(guest);
                if (!backing)
                    return -errno;
                rc = chmod(backing, perms) < 0 ? -errno :
                     klee_mount_table_add(mt, MOUNT_DIR, backing, guest, false, perms);
                free(backing);
                if (rc < 0)
                    return rc;
            } else {
                rc = klee_mount_table_translate_access(mt, guest, host, sizeof(host),
                                                        KLEE_OV_CREATE);
                if (rc < 0)
                    return rc;
                if (mkdir(host, perms) < 0) {
                    if (errno != EEXIST || stat(host, &st) < 0 || !S_ISDIR(st.st_mode))
                        return -errno;
                } else if (chmod(host, perms) < 0) {
                    return -errno;
                }
            }
        }

        *end = saved;
        if (!saved)
            return 0;
    }
}

static int create_dev_mount(KleeMountTable *mt, const char *dest, mode_t perms)
{
    int rc = create_backed_mount(mt, MOUNT_DEV, dest, perms);
    if (rc < 0)
        return rc;
    const KleeMount *dev = klee_mount_table_resolve(mt, dest);
    static const char *const devices[] = {"null", "zero", "full", "random",
                                          "urandom", "tty", "pts"};
    for (size_t i = 0; i < sizeof(devices) / sizeof(devices[0]); i++) {
        char host[32], guest[PATH_MAX], entry[PATH_MAX];
        snprintf(host, sizeof(host), "/dev/%s", devices[i]);
        if (access(host, F_OK) < 0)
            continue;
        if (snprintf(guest, sizeof(guest), "%s/%s", dest, devices[i]) >= (int)sizeof(guest) ||
            snprintf(entry, sizeof(entry), "%s/%s", dev->source, devices[i]) >= (int)sizeof(entry))
            return -ENAMETOOLONG;
        if (symlink(host, entry) < 0)
            return -errno;
        rc = klee_mount_table_add(mt, MOUNT_DEV_BIND, host, guest, false, 0666);
        if (rc < 0)
            return rc;
    }

    static const struct { const char *name, *target; } links[] = {
        {"stdin", "/proc/self/fd/0"}, {"stdout", "/proc/self/fd/1"},
        {"stderr", "/proc/self/fd/2"}, {"fd", "/proc/self/fd"},
        {"core", "/proc/kcore"}, {"ptmx", "pts/ptmx"},
    };
    for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", dev->source, links[i].name) >= (int)sizeof(path))
            return -ENAMETOOLONG;
        if (symlink(links[i].target, path) < 0)
            return -errno;
    }

    char shm[PATH_MAX];
    if (snprintf(shm, sizeof(shm), "%s/shm", dev->source) >= (int)sizeof(shm))
        return -ENAMETOOLONG;
    if (mkdir(shm, 01777) < 0)
        return -errno;
    return chmod(shm, 01777) < 0 ? -errno : 0;
}

static int apply_mount_op(KleeMountTable *mt, const KleeMountOp *op)
{
    const char *dest = op->dest;
    if (op->type == MOUNT_OVERLAY_SRC)
        return 0;
    if (!dest || dest[0] != '/')
        return -EINVAL;
    bool ro;
    char source[PATH_MAX];
    switch (op->type) {
    case MOUNT_BIND_RW:
    case MOUNT_BIND_TRY:
    case MOUNT_DEV_BIND:
    case MOUNT_DEV_BIND_TRY:
    case MOUNT_BIND_RO:
    case MOUNT_BIND_RO_TRY:
        ro = op->type == MOUNT_BIND_RO || op->type == MOUNT_BIND_RO_TRY;
        if (!realpath(op->source, source)) {
            int error = errno;
            if (error == ENOENT && (op->type == MOUNT_BIND_TRY ||
                                    op->type == MOUNT_BIND_RO_TRY ||
                                    op->type == MOUNT_DEV_BIND_TRY))
                return 0;
            return -error;
        }
        {
            int rc = add_config_mount(mt, op->type, source, dest, ro, op->perms);
            if (rc < 0 || !op->overlay_alias)
                return rc;
            KleeMount *mount = klee_mount_table_resolve(mt, dest);
            mount->overlay_prefix = klee_arena_strdup(mt->arena, op->overlay_prefix);
            if (!mount->overlay_prefix)
                return -ENOMEM;
            mount->overlay = op->overlay_alias;
            mount->is_readonly |= op->overlay_alias_readonly;
            klee_overlay_ref(mount->overlay);
            return 0;
        }

    case MOUNT_TMPFS:
    case MOUNT_MQUEUE:
        return create_backed_mount(mt, op->type, dest, op->perms);
    case MOUNT_PROC:
        return add_config_mount(mt, MOUNT_PROC, "/proc", dest, false, op->perms);
    case MOUNT_DEV:
        return create_dev_mount(mt, dest, op->perms);
    case MOUNT_DIR:
        return ensure_directory(mt, dest, op->perms);
    case MOUNT_SYMLINK:
        return add_config_mount(mt, MOUNT_SYMLINK, op->source, dest,
                                 klee_mount_table_is_readonly(mt, dest), 0777);

    case MOUNT_FILE:
    case MOUNT_BIND_DATA:
    case MOUNT_RO_BIND_DATA: {
        char *path = klee_tmpfs_create_file(dest, op->fd, op->perms);
        if (!path)
            return -errno;
        int rc = add_config_mount(mt, op->type, path, dest,
                                   op->type == MOUNT_RO_BIND_DATA, op->perms);
        free(path);
        return rc;
    }

    case MOUNT_REMOUNT_RO: {
        RadixNode *node = klee_radix_find_exact(mt->tree, dest);
        if (!node || !node->mount)
            return -EINVAL;
        node->mount->is_readonly = true;
        return 0;
    }

    case MOUNT_CHMOD: {
        if (klee_mount_table_is_readonly(mt, dest))
            return -EROFS;
        int rc = klee_mount_table_translate_access(mt, dest, source, sizeof(source),
                                                     KLEE_OV_SETATTR);
        if (rc < 0)
            return rc;
        return chmod(source, op->perms) < 0 ? -errno : 0;
    }

    case MOUNT_OVERLAY:
    case MOUNT_TMP_OVERLAY:
    case MOUNT_RO_OVERLAY: {
        ro = op->type == MOUNT_RO_OVERLAY;
        const char *upper = op->type == MOUNT_OVERLAY ? op->source : NULL;
        if (op->type == MOUNT_OVERLAY && !upper)
            return -EINVAL;
        KleeOverlayMount *ov = klee_overlay_create(dest, upper, op->overlay_srcs,
                                                    op->overlay_src_count, ro);
        if (!ov)
            return -errno;
        int rc = add_config_mount(mt, op->type, ov->merged_dir, dest, ro, op->perms);
        if (rc < 0) {
            klee_overlay_destroy(ov);
            return rc;
        }
        klee_mount_table_resolve(mt, dest)->overlay = ov;
        return 0;
    }

    case MOUNT_BIND_FD:
    case MOUNT_RO_BIND_FD: {
        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", op->fd);
        if (!realpath(fd_path, source))
            return -errno;
        return add_config_mount(mt, op->type, source, dest,
                                 op->type == MOUNT_RO_BIND_FD, op->perms);
    }
    case MOUNT_OVERLAY_SRC:
        break;
    }
    return -EINVAL;
}

int klee_mount_table_populate(KleeMountTable *mt, const KleeConfig *cfg)
{
    for (const KleeMountOp *op = cfg->mount_ops; op; op = op->next) {
        int rc = apply_mount_op(mt, op);
        if (rc < 0) {
            KLEE_ERROR("mount setup failed at %s: %s", op->dest, strerror(-rc));
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

static int overlay_relative(const KleeMount *mount, const char *remainder,
                            char *relative, size_t size)
{
    while (*remainder == '/')
        remainder++;
    const char *prefix = mount->overlay_prefix ? mount->overlay_prefix : "";
    int n = snprintf(relative, size, "%s%s%s", prefix, *prefix && *remainder ? "/" : "", remainder);
    return n < 0 || (size_t)n >= size ? -ENAMETOOLONG : 0;
}

int klee_mount_table_overlay_relative(const KleeMountTable *mt, const char *guest_path,
                                       char *relative, size_t size)
{
    const char *remainder;
    RadixNode *node = klee_radix_lookup(mt->tree, guest_path, NULL, &remainder);
    if (!node || !node->mount || !node->mount->overlay)
        return -EINVAL;
    return overlay_relative(node->mount, remainder, relative, size);
}

static int translate_depth(const KleeMountTable *mt, const char *guest_path,
                           char *out, size_t out_size, int depth,
                           KleeOvAccess access, bool nofollow)
{
    if (!mt || !guest_path || !out)
        return -EINVAL;

    const char *remainder;
    RadixNode *node = klee_radix_lookup(mt->tree, guest_path, NULL, &remainder);
    KleeMount *mount = node ? node->mount : NULL;

    if (mount && mount->overlay) {
        if (mount->is_readonly && access != KLEE_OV_LOOKUP && access != KLEE_OV_LIST)
            access = KLEE_OV_READ;
        char relative[PATH_MAX];
        int rc = overlay_relative(mount, remainder, relative, sizeof(relative));
        if (rc < 0)
            return rc;
        return klee_overlay_resolve(mount->overlay, relative, out, out_size, access);
    }

    const char *source = mount ? mount->source : NULL;
    if (source) {
        while (*remainder == '/')
            remainder++;
        if (mount->type == MOUNT_SYMLINK) {
            source = mount->link_path;
            if (!nofollow || *remainder) {
                char target[PATH_MAX];
                ssize_t len = readlink(source, target, sizeof(target));
                if (len >= (ssize_t)sizeof(target))
                    return -ENAMETOOLONG;
                if (len >= 0) {
                    if (depth >= 40)
                        return -ELOOP;
                    target[len] = '\0';
                    const char *parent = "";
                    size_t parent_len = 0;
                    if (target[0] != '/') {
                        parent = mount->dest;
                        parent_len = (size_t)(strrchr(parent, '/') - parent);
                    }
                    char next[PATH_MAX];
                    int n = snprintf(next, sizeof(next), "%.*s%s%s%s%s",
                                     (int)parent_len, parent, target[0] == '/' ? "" : "/",
                                     target, *remainder ? "/" : "", remainder);
                    if (n < 0 || (size_t)n >= sizeof(next))
                        return -ENAMETOOLONG;
                    return translate_depth(mt, next, out, out_size, depth + 1, access, false);
                }
                if (errno != ENOENT && errno != EINVAL)
                    return -errno;
            }
        }
    }

    int n;
    if (!source) {
        n = snprintf(out, out_size, "%s", guest_path);
    } else {
        size_t len = strlen(source);
        const char *separator = *remainder && len && source[len - 1] != '/' ? "/" : "";
        n = snprintf(out, out_size, "%s%s%s", source, separator, remainder);
    }
    return n < 0 || (size_t)n >= out_size ? -ENAMETOOLONG : 0;
}

int klee_mount_table_translate(const KleeMountTable *mt,
                                const char *guest_path,
                                char *host_path_out, size_t out_size)
{
    return translate_depth(mt, guest_path, host_path_out, out_size, 0, KLEE_OV_LOOKUP, false);
}

int klee_mount_table_translate_access(const KleeMountTable *mt,
                                       const char *guest_path,
                                       char *host_path_out, size_t out_size,
                                       KleeOvAccess access)
{
    return translate_depth(mt, guest_path, host_path_out, out_size, 0, access, false);
}

int klee_mount_table_translate_nofollow(const KleeMountTable *mt,
                                         const char *guest_path,
                                         char *host_path_out, size_t out_size,
                                         KleeOvAccess access)
{
    return translate_depth(mt, guest_path, host_path_out, out_size, 0, access, true);
}

typedef struct {
    const KleeMountTable *table;
    const char *host;
    char *guest;
    size_t size;
    size_t matched;
} ReversePath;

static void reverse_mount(const char *path, KleeMount *mount, void *data)
{
    ReversePath *rev = data;
    const char *src = mount->source;
    if (!src || src[0] != '/' || mount->link_path)
        return;
    size_t len = strlen(src);
    if (len <= rev->matched || strncmp(rev->host, src, len) != 0 ||
        (src[len - 1] != '/' && rev->host[len] && rev->host[len] != '/'))
        return;
    const char *suffix = rev->host + len;
    while (*suffix == '/')
        suffix++;
    char candidate[PATH_MAX], check[PATH_MAX];
    int n = snprintf(candidate, sizeof(candidate), "%s%s%s", path,
                     *suffix && path[strlen(path) - 1] != '/' ? "/" : "", suffix);
    if (n < 0 || (size_t)n >= sizeof(candidate) || (size_t)n >= rev->size)
        return;
    if (klee_mount_table_translate(rev->table, candidate, check, sizeof(check)) < 0 ||
        strcmp(check, rev->host) != 0)
        return;
    memcpy(rev->guest, candidate, (size_t)n + 1);
    rev->matched = len;
}

int klee_mount_table_host_to_guest(const KleeMountTable *mt, const char *host_path,
                                    char *guest, size_t size)
{
    if (!mt || host_path[0] != '/')
        return -EINVAL;
    ReversePath rev = {.table = mt, .host = host_path, .guest = guest, .size = size};
    klee_radix_walk(mt->tree, reverse_mount, &rev);
    if (rev.matched)
        return 0;

    char check[PATH_MAX];
    int rc = klee_mount_table_translate(mt, host_path, check, sizeof(check));
    if (rc < 0)
        return rc;
    if (strcmp(check, host_path) != 0)
        return -ENOENT;
    int n = snprintf(guest, size, "%s", host_path);
    return n < 0 || (size_t)n >= size ? -ENAMETOOLONG : 0;
}

KleeOverlayMount *klee_mount_table_overlay_at(const KleeMountTable *mt,
                                               const char *guest_path)
{
    KleeMount *mount = klee_mount_table_resolve(mt, guest_path);
    return mount ? mount->overlay : NULL;
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
    RadixNode *probe = klee_radix_find_exact(mt->tree, "/run/host");
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
        if ((size_t)snprintf(src_file, sizeof(src_file), "%s/%s", src_dir, de->d_name) >= sizeof(src_file))
            continue;

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
        if ((size_t)snprintf(dst_link, sizeof(dst_link), "%s/%s", dst_dir, de->d_name) >= sizeof(dst_link))
            continue;

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
            if ((size_t)snprintf(host_file, sizeof(host_file), "%s/%s",
                     host_lib_dir, de->d_name) >= sizeof(host_file))
                continue;

            struct stat st;
            if (lstat(host_file, &st) < 0)
                continue;

            /* Skip directories (e.g. dri/, which has its own symlinks) */
            if (S_ISDIR(st.st_mode))
                continue;

            /* guest symlink source: the GL extension lib path */
            char guest_src[PATH_MAX];
            if ((size_t)snprintf(guest_src, sizeof(guest_src), "%s/GL/%s/lib/%s",
                     libdir, vendor, de->d_name) >= sizeof(guest_src))
                continue;

            /* guest symlink dest: the standard library search path */
            char guest_dest[PATH_MAX];
            if ((size_t)snprintf(guest_dest, sizeof(guest_dest), "%s/%s",
                     libdir, de->d_name) >= sizeof(guest_dest))
                continue;

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
