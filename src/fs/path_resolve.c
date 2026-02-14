/*
 * Klee - Userspace bwrap translation layer
 * Path canonicalization implementation
 *
 * Reference: proot/src/path/canon.c
 * Component-by-component canonicalization with symlink resolution.
 */
#include "fs/path_resolve.h"
#include "util/log.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Internal resolve state */
typedef struct {
    char guest_path[PATH_MAX];    /* canonicalized guest path being built */
    char host_path[PATH_MAX];     /* translated host path for stat */
    int depth;                     /* stack depth in guest_path */
    KleeResolveCtx *ctx;
} ResolveState;

/* Append a component to the guest path.
 * Returns pointer to the end of guest_path after append. */
static int path_append(char *path, size_t max_len, const char *component,
                        size_t comp_len)
{
    size_t cur_len = strlen(path);

    /* Ensure trailing slash */
    if (cur_len > 0 && path[cur_len - 1] != '/') {
        if (cur_len + 1 >= max_len)
            return -ENAMETOOLONG;
        path[cur_len] = '/';
        path[cur_len + 1] = '\0';
        cur_len++;
    }

    if (cur_len + comp_len >= max_len)
        return -ENAMETOOLONG;

    memcpy(path + cur_len, component, comp_len);
    path[cur_len + comp_len] = '\0';
    return 0;
}

/* Remove last component from path (go to parent) */
static void path_pop(char *path)
{
    size_t len = strlen(path);

    /* Remove trailing slash */
    if (len > 1 && path[len - 1] == '/')
        path[--len] = '\0';

    /* Find last slash */
    char *last = strrchr(path, '/');
    if (last && last != path)
        *last = '\0';
    else if (last == path)
        path[1] = '\0'; /* Keep root "/" */
}

/* Check if path is under virtual root */
static int check_beneath(const char *path, const char *root)
{
    size_t root_len = strlen(root);
    if (root_len <= 1) /* root = "/" */
        return 0;
    if (strncmp(path, root, root_len) != 0)
        return -EXDEV;
    if (path[root_len] != '\0' && path[root_len] != '/')
        return -EXDEV;
    return 0;
}

static int resolve_symlink(ResolveState *state, const char *link_target,
                            const char *remaining);

static int resolve_components(ResolveState *state, const char *path)
{
    const char *p = path;

    while (*p) {
        /* Skip slashes */
        while (*p == '/')
            p++;
        if (*p == '\0')
            break;

        /* Extract component */
        const char *comp_start = p;
        while (*p != '\0' && *p != '/')
            p++;
        size_t comp_len = (size_t)(p - comp_start);

        /* Handle "." */
        if (comp_len == 1 && comp_start[0] == '.')
            continue;

        /* Handle ".." */
        if (comp_len == 2 && comp_start[0] == '.' && comp_start[1] == '.') {
            /* Determine the boundary: for RESOLVE_BENEATH use dirfd_path,
             * for RESOLVE_IN_ROOT use vroot, otherwise just vroot */
            const char *boundary;
            if ((state->ctx->flags & KLEE_RESOLVE_BENEATH) &&
                state->ctx->dirfd_path)
                boundary = state->ctx->dirfd_path;
            else
                boundary = state->ctx->vroot ? state->ctx->vroot : "/";

            if (strlen(state->guest_path) > strlen(boundary))
                path_pop(state->guest_path);
            else if (state->ctx->flags & (KLEE_RESOLVE_BENEATH | KLEE_RESOLVE_IN_ROOT))
                return -EXDEV;
            continue;
        }

        /* Append component */
        int rc = path_append(state->guest_path, PATH_MAX, comp_start, comp_len);
        if (rc < 0)
            return rc;

        /* Translate through mount table to get host path */
        rc = klee_mount_table_translate(state->ctx->mount_table,
                                         state->guest_path,
                                         state->host_path, PATH_MAX);
        if (rc < 0)
            return rc;

        /* Determine if this is the final path component — needed for
         * KLEE_RESOLVE_NOFOLLOW_LAST (lstat, unlink, readlink, etc.) */
        bool is_last_component = false;
        if (state->ctx->flags & KLEE_RESOLVE_NOFOLLOW_LAST) {
            const char *rest = p;
            while (*rest == '/')
                rest++;
            is_last_component = (*rest == '\0');
        }

        /* Check for virtual symlink (MOUNT_SYMLINK in the mount table).
         * These are synthesized from bwrap --symlink and don't exist on the
         * host filesystem, so the lstat check below would miss them. */
        if (!(state->ctx->flags & KLEE_RESOLVE_NO_SYMLINKS) &&
            !is_last_component) {
            KleeMount *vmount = klee_mount_table_resolve(
                state->ctx->mount_table, state->guest_path);
            if (vmount && vmount->type == MOUNT_SYMLINK &&
                vmount->dest && strcmp(vmount->dest, state->guest_path) == 0) {
                state->depth++;
                if (state->depth > KLEE_MAX_SYMLINK_DEPTH)
                    return -ELOOP;
                path_pop(state->guest_path);
                rc = resolve_symlink(state, vmount->source, p);
                if (rc < 0)
                    return rc;
                return 0;
            }
        }

        /* Check if this is a symlink (on the host filesystem) */
        if (!(state->ctx->flags & KLEE_RESOLVE_NO_SYMLINKS) &&
            !is_last_component) {
            struct stat st;
            if (lstat(state->host_path, &st) == 0 && S_ISLNK(st.st_mode)) {
                char link_target[PATH_MAX];
                ssize_t link_len = readlink(state->host_path, link_target,
                                            PATH_MAX - 1);
                if (link_len < 0)
                    return -errno;
                link_target[link_len] = '\0';

                /* Don't follow symlinks under /proc/.  All /proc symlinks
                 * are kernel magic links (proc fd, exe, cwd, etc.)
                 * whose targets are host-namespace paths, not guest
                 * paths.  Following them in userspace resolution would
                 * produce incorrect mount table translations.  Let the
                 * kernel resolve them at syscall time. */
                if (strncmp(state->host_path, "/proc/", 6) != 0) {
                    state->depth++;
                    if (state->depth > KLEE_MAX_SYMLINK_DEPTH)
                        return -ELOOP;

                    /* Remove the symlink component from guest path */
                    path_pop(state->guest_path);

                    /* Resolve the symlink target */
                    rc = resolve_symlink(state, link_target, p);
                    if (rc < 0)
                        return rc;

                    return 0; /* resolve_symlink handles remaining path */
                }
                /* Magic link: fall through, treat as non-symlink */
            }
        }

        /* Check RESOLVE_BENEATH against dirfd path, not vroot */
        if (state->ctx->flags & KLEE_RESOLVE_BENEATH) {
            const char *base = state->ctx->dirfd_path
                             ? state->ctx->dirfd_path
                             : (state->ctx->vroot ? state->ctx->vroot : "/");
            rc = check_beneath(state->guest_path, base);
            if (rc < 0)
                return rc;
        }

        /* Check RESOLVE_IN_ROOT against vroot */
        if (state->ctx->flags & KLEE_RESOLVE_IN_ROOT) {
            const char *vroot = state->ctx->vroot ? state->ctx->vroot : "/";
            rc = check_beneath(state->guest_path, vroot);
            if (rc < 0)
                return rc;
        }

        /* Check RESOLVE_NO_XDEV - detect mount point crossings */
        if (state->ctx->flags & KLEE_RESOLVE_NO_XDEV) {
            /* If the component crosses to a different mount, that's
             * a device boundary in Klee's model. Check if the resolved
             * host path is on a different device than the parent. */
            char parent_path[PATH_MAX];
            snprintf(parent_path, sizeof(parent_path), "%s", state->guest_path);
            path_pop(parent_path);
            char parent_host[PATH_MAX];
            if (klee_mount_table_translate(state->ctx->mount_table,
                                            parent_path, parent_host,
                                            PATH_MAX) == 0) {
                struct stat st_parent, st_child;
                if (stat(parent_host, &st_parent) == 0 &&
                    stat(state->host_path, &st_child) == 0 &&
                    st_parent.st_dev != st_child.st_dev)
                    return -EXDEV;
            }
        }
    }

    return 0;
}

static int resolve_symlink(ResolveState *state, const char *link_target,
                            const char *remaining)
{
    /* Build new path: link_target + remaining */
    char combined[PATH_MAX * 2];

    if (link_target[0] == '/') {
        /* RESOLVE_NO_MAGICLINKS: reject magic proc symlinks */
        if (state->ctx->flags & KLEE_RESOLVE_NO_MAGICLINKS) {
            /* Check if the host path is under /proc - magic symlinks */
            if (strncmp(state->host_path, "/proc/", 6) == 0)
                return -ELOOP;
        }

        /* Absolute symlink: restart from virtual root.
         * For RESOLVE_IN_ROOT, this enforces the constraint that
         * absolute symlinks cannot escape the vroot. */
        const char *vroot = state->ctx->vroot ? state->ctx->vroot : "/";
        snprintf(state->guest_path, PATH_MAX, "%s", vroot);
        snprintf(combined, sizeof(combined), "%s/%s", link_target, remaining);
    } else {
        /* Relative symlink: resolve relative to current position */
        snprintf(combined, sizeof(combined), "%s/%s", link_target, remaining);
    }

    return resolve_components(state, combined);
}

int klee_path_resolve(KleeResolveCtx *ctx, const char *guest_path,
                       char *resolved, int dirfd)
{
    if (!ctx || !guest_path || !resolved)
        return -EINVAL;

    ResolveState state;
    memset(&state, 0, sizeof(state));
    state.ctx = ctx;
    state.depth = ctx->symlink_depth;

    /* Determine starting point */
    if (guest_path[0] == '/') {
        /* Absolute path */
        const char *vroot = ctx->vroot ? ctx->vroot : "/";
        snprintf(state.guest_path, PATH_MAX, "%s", vroot);
    } else if (dirfd == AT_FDCWD || dirfd == -100) {
        /* Relative to vcwd */
        if (ctx->vcwd)
            snprintf(state.guest_path, PATH_MAX, "%s", ctx->vcwd);
        else
            strcpy(state.guest_path, "/");
    } else {
        /* Relative to dirfd - look up in FD table */
        const char *dir_path = NULL;
        if (ctx->fd_table)
            dir_path = klee_fd_table_get(ctx->fd_table, dirfd);
        if (dir_path)
            snprintf(state.guest_path, PATH_MAX, "%s", dir_path);
        else
            strcpy(state.guest_path, "/");
    }

    int rc = resolve_components(&state, guest_path);
    if (rc < 0)
        return rc;

    snprintf(resolved, PATH_MAX, "%s", state.guest_path);
    return 0;
}

int klee_path_guest_to_host(KleeResolveCtx *ctx, const char *guest_path,
                             char *host_path, int dirfd)
{
    char resolved[PATH_MAX];
    int rc = klee_path_resolve(ctx, guest_path, resolved, dirfd);
    if (rc < 0)
        return rc;

    return klee_mount_table_translate(ctx->mount_table, resolved,
                                       host_path, PATH_MAX);
}

int klee_path_resolve_nofollow(KleeResolveCtx *ctx, const char *guest_path,
                                char *resolved, int dirfd)
{
    /* Same as resolve but don't follow the final symlink component.
     * Intermediate symlinks ARE still followed (unlike NO_SYMLINKS
     * which blocks all symlink resolution). */
    unsigned int saved_flags = ctx->flags;
    ctx->flags |= KLEE_RESOLVE_NOFOLLOW_LAST;
    int rc = klee_path_resolve(ctx, guest_path, resolved, dirfd);
    ctx->flags = saved_flags;
    return rc;
}

int klee_path_guest_to_host_nofollow(KleeResolveCtx *ctx, const char *guest_path,
                                      char *host_path, int dirfd)
{
    char resolved[PATH_MAX];
    int rc = klee_path_resolve_nofollow(ctx, guest_path, resolved, dirfd);
    if (rc < 0)
        return rc;

    return klee_mount_table_translate(ctx->mount_table, resolved,
                                       host_path, PATH_MAX);
}
