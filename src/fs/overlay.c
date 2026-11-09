/*
 * Klee - Userspace bwrap translation layer
 * Userspace overlay mount implementation
 *
 * A name resolves to the topmost layer that has it: the upper directory,
 * then the lower layers from the top down.  Deleting a name that a lower
 * layer provides records a whiteout, which hides it and everything below
 * it in the lower layers.
 *
 * The lower layers are never modified.  A call that changes a file from a
 * lower layer gets a copy of it in the upper directory first (copy-up), new
 * names are created in the upper directory, and a deletion only ever
 * removes something from the upper directory.
 *
 * Directories resolve to a tmpfs-backed merged directory that mirrors the
 * mode and times of the real directory.  Its entries are placeholders of
 * the right type (directory, symlink, fifo, empty file), resynced from the
 * layers whenever the directory is opened, so a listing shows the union of
 * the layers.  Files always resolve to their real layer, never to a
 * placeholder.
 */
#include "fs/overlay.h"
#include "fs/tmpfs.h"
#include "util/log.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>

#define UPPER_LAYER (-1)
#define NO_MODE ((mode_t)-1)

/* An existing name and the layer that provides it */
typedef struct {
    int layer;            /* UPPER_LAYER or an index into lower_dirs */
    struct stat st;
    char path[PATH_MAX];  /* host path of the entry in that layer */
} OvEntry;

/* ==================== Paths ==================== */

static int put(char *out, size_t size, const char *path)
{
    int n = snprintf(out, size, "%s", path);
    return (n < 0 || (size_t)n >= size) ? -ENAMETOOLONG : 0;
}

/* base/rel, or base itself for the overlay root */
static int join(char *out, size_t size, const char *base, const char *rel)
{
    int n = *rel ? snprintf(out, size, "%s/%s", base, rel)
                 : snprintf(out, size, "%s", base);
    return (n < 0 || (size_t)n >= size) ? -ENAMETOOLONG : 0;
}

/* rel/name, or name in the overlay root */
static int child_of(char *out, size_t size, const char *rel, const char *name)
{
    int n = *rel ? snprintf(out, size, "%s/%s", rel, name)
                 : snprintf(out, size, "%s", name);
    return (n < 0 || (size_t)n >= size) ? -ENAMETOOLONG : 0;
}

/* Relative form without leading, trailing or repeated slashes and "." */
static int normalize(const char *in, char *out, size_t size)
{
    size_t o = 0;
    while (*in) {
        while (*in == '/')
            in++;
        const char *s = in;
        while (*in && *in != '/')
            in++;
        size_t len = (size_t)(in - s);
        if (len == 0 || (len == 1 && s[0] == '.'))
            continue;
        if (len == 2 && s[0] == '.' && s[1] == '.')
            return -EINVAL;   /* callers pass canonical guest paths */
        if (o + (o ? 1 : 0) + len >= size)
            return -ENAMETOOLONG;
        if (o)
            out[o++] = '/';
        memcpy(out + o, s, len);
        o += len;
    }
    out[o] = '\0';
    return 0;
}

/* "a/b/c" -> "a/b", "a" -> "" */
static void parent_of(const char *rel, char *out)
{
    const char *slash = strrchr(rel, '/');
    size_t len = slash ? (size_t)(slash - rel) : 0;
    memcpy(out, rel, len);
    out[len] = '\0';
}

static const char *base_of(const char *rel)
{
    const char *slash = strrchr(rel, '/');
    return slash ? slash + 1 : rel;
}

/* ==================== Whiteouts ==================== */

/* FNV-1a hash of the first len bytes of a relative path */
static uint64_t hash_path(const char *path, size_t len)
{
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (unsigned char)path[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* rel itself was deleted in the sandbox */
static bool whiteout_exact(const KleeOverlayMount *ov, const char *rel)
{
    return ov->whiteouts && *rel &&
           klee_ht_contains(ov->whiteouts, hash_path(rel, strlen(rel)));
}

/* rel or one of its ancestors was deleted: no lower layer shows it */
static bool whited_out(const KleeOverlayMount *ov, const char *rel)
{
    if (!ov->whiteouts || !*rel)
        return false;
    for (size_t i = 1;; i++) {
        if (rel[i] != '/' && rel[i] != '\0')
            continue;
        if (klee_ht_contains(ov->whiteouts, hash_path(rel, i)))
            return true;
        if (rel[i] == '\0')
            return false;
    }
}

static int add_whiteout(KleeOverlayMount *ov, const char *rel)
{
    uint64_t h = hash_path(rel, strlen(rel));
    klee_ht_put(ov->whiteouts, h, (void *)1);
    /* klee_ht_put returns NULL for a new key and on failure alike */
    return klee_ht_contains(ov->whiteouts, h) ? 0 : -ENOMEM;
}

/* ==================== Layers ==================== */

/* The topmost layer providing rel.  -ENOENT when no layer has it or it was
 * deleted, -ENOTDIR when a layer on top has a non-directory on its way. */
static int lookup(const KleeOverlayMount *ov, const char *rel, OvEntry *e)
{
    if (ov->upper_dir) {
        if (join(e->path, sizeof(e->path), ov->upper_dir, rel) < 0)
            return -ENAMETOOLONG;
        if (lstat(e->path, &e->st) == 0) {
            e->layer = UPPER_LAYER;
            return 0;
        }
        if (errno == ENOTDIR)
            return -ENOTDIR;
    }
    if (whited_out(ov, rel))
        return -ENOENT;
    for (int i = ov->lower_count - 1; i >= 0; i--) {
        if (join(e->path, sizeof(e->path), ov->lower_dirs[i], rel) < 0)
            return -ENAMETOOLONG;
        if (lstat(e->path, &e->st) == 0) {
            e->layer = i;
            return 0;
        }
        if (errno == ENOTDIR)
            return -ENOTDIR;
    }
    return -ENOENT;
}

/* Some lower layer has rel, whatever the whiteouts say */
static bool in_lower(const KleeOverlayMount *ov, const char *rel)
{
    char path[PATH_MAX];
    struct stat st;
    for (int i = 0; i < ov->lower_count; i++)
        if (join(path, sizeof(path), ov->lower_dirs[i], rel) == 0 &&
            lstat(path, &st) == 0)
            return true;
    return false;
}

/* The topmost lower directory at rel, for its mode and times */
static bool lower_dir(const KleeOverlayMount *ov, const char *rel,
                      struct stat *st)
{
    char path[PATH_MAX];
    for (int i = ov->lower_count - 1; i >= 0; i--)
        if (join(path, sizeof(path), ov->lower_dirs[i], rel) == 0 &&
            lstat(path, st) == 0 && S_ISDIR(st->st_mode))
            return true;
    return false;
}

/* Where a missing name would be.  Never a placeholder: the upper layer, or
 * for a read-only overlay the top lower layer. */
static int absent_path(const KleeOverlayMount *ov, const char *rel,
                       char *out, size_t size)
{
    const char *base = ov->upper_dir ? ov->upper_dir
                     : ov->lower_count ? ov->lower_dirs[ov->lower_count - 1]
                     : ov->merged_dir;
    return join(out, size, base, rel);
}

/* ==================== Directories klee writes into ==================== */

/* klee creates entries in upper and merged directories that it made, but
 * their mode, copied from the real directory, may not let it (0555). */
static mode_t unlock_dir(const char *dir)
{
    struct stat st;
    if (lstat(dir, &st) < 0 || !S_ISDIR(st.st_mode) ||
        (st.st_mode & S_IRWXU) == S_IRWXU)
        return NO_MODE;
    if (chmod(dir, (st.st_mode & 07777) | S_IRWXU) < 0)
        return NO_MODE;
    return st.st_mode & 07777;
}

static void relock_dir(const char *dir, mode_t mode)
{
    if (mode != NO_MODE)
        chmod(dir, mode);
}

static void set_times(const char *path, const struct stat *st)
{
    struct timespec ts[2] = { st->st_atim, st->st_mtim };
    utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW);
}

/* Give a directory klee created its final mode and times */
static void finish_dir(const char *path, const struct stat *src)
{
    chmod(path, src ? src->st_mode & 07777 : 0755);
    if (src)
        set_times(path, src);
}

/* ==================== Upper layer ==================== */

/* Create the upper copies of rel's ancestors (and of rel with include_self)
 * with the mode and times of the lower directory each one shadows.  A new
 * directory stays writable for klee until the next level is in it. */
static int make_upper_dirs(const KleeOverlayMount *ov, const char *rel,
                           bool include_self)
{
    char prefix[PATH_MAX], prel[PATH_MAX], up[PATH_MAX], parent[PATH_MAX];
    char pending[PATH_MAX] = "";
    struct stat pending_st;
    bool pending_src = false;
    size_t len = strlen(rel);
    int rc = 0;

    for (size_t i = 1; i <= len && rc == 0; i++) {
        if (rel[i] != '/' && rel[i] != '\0')
            continue;
        if (rel[i] == '\0' && !include_self)
            break;
        memcpy(prefix, rel, i);
        prefix[i] = '\0';
        parent_of(prefix, prel);
        if (join(up, sizeof(up), ov->upper_dir, prefix) < 0 ||
            join(parent, sizeof(parent), ov->upper_dir, prel) < 0) {
            rc = -ENAMETOOLONG;
            break;
        }

        struct stat st;
        if (lstat(up, &st) == 0) {
            if (!S_ISDIR(st.st_mode))
                rc = -ENOTDIR;
            continue;
        }

        mode_t locked = unlock_dir(parent);
        if (mkdir(up, S_IRWXU) < 0 && errno != EEXIST)
            rc = -errno;
        relock_dir(parent, locked);

        if (pending[0])
            finish_dir(pending, pending_src ? &pending_st : NULL);
        pending[0] = '\0';
        if (rc == 0) {
            memcpy(pending, up, sizeof(up));
            pending_src = lower_dir(ov, prefix, &pending_st);
        }
    }
    if (pending[0])
        finish_dir(pending, pending_src ? &pending_st : NULL);
    return rc;
}

/* Copy a regular file under a temporary name and rename it into place, so
 * that an interrupted copy never shadows the lower file. */
static int copy_file(const char *src, const char *dst, const struct stat *st)
{
    static unsigned serial;
    char tmp[PATH_MAX];
    const char *slash = strrchr(dst, '/');
    int n = snprintf(tmp, sizeof(tmp), "%.*s/.klee-copyup.%d.%u",
                     (int)(slash ? slash - dst : 0), dst, (int)getpid(),
                     serial++);
    if (n < 0 || (size_t)n >= sizeof(tmp))
        return -ENAMETOOLONG;

    int in = open(src, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (in < 0)
        return -errno;
    int out = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (out < 0) {
        int err = errno;
        close(in);
        return -err;
    }

    int rc = 0;
    char buf[65536];
    ssize_t got = 0;
    while (rc == 0 && (got = read(in, buf, sizeof(buf))) > 0) {
        for (ssize_t done = 0; done < got;) {
            ssize_t w = write(out, buf + done, (size_t)(got - done));
            if (w < 0) {
                rc = -errno;
                break;
            }
            done += w;
        }
    }
    if (rc == 0 && got < 0)
        rc = -errno;
    if (rc == 0) {
        if (fchown(out, st->st_uid, st->st_gid) < 0) {
            /* only root can keep another owner */
        }
        if (fchmod(out, st->st_mode & 07777) < 0)
            rc = -errno;
    }
    if (close(out) < 0 && rc == 0)
        rc = -errno;
    close(in);
    if (rc == 0 && rename(tmp, dst) < 0)
        rc = -errno;
    if (rc < 0)
        unlink(tmp);
    return rc;
}

/* Copy the lower entry e of rel into the upper layer.  -ENOTSUP for a
 * device or socket, which cannot be recreated. */
static int copy_up(const KleeOverlayMount *ov, const char *rel,
                   const OvEntry *e)
{
    char up[PATH_MAX], prel[PATH_MAX], updir[PATH_MAX];
    int rc = make_upper_dirs(ov, rel, false);
    if (rc < 0)
        return rc;
    parent_of(rel, prel);
    if (join(up, sizeof(up), ov->upper_dir, rel) < 0 ||
        join(updir, sizeof(updir), ov->upper_dir, prel) < 0)
        return -ENAMETOOLONG;

    mode_t mode = e->st.st_mode & 07777;
    mode_t locked = unlock_dir(updir);
    if (S_ISREG(e->st.st_mode)) {
        rc = copy_file(e->path, up, &e->st);
    } else if (S_ISDIR(e->st.st_mode)) {
        rc = mkdir(up, S_IRWXU) < 0 ? -errno : 0;
    } else if (S_ISLNK(e->st.st_mode)) {
        char target[PATH_MAX];
        ssize_t len = readlink(e->path, target, sizeof(target) - 1);
        if (len < 0) {
            rc = -errno;
        } else {
            target[len] = '\0';
            rc = symlink(target, up) < 0 ? -errno : 0;
        }
    } else if (S_ISFIFO(e->st.st_mode)) {
        rc = mkfifo(up, S_IRUSR | S_IWUSR) < 0 ? -errno : 0;
    } else {
        rc = -ENOTSUP;
    }
    relock_dir(updir, locked);
    if (rc == -EEXIST)
        rc = 0;   /* made meanwhile; the upper entry wins either way */
    if (rc < 0)
        return rc;

    if (!S_ISREG(e->st.st_mode)) {
        if (lchown(up, e->st.st_uid, e->st.st_gid) < 0) {
            /* only root can keep another owner */
        }
        if (!S_ISLNK(e->st.st_mode))
            chmod(up, mode);
    }
    set_times(up, &e->st);
    KLEE_DEBUG("overlay: copied up %s", e->path);
    return 0;
}

/* The upper entry of an existing name, copied up first if needed.  A device
 * or socket keeps its lower path when in_place: writing to it does not
 * change the layer. */
static int upper_copy(const KleeOverlayMount *ov, const char *rel,
                      const OvEntry *e, bool in_place, char *out, size_t size)
{
    if (e->layer == UPPER_LAYER)
        return put(out, size, e->path);
    int rc = copy_up(ov, rel, e);
    if (rc == -ENOTSUP)
        return in_place ? put(out, size, e->path) : -EXDEV;
    if (rc < 0)
        return rc;
    return join(out, size, ov->upper_dir, rel);
}

/* Upper path for a new name, with the parents the call needs to create it */
static int create_path(const KleeOverlayMount *ov, const char *rel,
                       char *out, size_t size)
{
    char prel[PATH_MAX];
    OvEntry pe;
    parent_of(rel, prel);
    /* Without the parent in the union the call fails with ENOENT anyway */
    if (!*prel || (lookup(ov, prel, &pe) == 0 && S_ISDIR(pe.st.st_mode))) {
        int rc = make_upper_dirs(ov, rel, false);
        if (rc < 0)
            return rc;
    }
    return join(out, size, ov->upper_dir, rel);
}

/* ==================== Merged view ==================== */

typedef struct {
    char *name;
    unsigned char type;   /* d_type of the placeholder */
    int prio;             /* 0 = upper; higher = further down */
} OvName;

typedef struct {
    OvName *v;
    size_t n, cap;
} OvNames;

static int names_add(OvNames *l, const char *name, unsigned char type, int prio)
{
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 64;
        OvName *v = realloc(l->v, cap * sizeof(*v));
        if (!v)
            return -ENOMEM;
        l->v = v;
        l->cap = cap;
    }
    char *copy = strdup(name);
    if (!copy)
        return -ENOMEM;
    l->v[l->n++] = (OvName){ copy, type, prio };
    return 0;
}

static void names_free(OvNames *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i].name);
    free(l->v);
    l->v = NULL;
    l->n = l->cap = 0;
}

static int name_prio_cmp(const void *a, const void *b)
{
    const OvName *x = a, *y = b;
    int c = strcmp(x->name, y->name);
    return c ? c : x->prio - y->prio;
}

static int name_cmp(const void *a, const void *b)
{
    return strcmp(((const OvName *)a)->name, ((const OvName *)b)->name);
}

static unsigned char dtype_at(int dfd, const char *name)
{
    struct stat st;
    if (fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0)
        return DT_UNKNOWN;
    return IFTODT(st.st_mode);
}

/* Placeholders exist for the types getdents reports most; anything else
 * (device, socket) is listed as a regular file. */
static unsigned char placeholder_type(unsigned char d_type)
{
    return d_type == DT_DIR || d_type == DT_LNK || d_type == DT_FIFO
           ? d_type : DT_REG;
}

/* Add the entries of one layer's directory; lower layers skip whiteouts */
static int scan_layer(const KleeOverlayMount *ov, const char *dir,
                      const char *rel, int prio, bool lower, OvNames *l)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;

    int rc = 0;
    struct dirent *de;
    char child[PATH_MAX];
    while (rc == 0 && (de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (lower && (child_of(child, sizeof(child), rel, de->d_name) < 0 ||
                      whiteout_exact(ov, child)))
            continue;
        unsigned char t = de->d_type == DT_UNKNOWN
                          ? dtype_at(dirfd(d), de->d_name) : de->d_type;
        rc = names_add(l, de->d_name, placeholder_type(t), prio);
    }
    closedir(d);
    return rc;
}

/* The entries of directory rel in the union: sorted, one per name */
static int collect(const KleeOverlayMount *ov, const char *rel, OvNames *l)
{
    char path[PATH_MAX];
    struct stat st;
    int rc = 0;
    bool lowers = !whited_out(ov, rel);

    if (ov->upper_dir && join(path, sizeof(path), ov->upper_dir, rel) == 0) {
        if (lstat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode))
                rc = scan_layer(ov, path, rel, 0, false, l);
            else
                lowers = false;   /* a non-directory hides the layers below */
        } else if (errno == ENOTDIR) {
            lowers = false;
        }
    }

    for (int i = ov->lower_count - 1; lowers && rc == 0 && i >= 0; i--) {
        if (join(path, sizeof(path), ov->lower_dirs[i], rel) < 0)
            break;
        if (lstat(path, &st) < 0) {
            if (errno == ENOTDIR)
                break;
            continue;
        }
        if (!S_ISDIR(st.st_mode))
            break;
        rc = scan_layer(ov, path, rel, ov->lower_count - i, true, l);
    }
    if (rc < 0)
        return rc;

    if (l->n)
        qsort(l->v, l->n, sizeof(*l->v), name_prio_cmp);
    size_t kept = 0;
    for (size_t i = 0; i < l->n; i++) {
        if (kept && strcmp(l->v[kept - 1].name, l->v[i].name) == 0) {
            free(l->v[i].name);   /* shadowed by a higher layer */
            continue;
        }
        l->v[kept++] = l->v[i];
    }
    l->n = kept;
    return 0;
}

static void remove_entry(int dfd, const char *name);

/* Delete a subtree of the merged view; it only holds placeholders */
static void remove_tree(int dfd, const char *name)
{
    int sub = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (sub >= 0) {
        struct stat st;
        if (fstat(sub, &st) == 0 && (st.st_mode & S_IRWXU) != S_IRWXU)
            fchmod(sub, (st.st_mode & 07777) | S_IRWXU);
        OvNames names = { 0 };
        int dup_fd = dup(sub);
        DIR *d = dup_fd >= 0 ? fdopendir(dup_fd) : NULL;
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL)
                if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..") &&
                    names_add(&names, de->d_name, 0, 0) < 0)
                    break;
            closedir(d);
        } else if (dup_fd >= 0) {
            close(dup_fd);
        }
        for (size_t i = 0; i < names.n; i++)
            remove_entry(sub, names.v[i].name);
        names_free(&names);
        close(sub);
    }
    unlinkat(dfd, name, AT_REMOVEDIR);
}

static void remove_entry(int dfd, const char *name)
{
    struct stat st;
    if (fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0)
        return;
    if (S_ISDIR(st.st_mode))
        remove_tree(dfd, name);
    else
        unlinkat(dfd, name, 0);
}

static void make_placeholder(int dfd, const char *name, unsigned char type)
{
    int fd;
    switch (type) {
    case DT_DIR:
        mkdirat(dfd, name, S_IRWXU);
        break;
    case DT_LNK:
        if (symlinkat(".klee-overlay", dfd, name) < 0)
            KLEE_DEBUG("overlay: placeholder %s: %s", name, strerror(errno));
        break;
    case DT_FIFO:
        mkfifoat(dfd, name, S_IRUSR | S_IWUSR);
        break;
    default:
        fd = openat(dfd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                    S_IRUSR | S_IWUSR);
        if (fd >= 0)
            close(fd);
        break;
    }
}

/* Make merged directory mp list exactly the entries of rel in the union */
static int sync_dir(const KleeOverlayMount *ov, const char *rel,
                    const char *mp)
{
    OvNames want = { 0 }, stale = { 0 };
    bool *present = NULL;
    DIR *d = NULL;
    int rc = collect(ov, rel, &want);
    int dfd = rc < 0 ? -1
            : open(mp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (rc == 0 && dfd < 0)
        rc = -errno;
    if (rc == 0) {
        present = calloc(want.n ? want.n : 1, sizeof(*present));
        int dup_fd = dup(dfd);
        d = dup_fd >= 0 ? fdopendir(dup_fd) : NULL;
        if (!d && dup_fd >= 0)
            close(dup_fd);
        if (!present || !d)
            rc = -ENOMEM;
    }

    struct dirent *de;
    while (rc == 0 && (de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        OvName key = { de->d_name, 0, 0 };
        OvName *hit = want.n ? bsearch(&key, want.v, want.n, sizeof(*want.v),
                                       name_cmp) : NULL;
        unsigned char t = de->d_type == DT_UNKNOWN
                          ? dtype_at(dfd, de->d_name) : de->d_type;
        if (hit && hit->type == t)
            present[hit - want.v] = true;
        else
            rc = names_add(&stale, de->d_name, t, 0);
    }

    if (rc == 0) {
        mode_t locked = unlock_dir(mp);
        for (size_t i = 0; i < stale.n; i++)
            remove_entry(dfd, stale.v[i].name);
        for (size_t i = 0; i < want.n; i++)
            if (!present[i])
                make_placeholder(dfd, want.v[i].name, want.v[i].type);
        relock_dir(mp, locked);
    }

    if (d)
        closedir(d);
    if (dfd >= 0)
        close(dfd);
    free(present);
    names_free(&want);
    names_free(&stale);
    return rc;
}

/* Mirror the real directory's mode and times on its merged directory */
static void mirror_dir(const char *mp, const struct stat *real)
{
    struct stat cur;
    if (lstat(mp, &cur) < 0)
        return;
    if ((cur.st_mode & 07777) != (real->st_mode & 07777))
        chmod(mp, real->st_mode & 07777);
    if (cur.st_mtim.tv_sec != real->st_mtim.tv_sec ||
        cur.st_mtim.tv_nsec != real->st_mtim.tv_nsec ||
        cur.st_atim.tv_sec != real->st_atim.tv_sec ||
        cur.st_atim.tv_nsec != real->st_atim.tv_nsec)
        set_times(mp, real);
}

/* The merged directory for directory rel, made along with its parents */
static int merged_dir(const KleeOverlayMount *ov, const char *rel,
                      char *mp, size_t size)
{
    char prefix[PATH_MAX], prel[PATH_MAX], path[PATH_MAX], parent[PATH_MAX];
    size_t len = strlen(rel);

    for (size_t i = 1; i <= len; i++) {
        if (rel[i] != '/' && rel[i] != '\0')
            continue;
        memcpy(prefix, rel, i);
        prefix[i] = '\0';
        parent_of(prefix, prel);
        if (join(path, sizeof(path), ov->merged_dir, prefix) < 0 ||
            join(parent, sizeof(parent), ov->merged_dir, prel) < 0)
            return -ENAMETOOLONG;

        struct stat st;
        if (lstat(path, &st) == 0 && S_ISDIR(st.st_mode))
            continue;

        mode_t locked = unlock_dir(parent);
        unlink(path);   /* a placeholder of another type */
        int rc = mkdir(path, S_IRWXU) < 0 && errno != EEXIST ? -errno : 0;
        relock_dir(parent, locked);
        if (rc < 0)
            return rc;

        OvEntry e;
        if (rel[i] == '/' && lookup(ov, prefix, &e) == 0 &&
            S_ISDIR(e.st.st_mode))
            mirror_dir(path, &e.st);
    }
    return join(mp, size, ov->merged_dir, rel);
}

/* What a directory resolves to: its merged directory, resynced for a
 * listing, with the real directory's mode and times. */
static int dir_view(const KleeOverlayMount *ov, const char *rel,
                    const struct stat *real, bool list, char *out, size_t size)
{
    char mp[PATH_MAX];
    int rc = merged_dir(ov, rel, mp, sizeof(mp));
    if (rc < 0)
        return rc;
    if (list && (rc = sync_dir(ov, rel, mp)) < 0)
        KLEE_DEBUG("overlay: cannot list %s: %s", rel, strerror(-rc));
    mirror_dir(mp, real);
    return put(out, size, mp);
}

/* Drop the placeholder of rel from the merged view */
static void merged_forget(const KleeOverlayMount *ov, const char *rel)
{
    char prel[PATH_MAX], parent[PATH_MAX];
    parent_of(rel, prel);
    if (join(parent, sizeof(parent), ov->merged_dir, prel) < 0)
        return;
    int dfd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0)
        return;
    mode_t locked = unlock_dir(parent);
    remove_entry(dfd, base_of(rel));
    relock_dir(parent, locked);
    close(dfd);
}

/* ==================== Deletions ==================== */

/* For a name only lower layers have: an upper entry of the same kind for
 * the syscall to remove, so that it succeeds without touching them. */
static int make_victim(const KleeOverlayMount *ov, const char *rel, bool dir)
{
    char up[PATH_MAX], prel[PATH_MAX], updir[PATH_MAX];
    int rc = make_upper_dirs(ov, rel, false);
    if (rc < 0)
        return rc;
    parent_of(rel, prel);
    if (join(up, sizeof(up), ov->upper_dir, rel) < 0 ||
        join(updir, sizeof(updir), ov->upper_dir, prel) < 0)
        return -ENAMETOOLONG;
    /* Fail as the deletion would, before anything is recorded */
    if (access(updir, W_OK | X_OK) < 0)
        return -errno;

    if (dir) {
        rc = mkdir(up, S_IRWXU) < 0 ? -errno : 0;
    } else {
        int fd = open(up, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, S_IRUSR | S_IWUSR);
        rc = fd < 0 ? -errno : 0;
        if (fd >= 0)
            close(fd);
    }
    return rc;
}

/* unlink/rmdir: the upper path for the syscall to remove.  A name a lower
 * layer has is whited out first; the whiteout is harmless while an upper
 * entry still exists, as that one is found first. */
static int delete_path(KleeOverlayMount *ov, const char *rel,
                       const OvEntry *e, bool dir, char *out, size_t size)
{
    bool is_dir = S_ISDIR(e->st.st_mode);
    if (!dir && is_dir)
        return -EISDIR;
    if (dir && !is_dir)
        return -ENOTDIR;
    if (dir && !*rel)
        return -EBUSY;
    if (dir) {
        OvNames l = { 0 };
        int rc = collect(ov, rel, &l);
        size_t n = l.n;
        names_free(&l);
        if (rc < 0)
            return rc;
        if (n)
            return -ENOTEMPTY;
    }

    if (e->layer != UPPER_LAYER) {
        int rc = make_victim(ov, rel, dir);
        if (rc < 0)
            return rc;
    }
    if (in_lower(ov, rel)) {
        int rc = add_whiteout(ov, rel);
        if (rc < 0)
            return rc;
    }
    merged_forget(ov, rel);
    KLEE_DEBUG("overlay: delete %s", rel);
    return join(out, size, ov->upper_dir, rel);
}

/* Source of a rename: copied up and whited out in the lower layers, so the
 * kernel moves the upper entry.  A directory a lower layer has is EXDEV, as
 * with overlayfs without redirect_dir: callers then copy it instead. */
static int move_path(KleeOverlayMount *ov, const char *rel, const OvEntry *e,
                     char *out, size_t size)
{
    if (!*rel)
        return -EBUSY;
    bool lower = in_lower(ov, rel);
    if (S_ISDIR(e->st.st_mode) && lower)
        return -EXDEV;
    int rc = upper_copy(ov, rel, e, false, out, size);
    if (rc < 0)
        return rc;
    if (lower && (rc = add_whiteout(ov, rel)) < 0)
        return rc;
    merged_forget(ov, rel);
    return 0;
}

/* ==================== Public API ==================== */

KleeOverlayMount *klee_overlay_create(const char *dest, const char *upper,
                                        char **lowers, int lower_count, bool ro)
{
    KleeOverlayMount *ov = calloc(1, sizeof(KleeOverlayMount));
    if (!ov)
        return NULL;

    ov->readonly = ro;

    ov->whiteouts = klee_ht_create();
    if (!ov->whiteouts)
        goto fail;

    /* Copy lower layer paths */
    if (lower_count > 0) {
        ov->lower_dirs = calloc((size_t)lower_count, sizeof(char *));
        if (!ov->lower_dirs)
            goto fail;
        ov->lower_count = lower_count;
        for (int i = 0; i < lower_count; i++) {
            ov->lower_dirs[i] = strdup(lowers[i]);
            if (!ov->lower_dirs[i])
                goto fail;
        }
    }

    /* Merged view, filled in as directories are opened */
    char merged_name[PATH_MAX];
    snprintf(merged_name, sizeof(merged_name), "%s/.merged", dest);
    ov->merged_dir = klee_tmpfs_create(merged_name);
    if (!ov->merged_dir) {
        KLEE_WARN("overlay: failed to create merged dir for %s", dest);
        goto fail;
    }

    /* Upper directory for writable overlays */
    struct stat root;
    if (!ro) {
        if (upper) {
            ov->upper_dir = strdup(upper);
        } else {
            char upper_name[PATH_MAX];
            snprintf(upper_name, sizeof(upper_name), "%s/.upper", dest);
            ov->upper_dir = klee_tmpfs_create(upper_name);
            /* A fresh upper root shows like the root it covers */
            if (ov->upper_dir && lower_dir(ov, "", &root))
                finish_dir(ov->upper_dir, &root);
        }
        if (!ov->upper_dir) {
            KLEE_WARN("overlay: failed to create upper dir for %s", dest);
            goto fail;
        }
    }

    OvEntry top;
    if (lookup(ov, "", &top) == 0 && S_ISDIR(top.st.st_mode))
        mirror_dir(ov->merged_dir, &top.st);

    KLEE_DEBUG("overlay: created for %s (%d lowers, %s)",
               dest, lower_count, ro ? "ro" : "rw");
    return ov;

fail:
    klee_overlay_destroy(ov);
    return NULL;
}

int klee_overlay_resolve(KleeOverlayMount *ov, const char *remainder,
                          char *host_path_out, size_t out_size,
                          KleeOvAccess access)
{
    if (!ov || !remainder || !host_path_out)
        return -EINVAL;

    char rel[PATH_MAX];
    int rc = normalize(remainder, rel, sizeof(rel));
    if (rc < 0)
        return rc;

    /* A read-only overlay is never changed.  The read-only checks refuse
     * what would modify it, with the kernel's errors. */
    bool writable = ov->upper_dir && !ov->readonly;
    if (!writable && access != KLEE_OV_LOOKUP && access != KLEE_OV_LIST)
        access = KLEE_OV_READ;

    OvEntry e;
    rc = lookup(ov, rel, &e);
    if (rc < 0 && rc != -ENOENT && rc != -ENOTDIR)
        return rc;
    bool found = rc == 0;
    bool is_dir = found && S_ISDIR(e.st.st_mode);
    char *out = host_path_out;
    size_t size = out_size;

    switch (access) {
    case KLEE_OV_LOOKUP:
        return found ? put(out, size, e.path) : absent_path(ov, rel, out, size);

    case KLEE_OV_READ:
    case KLEE_OV_LIST:
    case KLEE_OV_CREATE:
        if (!found)
            return access == KLEE_OV_CREATE ? create_path(ov, rel, out, size)
                                            : absent_path(ov, rel, out, size);
        if (is_dir)
            return dir_view(ov, rel, &e.st, access == KLEE_OV_LIST, out, size);
        return put(out, size, e.path);

    case KLEE_OV_WRITE:
    case KLEE_OV_WRITE_CREATE:
        if (!found)
            return access == KLEE_OV_WRITE_CREATE
                   ? create_path(ov, rel, out, size)
                   : absent_path(ov, rel, out, size);
        return upper_copy(ov, rel, &e, true, out, size);

    case KLEE_OV_CREATE_EXCL:
        return found ? -EEXIST : create_path(ov, rel, out, size);

    case KLEE_OV_UNLINK:
    case KLEE_OV_RMDIR:
        if (!found)
            return rc;
        return delete_path(ov, rel, &e, access == KLEE_OV_RMDIR, out, size);

    case KLEE_OV_RENAME_SRC:
        if (!found)
            return absent_path(ov, rel, out, size);
        return move_path(ov, rel, &e, out, size);

    case KLEE_OV_RENAME_DST:
        if (!*rel)
            return -EBUSY;
        /* Replacing a directory of a lower layer: see move_path */
        if (is_dir && in_lower(ov, rel))
            return -EXDEV;
        if (found && e.layer == UPPER_LAYER)
            return put(out, size, e.path);
        return create_path(ov, rel, out, size);

    case KLEE_OV_LINK_SRC:
        if (!found)
            return absent_path(ov, rel, out, size);
        if (is_dir)
            return -EPERM;
        return upper_copy(ov, rel, &e, false, out, size);
    }
    return -EINVAL;
}

void klee_overlay_whiteout(KleeOverlayMount *ov, const char *remainder)
{
    char rel[PATH_MAX];
    if (!ov || !remainder || !ov->whiteouts ||
        normalize(remainder, rel, sizeof(rel)) < 0 || !*rel)
        return;
    if (add_whiteout(ov, rel) == 0)
        merged_forget(ov, rel);
    KLEE_DEBUG("overlay: whiteout %s", rel);
}

bool klee_overlay_is_whiteout(const KleeOverlayMount *ov, const char *remainder)
{
    char rel[PATH_MAX];
    if (!ov || !remainder || normalize(remainder, rel, sizeof(rel)) < 0)
        return false;
    return whited_out(ov, rel);
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
