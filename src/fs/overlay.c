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
#include "fs/overlay_state.h"
#include "fs/tmpfs.h"
#include "util/log.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
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

/* rel itself was deleted in the sandbox */
static bool whiteout_exact(const KleeOverlayMount *ov, const char *rel)
{
    return klee_overlay_state_has(ov->state, rel, strlen(rel));
}

/* rel or one of its ancestors was deleted: no lower layer shows it */
static bool whited_out(const KleeOverlayMount *ov, const char *rel)
{
    if (!ov->state || !*rel)
        return false;
    for (size_t i = 1;; i++) {
        if (rel[i] != '/' && rel[i] != '\0')
            continue;
        if (klee_overlay_state_has(ov->state, rel, i))
            return true;
        if (rel[i] == '\0')
            return false;
    }
}

/* ==================== Layers ==================== */

static int lookup_lower(const KleeOverlayMount *ov, const char *rel, OvEntry *e)
{
    if (whited_out(ov, rel))
        return -ENOENT;
    for (int i = ov->lower_count - 1; i >= 0; i--) {
        if (join(e->path, sizeof(e->path), ov->lower_dirs[i], rel) < 0)
            return -ENAMETOOLONG;
        if (lstat(e->path, &e->st) == 0) {
            e->layer = i;
            return 0;
        }
        if (errno != ENOENT)
            return -errno;
    }
    return -ENOENT;
}

/* Lookup is independent of copy-up and never creates upper entries. */
static int lookup(const KleeOverlayMount *ov, const char *rel, OvEntry *e)
{
    if (ov->upper_dir) {
        if (join(e->path, sizeof(e->path), ov->upper_dir, rel) < 0)
            return -ENAMETOOLONG;
        if (lstat(e->path, &e->st) == 0) {
            e->layer = UPPER_LAYER;
            return 0;
        }
        if (errno != ENOENT)
            return -errno;
    }
    return lookup_lower(ov, rel, e);
}

/* The topmost lower directory at rel, for its mode and times */
static bool lower_dir(const KleeOverlayMount *ov, const char *rel,
                      struct stat *st)
{
    OvEntry entry;
    if (lookup_lower(ov, rel, &entry) < 0 || !S_ISDIR(entry.st.st_mode))
        return false;
    *st = entry.st;
    return true;
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

static mode_t unlock_temp_parent(const KleeOverlayState *state, int fd)
{
    struct stat st;
    if (state->durable || fstat(fd, &st) < 0 || (st.st_mode & S_IRWXU) == S_IRWXU ||
        fchmodat(fd, ".", (st.st_mode & 07777) | S_IRWXU, 0) < 0)
        return NO_MODE;
    return st.st_mode & 07777;
}

static void finish_upper_directory(int fd, const struct stat *source)
{
    fchmod(fd, source ? source->st_mode & 07777 : 0755);
    if (source) {
        struct timespec times[2] = { source->st_atim, source->st_mtim };
        futimens(fd, times);
    }
    close(fd);
}

/* Copy upper parents without following symlinks. Finish each new directory's
 * mode after putting the next level inside it. */
static int make_upper_dirs(const KleeOverlayMount *ov, const char *rel, bool include_self)
{
    char prefix[PATH_MAX];
    int pending_fd = -1;
    struct stat pending_stat;
    bool has_lower = false;
    int rc = 0;
    for (size_t i = 1; *rel && rc == 0; i++) {
        if (rel[i] != '/' && rel[i] != '\0')
            continue;
        if (!rel[i] && !include_self)
            break;

        memcpy(prefix, rel, i);
        prefix[i] = '\0';
        const char *name;
        int parent_fd = klee_overlay_open_parent(ov->state->upper_fd, prefix, &name);
        if (parent_fd < 0) {
            rc = parent_fd;
            break;
        }
        struct stat st;
        if (fstatat(parent_fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            rc = S_ISDIR(st.st_mode) ? 0 : -ENOTDIR;
        } else if (errno != ENOENT) {
            rc = -errno;
        } else {
            mode_t mode = unlock_temp_parent(ov->state, parent_fd);
            bool created = mkdirat(parent_fd, name, S_IRWXU) == 0;
            if (!created)
                rc = -errno;
            if (mode != NO_MODE && fchmodat(parent_fd, ".", mode, 0) < 0 && rc == 0)
                rc = -errno;
            if (created) {
                if (pending_fd >= 0)
                    finish_upper_directory(pending_fd, has_lower ? &pending_stat : NULL);
                pending_fd = openat(parent_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                if (pending_fd < 0)
                    rc = -errno;
                else
                    has_lower = lower_dir(ov, prefix, &pending_stat);
            }
        }
        close(parent_fd);
        if (!rel[i])
            break;
    }
    if (pending_fd >= 0)
        finish_upper_directory(pending_fd, has_lower ? &pending_stat : NULL);
    return rc;
}

static int copy_bytes(int in, int out, off_t length)
{
    char buf[65536];
    while (length > 0) {
        size_t want = length < (off_t)sizeof(buf) ? (size_t)length : sizeof(buf);
        ssize_t count = TEMP_FAILURE_RETRY(read(in, buf, want));
        if (count <= 0)
            return count < 0 ? -errno : -ESTALE;
        for (ssize_t offset = 0; offset < count;) {
            ssize_t written = TEMP_FAILURE_RETRY(write(out, buf + offset,
                                                        (size_t)(count - offset)));
            if (written <= 0)
                return written < 0 ? -errno : -EIO;
            offset += written;
        }
        length -= count;
    }
    return 0;
}

static int copy_file_data(int in, int out, off_t size)
{
    for (off_t pos = 0; pos < size;) {
        off_t data = lseek(in, pos, SEEK_DATA);
        if (data < 0) {
            if (errno == ENXIO)
                break;
            if (pos == 0 && (errno == EINVAL || errno == EOPNOTSUPP))
                return copy_bytes(in, out, size);
            return -errno;
        }
        if (data >= size)
            break;
        off_t hole = lseek(in, data, SEEK_HOLE);
        if (hole < 0)
            return -errno;
        if (hole <= data)
            return -EIO;
        if (hole > size)
            hole = size;
        if (lseek(in, data, SEEK_SET) < 0 || lseek(out, data, SEEK_SET) < 0)
            return -errno;
        int rc = copy_bytes(in, out, hole - data);
        if (rc < 0)
            return rc;
        pos = hole;
    }
    return ftruncate(out, size) < 0 ? -errno : 0;
}

static int copy_user_xattrs(int in, int out)
{
    ssize_t length = flistxattr(in, NULL, 0);
    if (length <= 0)
        return length == 0 || errno == EOPNOTSUPP ? 0 : -errno;
    char *names = malloc((size_t)length);
    if (!names)
        return -ENOMEM;
    length = flistxattr(in, names, (size_t)length);
    int rc = length < 0 ? -errno : 0;
    for (ssize_t i = 0; rc == 0 && i < length;) {
        const char *name = names + i;
        i += (ssize_t)strlen(name) + 1;
        if (strncmp(name, "user.", 5) != 0)
            continue;

        ssize_t size = fgetxattr(in, name, NULL, 0);
        if (size < 0) {
            rc = -errno;
            break;
        }
        void *value = malloc(size > 0 ? (size_t)size : 1);
        if (!value) {
            rc = -ENOMEM;
            break;
        }
        ssize_t got = fgetxattr(in, name, value, (size_t)size);
        if (got < 0 || (got == 0 && size != 0))
            rc = got < 0 ? -errno : -ESTALE;
        else if (got > size)
            rc = -ESTALE;
        else if (fsetxattr(out, name, value, (size_t)got, 0) < 0)
            rc = -errno;
        free(value);
    }
    free(names);
    return rc;
}

/* Copy a file into private staging. A partial copy is discarded. */
static int copy_file(const OvEntry *entry, int dirfd, const char *name, bool durable)
{
    int in = open(entry->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (in < 0)
        return -errno;
    struct stat current;
    if (fstat(in, &current) < 0) {
        int rc = -errno;
        close(in);
        return rc;
    }
    if (current.st_dev != entry->st.st_dev || current.st_ino != entry->st.st_ino ||
        !S_ISREG(current.st_mode)) {
        close(in);
        return -ESTALE;
    }

    int out = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (out < 0) {
        int rc = -errno;
        close(in);
        return rc;
    }
    off_t blocks = current.st_size / 512 + (current.st_size % 512 != 0);
    int rc = current.st_blocks >= blocks ?
             copy_bytes(in, out, current.st_size) :
             copy_file_data(in, out, current.st_size);
    if (rc == 0)
        rc = copy_user_xattrs(in, out);
    if (rc == 0) {
        mode_t mode = current.st_mode & 07777;
        if (fchown(out, current.st_uid, current.st_gid) < 0)
            mode &= ~(S_ISUID | S_ISGID);
        struct timespec times[2] = { current.st_atim, current.st_mtim };
        if (fchmod(out, mode) < 0 || futimens(out, times) < 0)
            rc = -errno;
        if (rc == 0 && durable && fsync(out) < 0)
            rc = -errno;
    }
    if (close(out) < 0 && rc == 0)
        rc = -errno;
    close(in);
    return rc;
}

static int stage_copy(KleeOverlayState *state, const OvEntry *entry, const char *name)
{
    mode_t mode = entry->st.st_mode;
    int dirfd = state->directory_fd;
    if (S_ISREG(mode))
        return copy_file(entry, dirfd, name, state->durable);
    if (S_ISLNK(mode)) {
        char target[PATH_MAX];
        ssize_t length = readlink(entry->path, target, sizeof(target));
        if (length < 0)
            return -errno;
        if ((size_t)length >= sizeof(target))
            return -ENAMETOOLONG;
        target[length] = '\0';
        if (symlinkat(target, dirfd, name) < 0)
            return -errno;
    } else if (S_ISFIFO(mode)) {
        if (mkfifoat(dirfd, name, 0600) < 0 ||
            fchmodat(dirfd, name, mode & 0777, 0) < 0)
            return -errno;
    } else {
        return -ENOTSUP;
    }
    struct timespec times[2] = { entry->st.st_atim, entry->st.st_mtim };
    if (utimensat(dirfd, name, times, AT_SYMLINK_NOFOLLOW) < 0)
        return -errno;
    return 0;
}

static int install_stage(KleeOverlayState *state, const char *stage, const char *path,
                         bool copy_up)
{
    const char *name;
    int parent = klee_overlay_open_parent(state->upper_fd, path, &name);
    if (parent < 0)
        return parent;
    mode_t mode = copy_up ? unlock_temp_parent(state, parent) : NO_MODE;
    int rc = renameat(state->directory_fd, stage, parent, name) == 0 ? 0 : -errno;
    if (mode != NO_MODE && fchmodat(parent, ".", mode, 0) < 0 && rc == 0)
        rc = -errno;
    close(parent);
    return rc;
}

static int copy_up(const KleeOverlayMount *ov, const char *rel, const OvEntry *entry)
{
    if (S_ISDIR(entry->st.st_mode))
        return make_upper_dirs(ov, rel, true);
    int rc = make_upper_dirs(ov, rel, false);
    if (rc < 0)
        return rc;
    KleeOverlayState *state = ov->state;
    rc = stage_copy(state, entry, KLEE_OVERLAY_STAGE_SOURCE);
    if (rc == 0)
        rc = install_stage(state, KLEE_OVERLAY_STAGE_SOURCE, rel, true);
    if (rc < 0)
        klee_overlay_state_clear_stage(state);
    return rc;
}

static int upper_copy(const KleeOverlayMount *ov, const char *rel,
                      const OvEntry *entry, char *out, size_t size)
{
    if (entry->layer == UPPER_LAYER)
        return put(out, size, entry->path);
    int rc = copy_up(ov, rel, entry);
    return rc < 0 ? rc : join(out, size, ov->upper_dir, rel);
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
        return -errno;

    int rc = 0;
    struct dirent *de;
    char child[PATH_MAX];
    while (rc == 0) {
        errno = 0;
        de = readdir(d);
        if (!de) {
            rc = -errno;
            break;
        }
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (ov->state && !*rel && strcmp(de->d_name, KLEE_OVERLAY_STATE_DIR) == 0)
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
        } else if (errno != ENOENT) {
            return -errno;
        }
    }

    for (int i = ov->lower_count - 1; lowers && rc == 0 && i >= 0; i--) {
        if (join(path, sizeof(path), ov->lower_dirs[i], rel) < 0)
            break;
        if (lstat(path, &st) < 0) {
            if (errno == ENOTDIR)
                break;
            if (errno != ENOENT)
                return -errno;
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

/* ==================== Namespace mutations ==================== */

static int writable_path(KleeOverlayMount *ov, const char *path, char *relative)
{
    if (!ov->state || ov->readonly)
        return -EROFS;
    if (ov->state->faulted)
        return -EIO;
    int rc = normalize(path, relative, PATH_MAX);
    if (rc < 0)
        return rc;
    return klee_overlay_state_path(relative) ? -ENOENT : 0;
}

static bool has_trailing_slash(const char *path)
{
    size_t length = strlen(path);
    return length && path[length - 1] == '/';
}

static int empty_directory(const KleeOverlayMount *ov, const char *relative)
{
    OvNames names = { 0 };
    int rc = collect(ov, relative, &names);
    if (rc == 0 && names.n)
        rc = -ENOTEMPTY;
    names_free(&names);
    return rc;
}

static int check_parent(const KleeOverlayMount *ov, const char *relative,
                        const OvEntry *entry)
{
    char parent_path[PATH_MAX];
    parent_of(relative, parent_path);
    OvEntry parent;
    int rc = lookup(ov, parent_path, &parent);
    if (rc < 0)
        return rc;
    if (!S_ISDIR(parent.st.st_mode))
        return -ENOTDIR;
    if (faccessat(AT_FDCWD, parent.path, W_OK | X_OK, AT_EACCESS) < 0)
        return -errno;
    uid_t uid = geteuid();
    if (entry && uid && (parent.st.st_mode & S_ISVTX) &&
        uid != parent.st.st_uid && uid != entry->st.st_uid)
        return -EPERM;
    return 0;
}

static int apply_mask(const KleeOverlayMount *ov, const char *relative,
                      unsigned int mask, bool reject_merged_dir, KleeOverlayChange *change)
{
    OvEntry lower;
    int rc = lookup_lower(ov, relative, &lower);
    if (rc == -ENOENT || rc == -ENOTDIR)
        return 0;
    if (rc < 0)
        return rc;
    if (reject_merged_dir && S_ISDIR(lower.st.st_mode))
        return -EXDEV;
    change->flags |= mask;
    return 0;
}

static int begin_change(KleeOverlayMount *ov, const KleeOverlayChange *change)
{
    int rc = klee_overlay_state_begin(ov->state, change);
    if (rc < 0 && !ov->state->faulted)
        klee_overlay_state_clear_stage(ov->state);
    return rc;
}

static int finish_change(KleeOverlayMount *ov, const KleeOverlayChange *change, int result)
{
    int rc = klee_overlay_state_finish(ov->state, change, result == 0);
    if (rc < 0)
        return rc;
    if (result == 0) {
        merged_forget(ov, change->old_path);
        if (*change->new_path)
            merged_forget(ov, change->new_path);
    }
    return result;
}

int klee_overlay_remove(KleeOverlayMount *ov, const char *path, bool directory)
{
    KleeOverlayChange change = { 0 };
    int rc = writable_path(ov, path, change.old_path);
    if (rc < 0)
        return rc;
    if (!*change.old_path)
        return directory ? -EBUSY : -EISDIR;

    OvEntry entry;
    rc = lookup(ov, change.old_path, &entry);
    if (rc < 0)
        return rc;
    bool is_dir = S_ISDIR(entry.st.st_mode);
    if ((directory || has_trailing_slash(path)) && !is_dir)
        return -ENOTDIR;
    if (!directory && is_dir)
        return -EISDIR;
    if (directory && (rc = empty_directory(ov, change.old_path)) < 0)
        return rc;
    rc = check_parent(ov, change.old_path, &entry);
    if (rc < 0)
        return rc;
    rc = apply_mask(ov, change.old_path, KLEE_OVERLAY_MASK_SOURCE, false, &change);
    if (rc < 0)
        return rc;

    change.operation = entry.layer == UPPER_LAYER ? KLEE_OVERLAY_REMOVE : KLEE_OVERLAY_MASK;
    change.old_inode = klee_overlay_inode(&entry.st);
    rc = begin_change(ov, &change);
    if (rc < 0)
        return rc;
    if (change.operation == KLEE_OVERLAY_REMOVE) {
        const char *name;
        int parent = klee_overlay_open_parent(ov->state->upper_fd, change.old_path, &name);
        if (parent < 0)
            rc = parent;
        else {
            if (unlinkat(parent, name, directory ? AT_REMOVEDIR : 0) < 0)
                rc = -errno;
            close(parent);
        }
    }
    return finish_change(ov, &change, rc);
}

static bool below_path(const char *directory, const char *child)
{
    size_t size = strlen(directory);
    return strncmp(directory, child, size) == 0 && child[size] == '/';
}

static int prepare_inode(KleeOverlayState *state, const OvEntry *entry,
                         const char *stage_name, KleeOverlayInode *inode)
{
    struct stat st = entry->st;
    if (entry->layer != UPPER_LAYER) {
        int rc = stage_copy(state, entry, stage_name);
        if (rc < 0)
            return rc == -ENOTSUP ? -EXDEV : rc;
        if (fstatat(state->directory_fd, stage_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
            return -errno;
    }
    *inode = klee_overlay_inode(&st);
    return 0;
}

static int change_name(KleeOverlayState *state, const KleeOverlayChange *change,
                       unsigned int rename_flags)
{
    bool private_source = change->operation == KLEE_OVERLAY_RENAME &&
                          (change->flags & KLEE_OVERLAY_STAGE_OLD);
    const char *old_name = KLEE_OVERLAY_STAGE_SOURCE;
    const char *new_name;
    int from = private_source ? state->directory_fd :
               klee_overlay_open_parent(state->upper_fd, change->old_path, &old_name);
    if (from < 0)
        return from;
    int to = klee_overlay_open_parent(state->upper_fd, change->new_path, &new_name);
    int rc = to;
    if (to >= 0) {
        int result;
        if (change->operation == KLEE_OVERLAY_LINK)
            result = linkat(from, old_name, to, new_name, 0);
        else if (rename_flags)
            result = syscall(SYS_renameat2, from, old_name, to, new_name, rename_flags);
        else
            result = renameat(from, old_name, to, new_name);
        rc = result == 0 ? 0 : -errno;
        close(to);
    }
    if (!private_source)
        close(from);
    return rc;
}

int klee_overlay_rename(KleeOverlayMount *ov, const char *old_path,
                        const char *new_path, unsigned int flags)
{
    if (flags && flags != RENAME_NOREPLACE && flags != RENAME_EXCHANGE)
        return -EINVAL;
    bool exchange = flags == RENAME_EXCHANGE;
    KleeOverlayChange change = {
        .operation = exchange ? KLEE_OVERLAY_EXCHANGE : KLEE_OVERLAY_RENAME,
    };
    int rc = writable_path(ov, old_path, change.old_path);
    if (rc == 0)
        rc = writable_path(ov, new_path, change.new_path);
    if (rc < 0)
        return rc;
    if (!*change.old_path || !*change.new_path)
        return -EBUSY;

    OvEntry old_entry, new_entry;
    rc = lookup(ov, change.old_path, &old_entry);
    if (rc < 0)
        return rc;
    rc = lookup(ov, change.new_path, &new_entry);
    if (rc < 0 && (rc != -ENOENT || exchange))
        return rc;
    bool target_exists = rc == 0;
    bool old_dir = S_ISDIR(old_entry.st.st_mode);
    bool new_dir = target_exists && S_ISDIR(new_entry.st.st_mode);
    if ((has_trailing_slash(old_path) && !old_dir) ||
        (has_trailing_slash(new_path) && !(target_exists ? new_dir : old_dir)))
        return -ENOTDIR;
    if (flags == RENAME_NOREPLACE && target_exists)
        return -EEXIST;
    if (target_exists && old_entry.st.st_dev == new_entry.st.st_dev &&
        old_entry.st.st_ino == new_entry.st.st_ino)
        return 0;
    if ((old_dir && below_path(change.old_path, change.new_path)) ||
        (new_dir && below_path(change.new_path, change.old_path)))
        return -EINVAL;

    if (!exchange && target_exists) {
        if (old_dir != new_dir)
            return new_dir ? -EISDIR : -ENOTDIR;
        if (new_dir && (rc = empty_directory(ov, change.new_path)) < 0)
            return rc;
    }
    rc = check_parent(ov, change.old_path, &old_entry);
    if (rc == 0)
        rc = check_parent(ov, change.new_path, target_exists ? &new_entry : NULL);
    if (rc == 0)
        rc = apply_mask(ov, change.old_path, KLEE_OVERLAY_MASK_SOURCE, old_dir, &change);
    if (rc == 0)
        rc = apply_mask(ov, change.new_path, KLEE_OVERLAY_MASK_TARGET, exchange && new_dir, &change);
    if (rc < 0)
        return rc;

    /* A moved opaque directory must still hide the destination's lowers. */
    if (old_dir && whited_out(ov, change.old_path))
        change.flags |= KLEE_OVERLAY_MASK_TARGET;
    if (exchange && new_dir && whited_out(ov, change.new_path))
        change.flags |= KLEE_OVERLAY_MASK_SOURCE;

    if (old_entry.layer != UPPER_LAYER)
        change.flags |= KLEE_OVERLAY_STAGE_OLD;
    if (exchange && new_entry.layer != UPPER_LAYER)
        change.flags |= KLEE_OVERLAY_STAGE_NEW;

    rc = make_upper_dirs(ov, change.new_path, false);
    if (rc == 0 && (change.flags & KLEE_OVERLAY_STAGE_OLD) && exchange)
        rc = make_upper_dirs(ov, change.old_path, false);
    if (rc < 0)
        return rc;

    KleeOverlayState *state = ov->state;
    rc = prepare_inode(state, &old_entry, KLEE_OVERLAY_STAGE_SOURCE, &change.old_inode);
    if (rc == 0 && exchange)
        rc = prepare_inode(state, &new_entry, KLEE_OVERLAY_STAGE_TARGET, &change.new_inode);
    else if (target_exists && new_entry.layer == UPPER_LAYER)
        change.new_inode = klee_overlay_inode(&new_entry.st);
    if (rc < 0) {
        klee_overlay_state_clear_stage(state);
        return rc;
    }
    rc = begin_change(ov, &change);
    if (rc < 0)
        return rc;

    if (exchange) {
        if (change.flags & KLEE_OVERLAY_STAGE_OLD)
            rc = install_stage(state, KLEE_OVERLAY_STAGE_SOURCE, change.old_path, false);
        if (rc == 0 && (change.flags & KLEE_OVERLAY_STAGE_NEW))
            rc = install_stage(state, KLEE_OVERLAY_STAGE_TARGET, change.new_path, false);
        if (rc == 0)
            rc = klee_overlay_state_sync(state, &change);
    }
    if (rc == 0)
        rc = change_name(state, &change, flags);
    return finish_change(ov, &change, rc);
}

int klee_overlay_link(KleeOverlayMount *ov, const char *old_path, const char *new_path)
{
    KleeOverlayChange change = { .operation = KLEE_OVERLAY_LINK };
    int rc = writable_path(ov, old_path, change.old_path);
    if (rc == 0)
        rc = writable_path(ov, new_path, change.new_path);
    if (rc < 0)
        return rc;

    OvEntry entry, target;
    rc = lookup(ov, change.old_path, &entry);
    if (rc < 0)
        return rc;
    if (S_ISDIR(entry.st.st_mode))
        return -EPERM;
    if (has_trailing_slash(old_path))
        return -ENOTDIR;
    rc = lookup(ov, change.new_path, &target);
    if (rc == 0)
        return -EEXIST;
    if (rc != -ENOENT || has_trailing_slash(new_path))
        return rc;
    rc = check_parent(ov, change.new_path, NULL);
    if (rc == 0)
        rc = make_upper_dirs(ov, change.new_path, false);
    if (rc == 0 && entry.layer != UPPER_LAYER) {
        change.flags |= KLEE_OVERLAY_STAGE_OLD;
        rc = make_upper_dirs(ov, change.old_path, false);
    }
    if (rc < 0)
        return rc;

    KleeOverlayState *state = ov->state;
    rc = prepare_inode(state, &entry, KLEE_OVERLAY_STAGE_SOURCE, &change.old_inode);
    if (rc < 0) {
        klee_overlay_state_clear_stage(state);
        return rc;
    }
    rc = begin_change(ov, &change);
    if (rc < 0)
        return rc;
    if (change.flags & KLEE_OVERLAY_STAGE_OLD) {
        rc = install_stage(state, KLEE_OVERLAY_STAGE_SOURCE, change.old_path, false);
        if (rc == 0)
            rc = klee_overlay_state_sync(state, &change);
    }
    if (rc == 0)
        rc = change_name(state, &change, 0);
    return finish_change(ov, &change, rc);
}

/* ==================== Public API ==================== */

KleeOverlayMount *klee_overlay_create(const char *dest, const char *upper,
                                        char **lowers, int lower_count, bool ro)
{
    KleeOverlayMount *ov = calloc(1, sizeof(KleeOverlayMount));
    if (!ov)
        return NULL;

    ov->readonly = ro;
    ov->refs = 1;
    int error = ENOMEM;

    /* Copy lower layer paths */
    if (lower_count > 0) {
        ov->lower_dirs = calloc((size_t)lower_count, sizeof(char *));
        if (!ov->lower_dirs)
            goto fail;
        ov->lower_count = lower_count;
        for (int i = 0; i < lower_count; i++) {
            ov->lower_dirs[i] = upper ? realpath(lowers[i], NULL) : strdup(lowers[i]);
            if (!ov->lower_dirs[i]) {
                error = upper ? errno : ENOMEM;
                goto fail;
            }
            if (upper) {
                struct stat st;
                if (stat(ov->lower_dirs[i], &st) < 0) {
                    error = errno;
                    goto fail;
                }
                if (!S_ISDIR(st.st_mode)) {
                    error = ENOTDIR;
                    goto fail;
                }
            }
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
    if (!ro) {
        if (upper) {
            ov->upper_dir = realpath(upper, NULL);
            if (!ov->upper_dir) {
                error = errno;
                goto fail;
            }
            for (int i = 0; i < lower_count; i++) {
                if (strcmp(ov->upper_dir, ov->lower_dirs[i]) == 0) {
                    error = EINVAL;
                    goto fail;
                }
            }
        } else {
            char upper_name[PATH_MAX];
            snprintf(upper_name, sizeof(upper_name), "%s/.upper", dest);
            ov->upper_dir = klee_tmpfs_create(upper_name);
        }
        if (!ov->upper_dir) {
            KLEE_WARN("overlay: failed to create upper dir for %s", dest);
            goto fail;
        }
        int rc = klee_overlay_state_open(ov->upper_dir, upper != NULL, &ov->state);
        if (rc < 0) {
            error = -rc;
            goto fail;
        }
        struct stat root;
        if (!upper && lower_dir(ov, "", &root))
            finish_dir(ov->upper_dir, &root);
    }

    OvEntry top;
    if (lookup(ov, "", &top) == 0 && S_ISDIR(top.st.st_mode))
        mirror_dir(ov->merged_dir, &top.st);

    KLEE_DEBUG("overlay: created for %s (%d lowers, %s)",
               dest, lower_count, ro ? "ro" : "rw");
    return ov;

fail:
    klee_overlay_destroy(ov);
    errno = error;
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

    if (ov->state) {
        if (ov->state->faulted)
            return -EIO;
        if (klee_overlay_state_path(rel))
            return -ENOENT;
    }

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
        /* Data I/O on a special entry uses the same object as readers. */
        if (S_ISFIFO(e.st.st_mode) || S_ISSOCK(e.st.st_mode) ||
            S_ISCHR(e.st.st_mode) || S_ISBLK(e.st.st_mode))
            return put(out, size, e.path);
        return upper_copy(ov, rel, &e, out, size);

    case KLEE_OV_CREATE_EXCL:
        return found ? -EEXIST : create_path(ov, rel, out, size);

    case KLEE_OV_SETATTR:
        return found ? upper_copy(ov, rel, &e, out, size)
                     : absent_path(ov, rel, out, size);
    }
    return -EINVAL;
}

bool klee_overlay_is_whiteout(const KleeOverlayMount *ov, const char *remainder)
{
    char rel[PATH_MAX];
    if (!ov || !remainder || normalize(remainder, rel, sizeof(rel)) < 0)
        return false;
    return whited_out(ov, rel);
}

void klee_overlay_ref(KleeOverlayMount *ov)
{
    if (ov)
        ov->refs++;
}

void klee_overlay_destroy(KleeOverlayMount *ov)
{
    if (!ov || --ov->refs)
        return;

    /* lower_dirs are just path copies; tmpfs cleanup handles actual dirs */
    if (ov->lower_dirs) {
        for (int i = 0; i < ov->lower_count; i++)
            free(ov->lower_dirs[i]);
        free(ov->lower_dirs);
    }
    klee_overlay_state_close(ov->state);
    free(ov->upper_dir);
    /* merged_dir is managed by tmpfs subsystem */
    free(ov->merged_dir);
    free(ov);
}
