/*
 * Persistent overlay namespace state. The upper and its state directory
 * share a filesystem. After fsyncing a prepared record, a single kernel
 * rename or unlink decides the operation. Recovery compares inode identities
 * before replaying whiteouts. A committed record only needs its path masks.
 */
#include "fs/overlay_state.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#define RECORD_MAGIC UINT64_C(0x314c564f45454c4b)  /* KLEEOVL1 */
#define PENDING "pending"
#define DRAFT "pending.new"
#define FORMAT "format-v1"
#define MASKS (KLEE_OVERLAY_MASK_SOURCE | KLEE_OVERLAY_MASK_TARGET)
#define STAGES (KLEE_OVERLAY_STAGE_OLD | KLEE_OVERLAY_STAGE_NEW)

typedef struct {
    uint64_t magic;
    uint32_t operation;
    uint32_t flags;
    KleeOverlayInode old_inode;
    KleeOverlayInode new_inode;
    uint32_t old_length;
    uint32_t new_length;
} RecordHeader;

typedef struct Whiteout {
    struct Whiteout *next;
    char path[];
} Whiteout;

bool klee_overlay_state_path(const char *relative)
{
    return strncmp(relative, KLEE_OVERLAY_STATE_DIR, sizeof(KLEE_OVERLAY_STATE_DIR) - 1) == 0 &&
           (relative[sizeof(KLEE_OVERLAY_STATE_DIR) - 1] == '/' ||
            relative[sizeof(KLEE_OVERLAY_STATE_DIR) - 1] == '\0');
}

static uint64_t path_hash(const char *path, size_t length)
{
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < length; i++) {
        hash ^= (unsigned char)path[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

bool klee_overlay_state_has(const KleeOverlayState *state, const char *path, size_t length)
{
    if (!state || !length)
        return false;
    Whiteout *head = klee_ht_get(state->whiteouts, path_hash(path, length));
    for (Whiteout *entry = head; entry; entry = entry->next) {
        if (strncmp(entry->path, path, length) == 0 && entry->path[length] == '\0')
            return true;
    }
    return false;
}

static int remember_whiteout(KleeOverlayState *state, const char *path)
{
    size_t length = strlen(path);
    if (klee_overlay_state_has(state, path, length))
        return 0;
    uint64_t hash = path_hash(path, length);
    Whiteout *item = malloc(sizeof(*item) + length + 1);
    if (!item)
        return -ENOMEM;
    strcpy(item->path, path);
    item->next = klee_ht_get(state->whiteouts, hash);
    klee_ht_put(state->whiteouts, hash, item);
    if (klee_ht_get(state->whiteouts, hash) == item)
        return 0;
    free(item);
    return -ENOMEM;
}

static int remember_change(KleeOverlayState *state, const KleeOverlayChange *change)
{
    int rc = 0;
    if (change->flags & KLEE_OVERLAY_MASK_SOURCE)
        rc = remember_whiteout(state, change->old_path);
    if (rc == 0 && (change->flags & KLEE_OVERLAY_MASK_TARGET))
        rc = remember_whiteout(state, change->new_path);
    return rc;
}

static int free_whiteouts(uint64_t key, void *value, void *ctx)
{
    (void)key;
    (void)ctx;
    Whiteout *entry = value;
    while (entry) {
        Whiteout *next = entry->next;
        free(entry);
        entry = next;
    }
    return 0;
}

KleeOverlayInode klee_overlay_inode(const struct stat *st)
{
    return (KleeOverlayInode){ st->st_dev, st->st_ino };
}

static bool same_inode(KleeOverlayInode a, KleeOverlayInode b)
{
    return a.device == b.device && a.inode == b.inode;
}

static bool missing(KleeOverlayInode inode)
{
    return inode.device == 0 && inode.inode == 0;
}

/* Record paths must stay relative to the upper directory. */
static bool valid_path(const char *path)
{
    if (!*path || klee_overlay_state_path(path))
        return false;
    for (const char *p = path; ; ) {
        size_t length = strcspn(p, "/");
        if (!length || (length == 1 && p[0] == '.') ||
            (length == 2 && p[0] == '.' && p[1] == '.'))
            return false;
        if (!p[length])
            return true;
        p += length + 1;
    }
}

static int transfer(int fd, void *buffer, size_t size, bool writing)
{
    char *p = buffer;
    while (size) {
        ssize_t n = writing ? write(fd, p, size) : read(fd, p, size);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return n < 0 ? -errno : -EIO;
        p += n;
        size -= (size_t)n;
    }
    return 0;
}

static int load_record(int dirfd, const char *name, KleeOverlayChange *change)
{
    int fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return -errno;
    struct stat st;
    RecordHeader header;
    int rc = fstat(fd, &st) < 0 ? -errno : 0;
    if (rc == 0)
        rc = S_ISREG(st.st_mode) ? transfer(fd, &header, sizeof(header), false) : -EINVAL;
    if (rc == 0 &&
        (header.magic != RECORD_MAGIC || header.operation < KLEE_OVERLAY_MASK ||
         header.operation > KLEE_OVERLAY_LINK || header.flags & ~(MASKS | STAGES) ||
         !header.old_length || header.old_length >= PATH_MAX ||
         header.new_length >= PATH_MAX ||
         st.st_size != (off_t)(sizeof(header) + header.old_length + header.new_length)))
        rc = -EINVAL;
    if (rc == 0) {
        change->operation = header.operation;
        change->flags = header.flags;
        change->old_inode = header.old_inode;
        change->new_inode = header.new_inode;
        rc = transfer(fd, change->old_path, header.old_length, false);
        if (rc == 0)
            rc = transfer(fd, change->new_path, header.new_length, false);
        change->old_path[header.old_length] = '\0';
        change->new_path[header.new_length] = '\0';
        bool needs_target = change->operation >= KLEE_OVERLAY_RENAME;
        if (rc == 0 &&
            (strlen(change->old_path) != header.old_length ||
             !valid_path(change->old_path) ||
             strlen(change->new_path) != header.new_length ||
             (needs_target ? !valid_path(change->new_path) : header.new_length != 0) ||
             ((change->flags & KLEE_OVERLAY_MASK_TARGET) && !needs_target)))
            rc = -EINVAL;
    }
    close(fd);
    return rc;
}

/* Open each component without following symlinks in the upper tree. */
static int walk_parent(int root_fd, const char *path, const char **name, bool sync)
{
    int fd = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (fd < 0)
        return -errno;
    for (;;) {
        int rc = 0;
        if (sync && fsync(fd) < 0)
            rc = -errno;
        const char *slash = strchr(path, '/');
        if (rc == 0 && !slash) {
            *name = path;
            return fd;
        }
        int next = -1;
        if (rc == 0) {
            size_t length = (size_t)(slash - path);
            char part[NAME_MAX + 1];
            if (!length || length > NAME_MAX) {
                rc = -ENAMETOOLONG;
            } else {
                memcpy(part, path, length);
                part[length] = '\0';
                int flags = O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
                next = openat(fd, part, flags | (sync ? O_RDONLY : O_PATH));
                if (next < 0)
                    rc = -errno;
            }
        }
        close(fd);
        if (rc < 0)
            return rc;
        fd = next;
        path = slash + 1;
    }
}

int klee_overlay_open_parent(int root_fd, const char *path, const char **name)
{
    return walk_parent(root_fd, path, name, false);
}

static int stat_entry(int fd, const char *name, KleeOverlayInode *inode)
{
    struct stat st;
    if (fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0) {
        *inode = klee_overlay_inode(&st);
        return 0;
    }
    if (errno != ENOENT)
        return -errno;
    *inode = (KleeOverlayInode){ 0 };
    return 0;
}

static int stat_inode(int root_fd, const char *path, KleeOverlayInode *inode)
{
    const char *name;
    int fd = klee_overlay_open_parent(root_fd, path, &name);
    if (fd == -ENOENT) {
        *inode = (KleeOverlayInode){ 0 };
        return 0;
    }
    if (fd < 0)
        return fd;
    int rc = stat_entry(fd, name, inode);
    close(fd);
    return rc;
}

/* Flush ancestors too because copy-up can create a chain of upper parents. */
static int sync_parents(int upper_fd, const char *path)
{
    const char *name;
    int fd = walk_parent(upper_fd, path, &name, true);
    if (fd < 0)
        return fd;
    close(fd);
    return 0;
}

int klee_overlay_state_sync(KleeOverlayState *state, const KleeOverlayChange *change)
{
    if (!state->durable || change->operation == KLEE_OVERLAY_MASK)
        return 0;
    bool private_source = change->operation == KLEE_OVERLAY_RENAME &&
                          (change->flags & KLEE_OVERLAY_STAGE_OLD);
    int rc = private_source ? 0 : sync_parents(state->upper_fd, change->old_path);
    if (rc == 0 && *change->new_path)
        rc = sync_parents(state->upper_fd, change->new_path);
    return rc;
}

static int unlink_if_present(int fd, const char *path)
{
    return unlinkat(fd, path, 0) == 0 || errno == ENOENT ? 0 : -errno;
}

int klee_overlay_state_clear_stage(KleeOverlayState *state)
{
    int rc = unlink_if_present(state->directory_fd, KLEE_OVERLAY_STAGE_SOURCE);
    return rc < 0 ? rc : unlink_if_present(state->directory_fd, KLEE_OVERLAY_STAGE_TARGET);
}

int klee_overlay_state_begin(KleeOverlayState *state, const KleeOverlayChange *change)
{
    if (state->faulted)
        return -EIO;
    if (!state->durable)
        return 0;
    if ((change->flags & MASKS) && state->next_record == UINT64_MAX)
        return -EOVERFLOW;
    int rc = klee_overlay_state_sync(state, change);
    if (rc < 0)
        return rc;
    int dirfd = state->directory_fd;
    int fd = openat(dirfd, DRAFT, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return -errno;
    RecordHeader header = {
        .magic = RECORD_MAGIC, .operation = change->operation, .flags = change->flags,
        .old_inode = change->old_inode, .new_inode = change->new_inode,
        .old_length = strlen(change->old_path), .new_length = strlen(change->new_path),
    };
    rc = transfer(fd, &header, sizeof(header), true);
    /* transfer does not modify buffers used for a write. */
    if (rc == 0)
        rc = transfer(fd, (void *)change->old_path, header.old_length, true);
    if (rc == 0)
        rc = transfer(fd, (void *)change->new_path, header.new_length, true);
    if (rc == 0 && fsync(fd) < 0)
        rc = -errno;
    if (close(fd) < 0 && rc == 0)
        rc = -errno;
    if (rc == 0 && renameat(dirfd, DRAFT, dirfd, PENDING) < 0)
        rc = -errno;
    if (rc < 0) {
        unlink_if_present(dirfd, DRAFT);
        return rc;
    }
    if (fsync(dirfd) < 0) {
        state->faulted = true;
        return -errno;
    }
    return 0;
}

static int remove_staged_name(int upper_fd, const char *path, KleeOverlayInode expected)
{
    const char *name;
    int fd = klee_overlay_open_parent(upper_fd, path, &name);
    if (fd < 0)
        return fd == -ENOENT ? 0 : fd;
    KleeOverlayInode current = { 0 };
    int rc = stat_entry(fd, name, &current);
    if (rc == 0 && !missing(current))
        rc = same_inode(current, expected) ? unlink_if_present(fd, name) : -EIO;
    close(fd);
    return rc;
}

int klee_overlay_state_finish(KleeOverlayState *state, const KleeOverlayChange *change,
                               bool committed)
{
    int rc = 0;
    if (!committed && (change->operation == KLEE_OVERLAY_EXCHANGE ||
                       change->operation == KLEE_OVERLAY_LINK)) {
        if (change->flags & KLEE_OVERLAY_STAGE_OLD)
            rc = remove_staged_name(state->upper_fd, change->old_path, change->old_inode);
        if (rc == 0 && (change->flags & KLEE_OVERLAY_STAGE_NEW))
            rc = remove_staged_name(state->upper_fd, change->new_path, change->new_inode);
    }
    if (rc == 0)
        rc = klee_overlay_state_sync(state, change);
    if (rc == 0)
        rc = klee_overlay_state_clear_stage(state);
    if (rc == 0 && state->durable) {
        int dirfd = state->directory_fd;
        if (committed && (change->flags & MASKS)) {
            char name[32];
            snprintf(name, sizeof(name), "r%016" PRIx64, state->next_record);
            if (state->next_record == UINT64_MAX)
                rc = -EOVERFLOW;
            else if (renameat(dirfd, PENDING, dirfd, name) < 0)
                rc = -errno;
            else
                state->next_record++;
        } else {
            rc = unlink_if_present(dirfd, PENDING);
        }
        if (rc == 0 && fsync(dirfd) < 0)
            rc = -errno;
    }
    if (rc == 0 && committed)
        rc = remember_change(state, change);
    if (rc < 0)
        state->faulted = true;
    return rc;
}

static int recover(KleeOverlayState *state)
{
    KleeOverlayChange change;
    int rc = load_record(state->directory_fd, PENDING, &change);
    if (rc == -ENOENT)
        return klee_overlay_state_clear_stage(state);
    if (rc < 0)
        return rc;
    if (change.operation == KLEE_OVERLAY_MASK)
        return klee_overlay_state_finish(state, &change, true);

    KleeOverlayInode old = { 0 }, new = { 0 };
    rc = stat_inode(state->upper_fd, change.old_path, &old);
    if (rc == 0 && *change.new_path)
        rc = stat_inode(state->upper_fd, change.new_path, &new);
    if (rc < 0)
        return rc;

    bool committed;
    bool unchanged;
    switch (change.operation) {
    case KLEE_OVERLAY_REMOVE:
        committed = missing(old);
        unchanged = same_inode(old, change.old_inode);
        break;
    case KLEE_OVERLAY_RENAME:
        committed = missing(old) && same_inode(new, change.old_inode);
        unchanged = same_inode(new, change.new_inode) &&
                    ((change.flags & KLEE_OVERLAY_STAGE_OLD)
                     ? missing(old) : same_inode(old, change.old_inode));
        break;
    case KLEE_OVERLAY_EXCHANGE:
        committed = same_inode(old, change.new_inode) && same_inode(new, change.old_inode);
        unchanged = (same_inode(old, change.old_inode) ||
                     ((change.flags & KLEE_OVERLAY_STAGE_OLD) && missing(old))) &&
                    (same_inode(new, change.new_inode) ||
                     ((change.flags & KLEE_OVERLAY_STAGE_NEW) && missing(new)));
        break;
    case KLEE_OVERLAY_LINK:
        committed = same_inode(old, change.old_inode) && same_inode(new, change.old_inode);
        unchanged = missing(new) &&
                    (same_inode(old, change.old_inode) ||
                     ((change.flags & KLEE_OVERLAY_STAGE_OLD) && missing(old)));
        break;
    default:
        return -EINVAL;
    }
    if (!committed && !unchanged)
        return -EIO;
    return klee_overlay_state_finish(state, &change, committed);
}

static int load_state(KleeOverlayState *state)
{
    int scan_fd = dup(state->directory_fd);
    if (scan_fd < 0)
        return -errno;
    DIR *dir = fdopendir(scan_fd);
    if (!dir) {
        int rc = -errno;
        close(scan_fd);
        return rc;
    }
    int rc = 0;
    while (rc == 0) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) {
            rc = -errno;
            break;
        }
        const char *name = entry->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..") ||
            !strcmp(name, FORMAT) || !strcmp(name, PENDING) || !strcmp(name, DRAFT) ||
            !strcmp(name, KLEE_OVERLAY_STAGE_SOURCE) || !strcmp(name, KLEE_OVERLAY_STAGE_TARGET))
            continue;
        uint64_t serial;
        char tail;
        if (strlen(name) != 17 || strspn(name + 1, "0123456789abcdef") != 16 ||
            sscanf(name, "r%16" SCNx64 "%c", &serial, &tail) != 1 || serial == UINT64_MAX) {
            rc = -EINVAL;
            break;
        }
        if (serial >= state->next_record)
            state->next_record = serial + 1;
        KleeOverlayChange change;
        rc = load_record(state->directory_fd, name, &change);
        if (rc == 0)
            rc = remember_change(state, &change);
    }
    closedir(dir);
    if (rc == 0)
        rc = unlink_if_present(state->directory_fd, DRAFT);
    return rc < 0 ? rc : recover(state);
}

/* Adopt an empty state directory with an atomic format marker. Never clean
 * staging names in an unrelated pre-existing directory. */
static int ensure_format(int dirfd)
{
    struct stat marker;
    if (fstatat(dirfd, FORMAT, &marker, AT_SYMLINK_NOFOLLOW) == 0)
        return S_ISDIR(marker.st_mode) ? 0 : -EINVAL;
    if (errno != ENOENT)
        return -errno;

    int scan_fd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (scan_fd < 0)
        return -errno;
    DIR *dir = fdopendir(scan_fd);
    if (!dir) {
        int rc = -errno;
        close(scan_fd);
        return rc;
    }
    int rc = 0;
    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
            rc = -EINVAL;
            break;
        }
    }
    if (rc == 0 && errno)
        rc = -errno;
    closedir(dir);
    if (rc < 0)
        return rc;
    if (mkdirat(dirfd, FORMAT, 0700) < 0 || fsync(dirfd) < 0)
        return -errno;
    return 0;
}

int klee_overlay_state_open(const char *upper, bool durable, KleeOverlayState **out)
{
    KleeOverlayState *state = calloc(1, sizeof(*state));
    if (!state)
        return -ENOMEM;
    state->upper_fd = -1;
    state->directory_fd = -1;
    state->durable = durable;
    state->whiteouts = klee_ht_create();
    int rc = -ENOMEM;
    if (!state->whiteouts)
        goto fail;

    state->upper_fd = open(upper, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (state->upper_fd < 0)
        goto system_error;
    if (durable && flock(state->upper_fd, LOCK_EX | LOCK_NB) < 0)
        goto system_error;
    if (mkdirat(state->upper_fd, KLEE_OVERLAY_STATE_DIR, 0700) < 0 && errno != EEXIST)
        goto system_error;
    state->directory_fd = openat(state->upper_fd, KLEE_OVERLAY_STATE_DIR,
                                 O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (state->directory_fd < 0)
        goto system_error;
    struct stat st, upper_stat;
    if (fstat(state->directory_fd, &st) < 0 || fstat(state->upper_fd, &upper_stat) < 0)
        goto system_error;
    if (st.st_dev != upper_stat.st_dev) {
        rc = -EXDEV;
        goto fail;
    }
    if (st.st_uid != geteuid() || (st.st_mode & 0077)) {
        rc = -EACCES;
        goto fail;
    }
    if (durable) {
        if (fsync(state->upper_fd) < 0)
            goto system_error;
        rc = ensure_format(state->directory_fd);
        if (rc == 0)
            rc = load_state(state);
        if (rc < 0)
            goto fail;
    }
    *out = state;
    return 0;

system_error:
    rc = -errno;
fail:
    klee_overlay_state_close(state);
    return rc;
}

void klee_overlay_state_close(KleeOverlayState *state)
{
    if (!state)
        return;
    if (state->whiteouts) {
        klee_ht_foreach(state->whiteouts, free_whiteouts, NULL);
        klee_ht_destroy(state->whiteouts);
    }
    if (state->directory_fd >= 0)
        close(state->directory_fd);
    if (state->upper_fd >= 0)
        close(state->upper_fd);
    free(state);
}
