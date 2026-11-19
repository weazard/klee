/*
 * Klee - Userspace bwrap translation layer
 * Exec shim: start sandbox binaries under the sandbox's own ELF interpreter
 * without re-executing them through ld.so.
 *
 * The kernel resolves PT_INTERP on the host filesystem, so a dynamic binary
 * from a rootfs that is not mounted at / would be started with the host's
 * loader.  klee used to work around that by executing the sandbox's ld.so
 * directly with the program as its first argument.  That keeps the ABI
 * right but changes everything that identifies a process: comm becomes
 * "ld-linux-x86-64", /proc/<pid>/cmdline grows a loader prefix, the
 * program's argv[0] turns into its resolved path and /proc/<pid>/exe points
 * at the loader.  ps, pgrep, pidof, killall and every peer that goes by
 * name were wrong for every process in a Conty or Steam-runtime sandbox.
 *
 * Instead, exec a private copy of the binary whose PT_INTERP string names a
 * short symlink to the sandbox's loader.  The kernel then loads the right
 * loader itself. The caller supplies argv and envp, and the staged path
 * controls comm and AT_EXECFN.
 *
 * Layout, all per klee session and removed on exit:
 *
 *   /tmp/kl-XXXXXX/<n>               -> loader n (host path).  Short enough
 *                                       to fit in any PT_INTERP string.
 *   /tmp/kl-XXXXXX/a<n>/<name>       -> loader n, for the ld.so fallback
 *   <dir>/klee-exec.XXXXXX/<key>/<prog>     patched copy of one binary
 *   <dir>/klee-exec.XXXXXX/<key>/<name>     -> <prog> (gives comm)
 *
 * <key> identifies the source file (device, inode, size, mtime, ctime) and
 * the loader it was patched for, so a binary is copied once per session.
 * Every session directory holds a .lock file that its klee keeps flock()ed;
 * a later klee removes any directory whose lock is free, so sessions that
 * died without running their cleanup do not pile up.
 *
 * Environment:
 *   KLEE_EXEC_SHIM=0           never copy; always fall back to ld.so
 *   KLEE_EXEC_DIR=<dir>        where to keep the copies (default: $TMPDIR,
 *                              /tmp, /var/tmp; must allow exec)
 *   KLEE_EXEC_COPY_MAX_MB=<n>  binaries larger than this use ld.so
 *                              (default 512, 0 = no limit)
 */
#include "syscall/exec_shim.h"
#include "util/log.h"

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#define LOCK_FILE ".lock"
#define COPY_TMP  ".staging"
#define COPY_DIR_PREFIX "klee-exec."
#define LINK_DIR_PREFIX "kl-"
#define DEFAULT_COPY_MAX_MB 512ULL
#define COPY_NAME_MAX 64

/* ==================== ELF ==================== */

int klee_elf_read_interp(int fd, KleeElfInfo *info)
{
    memset(info, 0, sizeof(*info));

    int found = -1;
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode))
        goto out;
    unsigned char ident[EI_NIDENT];
    uint64_t phoff;
    uint16_t phentsize, phnum;
    size_t phsize;

    if (pread(fd, ident, sizeof(ident), 0) != (ssize_t)sizeof(ident) ||
        memcmp(ident, ELFMAG, SELFMAG) != 0 ||
        ident[EI_DATA] != ELFDATA2LSB)
        goto out;

    if (ident[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr eh;
        if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh))
            goto out;
        phoff = eh.e_phoff;
        phentsize = eh.e_phentsize;
        phnum = eh.e_phnum;
        phsize = sizeof(Elf64_Phdr);
    } else if (ident[EI_CLASS] == ELFCLASS32) {
        Elf32_Ehdr eh;
        if (pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh))
            goto out;
        phoff = eh.e_phoff;
        phentsize = eh.e_phentsize;
        phnum = eh.e_phnum;
        phsize = sizeof(Elf32_Phdr);
    } else {
        goto out;
    }

    if (phentsize != phsize || phnum == 0 || phnum > 4096)
        goto out;

    info->elf_class = ident[EI_CLASS];

    for (uint16_t i = 0; i < phnum; i++) {
        uint32_t p_type;
        uint64_t p_offset, p_filesz;
        off_t at = (off_t)(phoff + (uint64_t)i * phsize);

        if (ident[EI_CLASS] == ELFCLASS64) {
            Elf64_Phdr ph;
            if (pread(fd, &ph, sizeof(ph), at) != (ssize_t)sizeof(ph))
                break;
            p_type = ph.p_type;
            p_offset = ph.p_offset;
            p_filesz = ph.p_filesz;
        } else {
            Elf32_Phdr ph;
            if (pread(fd, &ph, sizeof(ph), at) != (ssize_t)sizeof(ph))
                break;
            p_type = ph.p_type;
            p_offset = ph.p_offset;
            p_filesz = ph.p_filesz;
        }

        if (p_type != PT_INTERP)
            continue;

        /* Same limits as the kernel's load_elf_binary(); a binary that
         * fails them does not exec at all, so leave it alone. */
        if (p_filesz < 2 || p_filesz >= sizeof(info->interp))
            break;
        if (pread(fd, info->interp, p_filesz, (off_t)p_offset)
            != (ssize_t)p_filesz)
            break;
        if (info->interp[p_filesz - 1] != '\0')
            break;

        info->interp_off = p_offset;
        info->interp_size = p_filesz;
        found = 0;
        break;
    }

out:
    return found;
}

/* ==================== Shim state ==================== */

typedef struct {
    char *host;                /* loader / interpreter host path */
    char link[PATH_MAX];       /* short symlink to it, "" if none */
    bool alias_dir_ok;         /* <link_dir>/a<n> exists */
} ShimTarget;

struct klee_exec_shim {
    pid_t owner;
    bool copies_enabled;
    char link_dir[PATH_MAX];   /* "" if unavailable */
    char copy_dir[PATH_MAX];   /* "" if unavailable */
    int copy_dirfd;
    int link_lock_fd, copy_lock_fd;   /* flock()ed for the session */
    uint64_t max_copy_bytes;   /* 0 = unlimited */
    ShimTarget *targets;
    size_t ntargets, cap;
};

static KleeExecShim *the_shim;

static bool env_is_off(const char *v)
{
    return v && (strcmp(v, "0") == 0 || strcasecmp(v, "off") == 0 ||
                 strcasecmp(v, "no") == 0 || strcasecmp(v, "false") == 0);
}

static bool valid_name(const char *name)
{
    size_t len = name ? strlen(name) : 0;
    return len > 0 && len <= NAME_MAX && strchr(name, '/') == NULL &&
           strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

static void rm_tree_at(int dirfd, const char *name);

/* Open and flock() dir/.lock.  Returns the fd (kept open for the lock's
 * lifetime) or -1 if the lock is held by another process or unavailable. */
static int lock_session_dir(int dirfd, bool create)
{
    int flags = O_RDWR | O_CLOEXEC | (create ? O_CREAT : 0);
    int fd = openat(dirfd, LOCK_FILE, flags, 0600);
    if (fd < 0)
        return -1;
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Remove session directories under base whose owner klee is gone.  Only
 * directories we own and that carry an unlocked .lock are touched; one that
 * has no .lock yet is being set up by a klee that is still alive. */
static void reclaim_stale(const char *base, const char *prefix)
{
    if (!base || !*base)
        return;
    DIR *d = opendir(base);
    if (!d)
        return;
    int base_fd = dirfd(d);
    size_t plen = strlen(prefix);
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, prefix, plen) != 0 ||
            strlen(de->d_name) != plen + 6)
            continue;
        struct stat st;
        if (fstatat(base_fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISDIR(st.st_mode) || st.st_uid != geteuid())
            continue;
        int fd = openat(base_fd, de->d_name,
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
            continue;
        int lock = lock_session_dir(fd, false);
        close(fd);
        if (lock < 0)
            continue;
        KLEE_DEBUG("exec shim: removing stale %s/%s", base, de->d_name);
        rm_tree_at(base_fd, de->d_name);
        close(lock);
    }
    closedir(d);
}

/* mkdtemp(base/prefixXXXXXX) with its lock taken, optionally requiring an
 * exec-capable mount.  The directory is 0711: a sandboxed process that
 * really dropped to another uid can still traverse it; the copies carry
 * the originals' permissions. */
static bool make_session_dir(const char *base, const char *prefix,
                             bool need_exec, char *out, size_t out_size,
                             int *dirfd_out, int *lock_out)
{
    if (!base || !*base)
        return false;

    /* Publish the session name after the lock is held. The stale-session
     * scanner ignores the temporary name while setup is in progress. */
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/.%sXXXXXX", base, prefix);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;
    if (!mkdtemp(path))
        return false;
    (void)chmod(path, 0711);

    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int lock = fd >= 0 ? lock_session_dir(fd, true) : -1;
    bool ok = lock >= 0;
    if (ok && need_exec) {
        struct statvfs sv;
        if (fstatvfs(fd, &sv) == 0 && (sv.f_flag & ST_NOEXEC)) {
            KLEE_DEBUG("exec shim: %s is mounted noexec", path);
            ok = false;
        }
    }
    if (!ok) {
        if (lock >= 0)
            close(lock);
        if (fd >= 0)
            close(fd);
        rm_tree_at(AT_FDCWD, path);
        return false;
    }

    int length = snprintf(out, out_size, "%s/%s", base, strrchr(path, '/') + 2);
    if (length < 0 || (size_t)length >= out_size ||
        renameat2(AT_FDCWD, path, AT_FDCWD, out, RENAME_NOREPLACE) < 0) {
        close(lock);
        close(fd);
        rm_tree_at(AT_FDCWD, path);
        out[0] = '\0';
        return false;
    }
    *lock_out = lock;
    if (dirfd_out)
        *dirfd_out = fd;
    else
        close(fd);
    return true;
}

static KleeExecShim *shim_create(void)
{
    KleeExecShim *s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->owner = getpid();
    s->copy_dirfd = -1;
    s->link_lock_fd = -1;
    s->copy_lock_fd = -1;
    s->copies_enabled = !env_is_off(getenv("KLEE_EXEC_SHIM"));
    s->max_copy_bytes = DEFAULT_COPY_MAX_MB << 20;

    const char *e = getenv("KLEE_EXEC_COPY_MAX_MB");
    if (e && *e) {
        char *end;
        unsigned long long v = strtoull(e, &end, 10);
        if (*end == '\0' && v < (1ULL << 40))
            s->max_copy_bytes = v << 20;
    }

    const char *bases[] = { getenv("KLEE_EXEC_DIR"), getenv("TMPDIR"),
                            "/tmp", "/var/tmp" };
    for (size_t i = 0; i < sizeof(bases) / sizeof(bases[0]); i++)
        reclaim_stale(bases[i], COPY_DIR_PREFIX);
    reclaim_stale("/tmp", LINK_DIR_PREFIX);
    reclaim_stale(getenv("TMPDIR"), LINK_DIR_PREFIX);

    /* Loader links must fit inside PT_INTERP strings as short as
     * "/lib/ld-linux.so.2", so try /tmp before anything longer. */
    if (!make_session_dir("/tmp", LINK_DIR_PREFIX, false, s->link_dir,
                          sizeof(s->link_dir), NULL, &s->link_lock_fd) &&
        !make_session_dir(getenv("TMPDIR"), LINK_DIR_PREFIX, false,
                          s->link_dir, sizeof(s->link_dir), NULL,
                          &s->link_lock_fd)) {
        s->link_dir[0] = '\0';
        KLEE_WARN("exec shim: cannot create a directory under /tmp; "
                  "processes started through ld.so keep its name");
    }

    if (s->copies_enabled) {
        for (size_t i = 0; i < sizeof(bases) / sizeof(bases[0]); i++) {
            if (make_session_dir(bases[i], COPY_DIR_PREFIX, true,
                                 s->copy_dir, sizeof(s->copy_dir),
                                 &s->copy_dirfd, &s->copy_lock_fd))
                break;
        }
        if (!s->copy_dir[0]) {
            s->copies_enabled = false;
            KLEE_WARN("exec shim: no writable, exec-capable temporary "
                      "directory (set KLEE_EXEC_DIR); programs from the "
                      "sandbox's rootfs will be started through ld.so");
        }
    }

    KLEE_DEBUG("exec shim: links=%s copies=%s max=%" PRIu64 "MiB",
               s->link_dir[0] ? s->link_dir : "(none)",
               s->copy_dir[0] ? s->copy_dir : "(disabled)",
               s->max_copy_bytes >> 20);
    return s;
}

KleeExecShim *klee_exec_shim_get(void)
{
    if (!the_shim)
        the_shim = shim_create();
    return the_shim;
}

static ShimTarget *get_target(KleeExecShim *s, const char *host)
{
    for (size_t i = 0; i < s->ntargets; i++)
        if (strcmp(s->targets[i].host, host) == 0)
            return &s->targets[i];

    if (s->ntargets == s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 4;
        ShimTarget *t = realloc(s->targets, cap * sizeof(*t));
        if (!t)
            return NULL;
        s->targets = t;
        s->cap = cap;
    }

    ShimTarget *t = &s->targets[s->ntargets];
    memset(t, 0, sizeof(*t));
    t->host = strdup(host);
    if (!t->host)
        return NULL;
    size_t idx = s->ntargets++;

    if (s->link_dir[0]) {
        int n = snprintf(t->link, sizeof(t->link), "%s/%zu", s->link_dir, idx);
        if (n < 0 || (size_t)n >= sizeof(t->link) ||
            symlink(host, t->link) < 0) {
            KLEE_WARN("exec shim: symlink %s -> %s: %s", t->link, host,
                      strerror(errno));
            t->link[0] = '\0';
        }
    }
    return t;
}

/* ==================== Copies ==================== */

static int copy_all(int in, int out, uint64_t size)
{
    bool try_cfr = true, try_sendfile = true;
    uint64_t left = size;

    while (left > 0) {
        size_t chunk = left > 0x7ffff000 ? 0x7ffff000 : (size_t)left;
        ssize_t n;

        if (try_cfr) {
            n = copy_file_range(in, NULL, out, NULL, chunk, 0);
            if (n < 0 && (errno == EXDEV || errno == EINVAL ||
                          errno == ENOSYS || errno == EOPNOTSUPP ||
                          errno == EPERM)) {
                try_cfr = false;
                continue;
            }
        } else if (try_sendfile) {
            n = sendfile(out, in, NULL, chunk);
            if (n < 0 && (errno == EINVAL || errno == ENOSYS)) {
                try_sendfile = false;
                continue;
            }
        } else {
            char buf[1 << 16];
            n = read(in, buf, sizeof(buf) < chunk ? sizeof(buf) : chunk);
            if (n > 0) {
                ssize_t done = 0;
                while (done < n) {
                    ssize_t w = write(out, buf + done, (size_t)(n - done));
                    if (w < 0) {
                        if (errno == EINTR)
                            continue;
                        return -1;
                    }
                    done += w;
                }
            }
        }

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;   /* file shrank underneath us */
            return -1;
        }
        left -= (uint64_t)n;
    }
    return 0;
}

static int make_copy(KleeExecShim *s, const char *binary_host, int in,
                     const struct stat *st, const KleeElfInfo *elf,
                     const char *link, int key_fd, const char *copy_name)
{
    uint64_t size = (uint64_t)st->st_size;

    if (s->max_copy_bytes && size > s->max_copy_bytes) {
        KLEE_INFO("exec shim: %s is %" PRIu64 " MiB, above "
                  "KLEE_EXEC_COPY_MAX_MB; starting it through ld.so",
                  binary_host, size >> 20);
        return -1;
    }
    if (elf->interp_off + elf->interp_size > size) {
        errno = ENOEXEC;
        return -1;
    }

    struct statvfs sv;
    if (fstatvfs(s->copy_dirfd, &sv) == 0 &&
        (uint64_t)sv.f_bavail * sv.f_frsize < size + (1u << 20)) {
        KLEE_WARN("exec shim: not enough space in %s for %s (%" PRIu64
                  " MiB); starting it through ld.so",
                  s->copy_dir, binary_host, size >> 20);
        return -1;
    }

    (void)unlinkat(key_fd, COPY_TMP, 0);
    int out = openat(key_fd, COPY_TMP, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                     0600);
    if (out < 0)
        return -1;

    int rc = copy_all(in, out, size);

    if (rc == 0) {
        /* Replace the PT_INTERP string in place; the kernel only needs the
         * last byte to be NUL, so a shorter path padded with NULs is fine. */
        char patched[PATH_MAX];
        memset(patched, 0, sizeof(patched));
        memcpy(patched, link, strlen(link));
        if (pwrite(out, patched, elf->interp_size, (off_t)elf->interp_off)
            != (ssize_t)elf->interp_size)
            rc = -1;
    }

    /* Keep the original's permission bits for the owner, group and others
     * but never setuid/setgid: bwrap mounts everything nosuid anyway. */
    if (rc == 0 && fchmod(out, (st->st_mode & 0777) | 0700) < 0)
        rc = -1;

    int saved = errno;
    close(out);
    errno = saved;

    if (rc == 0 && renameat(key_fd, COPY_TMP, key_fd, copy_name) < 0)
        rc = -1;

    if (rc < 0) {
        saved = errno;
        KLEE_WARN("exec shim: could not stage %s: %s; starting it through "
                  "ld.so", binary_host, strerror(saved));
        (void)unlinkat(key_fd, COPY_TMP, 0);
        errno = saved;
    } else {
        KLEE_DEBUG("exec shim: staged %s (%" PRIu64 " bytes) with "
                   "PT_INTERP %s", binary_host, size, link);
    }
    return rc;
}

int klee_exec_shim_prepare(KleeExecShim *s, int in, const char *binary_host,
                           const KleeElfInfo *elf, const char *loader_host,
                           const char *name, char *out_path, size_t out_size)
{
    if (!s || !s->copies_enabled || !elf || elf->interp_size == 0)
        return -1;

    ShimTarget *t = get_target(s, loader_host);
    if (!t || !t->link[0])
        return -1;
    if (strlen(t->link) + 1 > elf->interp_size) {
        KLEE_DEBUG("exec shim: PT_INTERP of %s (%" PRIu64 " bytes) cannot "
                   "hold %s", binary_host, elf->interp_size, t->link);
        return -1;
    }
    size_t idx = (size_t)(t - s->targets);

    struct stat st;
    if (fstat(in, &st) < 0 || !S_ISREG(st.st_mode))
        return -1;

    char key[NAME_MAX + 1];
    snprintf(key, sizeof(key),
             "%" PRIxMAX "-%" PRIxMAX "-%" PRIxMAX "-%" PRIxMAX ".%lx-%"
             PRIxMAX ".%lx-%zu",
             (uintmax_t)st.st_dev, (uintmax_t)st.st_ino,
             (uintmax_t)st.st_size,
             (uintmax_t)st.st_mtim.tv_sec, (unsigned long)st.st_mtim.tv_nsec,
             (uintmax_t)st.st_ctim.tv_sec, (unsigned long)st.st_ctim.tv_nsec,
             idx);

    if (mkdirat(s->copy_dirfd, key, 0711) < 0 && errno != EEXIST)
        return -1;
    int key_fd = openat(s->copy_dirfd, key, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (key_fd < 0)
        return -1;

    /* The copy is named after the program so /proc/<pid>/exe stays
     * readable from the host.  Everything in a key directory is a copy of
     * the same file, so an existing entry of any kind is a cache hit. */
    char copy_name[COPY_NAME_MAX + 1];
    const char *base = strrchr(binary_host, '/');
    snprintf(copy_name, sizeof(copy_name), "%s", base ? base + 1 : binary_host);
    if (!valid_name(copy_name) || strcmp(copy_name, LOCK_FILE) == 0 ||
        strcmp(copy_name, COPY_TMP) == 0)
        snprintf(copy_name, sizeof(copy_name), "exe");

    int rc = 0;
    struct stat cst;
    if (fstatat(key_fd, copy_name, &cst, AT_SYMLINK_NOFOLLOW) != 0)
        rc = make_copy(s, binary_host, in, &st, elf, t->link, key_fd,
                       copy_name);
    if (rc < 0) {
        close(key_fd);
        return -1;
    }

    /* The last component of the path we exec becomes the process's comm. */
    const char *leaf = copy_name;
    if (valid_name(name) && strcmp(name, copy_name) != 0 &&
        strcmp(name, LOCK_FILE) != 0 && strcmp(name, COPY_TMP) != 0 &&
        (symlinkat(copy_name, key_fd, name) == 0 || errno == EEXIST))
        leaf = name;
    close(key_fd);

    int n = snprintf(out_path, out_size, "%s/%s/%s", s->copy_dir, key, leaf);
    if (n < 0 || (size_t)n >= out_size)
        return -1;
    return 0;
}

int klee_exec_shim_alias(KleeExecShim *s, const char *target_host,
                         const char *name, char *out_path, size_t out_size)
{
    if (!s || !s->link_dir[0] || !valid_name(name))
        return -1;

    ShimTarget *t = get_target(s, target_host);
    if (!t)
        return -1;
    size_t idx = (size_t)(t - s->targets);

    char dir[PATH_MAX];
    int n = snprintf(dir, sizeof(dir), "%s/a%zu", s->link_dir, idx);
    if (n < 0 || (size_t)n >= sizeof(dir))
        return -1;
    if (!t->alias_dir_ok) {
        if (mkdir(dir, 0711) < 0 && errno != EEXIST)
            return -1;
        t->alias_dir_ok = true;
    }

    n = snprintf(out_path, out_size, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= out_size)
        return -1;
    if (symlink(target_host, out_path) < 0 && errno != EEXIST)
        return -1;
    return 0;
}

/* ==================== Cleanup ==================== */

static void rm_tree_at(int dirfd, const char *name)
{
    int fd = openat(dirfd, name,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        (void)unlinkat(dirfd, name, 0);
        return;
    }
    DIR *d = fdopendir(fd);
    if (!d) {
        close(fd);
        return;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        struct stat st;
        if (fstatat(fd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
            S_ISDIR(st.st_mode))
            rm_tree_at(fd, de->d_name);
        else
            (void)unlinkat(fd, de->d_name, 0);
    }
    closedir(d);
    (void)unlinkat(dirfd, name, AT_REMOVEDIR);
}

void klee_exec_shim_cleanup(void)
{
    KleeExecShim *s = the_shim;
    if (!s)
        return;
    the_shim = NULL;

    /* Only the process that created the directories removes them. */
    if (s->owner == getpid()) {
        if (s->copy_dirfd >= 0)
            close(s->copy_dirfd);
        if (s->copy_dir[0])
            rm_tree_at(AT_FDCWD, s->copy_dir);
        if (s->link_dir[0])
            rm_tree_at(AT_FDCWD, s->link_dir);
        if (s->copy_lock_fd >= 0)
            close(s->copy_lock_fd);
        if (s->link_lock_fd >= 0)
            close(s->link_lock_fd);
    }
    for (size_t i = 0; i < s->ntargets; i++)
        free(s->targets[i].host);
    free(s->targets);
    free(s);
}
