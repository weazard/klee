/*
 * Klee - Userspace bwrap translation layer
 * FUSE /proc overlay implementation
 */
#include "fuse/fuse_proc.h"
#include "fuse/fuse_mountinfo.h"
#include "fuse/fuse_pidns.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>

#ifdef HAVE_FUSE3
#define FUSE_USE_VERSION 31
#include <fuse3/fuse_lowlevel.h>
#include <fuse3/fuse.h>

struct klee_fuse_proc {
    struct fuse *fuse;
    struct fuse_session *se;
    char mount_path[PATH_MAX];
    KleeProcessTable *proctable;
    KleeSandbox *sandbox;
    int fuse_fd;
    pthread_t fuse_thread;
    bool thread_started;
};

/* FUSE operations - passthrough with selective synthesis */

/* Translate a FUSE /proc path with virtual PIDs to a real /proc path */
static void translate_proc_path(const char *path, char *real_path, size_t size)
{
    struct fuse_context *fctx = fuse_get_context();
    KleeFuseProc *fp = fctx ? fctx->private_data : NULL;
    KleePidMap *pid_map = (fp && fp->sandbox) ? fp->sandbox->pid_map : NULL;

    if (pid_map && path[0] == '/') {
        /* Check if path starts with /<number> */
        const char *p = path + 1;
        const char *end = p;
        while (*end >= '0' && *end <= '9')
            end++;
        if (end > p && (*end == '/' || *end == '\0')) {
            char vpid_str[32];
            size_t len = (size_t)(end - p);
            if (len < sizeof(vpid_str)) {
                memcpy(vpid_str, p, len);
                vpid_str[len] = '\0';
                pid_t vpid = (pid_t)atoi(vpid_str);
                pid_t real_pid = klee_pid_map_v2r(pid_map, vpid);
                if (real_pid > 0) {
                    snprintf(real_path, size, "/proc/%d%s", real_pid, end);
                    return;
                }
            }
        }
    }
    snprintf(real_path, size, "/proc%s", path);
}

/* Paths that bwrap masks as read-only within /proc */
static bool is_masked_proc_path(const char *path)
{
    return (strcmp(path, "/sys") == 0 ||
            strncmp(path, "/sys/", 5) == 0 ||
            strcmp(path, "/sysrq-trigger") == 0 ||
            strcmp(path, "/irq") == 0 ||
            strncmp(path, "/irq/", 5) == 0 ||
            strcmp(path, "/bus") == 0 ||
            strncmp(path, "/bus/", 5) == 0);
}

static int fuse_proc_getattr(const char *path, struct stat *stbuf,
                              struct fuse_file_info *fi)
{
    (void)fi;
    char real_path[PATH_MAX];
    translate_proc_path(path, real_path, sizeof(real_path));

    if (lstat(real_path, stbuf) < 0)
        return -errno;

    /* Mask sensitive paths as read-only, matching bwrap behavior */
    if (is_masked_proc_path(path))
        stbuf->st_mode &= ~(mode_t)(S_IWUSR | S_IWGRP | S_IWOTH);

    return 0;
}

static int fuse_proc_readdir(const char *path, void *buf,
                              fuse_fill_dir_t filler, off_t offset,
                              struct fuse_file_info *fi,
                              enum fuse_readdir_flags flags)
{
    (void)offset;
    (void)fi;
    (void)flags;

    char real_path[PATH_MAX];
    translate_proc_path(path, real_path, sizeof(real_path));

    DIR *dp = opendir(real_path);
    if (!dp)
        return -errno;

    /* Get sandbox for PID namespace filtering */
    struct fuse_context *fctx = fuse_get_context();
    KleeFuseProc *fp = fctx ? fctx->private_data : NULL;
    KleePidMap *pid_map = (fp && fp->sandbox) ? fp->sandbox->pid_map : NULL;

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        /* Filter PID directories when in a PID namespace */
        if (pid_map && strcmp(path, "/") == 0) {
            if (!klee_pidns_filter_proc_entry(pid_map, de->d_name))
                continue;

            /* Translate real PID to virtual PID for display */
            const char *p = de->d_name;
            bool is_pid = true;
            while (*p) {
                if (!(*p >= '0' && *p <= '9')) { is_pid = false; break; }
                p++;
            }
            if (is_pid && de->d_name[0] != '\0') {
                pid_t real_pid = (pid_t)atoi(de->d_name);
                pid_t vpid = klee_pid_map_r2v(pid_map, real_pid);
                if (vpid > 0) {
                    char vpid_str[32];
                    snprintf(vpid_str, sizeof(vpid_str), "%d", vpid);
                    filler(buf, vpid_str, NULL, 0, 0);
                    continue;
                }
            }
        }
        filler(buf, de->d_name, NULL, 0, 0);
    }
    closedir(dp);
    return 0;
}

/* Check if path ends with a given suffix after a PID directory */
static bool is_pid_subfile(const char *path, const char *suffix)
{
    if (strncmp(path, "/self/", 6) == 0)
        return strcmp(path + 5, suffix) == 0;
    if (path[0] == '/') {
        const char *p = path + 1;
        while (*p >= '0' && *p <= '9')
            p++;
        return strcmp(p, suffix) == 0;
    }
    return false;
}

/*
 * Return a synthesized buffer from offset, handling paging.
 * Returns bytes copied, or 0 if offset is past end.
 */
static int serve_synthetic(const char *synth, int total,
                            char *buf, size_t size, off_t offset)
{
    if (offset >= total)
        return 0;
    int avail = total - (int)offset;
    int copy = (int)size < avail ? (int)size : avail;
    memcpy(buf, synth + offset, (size_t)copy);
    return copy;
}

/*
 * Rewrite PID fields in /proc/<pid>/status content.
 * The kernel's status file has lines like:
 *   Pid:\t<real_pid>
 *   PPid:\t<real_ppid>
 *   Tgid:\t<real_tgid>
 *   NSpid:\t<outer_pid>\t<ns_pid>
 *
 * We rewrite Pid/PPid/Tgid to show virtual PIDs and emit NSpid
 * showing only the virtual PID (matching single-level namespace).
 */
static int rewrite_status(const char *real_content, int real_len,
                           const KleePidMap *pid_map,
                           char *out, size_t out_size)
{
    size_t opos = 0;
    const char *p = real_content;
    const char *end = real_content + real_len;

    while (p < end && opos < out_size - 1) {
        /* Find end of current line */
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        if (!eol)
            eol = end;
        size_t line_len = (size_t)(eol - p);

        if (pid_map &&
            (strncmp(p, "Pid:\t", 5) == 0 ||
             strncmp(p, "Tgid:\t", 6) == 0)) {
            /* Rewrite: extract real PID, translate to virtual */
            const char *val = strchr(p, '\t');
            if (val) {
                val++;
                pid_t real_pid = (pid_t)atoi(val);
                pid_t vpid = klee_pid_map_r2v(pid_map, real_pid);
                if (vpid > 0) {
                    int n;
                    if (p[0] == 'P')
                        n = snprintf(out + opos, out_size - opos,
                                     "Pid:\t%d\n", vpid);
                    else
                        n = snprintf(out + opos, out_size - opos,
                                     "Tgid:\t%d\n", vpid);
                    if (n > 0) opos += (size_t)n;
                    p = (eol < end) ? eol + 1 : eol;
                    continue;
                }
            }
        } else if (pid_map && strncmp(p, "PPid:\t", 6) == 0) {
            const char *val = p + 6;
            pid_t real_ppid = (pid_t)atoi(val);
            pid_t vppid = klee_pid_map_r2v(pid_map, real_ppid);
            /* PID 0 (kernel) stays 0 */
            if (vppid > 0 || real_ppid == 0) {
                int n = snprintf(out + opos, out_size - opos,
                                 "PPid:\t%d\n", vppid);
                if (n > 0) opos += (size_t)n;
                p = (eol < end) ? eol + 1 : eol;
                continue;
            }
        } else if (pid_map && strncmp(p, "NSpid:\t", 7) == 0) {
            /* Rewrite NSpid to show only the virtual PID */
            const char *val = p + 7;
            pid_t real_pid = (pid_t)atoi(val);
            pid_t vpid = klee_pid_map_r2v(pid_map, real_pid);
            if (vpid > 0) {
                int n = snprintf(out + opos, out_size - opos,
                                 "NSpid:\t%d\n", vpid);
                if (n > 0) opos += (size_t)n;
                p = (eol < end) ? eol + 1 : eol;
                continue;
            }
        } else if (pid_map && strncmp(p, "NStgid:\t", 8) == 0) {
            const char *val = p + 8;
            pid_t real_pid = (pid_t)atoi(val);
            pid_t vpid = klee_pid_map_r2v(pid_map, real_pid);
            if (vpid > 0) {
                int n = snprintf(out + opos, out_size - opos,
                                 "NStgid:\t%d\n", vpid);
                if (n > 0) opos += (size_t)n;
                p = (eol < end) ? eol + 1 : eol;
                continue;
            }
        } else if (pid_map && strncmp(p, "TracerPid:\t", 11) == 0) {
            /* Mask TracerPid to 0 to hide ptrace interception from apps.
             * Real bwrap with kernel PID namespace shows 0 since the
             * tracer is in the parent namespace and invisible. */
            int n = snprintf(out + opos, out_size - opos,
                             "TracerPid:\t0\n");
            if (n > 0) opos += (size_t)n;
            p = (eol < end) ? eol + 1 : eol;
            continue;
        }

        /* Copy line as-is */
        size_t to_copy = line_len;
        if (eol < end)
            to_copy++; /* include newline */
        if (opos + to_copy >= out_size)
            to_copy = out_size - opos - 1;
        memcpy(out + opos, p, to_copy);
        opos += to_copy;
        p = (eol < end) ? eol + 1 : eol;
    }

    return (int)opos;
}

/*
 * Rewrite PID in /proc/<pid>/stat content.
 * Format: "<pid> (comm) S <ppid> <pgrp> <session> ..."
 * The first field is the PID which we need to translate.
 */
static int rewrite_stat(const char *real_content, int real_len,
                         const KleePidMap *pid_map,
                         char *out, size_t out_size)
{
    if (!pid_map || real_len <= 0)
        return 0;

    /* Parse: first number is the PID */
    pid_t real_pid = (pid_t)atoi(real_content);
    pid_t vpid = klee_pid_map_r2v(pid_map, real_pid);
    if (vpid <= 0)
        return 0; /* PID not in namespace - don't expose real PID */

    /* Find the first space (after PID) */
    const char *rest = real_content;
    while (*rest && *rest != ' ')
        rest++;

    /* Find ppid: it's after "(comm) X " */
    const char *close_paren = strrchr(real_content, ')');
    if (!close_paren || close_paren + 4 >= real_content + real_len) {
        /* Can't parse, copy as-is with PID replaced */
        int n = snprintf(out, out_size, "%d%.*s",
                         vpid, (int)(real_content + real_len - rest), rest);
        return n > 0 ? n : 0;
    }

    /* Copy: vpid + everything from first space to after ")" + " " + state + " " */
    const char *after_state = close_paren + 2; /* skip ") " */
    while (*after_state && *after_state != ' ')
        after_state++; /* skip state char */
    if (*after_state == ' ')
        after_state++; /* skip space before ppid */

    /* Parse and translate ppid */
    pid_t real_ppid = (pid_t)atoi(after_state);
    pid_t vppid = klee_pid_map_r2v(pid_map, real_ppid);
    if (vppid <= 0 && real_ppid != 0)
        vppid = 0; /* Parent not in namespace - show 0 like kernel does */

    /* Skip the ppid digits */
    const char *after_ppid = after_state;
    while (*after_ppid && *after_ppid != ' ')
        after_ppid++;

    /* Reconstruct: vpid (comm) S vppid rest... */
    int n = snprintf(out, out_size, "%d%.*s%d%.*s",
                     vpid,
                     (int)(after_state - rest), rest,
                     vppid,
                     (int)(real_content + real_len - after_ppid), after_ppid);
    return n > 0 ? n : 0;
}

static int fuse_proc_read(const char *path, char *buf, size_t size,
                           off_t offset, struct fuse_file_info *fi)
{
    (void)fi;

    struct fuse_context *fctx = fuse_get_context();
    KleeFuseProc *fp = fctx ? fctx->private_data : NULL;
    KleePidMap *pid_map = (fp && fp->sandbox) ? fp->sandbox->pid_map : NULL;

    /* Synthesize mountinfo from virtual mount table */
    if (is_pid_subfile(path, "/mountinfo")) {
        if (fp && fp->sandbox && fp->sandbox->mount_table) {
            char synth_buf[8192];
            int total = klee_gen_mountinfo(fp->sandbox->mount_table,
                                            synth_buf, sizeof(synth_buf));
            if (total > 0)
                return serve_synthetic(synth_buf, total, buf, size, offset);
        }
    }

    /* Block /proc/sysvipc entries under IPC namespace to show empty */
    if (fp && fp->sandbox && fp->sandbox->unshare_ipc) {
        if (strncmp(path, "/sysvipc/", 9) == 0) {
            /* Return empty content (just the header line for ipcs compat) */
            const char *name = path + 9;
            const char *header = NULL;
            if (strcmp(name, "shm") == 0)
                header = "       key      shmid      perms       size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime        rss       swap\n";
            else if (strcmp(name, "msg") == 0)
                header = "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n";
            else if (strcmp(name, "sem") == 0)
                header = "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n";

            if (header) {
                int total = (int)strlen(header);
                return serve_synthetic(header, total, buf, size, offset);
            }
        }
    }

    /* Read the real /proc content */
    char real_path[PATH_MAX];
    translate_proc_path(path, real_path, sizeof(real_path));

    int fd = open(real_path, O_RDONLY);
    if (fd < 0)
        return -errno;

    /* For /proc/<pid>/status and /proc/<pid>/stat, rewrite PID values */
    if (pid_map && is_pid_subfile(path, "/status")) {
        char real_buf[8192];
        int real_len = (int)read(fd, real_buf, sizeof(real_buf) - 1);
        close(fd);
        if (real_len <= 0)
            return real_len < 0 ? -errno : 0;
        real_buf[real_len] = '\0';

        char synth_buf[8192];
        int total = rewrite_status(real_buf, real_len, pid_map,
                                    synth_buf, sizeof(synth_buf));
        if (total > 0)
            return serve_synthetic(synth_buf, total, buf, size, offset);
        /* fallthrough to raw content on rewrite failure */
        return serve_synthetic(real_buf, real_len, buf, size, offset);
    }

    if (pid_map && is_pid_subfile(path, "/stat")) {
        char real_buf[4096];
        int real_len = (int)read(fd, real_buf, sizeof(real_buf) - 1);
        close(fd);
        if (real_len <= 0)
            return real_len < 0 ? -errno : 0;
        real_buf[real_len] = '\0';

        char synth_buf[4096];
        int total = rewrite_stat(real_buf, real_len, pid_map,
                                  synth_buf, sizeof(synth_buf));
        if (total > 0)
            return serve_synthetic(synth_buf, total, buf, size, offset);
        return serve_synthetic(real_buf, real_len, buf, size, offset);
    }

    /* Default: passthrough read */
    int res = pread(fd, buf, size, offset);
    if (res < 0)
        res = -errno;
    close(fd);
    return res;
}

static int fuse_proc_readlink(const char *path, char *buf, size_t size)
{
    char real_path[PATH_MAX];
    translate_proc_path(path, real_path, sizeof(real_path));

    int res = readlink(real_path, buf, size - 1);
    if (res < 0)
        return -errno;
    buf[res] = '\0';
    return 0;
}

static int fuse_proc_open(const char *path, struct fuse_file_info *fi)
{
    /* Block write access to sensitive /proc subdirectories */
    if (is_masked_proc_path(path) &&
        ((fi->flags & O_ACCMODE) == O_WRONLY ||
         (fi->flags & O_ACCMODE) == O_RDWR))
        return -EACCES;

    char real_path[PATH_MAX];
    translate_proc_path(path, real_path, sizeof(real_path));

    int fd = open(real_path, fi->flags & ~(O_CREAT | O_EXCL | O_TRUNC));
    if (fd < 0)
        return -errno;
    fi->fh = (uint64_t)fd;
    return 0;
}

static int fuse_proc_write(const char *path, const char *buf, size_t size,
                            off_t offset, struct fuse_file_info *fi)
{
    /* Block writes to sensitive /proc subdirectories */
    if (is_masked_proc_path(path))
        return -EACCES;

    char real_path[PATH_MAX];
    translate_proc_path(path, real_path, sizeof(real_path));

    int fd = (int)fi->fh;
    if (fd <= 0) {
        fd = open(real_path, O_WRONLY);
        if (fd < 0)
            return -errno;
    }
    int res = (int)pwrite(fd, buf, size, offset);
    if (res < 0)
        res = -errno;
    if ((int)fi->fh <= 0)
        close(fd);
    return res;
}

static int fuse_proc_truncate(const char *path, off_t size,
                               struct fuse_file_info *fi)
{
    (void)fi;
    if (is_masked_proc_path(path))
        return -EACCES;

    char real_path[PATH_MAX];
    translate_proc_path(path, real_path, sizeof(real_path));

    int res = truncate(real_path, size);
    if (res < 0)
        return -errno;
    return 0;
}

static const struct fuse_operations fuse_proc_ops = {
    .getattr  = fuse_proc_getattr,
    .readdir  = fuse_proc_readdir,
    .open     = fuse_proc_open,
    .read     = fuse_proc_read,
    .write    = fuse_proc_write,
    .truncate = fuse_proc_truncate,
    .readlink = fuse_proc_readlink,
};

static void *fuse_loop_thread(void *arg)
{
    KleeFuseProc *fp = arg;
    fuse_loop(fp->fuse);
    return NULL;
}

KleeFuseProc *klee_fuse_proc_create(KleeProcessTable *pt, KleeSandbox *sb)
{
    KleeFuseProc *fp = calloc(1, sizeof(KleeFuseProc));
    if (!fp)
        return NULL;

    fp->proctable = pt;
    fp->sandbox = sb;
    fp->fuse_fd = -1;

    snprintf(fp->mount_path, sizeof(fp->mount_path),
             "/tmp/klee-proc-%d", getpid());

    if (mkdir(fp->mount_path, 0755) < 0 && errno != EEXIST) {
        KLEE_WARN("failed to create FUSE mount point: %s", strerror(errno));
        free(fp);
        return NULL;
    }

    /* Try allow_other first (requires user_allow_other in /etc/fuse.conf),
     * fall back without it for same-user access */
    char *argv_ao[] = { "klee-fuse", "-o", "allow_other", NULL };
    struct fuse_args args = FUSE_ARGS_INIT(3, argv_ao);

    struct fuse *fuse = fuse_new(&args, &fuse_proc_ops,
                                  sizeof(fuse_proc_ops), fp);
    if (!fuse) {
        /* Retry without allow_other */
        char *argv_plain[] = { "klee-fuse", NULL };
        struct fuse_args args2 = FUSE_ARGS_INIT(1, argv_plain);
        fuse = fuse_new(&args2, &fuse_proc_ops, sizeof(fuse_proc_ops), fp);
        if (!fuse) {
            KLEE_WARN("failed to create FUSE session");
            rmdir(fp->mount_path);
            free(fp);
            return NULL;
        }
    }

    if (fuse_mount(fuse, fp->mount_path) < 0) {
        KLEE_WARN("failed to mount FUSE at %s", fp->mount_path);
        fuse_destroy(fuse);
        rmdir(fp->mount_path);
        free(fp);
        return NULL;
    }

    fp->fuse = fuse;
    fp->se = fuse_get_session(fuse);
    fp->fuse_fd = fuse_session_fd(fp->se);

    /* Start FUSE processing thread */
    if (pthread_create(&fp->fuse_thread, NULL, fuse_loop_thread, fp) != 0) {
        KLEE_WARN("failed to start FUSE thread: %s", strerror(errno));
        fuse_unmount(fuse);
        fuse_destroy(fuse);
        rmdir(fp->mount_path);
        free(fp);
        return NULL;
    }
    fp->thread_started = true;

    KLEE_INFO("FUSE /proc overlay mounted at %s", fp->mount_path);
    return fp;
}

void klee_fuse_proc_destroy(KleeFuseProc *fp)
{
    if (!fp)
        return;
    if (fp->se)
        fuse_session_exit(fp->se);
    if (fp->thread_started)
        pthread_join(fp->fuse_thread, NULL);
    if (fp->fuse) {
        fuse_unmount(fp->fuse);
        fuse_destroy(fp->fuse);
    }
    rmdir(fp->mount_path);
    free(fp);
}

const char *klee_fuse_proc_get_path(const KleeFuseProc *fp)
{
    return fp ? fp->mount_path : NULL;
}

int klee_fuse_proc_get_fd(const KleeFuseProc *fp)
{
    return fp ? fp->fuse_fd : -1;
}

int klee_fuse_proc_process(KleeFuseProc *fp)
{
    if (!fp || !fp->se)
        return -1;

    struct fuse_buf fbuf = { .mem = NULL };
    int res = fuse_session_receive_buf(fp->se, &fbuf);
    if (res <= 0)
        return res;
    fuse_session_process_buf(fp->se, &fbuf);
    free(fbuf.mem);
    return 0;
}

#else /* !HAVE_FUSE3 */

struct klee_fuse_proc {
    int dummy;
};

KleeFuseProc *klee_fuse_proc_create(KleeProcessTable *pt, KleeSandbox *sb)
{
    (void)pt; (void)sb;
    KLEE_INFO("FUSE3 not available, /proc synthesis will use syscall interception");
    return NULL;
}

void klee_fuse_proc_destroy(KleeFuseProc *fp) { free(fp); }
const char *klee_fuse_proc_get_path(const KleeFuseProc *fp) { (void)fp; return NULL; }
int klee_fuse_proc_get_fd(const KleeFuseProc *fp) { (void)fp; return -1; }
int klee_fuse_proc_process(KleeFuseProc *fp) { (void)fp; return -1; }

#endif /* HAVE_FUSE3 */

/*
 * Tmpfs-based /proc snapshot fallback.
 * Used when FUSE is not available (no CAP_SYS_ADMIN, no /dev/fuse, etc).
 * Creates a directory tree with:
 *   - Non-PID entries: symlinks to real /proc/X
 *   - Virtual PID entries: directories with symlinks to real /proc/<real_pid>/Y
 *   - self → <virtual PID 1 directory>
 * Limitation: /proc/<vpid>/status still shows real PIDs (would need FUSE for rewriting).
 */

#include "fs/mount_table.h"
#include "fs/tmpfs.h"
#include "ns/pid_ns.h"

static bool is_all_digits(const char *s)
{
    if (!s || !*s) return false;
    for (; *s; s++)
        if (*s < '0' || *s > '9') return false;
    return true;
}

/*
 * Snapshot approach: create a tmpfs directory for `ls /proc` listing,
 * then use mount table entries (not symlinks) for actual file access.
 *
 * - Non-PID entries: empty placeholder in tmpfs + mount table bind to real /proc/X
 * - Virtual PID dirs: empty dir in tmpfs + mount table bind /proc/<vpid> → /proc/<real_pid>
 * - "self" and "thread-self": placeholder dirs + passthrough binds
 *
 * This avoids symlinks entirely, preventing the path resolver from
 * re-entering the /proc mount and causing double-translation loops.
 */

char *klee_proc_snapshot_create(KleePidMap *pid_map, KleeMountTable *mt)
{
    char *proc_dir = klee_tmpfs_create("/proc");
    if (!proc_dir)
        return NULL;

    DIR *dp = opendir("/proc");
    if (!dp) {
        KLEE_WARN("cannot open /proc for snapshot");
        return proc_dir;
    }

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (de->d_name[0] == '.')
            continue;

        char entry_path[PATH_MAX];

        if (is_all_digits(de->d_name)) {
            /* PID directory - filter through pid_map */
            if (!pid_map)
                continue;
            pid_t real_pid = (pid_t)atoi(de->d_name);
            pid_t vpid = klee_pid_map_r2v(pid_map, real_pid);
            if (vpid <= 0)
                continue;
            /* Create placeholder directory for ls listing */
            snprintf(entry_path, sizeof(entry_path), "%s/%d", proc_dir, vpid);
            mkdir(entry_path, 0555);
            /* Mount table entry: /proc/<vpid> → /proc/<real_pid> */
            if (mt) {
                char guest[64], host[64];
                snprintf(guest, sizeof(guest), "/proc/%d", vpid);
                snprintf(host, sizeof(host), "/proc/%d", real_pid);
                klee_mount_table_add(mt, MOUNT_BIND_RW, host, guest, false, 0555);
            }
        } else {
            /* Non-PID entry: create placeholder matching real type.
             * Skip self/thread-self here - they are handled by
             * translate_path_arg() rewriting them to /proc/<vpid>. */
            if (strcmp(de->d_name, "self") == 0 ||
                strcmp(de->d_name, "thread-self") == 0) {
                /* Create directory placeholder for ls listing only */
                snprintf(entry_path, sizeof(entry_path), "%s/%s",
                         proc_dir, de->d_name);
                mkdir(entry_path, 0555);
                continue;
            }
            snprintf(entry_path, sizeof(entry_path), "%s/%s", proc_dir, de->d_name);
            char real_path[PATH_MAX];
            snprintf(real_path, sizeof(real_path), "/proc/%s", de->d_name);
            struct stat st;
            if (lstat(real_path, &st) == 0 && S_ISDIR(st.st_mode))
                mkdir(entry_path, 0555);
            else {
                int fd = open(entry_path, O_CREAT | O_WRONLY, 0444);
                if (fd >= 0) close(fd);
            }
            /* Mount table entry: /proc/<name> → /proc/<name> (passthrough) */
            if (mt) {
                char guest[PATH_MAX];
                snprintf(guest, sizeof(guest), "/proc/%s", de->d_name);
                klee_mount_table_add(mt, MOUNT_BIND_RW, real_path, guest,
                                      false, 0555);
            }
        }
    }
    closedir(dp);

    KLEE_INFO("created /proc snapshot at %s (%s)",
              proc_dir, mt ? "with mount entries" : "standalone");
    return proc_dir;
}

void klee_proc_snapshot_refresh(const char *snapshot_path,
                                 KleePidMap *pid_map, KleeMountTable *mt)
{
    if (!snapshot_path || !pid_map)
        return;

    DIR *dp = opendir(snapshot_path);
    if (!dp)
        return;

    /* Remove stale virtual PID directories */
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        if (!is_all_digits(de->d_name))
            continue;
        pid_t vpid = (pid_t)atoi(de->d_name);
        pid_t real_pid = klee_pid_map_v2r(pid_map, vpid);
        if (real_pid <= 0) {
            char dir_path[PATH_MAX];
            snprintf(dir_path, sizeof(dir_path), "%s/%s",
                     snapshot_path, de->d_name);
            rmdir(dir_path);
        }
    }
    closedir(dp);

    /* Add new virtual PIDs from /proc */
    dp = opendir("/proc");
    if (!dp)
        return;

    while ((de = readdir(dp)) != NULL) {
        if (!is_all_digits(de->d_name))
            continue;
        pid_t real_pid = (pid_t)atoi(de->d_name);
        pid_t vpid = klee_pid_map_r2v(pid_map, real_pid);
        if (vpid <= 0)
            continue;
        char vpid_dir[PATH_MAX];
        snprintf(vpid_dir, sizeof(vpid_dir), "%s/%d", snapshot_path, vpid);
        struct stat st;
        if (stat(vpid_dir, &st) == 0)
            continue; /* Already exists */
        mkdir(vpid_dir, 0555);
        /* Add mount table entry for new PID */
        if (mt) {
            char guest[64], host[64];
            snprintf(guest, sizeof(guest), "/proc/%d", vpid);
            snprintf(host, sizeof(host), "/proc/%d", real_pid);
            klee_mount_table_add(mt, MOUNT_BIND_RW, host, guest, false, 0555);
        }
    }
    closedir(dp);
}
