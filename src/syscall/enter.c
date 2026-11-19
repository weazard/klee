/*
 * Klee - Userspace bwrap translation layer
 * Syscall-enter handler implementations
 */
#include "syscall/enter.h"
#include "syscall/sysnum.h"
#include "syscall/sysnum32.h"
#include "syscall/sysnum32.h"
#include "syscall/abi.h"
#include "syscall/exec_shim.h"
#include "process/memory.h"
#include "process/regs.h"
#include "fs/path_resolve.h"
#include "fs/readonly.h"
#include "ns/pid_ns.h"
#include "ns/proc_synth.h"
#include "ns/user_ns.h"
#include "ns/uts_ns.h"
#include "ns/ipc_ns.h"
#include "compat/nested.h"
#include "compat/zypak_compat.h"
#include "util/log.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/openat2.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <sys/prctl.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

/*
 * Helper: translate a path argument at the given register index.
 * Reads the guest path from tracee memory, resolves it through the
 * virtual mount table, and writes the translated host path back.
 *
 * For seccomp_unotify: path translation happens in supervisor, then
 * we perform the syscall on behalf of the tracee.
 * For ptrace: we rewrite the path in tracee memory before the syscall.
 */
static int translate_path_arg_ex(KleeProcess *proc, KleeInterceptor *ic,
                                 KleeEvent *ev, int arg_idx, int dirfd_idx,
                                 bool nofollow, KleeOvAccess access);
static pid_t resolve_target_pid(KleeProcess *proc, pid_t pid);

static int translate_path_arg(KleeProcess *proc, KleeInterceptor *ic,
                               KleeEvent *ev, int arg_idx, int dirfd_idx)
{
    return translate_path_arg_ex(proc, ic, ev, arg_idx, dirfd_idx, false,
                                 KLEE_OV_READ);
}

/* Like translate_path_arg but does not follow the final symlink.
 * Used by lstat, unlink, readlink, symlink(linkpath), rename, rmdir, etc. */
static int translate_path_arg_nofollow(KleeProcess *proc, KleeInterceptor *ic,
                                        KleeEvent *ev, int arg_idx,
                                        int dirfd_idx)
{
    return translate_path_arg_ex(proc, ic, ev, arg_idx, dirfd_idx, true,
                                 KLEE_OV_READ);
}

/* For a call that changes the file system: access tells an overlay what
 * to prepare (copy-up, upper directories, whiteouts). */
static int translate_path_arg_for(KleeProcess *proc, KleeInterceptor *ic,
                                  KleeEvent *ev, int arg_idx, int dirfd_idx,
                                  bool nofollow, KleeOvAccess access)
{
    return translate_path_arg_ex(proc, ic, ev, arg_idx, dirfd_idx, nofollow,
                                 access);
}

/* Stage the translated path without changing the caller's buffer. */
static int stage_path_arg(KleeProcess *proc, KleeInterceptor *ic, int arg_idx)
{
    if (ic->backend != INTERCEPT_PTRACE)
        return 0;

    uint64_t scratch;
    int rc = klee_scratch_string(proc, ic, proc->translated_path, &scratch);
    if (rc < 0)
        return rc;
    klee_regs_set_arg(proc, arg_idx, scratch);
    return klee_regs_push(ic, proc);
}

static int translate_path_arg_ex(KleeProcess *proc, KleeInterceptor *ic,
                                  KleeEvent *ev, int arg_idx, int dirfd_idx,
                                  bool nofollow, KleeOvAccess access)
{
    proc->saved_path[0] = '\0';
    proc->translated_path[0] = '\0';
    proc->resolved_guest[0] = '\0';

    void *path_addr = (void *)(uintptr_t)ev->args[arg_idx];
    if (!path_addr)
        return access == KLEE_OV_LOOKUP ? -EFAULT : 0;

    /* Read guest path */
    int rc = klee_read_path(ic, ev->pid, proc->saved_path,
                            sizeof(proc->saved_path), path_addr);
    if (rc < 0) {
        KLEE_DEBUG("failed to read path from tracee: %d", rc);
        return rc;
    }
    if (rc == 0)
        return access == KLEE_OV_LOOKUP ? -ENOENT : 0;

    /* Rewrite /proc/self and /proc/thread-self to use the tracee's real PID.
     * The kernel's /proc/self is a magic symlink to the CURRENT process's PID.
     * Since klee (not the tracee) performs path resolution, /proc/self would
     * resolve to klee's own PID, giving the tracee access to klee's /proc
     * entries instead of its own.  Always rewrite to /proc/<real_pid> so
     * the host kernel targets the correct process. */
    bool proc_self_rewritten = false;
    pid_t proc_rewrite_real_pid = 0;
    if (proc->sandbox) {
        pid_t target_pid = proc->real_tgid;
        if (strncmp(proc->saved_path, "/proc/self/", 11) == 0) {
            char rewritten[PATH_MAX];
            int n = snprintf(rewritten, sizeof(rewritten), "/proc/%d/%s",
                             target_pid, proc->saved_path + 11);
            if (n < 0 || (size_t)n >= sizeof(rewritten))
                return -ENAMETOOLONG;
            memcpy(proc->saved_path, rewritten, (size_t)n + 1);
            proc_self_rewritten = true;
            proc_rewrite_real_pid = target_pid;
        } else if (strcmp(proc->saved_path, "/proc/self") == 0) {
            snprintf(proc->saved_path, PATH_MAX, "/proc/%d", target_pid);
            proc_self_rewritten = true;
            proc_rewrite_real_pid = target_pid;
        } else if (strncmp(proc->saved_path, "/proc/thread-self/", 18) == 0) {
            char rewritten[PATH_MAX];
            int n = snprintf(rewritten, sizeof(rewritten), "/proc/%d/task/%d/%s",
                             target_pid, ev->pid, proc->saved_path + 18);
            if (n < 0 || (size_t)n >= sizeof(rewritten))
                return -ENAMETOOLONG;
            memcpy(proc->saved_path, rewritten, (size_t)n + 1);
            proc_self_rewritten = true;
            proc_rewrite_real_pid = ev->pid;
        } else if (strcmp(proc->saved_path, "/proc/thread-self") == 0) {
            snprintf(proc->saved_path, PATH_MAX, "/proc/%d/task/%d",
                     target_pid, ev->pid);
            proc_self_rewritten = true;
            proc_rewrite_real_pid = ev->pid;
        }
    }

    /* Rewrite /proc/<vpid>/... to /proc/<real_pid>/... when the tracee
     * uses its virtual PID to access /proc entries.  This is necessary
     * when /proc is passthrough (no FUSE overlay) but getpid() returns
     * virtual PIDs — programs like `ps` use getpid() to construct
     * /proc/<pid>/... paths that don't exist on the host. */
    bool vpid_rewritten = false;
    if (!proc_self_rewritten && proc->sandbox &&
        proc->sandbox->unshare_pid && proc->sandbox->pid_map &&
        strncmp(proc->saved_path, "/proc/", 6) == 0) {
        const char *p = proc->saved_path + 6;
        if (*p >= '1' && *p <= '9') {
            char *q;
            unsigned long parsed = strtoul(p, &q, 10);
            if (*q == '/' || *q == '\0') {
                if (parsed > INT_MAX)
                    return -ENOENT;
                pid_t vpid_val = (pid_t)parsed;
                pid_t real_pid = klee_pid_map_v2r(proc->sandbox->pid_map,
                                                   vpid_val);
                if (real_pid > 0 && real_pid != vpid_val) {
                    char rewritten[PATH_MAX];
                    int n = snprintf(rewritten, sizeof(rewritten), "/proc/%d%s",
                                     real_pid, q);
                    if (n < 0 || (size_t)n >= sizeof(rewritten))
                        return -ENAMETOOLONG;
                    memcpy(proc->saved_path, rewritten, (size_t)n + 1);
                    vpid_rewritten = true;
                    proc_rewrite_real_pid = real_pid;
                } else if (real_pid <= 0 &&
                           resolve_target_pid(proc, vpid_val) <= 0) {
                    /* A host process: in a real PID namespace this
                     * /proc entry does not exist. */
                    KLEE_TRACE("/proc/%d: not in namespace -> ENOENT",
                               vpid_val);
                    return -ENOENT;
                }
            }
        }
    }

    /* Get dirfd for *at() variants */
    int dirfd = AT_FDCWD;
    if (dirfd_idx >= 0)
        dirfd = (int)ev->args[dirfd_idx];

    /* Build resolve context */
    KleeResolveCtx ctx = {
        .mount_table = proc->sandbox ? proc->sandbox->mount_table : NULL,
        .fd_table = proc->fd_table,
        .tracee_pid = proc->real_pid,
        .vcwd = proc->vcwd,
        .vroot = proc->sandbox ? klee_mount_table_get_root(proc->sandbox->mount_table) : "/",
        .flags = 0,
    };

    if (!ctx.mount_table)
        return 0;

    /* Resolve to absolute guest path, then translate to host path.
     * We split these steps so the resolved guest path is available for
     * readonly checks (raw saved_path may be relative, which doesn't
     * match mount table entries correctly). */
    bool trailing_slash = proc->saved_path[strlen(proc->saved_path) - 1] == '/';
    if (trailing_slash && (access == KLEE_OV_READ || access == KLEE_OV_LIST))
        nofollow = false;
    if (nofollow)
        rc = klee_path_resolve_nofollow(&ctx, proc->saved_path,
                                         proc->resolved_guest, dirfd);
    else
        rc = klee_path_resolve(&ctx, proc->saved_path,
                                proc->resolved_guest, dirfd);
    if (rc < 0) {
        KLEE_DEBUG("path resolution failed for %s: %d", proc->saved_path, rc);
        proc->resolved_guest[0] = '\0';
        /* Inherited dirfds without a guest mapping keep kernel semantics. */
        return rc == -EBADF ? 0 : rc;
    }

    if (nofollow)
        rc = klee_mount_table_translate_nofollow(ctx.mount_table, proc->resolved_guest,
                                                  proc->translated_path, PATH_MAX, access);
    else
        rc = klee_mount_table_translate_access(ctx.mount_table, proc->resolved_guest,
                                                proc->translated_path, PATH_MAX, access);
    if (rc < 0) {
        KLEE_DEBUG("path translation failed for %s: %d", proc->resolved_guest, rc);
        return rc;
    }
    if (access == KLEE_OV_LOOKUP &&
        klee_mount_table_overlay_at(ctx.mount_table, proc->resolved_guest))
        return 0;

    /* Generate synthetic /proc/<pid>/stat and /proc/<pid>/status files
     * with virtual PIDs.  The kernel's real /proc files contain host PIDs
     * which would cause libproc2 (ps, top, etc.) to fail PID lookups. */
    if ((proc_self_rewritten || vpid_rewritten) &&
        proc_rewrite_real_pid > 0 &&
        proc->sandbox && proc->sandbox->pid_map) {
        const char *base = strrchr(proc->translated_path, '/');
        if (base) {
            base++;
            char synth_path[PATH_MAX];
            int src = -1;
            if (strcmp(base, "stat") == 0)
                src = klee_proc_synth_stat(proc_rewrite_real_pid,
                                            proc->sandbox->pid_map,
                                            synth_path, sizeof(synth_path));
            else if (strcmp(base, "status") == 0)
                src = klee_proc_synth_status(proc_rewrite_real_pid,
                                              proc->sandbox->pid_map,
                                              synth_path, sizeof(synth_path));
            if (src == 0)
                snprintf(proc->translated_path, PATH_MAX, "%s", synth_path);
        }
    }

    if (trailing_slash) {
        size_t len = strlen(proc->translated_path);
        if (len + 1 >= sizeof(proc->translated_path))
            return -ENAMETOOLONG;
        if (len != 0 && proc->translated_path[len - 1] != '/')
            strcpy(proc->translated_path + len, "/");
    }

    /* If /proc/self or /proc/<vpid> was rewritten, always force the write
     * even if the mount table didn't change the path further — the tracee's
     * memory still has the original path which the kernel can't resolve. */
    if (strcmp(proc->saved_path, proc->translated_path) == 0 &&
        !proc_self_rewritten && !vpid_rewritten)
        return 0;

    rc = stage_path_arg(proc, ic, arg_idx);
    if (rc < 0)
        return rc;

    KLEE_TRACE("translated: %s -> %s", proc->saved_path, proc->translated_path);
    return 0;
}

/* Helper for checking RO enforcement.
 * Uses resolved_guest (absolute guest path) rather than saved_path
 * (raw tracee path, may be relative) so mount table lookups are correct. */
static int check_readonly(KleeProcess *proc, int syscall_nr)
{
    if (!proc->sandbox || !proc->sandbox->mount_table)
        return 0;

    if (klee_readonly_check_path(proc->sandbox->mount_table,
                                  proc->resolved_guest, syscall_nr))
        return -EROFS;
    return 0;
}

static int check_readonly_open(KleeProcess *proc, int flags)
{
    if (!proc->sandbox || !proc->sandbox->mount_table)
        return 0;

    if (klee_readonly_check_open(proc->sandbox->mount_table,
                                  proc->resolved_guest, proc->translated_path,
                                  flags))
        return -EROFS;
    return 0;
}

/* ==================== Filesystem Enter Handlers ==================== */

/* What an open with these flags does with the file */
static KleeOvAccess open_access(int flags)
{
    if ((flags & O_TMPFILE) == O_TMPFILE)
        return KLEE_OV_WRITE;   /* a new file in the directory */
    if (flags & O_PATH)
        return KLEE_OV_READ;
    if ((flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL))
        return KLEE_OV_CREATE_EXCL;
    int acc = flags & O_ACCMODE;
    if (acc == O_WRONLY || acc == O_RDWR || (flags & O_TRUNC))
        return (flags & O_CREAT) ? KLEE_OV_WRITE_CREATE : KLEE_OV_WRITE;
    return (flags & O_CREAT) ? KLEE_OV_CREATE : KLEE_OV_LIST;
}

/* The kernel does not follow a final symlink for these */
static bool open_nofollow(int flags)
{
    return (flags & O_NOFOLLOW) ||
           (flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL);
}

int klee_enter_open(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int flags = (int)ev->args[1];
    int rc = translate_path_arg_for(proc, ic, ev, 0, -1, open_nofollow(flags),
                                    open_access(flags));
    if (rc < 0) return rc;
    return check_readonly_open(proc, flags);
}

int klee_enter_openat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int flags = (int)ev->args[2];
    int rc = translate_path_arg_for(proc, ic, ev, 1, 0, open_nofollow(flags),
                                    open_access(flags));
    if (rc < 0) return rc;
    return check_readonly_open(proc, flags);
}

int klee_enter_creat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    const int flags = O_CREAT | O_WRONLY | O_TRUNC;
    int rc = translate_path_arg_for(proc, ic, ev, 0, -1, false,
                                    open_access(flags));
    if (rc < 0) return rc;
    return check_readonly_open(proc, flags);
}

int klee_enter_openat2(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    struct open_how how;
    const void *how_addr = (const void *)(uintptr_t)ev->args[2];
    if (ev->args[3] < sizeof(how) || !how_addr ||
        klee_read_mem(ic, ev->pid, &how, how_addr, sizeof(how)) < 0)
        return 0;

    int flags = (int)how.flags;
    if (!how.resolve) {
        int rc = translate_path_arg_for(proc, ic, ev, 1, 0, open_nofollow(flags),
                                        open_access(flags));
        return rc < 0 ? rc : check_readonly_open(proc, flags);
    }
    const uint64_t known = RESOLVE_IN_ROOT | RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
                           RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_CACHED;
    bool in_root = (how.resolve & RESOLVE_IN_ROOT) != 0;
    bool beneath = (how.resolve & RESOLVE_BENEATH) != 0;
    if ((how.resolve & ~known) || (in_root && beneath))
        return -EINVAL;

    KleeResolveCtx ctx = {
        .mount_table = proc->sandbox ? proc->sandbox->mount_table : NULL,
        .fd_table = proc->fd_table,
        .tracee_pid = proc->real_pid,
        .vcwd = proc->vcwd,
    };
    if (!ctx.mount_table)
        return 0;
    ctx.vroot = klee_mount_table_get_root(ctx.mount_table);

    const void *path = (const void *)(uintptr_t)ev->args[1];
    if (!path)
        return 0;
    int rc = klee_read_path(ic, ev->pid, proc->saved_path, sizeof(proc->saved_path), path);
    if (rc <= 0)
        return rc;
    if (beneath && proc->saved_path[0] == '/')
        return -EXDEV;
    if (how.resolve & RESOLVE_CACHED)
        return -EAGAIN;

    int dirfd = (int)ev->args[0];
    char base[PATH_MAX];
    if (in_root || beneath) {
        rc = klee_path_dirfd(&ctx, dirfd, base);
        if (rc < 0)
            return rc == -EBADF ? 0 : rc;
        ctx.dirfd_path = base;
        if (in_root)
            ctx.vroot = base;
    }
    if (in_root)
        ctx.flags |= KLEE_RESOLVE_IN_ROOT;
    if (beneath)
        ctx.flags |= KLEE_RESOLVE_BENEATH;
    if (how.resolve & RESOLVE_NO_XDEV)
        ctx.flags |= KLEE_RESOLVE_NO_XDEV;
    if (how.resolve & RESOLVE_NO_MAGICLINKS)
        ctx.flags |= KLEE_RESOLVE_NO_MAGICLINKS;
    if (how.resolve & RESOLVE_NO_SYMLINKS)
        ctx.flags |= KLEE_RESOLVE_NO_SYMLINKS;

    bool trailing_slash = proc->saved_path[strlen(proc->saved_path) - 1] == '/';
    bool nofollow = open_nofollow(flags) && !trailing_slash;
    rc = nofollow ? klee_path_resolve_nofollow(&ctx, proc->saved_path, proc->resolved_guest, dirfd) :
                    klee_path_resolve(&ctx, proc->saved_path, proc->resolved_guest, dirfd);
    if (rc < 0)
        return rc == -EBADF ? 0 : rc;

    if (nofollow)
        rc = klee_mount_table_translate_nofollow(ctx.mount_table, proc->resolved_guest,
                                                  proc->translated_path, PATH_MAX, open_access(flags));
    else
        rc = klee_mount_table_translate_access(ctx.mount_table, proc->resolved_guest,
                                                proc->translated_path, PATH_MAX, open_access(flags));
    if (rc < 0)
        return rc;
    rc = check_readonly_open(proc, flags);
    if (rc < 0)
        return rc;

    if (in_root || beneath) {
        char host_base[PATH_MAX];
        rc = klee_mount_table_translate(ctx.mount_table, base, host_base, sizeof(host_base));
        if (rc < 0)
            return rc;
        size_t len = strlen(host_base);
        while (len > 1 && host_base[len - 1] == '/')
            len--;
        const char *name = proc->translated_path;
        if (strncmp(name, host_base, len) != 0 ||
            (len > 1 && name[len] != '/' && name[len] != '\0'))
            return -EXDEV;
        name += len;
        while (*name == '/')
            name++;
        memmove(proc->translated_path, *name ? name : ".", *name ? strlen(name) + 1 : 2);
    }

    if (trailing_slash) {
        size_t len = strlen(proc->translated_path);
        if (len + 1 >= sizeof(proc->translated_path))
            return -ENAMETOOLONG;
        if (len != 0 && proc->translated_path[len - 1] != '/')
            strcpy(proc->translated_path + len, "/");
    }
    if (strcmp(proc->saved_path, proc->translated_path) == 0)
        return 0;
    return stage_path_arg(proc, ic, 1);
}

int klee_enter_stat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_path_arg(proc, ic, ev, 0, -1);
}

int klee_enter_lstat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_path_arg_nofollow(proc, ic, ev, 0, -1);
}

int klee_enter_newfstatat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int flags = (int)ev->args[3];
    if (flags & AT_SYMLINK_NOFOLLOW)
        return translate_path_arg_nofollow(proc, ic, ev, 1, 0);
    return translate_path_arg(proc, ic, ev, 1, 0);
}

int klee_enter_statx(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (ev->args[2] & AT_SYMLINK_NOFOLLOW)
        return translate_path_arg_nofollow(proc, ic, ev, 1, 0);
    return translate_path_arg(proc, ic, ev, 1, 0);
}

int klee_enter_access(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_path_arg(proc, ic, ev, 0, -1);
}

int klee_enter_faccessat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
#ifdef KLEE_SYS_faccessat2
    if (ev->syscall_nr == KLEE_SYS_faccessat2 && (ev->args[3] & AT_SYMLINK_NOFOLLOW))
        return translate_path_arg_nofollow(proc, ic, ev, 1, 0);
#endif
    return translate_path_arg(proc, ic, ev, 1, 0);
}

int klee_enter_readlink(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_path_arg_nofollow(proc, ic, ev, 0, -1);
}

int klee_enter_readlinkat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_path_arg_nofollow(proc, ic, ev, 1, 0);
}

/*
 * Handle interpreter translation for execve.
 *
 * The kernel resolves two types of interpreters directly on the HOST
 * filesystem, bypassing klee's mount table:
 *
 * 1. Shebang scripts: #!/bin/bash → kernel opens /bin/bash from host
 * 2. ELF PT_INTERP: /lib64/ld-linux-x86-64.so.2 → kernel loads host ld-linux
 *
 * Both can cause ABI mismatches (host binary + sandbox libraries → crash).
 * We detect these and rewrite the execve to use the correctly translated
 * interpreter/loader, building the full argv chain in the tracee's stack.
 */

/*
 * Parse a shebang line from a file buffer.
 * Returns the interpreter path in interp_out and optional arg in optarg_out.
 * Returns 0 if shebang found, -1 otherwise.
 */
static int parse_shebang(const char *buf, ssize_t len,
                          char *interp_out, size_t interp_size,
                          char *optarg_out, size_t optarg_size)
{
    if (len < 3 || buf[0] != '#' || buf[1] != '!')
        return -1;

    /* Work on a mutable copy */
    char line[256];
    ssize_t copy_len = len < (ssize_t)sizeof(line) - 1 ? len : (ssize_t)sizeof(line) - 1;
    memcpy(line, buf, (size_t)copy_len);
    line[copy_len] = '\0';

    char *nl = strchr(line + 2, '\n');
    if (nl) *nl = '\0';

    char *ip = line + 2;
    while (*ip == ' ' || *ip == '\t') ip++;
    if (*ip == '\0') return -1;

    char *ip_end = ip;
    while (*ip_end && *ip_end != ' ' && *ip_end != '\t') ip_end++;
    if (!nl && len >= (ssize_t)sizeof(line) && ip_end == line + copy_len)
        return -1;  /* interpreter name did not fit in the kernel's buffer */

    char *oa = NULL;
    if (*ip_end) {
        *ip_end = '\0';
        oa = ip_end + 1;
        while (*oa == ' ' || *oa == '\t') oa++;
        if (*oa == '\0') oa = NULL;
        else {
            char *end = oa + strlen(oa) - 1;
            while (end > oa && (*end == ' ' || *end == '\t'))
                *end-- = '\0';
        }
    }

    snprintf(interp_out, interp_size, "%s", ip);
    if (oa && optarg_out)
        snprintf(optarg_out, optarg_size, "%s", oa);
    else if (optarg_out)
        optarg_out[0] = '\0';

    return 0;
}

/* True when both host paths name the same file.  If the kernel's own
 * PT_INTERP lookup would load the very loader the sandbox maps there, the
 * ld.so indirection buys nothing, and skipping it keeps comm, cmdline and
 * /proc/<pid>/exe (what ps, pgrep, pidof and IPC peers go by) pointing at
 * the real program instead of ld-linux. */
static bool same_host_file(const char *a, const char *b)
{
    struct stat sa, sb;
    return stat(a, &sa) == 0 && stat(b, &sb) == 0 &&
           sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

/* The kernel derives comm from the last component of the path handed to
 * execve, before following symlinks: "sh" for /bin/sh even when that is
 * dash, and a script's own name for a script.  Reproduce that from the raw
 * path the tracee used, falling back to the file we actually run. */
static void exec_comm_name(const char *raw_path, const char *host_path,
                           char *out, size_t out_size)
{
    const char *candidates[2] = { raw_path, host_path };
    for (int i = 0; i < 2; i++) {
        const char *p = candidates[i];
        if (!p || !*p)
            continue;
        const char *base = strrchr(p, '/');
        base = base ? base + 1 : p;
        if (*base && strcmp(base, ".") != 0 && strcmp(base, "..") != 0) {
            snprintf(out, out_size, "%s", base);
            return;
        }
    }
    out[0] = '\0';
}

/* Build the interpreter prefix followed by the original argv[1..]. */
static int stage_exec_argv(KleeProcess *proc, KleeInterceptor *ic,
                           const char *const *prefix, size_t prefix_count,
                           uint64_t argv_base, uint64_t *argv_addr)
{
    size_t capacity = 32;
    size_t count = 0;
    uint64_t *argv = malloc(capacity * sizeof(*argv));
    if (!argv)
        return -ENOMEM;
    int rc;
    for (size_t i = 0; i < prefix_count; i++) {
        rc = klee_scratch_string(proc, ic, prefix[i], &argv[count++]);
        if (rc < 0)
            goto out;
    }

    size_t ptr_size = klee_abi_ptr_size(proc->abi);
    long arg_max = sysconf(_SC_ARG_MAX);
    size_t max_args = (arg_max > 0 ? (size_t)arg_max : 131072) / ptr_size;
    if (argv_base) {
        for (size_t i = 0;; i++) {
            uint64_t ptr;
            if (i >= max_args || count >= max_args) {
                rc = -E2BIG;
                goto out;
            }
            rc = klee_abi_read_ptr(ic, proc->real_pid, proc->abi,
                                  argv_base + i * ptr_size, &ptr);
            if (rc < 0)
                goto out;
            if (!ptr)
                break;
            if (i == 0)
                continue;
            if (count + 1 == capacity) {
                capacity *= 2;
                uint64_t *larger = realloc(argv, capacity * sizeof(*argv));
                if (!larger) {
                    rc = -ENOMEM;
                    goto out;
                }
                argv = larger;
            }
            argv[count++] = ptr;
        }
    }

    argv[count++] = 0;
    rc = klee_abi_stage_ptrs(proc, ic, argv, count, argv_addr);
out:
    free(argv);
    return rc;
}

typedef struct {
    char interpreter[256];
    char argument[256];
} Shebang;

static int handle_exec_interp(KleeProcess *proc, KleeInterceptor *ic,
                              KleeEvent *ev, int path_arg, int argv_arg)
{
    if (!proc->translated_path[0])
        return 0;

    KleeResolveCtx ctx = {
        .mount_table = proc->sandbox->mount_table,
        .fd_table = proc->fd_table,
        .tracee_pid = proc->real_pid,
        .vcwd = proc->vcwd,
        .vroot = klee_mount_table_get_root(proc->sandbox->mount_table),
    };
    char current_host[PATH_MAX], current_guest[PATH_MAX];
    strcpy(current_host, proc->translated_path);
    strcpy(current_guest, proc->resolved_guest);
    if (ev->syscall_nr == KLEE_SYS_execveat && (ev->args[4] & AT_SYMLINK_NOFOLLOW)) {
        struct stat st;
        if (lstat(current_host, &st) == 0 && S_ISLNK(st.st_mode))
            return 0;
    }

    Shebang scripts[5];
    size_t depth = 0;
    int binary = -1;
    for (;;) {
        int fd = open(current_host, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0)
            break;
        struct stat st;
        if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
            close(fd);
            break;
        }
        char buf[256];
        ssize_t n = pread(fd, buf, sizeof(buf), 0);

        Shebang next;
        if (parse_shebang(buf, n, next.interpreter, sizeof(next.interpreter),
                          next.argument, sizeof(next.argument)) < 0) {
            binary = fd;
            break;
        }
        close(fd);
        if (depth == sizeof(scripts) / sizeof(scripts[0]))
            return -ELOOP;
        if (access(current_host, X_OK) < 0)
            return -errno;
        scripts[depth++] = next;
        int rc = klee_path_resolve(&ctx, next.interpreter, current_guest, AT_FDCWD);
        if (rc < 0)
            return rc;
        rc = klee_mount_table_translate(ctx.mount_table, current_guest,
                                         current_host, sizeof(current_host));
        if (rc < 0)
            return rc;
    }
    snprintf(proc->next_exe, PATH_MAX, "%s", current_guest);

    char loader_host[PATH_MAX] = {0};
    KleeElfInfo elf;
    bool need_loader = binary >= 0 && klee_elf_read_interp(binary, &elf) == 0 &&
                       klee_path_guest_to_host(&ctx, elf.interp, loader_host, AT_FDCWD) == 0 &&
                       strcmp(elf.interp, loader_host) != 0 &&
                       !same_host_file(elf.interp, loader_host);
    if (!need_loader && binary >= 0)
        close(binary);
    if (!need_loader && depth == 0)
        return 0;
    if (access(current_host, X_OK) < 0) {
        int error = errno;
        if (need_loader)
            close(binary);
        return -error;
    }

    char name[NAME_MAX + 1], filename_host[PATH_MAX];
    exec_comm_name(proc->saved_path, current_host, name, sizeof(name));
    KleeExecShim *shim = klee_exec_shim_get();
    bool via_ldso = false;
    if (need_loader) {
        via_ldso = klee_exec_shim_prepare(shim, binary, current_host, &elf, loader_host, name,
                                         filename_host, sizeof(filename_host)) < 0;
        close(binary);
        if (via_ldso && klee_exec_shim_alias(shim, loader_host, name, filename_host,
                                              sizeof(filename_host)) < 0)
            strcpy(filename_host, loader_host);
    } else if (klee_exec_shim_alias(shim, current_host, name, filename_host,
                                     sizeof(filename_host)) < 0) {
        strcpy(filename_host, current_host);
    }

    uint64_t filename;
    int rc = klee_scratch_string(proc, ic, filename_host, &filename);
    if (rc < 0)
        return rc;

    if (via_ldso || depth != 0) {
        const char *prefix[2 + 2 * (sizeof(scripts) / sizeof(scripts[0]))];
        size_t count = 0;
        if (via_ldso)
            prefix[count++] = elf.interp;
        prefix[count++] = depth == 0 ? current_guest : scripts[depth - 1].interpreter;
        char fd_path[PATH_MAX];
        const char *script_path = proc->saved_path;
        if (ev->syscall_nr == KLEE_SYS_execveat && script_path[0] != '/' &&
            (int)ev->args[0] != AT_FDCWD) {
            int fd = (int)ev->args[0];
            if (klee_fd_table_is_cloexec(proc->fd_table, fd))
                return -ENOENT;
            if (snprintf(fd_path, sizeof(fd_path), "/dev/fd/%d%s%s", fd,
                         *script_path ? "/" : "", script_path) >= (int)sizeof(fd_path))
                return -ENAMETOOLONG;
            script_path = fd_path;
        }
        for (size_t i = depth; i > 0; i--) {
            if (scripts[i - 1].argument[0])
                prefix[count++] = scripts[i - 1].argument;
            prefix[count++] = i > 1 ? scripts[i - 2].interpreter : script_path;
        }
        uint64_t argv_addr;
        rc = stage_exec_argv(proc, ic, prefix, count, ev->args[argv_arg], &argv_addr);
        if (rc < 0)
            return rc;
        klee_regs_set_arg(proc, argv_arg, argv_addr);
    }
    klee_regs_set_arg(proc, path_arg, filename);
    return klee_regs_push(ic, proc);
}

/* Scan tracee argv for --no-sandbox (used for per-process UID virt in Zypak mode).
 * Returns true if found. Reads up to 256 argv entries from tracee memory. */
static bool tracee_argv_has_no_sandbox(KleeInterceptor *ic, pid_t pid,
                                        KleeAbi abi, uint64_t argv_addr)
{
    if (!argv_addr)
        return false;

    size_t psz = klee_abi_ptr_size(abi);
    for (int i = 0; i < 256; i++) {
        uint64_t ptr = 0;
        int rc = klee_abi_read_ptr(ic, pid, abi, argv_addr + (uint64_t)i * psz,
                                   &ptr);
        if (rc < 0 || ptr == 0)
            break;

        char arg[32]; /* "--no-sandbox" is 12 chars + NUL */
        rc = klee_read_string(ic, pid, arg, sizeof(arg),
                              (const void *)(uintptr_t)ptr);
        if (rc < 0)
            continue;

        if (strcmp(arg, "--no-sandbox") == 0)
            return true;
    }
    return false;
}

int klee_enter_execve(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg(proc, ic, ev, 0, -1);
    if (rc < 0) return rc;

    const char *exe = klee_process_exe_at(proc, proc->resolved_guest);
    if (exe && proc->sandbox && proc->sandbox->mount_table) {
        snprintf(proc->saved_path, PATH_MAX, "%s", exe);
        snprintf(proc->resolved_guest, PATH_MAX, "%s", exe);
        rc = klee_mount_table_translate(proc->sandbox->mount_table, exe,
                                        proc->translated_path, PATH_MAX);
        if (rc < 0)
            return rc;
        rc = stage_path_arg(proc, ic, 0);
        if (rc < 0)
            return rc;
    }

    /* Check for nested bwrap invocation — parse inline and rewrite */
    if (klee_nested_is_bwrap(proc->saved_path)) {
        rc = klee_nested_handle_exec(proc, ic, ev);
        if (rc < 0)
            return rc;
        ev->args[1] = klee_regs_get_arg(proc, 1);
    }

    /* Check for flatpak-spawn (Zypak mimic strategy) — intercept and
     * run target command directly inside klee's process tree */
    if (proc->sandbox && proc->sandbox->zypak_detected &&
        klee_zypak_is_flatpak_spawn(proc->saved_path)) {
        rc = klee_zypak_handle_flatpak_spawn(proc, ic, ev);
        if (rc < 0)
            return rc;
        ev->args[1] = klee_regs_get_arg(proc, 1);
    }

    /* Check for chrome-sandbox exec (Chrome SUID sandbox helper).
     * Chrome execs chrome-sandbox via raw syscall, bypassing Zypak's
     * LD_PRELOAD exec overrides that set up FD 235 IPC.  Without that
     * IPC, zypak-sandbox exits immediately ("Host is gone").
     *
     * Rewrite the execve to run the target binary (argv[1]) directly,
     * skipping the sandbox helper.  Also nullify CHROME_DEVEL_SANDBOX
     * in envp so child processes don't retry the SUID sandbox.
     *
     * Falls through to shebang/interp handling so the target binary's
     * PT_INTERP gets correctly translated. */
    if (proc->sandbox && proc->sandbox->zypak_detected &&
        klee_zypak_is_chrome_sandbox(proc->saved_path) &&
        ic->backend == INTERCEPT_PTRACE) {
        uint64_t argv_addr = ev->args[1] + klee_abi_ptr_size(proc->abi);
        uint64_t target_ptr;
        rc = klee_abi_read_ptr(ic, ev->pid, proc->abi, argv_addr, &target_ptr);
        if (rc < 0 || !target_ptr)
            return rc < 0 ? rc : -EINVAL;

        rc = klee_read_string(ic, ev->pid, proc->saved_path, PATH_MAX,
                              (void *)(uintptr_t)target_ptr);
        if (rc <= 0)
            return rc < 0 ? rc : -ENOENT;

        KleeResolveCtx ctx = {
            .mount_table = proc->sandbox->mount_table,
            .fd_table = proc->fd_table,
            .tracee_pid = proc->real_pid,
            .vcwd = proc->vcwd,
            .vroot = klee_mount_table_get_root(proc->sandbox->mount_table),
        };
        rc = klee_path_resolve(&ctx, proc->saved_path, proc->resolved_guest, AT_FDCWD);
        if (rc < 0)
            return rc;
        rc = klee_mount_table_translate(ctx.mount_table, proc->resolved_guest,
                                        proc->translated_path, PATH_MAX);
        if (rc < 0)
            return rc;
        rc = stage_path_arg(proc, ic, 0);
        if (rc < 0)
            return rc;
        klee_regs_set_arg(proc, 1, argv_addr);
        rc = klee_regs_push(ic, proc);
        if (rc < 0)
            return rc;
        ev->args[1] = argv_addr;
        klee_zypak_nullify_sandbox_env(ic, ev->pid, proc->abi, ev->args[2]);
    }

    /* A program at the same host and guest path can still use a remapped loader. */
    if (proc->sandbox && proc->sandbox->mount_table &&
        ic->backend == INTERCEPT_PTRACE) {
        rc = handle_exec_interp(proc, ic, ev, 0, 1);
        if (rc < 0)
            return rc;
    }

    /* Per-process UID virtualization for Zypak: on exec, determine whether
     * this process should skip UID virtualization.  Processes with --no-sandbox
     * (Chrome main, GPU) skip it so getuid() returns real uid=0 for D-Bus
     * AUTH EXTERNAL.  Processes without it (zygote, utility) keep virtual
     * uid to pass Chrome's root check. */
    if (proc->sandbox && proc->sandbox->zypak_detected) {
        proc->next_skip_uid_virt = tracee_argv_has_no_sandbox(ic, ev->pid, proc->abi, ev->args[1]);
        KLEE_DEBUG("execve pid=%d %s: skip_uid_virt=%d",
                   proc->real_pid, proc->saved_path, proc->next_skip_uid_virt);
    }

    return 0;
}

int klee_enter_execveat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    bool nofollow = (ev->args[4] & AT_SYMLINK_NOFOLLOW) != 0;
    int rc = translate_path_arg_ex(proc, ic, ev, 1, 0, nofollow, KLEE_OV_READ);
    if (rc < 0)
        return rc;

    if ((ev->args[4] & AT_EMPTY_PATH) && proc->saved_path[0] == '\0') {
        int fd = (int)ev->args[0];
        snprintf(proc->translated_path, PATH_MAX, "/proc/%d/fd/%d",
                 proc->real_pid, fd);
        const char *vpath = klee_fd_table_get(proc->fd_table, fd);
        snprintf(proc->resolved_guest, PATH_MAX, "%s", vpath ? vpath : "");
    }

    if (proc->sandbox && proc->sandbox->mount_table && ic->backend == INTERCEPT_PTRACE) {
        rc = handle_exec_interp(proc, ic, ev, 1, 2);
        if (rc < 0)
            return rc;
    }

    if (proc->sandbox && proc->sandbox->zypak_detected)
        proc->next_skip_uid_virt = tracee_argv_has_no_sandbox(ic, ev->pid, proc->abi, ev->args[2]);

    return 0;
}

typedef struct {
    KleeMount *mount;
    bool mount_root;
    char relative[PATH_MAX];
} OverlayOperand;

/* Resolve both operands before permitting any change to an upper layer. */
static int lookup_operand(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev,
                           int path_idx, int dir_idx, bool nofollow, OverlayOperand *out)
{
    int rc = translate_path_arg_for(proc, ic, ev, path_idx, dir_idx, nofollow,
                                    KLEE_OV_LOOKUP);
    if (rc < 0 || !proc->resolved_guest[0] || !proc->sandbox || !proc->sandbox->mount_table)
        return rc;
    KleeMountTable *table = proc->sandbox->mount_table;
    KleeMount *mount = klee_mount_table_resolve(table, proc->resolved_guest);
    if (!mount || !mount->overlay)
        return 0;
    out->mount = mount;
    RadixNode *exact = klee_radix_find_exact(table->tree, proc->resolved_guest);
    out->mount_root = exact && exact->mount == mount;
    rc = klee_mount_table_overlay_relative(table, proc->resolved_guest,
                                           out->relative, sizeof(out->relative));
    if (rc == 0) {
        size_t length = strlen(proc->saved_path);
        if (length && proc->saved_path[length - 1] == '/') {
            size_t tail = strlen(out->relative);
            if (tail + 1 >= sizeof(out->relative))
                return -ENAMETOOLONG;
            out->relative[tail] = '/';
            out->relative[tail + 1] = '\0';
        }
    }
    return rc;
}

static int overlay_result(KleeEvent *event, int result)
{
    event->emulated = result == 0;
    return result;
}

static bool status_field(FILE *status, const char *key, char **line, size_t *size)
{
    size_t length = strlen(key);
    while (getline(line, size, status) >= 0) {
        if (strncmp(*line, key, length) == 0)
            return true;
    }
    return false;
}

/* Namespace mutations run in the supervisor, so they require the same
 * actual kernel credentials. Virtual UID/GID settings remain independent. */
static int overlay_credentials(pid_t pid)
{
    char path[64];
    struct stat supervisor, tracee;
    snprintf(path, sizeof(path), "/proc/%d/ns/user", pid);
    if (stat("/proc/self/ns/user", &supervisor) < 0 || stat(path, &tracee) < 0)
        return -errno;
    if (supervisor.st_dev != tracee.st_dev || supervisor.st_ino != tracee.st_ino)
        return -EPERM;

    FILE *self_status = fopen("/proc/self/status", "re");
    if (!self_status)
        return -errno;
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *tracee_status = fopen(path, "re");
    if (!tracee_status) {
        int rc = -errno;
        fclose(self_status);
        return rc;
    }
    const char *const keys[] = { "Uid:", "Gid:", "Groups:", "CapEff:" };
    char *self_line = NULL, *tracee_line = NULL;
    size_t self_size = 0, tracee_size = 0;
    int rc = 0;
    for (size_t i = 0; i < sizeof(keys) / sizeof(*keys); i++) {
        if (!status_field(self_status, keys[i], &self_line, &self_size) ||
            !status_field(tracee_status, keys[i], &tracee_line, &tracee_size)) {
            rc = -EIO;
            break;
        }
        if (strcmp(self_line, tracee_line)) {
            rc = -EPERM;
            break;
        }
    }
    free(self_line);
    free(tracee_line);
    fclose(self_status);
    fclose(tracee_status);
    return rc;
}

static int enter_rename(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev,
                        int old_idx, int olddir_idx, int new_idx,
                        int newdir_idx, unsigned int flags)
{
    OverlayOperand old = {0}, new = {0};
    int rc = lookup_operand(proc, ic, ev, old_idx, olddir_idx, true, &old);
    if (rc == 0)
        rc = check_readonly(proc, ev->syscall_nr);
    if (rc == 0)
        rc = lookup_operand(proc, ic, ev, new_idx, newdir_idx, true, &new);
    if (rc < 0)
        return rc;
    if (old.mount != new.mount)
        return -EXDEV;
    rc = check_readonly(proc, ev->syscall_nr);
    if (rc < 0 || !old.mount)
        return rc;
    if (old.mount_root || new.mount_root)
        return -EBUSY;
    rc = overlay_credentials(ev->pid);
    if (rc < 0)
        return rc;
    return overlay_result(ev, klee_overlay_rename(old.mount->overlay,
                                                  old.relative, new.relative, flags));
}

int klee_enter_rename(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return enter_rename(proc, ic, ev, 0, -1, 1, -1, 0);
}

int klee_enter_renameat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return enter_rename(proc, ic, ev, 1, 0, 3, 2, 0);
}

int klee_enter_renameat2(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* renameat2(olddirfd, oldpath, newdirfd, newpath, flags) */
    return enter_rename(proc, ic, ev, 1, 0, 3, 2, (unsigned int)ev->args[4]);
}

int klee_enter_mkdir(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_for(proc, ic, ev, 0, -1, true,
                                    KLEE_OV_CREATE_EXCL);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_mkdirat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_for(proc, ic, ev, 1, 0, true,
                                    KLEE_OV_CREATE_EXCL);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

static int enter_remove(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev,
                        int path_idx, int dir_idx, bool directory)
{
    OverlayOperand path = {0};
    int rc = lookup_operand(proc, ic, ev, path_idx, dir_idx, true, &path);
    if (rc == 0)
        rc = check_readonly(proc, ev->syscall_nr);
    if (rc < 0 || !path.mount)
        return rc;
    if (path.mount_root)
        return directory ? -EBUSY : -EISDIR;
    rc = overlay_credentials(ev->pid);
    if (rc < 0)
        return rc;
    return overlay_result(ev, klee_overlay_remove(path.mount->overlay, path.relative,
                                                  directory));
}

int klee_enter_rmdir(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return enter_remove(proc, ic, ev, 0, -1, true);
}

int klee_enter_unlink(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return enter_remove(proc, ic, ev, 0, -1, false);
}

int klee_enter_unlinkat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    unsigned int flags = ev->args[2];
    if (flags & ~AT_REMOVEDIR)
        return -EINVAL;
    return enter_remove(proc, ic, ev, 1, 0, (flags & AT_REMOVEDIR) != 0);
}

/* A procfd names an open description. Its recorded layer may differ from
 * what a fresh lookup of the pathname would find after copy-up or rename. */
static int self_proc_fd(const KleeProcess *proc)
{
    if (!proc->resolved_guest[0])
        return -1;
    int pid, fd;
    char extra;
    if (sscanf(proc->resolved_guest, "/proc/%d/fd/%d%c", &pid, &fd, &extra) != 2 ||
        pid != proc->real_pid || fd < 0)
        return -1;
    return fd;
}

static int enter_link(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev,
                      int old_idx, int olddir_idx, int new_idx,
                      int newdir_idx, int flags)
{
    if (flags & ~(AT_EMPTY_PATH | AT_SYMLINK_FOLLOW))
        return -EINVAL;

    char first;
    bool by_fd = olddir_idx >= 0 && (flags & AT_EMPTY_PATH) && ev->args[old_idx] &&
                 klee_read_mem(ic, ev->pid, &first,
                               (const void *)(uintptr_t)ev->args[old_idx], 1) == 0 &&
                 first == '\0';
    int source_fd = by_fd ? (int)ev->args[olddir_idx] : -1;
    OverlayOperand old = {0}, new = {0};
    int rc = 0;
    if (!by_fd) {
        rc = lookup_operand(proc, ic, ev, old_idx, olddir_idx,
                            !(flags & AT_SYMLINK_FOLLOW), &old);
        if (rc < 0)
            return rc;
        if (flags & AT_SYMLINK_FOLLOW)
            source_fd = self_proc_fd(proc);
    }
    rc = lookup_operand(proc, ic, ev, new_idx, newdir_idx, true, &new);
    if (rc == 0)
        rc = check_readonly(proc, ev->syscall_nr);
    if (rc < 0)
        return rc;

    if (by_fd || source_fd >= 0) {
        uint64_t mount_id = 0;
        bool upper = false;
        klee_fd_table_get_overlay(proc->fd_table, source_fd, &mount_id, &upper);
        if (mount_id != (new.mount ? new.mount->id : 0) || (mount_id && !upper))
            return -EXDEV;
        return new.mount ? translate_path_arg_for(proc, ic, ev, new_idx, newdir_idx,
                                                    true, KLEE_OV_CREATE_EXCL) : 0;
    }
    if (old.mount != new.mount)
        return -EXDEV;
    if (!old.mount)
        return 0;
    rc = overlay_credentials(ev->pid);
    if (rc < 0)
        return rc;
    return overlay_result(ev, klee_overlay_link(old.mount->overlay, old.relative, new.relative));
}

int klee_enter_link(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* link(oldpath, newpath) - oldpath should not follow final symlink */
    return enter_link(proc, ic, ev, 0, -1, 1, -1, 0);
}

int klee_enter_linkat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* linkat(olddirfd, oldpath, newdirfd, newpath, flags)
     * Default: don't follow on oldpath. AT_SYMLINK_FOLLOW changes this. */
    return enter_link(proc, ic, ev, 1, 0, 3, 2, (int)ev->args[4]);
}

int klee_enter_symlink(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* symlink(target, linkpath) - translate linkpath (arg 1), nofollow */
    int rc = translate_path_arg_for(proc, ic, ev, 1, -1, true,
                                    KLEE_OV_CREATE_EXCL);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_symlinkat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* symlinkat(target, dirfd, linkpath) - translate linkpath (arg 2), nofollow */
    int rc = translate_path_arg_for(proc, ic, ev, 2, 1, true,
                                    KLEE_OV_CREATE_EXCL);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_chmod(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_for(proc, ic, ev, 0, -1, false, KLEE_OV_SETATTR);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_fchmodat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_for(proc, ic, ev, 1, 0, false, KLEE_OV_SETATTR);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_chown(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_for(proc, ic, ev, 0, -1, false, KLEE_OV_SETATTR);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_lchown(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_for(proc, ic, ev, 0, -1, true, KLEE_OV_SETATTR);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_fchownat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* fchownat(dirfd, path, uid, gid, flags) */
    bool nofollow = (ev->args[4] & AT_SYMLINK_NOFOLLOW) != 0;
    int rc = translate_path_arg_for(proc, ic, ev, 1, 0, nofollow,
                                    KLEE_OV_SETATTR);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_truncate(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_for(proc, ic, ev, 0, -1, false, KLEE_OV_WRITE);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_mknod(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_for(proc, ic, ev, 0, -1, true,
                                    KLEE_OV_CREATE_EXCL);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_mknodat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_for(proc, ic, ev, 1, 0, true,
                                    KLEE_OV_CREATE_EXCL);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_chdir(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_path_arg(proc, ic, ev, 0, -1);
}

int klee_enter_chroot(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* Intercept chroot: update virtual root instead */
    translate_path_arg(proc, ic, ev, 0, -1);
    return -EPERM; /* Block real chroot, simulate it */
}

int klee_enter_mount(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic; (void)ev;
    KLEE_DEBUG("mount() intercepted from pid=%d, denying", proc->real_pid);
    return -EPERM;
}

int klee_enter_umount(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic; (void)ev;
    KLEE_DEBUG("umount2() intercepted from pid=%d, denying", proc->real_pid);
    return -EPERM;
}

int klee_enter_close(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    int fd = (int)ev->args[0];
    klee_fd_table_remove(proc->fd_table, fd);
    return 0; /* Let it proceed */
}

/* ==================== PID Namespace Enter Handlers ==================== */

/* Helper: translate a PID from the virtual namespace to real.
 * Handles three cases:
 *   1. pid is a known virtual PID → return v2r translation
 *   2. pid is already a known real PID (glibc caches the real PID in the
 *      thread descriptor and uses it directly in raise/abort) → passthrough
 *   3. pid is unknown → return 0 (caller should return -ESRCH) */
static pid_t translate_pid(KleePidMap *pm, pid_t pid)
{
    pid_t real = klee_pid_map_v2r(pm, pid);
    if (real > 0)
        return real;
    /* Check if this is already a real PID in our namespace */
    pid_t vpid = klee_pid_map_r2v(pm, pid);
    if (vpid > 0)
        return pid; /* Already a real PID, pass through */
    return 0;
}

/* Resolve the target of a signal or pidfd syscall to a real PID, or 0 if it
 * names nothing in this namespace.  Unknown PIDs must not be passed through:
 * the kernel would deliver to whichever host process owns that number. */
static pid_t resolve_target_pid(KleeProcess *proc, pid_t pid)
{
    if (pid <= 0)
        return 0;
    KleePidMap *pm = proc->sandbox->pid_map;
    pid_t real = translate_pid(pm, pid);
    if (real > 0)
        return real;
    /* klee forgets a process when it exits, but until reaped it is still a
     * valid target.  Such a zombie's parent is a sandbox process, or klee
     * itself as subreaper. */
    pid_t ppid;
    if (klee_proc_status_ids(pid, NULL, &ppid) == 0 &&
        (klee_pid_map_r2v(pm, ppid) > 0 || ppid == getpid()))
        return pid;
    return 0;
}

/* Does any process in this namespace belong to process group pgid? */
static bool pgrp_in_namespace(const KleePidMap *pm, pid_t pgid)
{
    const KleeHashTable *ht = pm->real_to_virtual;
    for (size_t i = 0; i < ht->capacity; i++) {
        const KleeHTEntry *e = &ht->entries[i];
        if (e->occupied && !e->deleted && getpgid((pid_t)e->key) == pgid)
            return true;
    }
    return false;
}

/* Resolve a process-group argument.  Shells hold real pgids (fork()
 * returns real PIDs), possibly of a leader that has already exited, so
 * check membership first; getpgrp() hands out virtual ones.  Returns the
 * real pgid, or 0 if no process in this namespace belongs to it. */
static pid_t resolve_target_pgid(KleeProcess *proc, pid_t pgid)
{
    KleePidMap *pm = proc->sandbox->pid_map;
    if (pgid <= 0)
        return 0;
    if (pgrp_in_namespace(pm, pgid))
        return pgid;
    pid_t leader = klee_pid_map_v2r(pm, pgid);
    if (leader > 0 && pgrp_in_namespace(pm, leader))
        return leader;
    return 0;
}

/* kill(-1, sig) in a PID namespace reaches every process in it except init
 * and the caller's own thread group.  Deliver it to exactly those, then turn
 * the syscall into a harmless kill(self, 0) so the caller still sees 0. */
static int kill_namespace_broadcast(KleeProcess *proc, KleeInterceptor *ic,
                                    int sig)
{
    KleePidMap *pm = proc->sandbox->pid_map;
    pid_t self_tgid = proc->real_pid;
    klee_proc_status_ids(proc->real_pid, &self_tgid, NULL);

    int count = 0, result = 0;
    const KleeHashTable *ht = pm->real_to_virtual;
    for (size_t i = 0; i < ht->capacity; i++) {
        const KleeHTEntry *e = &ht->entries[i];
        if (!e->occupied || e->deleted)
            continue;
        pid_t real = (pid_t)e->key;
        pid_t tgid;
        /* The map holds threads too: signal each thread group once. */
        if (real <= 0 || klee_proc_status_ids(real, &tgid, NULL) < 0 ||
            tgid != real)
            continue;
        if (real == self_tgid || klee_pid_map_is_init(pm, real))
            continue;
        count++;
        /* Same error folding as the kernel: EPERM alone is not reported. */
        if (kill(real, sig) < 0 && errno != EPERM)
            result = -errno;
    }
    if (count == 0)
        return -ESRCH;
    if (result < 0)
        return result;

    klee_regs_fetch(ic, proc);
    klee_regs_set_arg(proc, 0, (uint64_t)proc->real_pid);
    klee_regs_set_arg(proc, 1, 0);
    klee_regs_push(ic, proc);
    return 0;
}

int klee_enter_kill(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!proc->sandbox || !proc->sandbox->unshare_pid || !proc->sandbox->pid_map)
        return 0;

    pid_t target = (pid_t)ev->args[0];
    if (target == 0)
        return 0; /* caller's own process group */
    if (target == -1)
        return kill_namespace_broadcast(proc, ic, (int)ev->args[1]);
    if (target == INT_MIN)
        return -ESRCH;

    pid_t real;
    if (target > 0) {
        real = resolve_target_pid(proc, target);
    } else {
        pid_t rpgid = resolve_target_pgid(proc, -target);
        real = rpgid > 0 ? -rpgid : 0;
    }

    if (real == 0) {
        KLEE_TRACE("kill: pid=%d target=%d not in namespace -> ESRCH",
                   proc->real_pid, target);
        return -ESRCH;
    }
    if (real != target) {
        klee_regs_fetch(ic, proc);
        klee_regs_set_arg(proc, 0, (uint64_t)(unsigned int)real);
        klee_regs_push(ic, proc);
    }
    return 0;
}

/* Shared by tgkill and rt_tgsigqueueinfo: (tgid, tid) in arg0/arg1. */
static int translate_tgid_tid(KleeProcess *proc, KleeInterceptor *ic,
                              KleeEvent *ev, const char *name)
{
    if (!proc->sandbox || !proc->sandbox->unshare_pid || !proc->sandbox->pid_map)
        return 0;

    pid_t vtgid = (pid_t)ev->args[0];
    pid_t vtid = (pid_t)ev->args[1];
    if (vtgid <= 0 || vtid <= 0)
        return 0; /* the kernel rejects these itself */
    pid_t real_tgid = resolve_target_pid(proc, vtgid);
    pid_t real_tid = resolve_target_pid(proc, vtid);

    if (real_tgid <= 0 || real_tid <= 0) {
        KLEE_TRACE("%s: pid=%d tgid=%d tid=%d not in namespace -> ESRCH",
                   name, proc->real_pid, vtgid, vtid);
        return -ESRCH;
    }

    if (real_tgid != vtgid || real_tid != vtid) {
        klee_regs_fetch(ic, proc);
        klee_regs_set_arg(proc, 0, (uint64_t)real_tgid);
        klee_regs_set_arg(proc, 1, (uint64_t)real_tid);
        klee_regs_push(ic, proc);
    }
    return 0;
}

/* A PID in argument idx.  0 (and negative values, which are process-group
 * or "all" forms the callers handle themselves) is left alone; anything
 * else must name a process in this namespace, or the call fails with
 * ESRCH as it would in a real PID namespace where host PIDs do not exist. */
static int translate_pid_arg(KleeProcess *proc, KleeInterceptor *ic,
                             KleeEvent *ev, int idx, const char *name)
{
    if (!proc->sandbox || !proc->sandbox->unshare_pid || !proc->sandbox->pid_map)
        return 0;

    pid_t vpid = (pid_t)ev->args[idx];
    if (vpid <= 0)
        return 0;
    pid_t real = resolve_target_pid(proc, vpid);
    if (real <= 0) {
        KLEE_TRACE("%s: pid=%d target=%d not in namespace -> ESRCH", name,
                   proc->real_pid, vpid);
        return -ESRCH;
    }

    if (real != vpid) {
        klee_regs_fetch(ic, proc);
        klee_regs_set_arg(proc, idx, (uint64_t)real);
        klee_regs_push(ic, proc);
    }
    return 0;
}

/* A process group in argument idx (0 = the caller's own, left alone). */
static int translate_pgid_arg(KleeProcess *proc, KleeInterceptor *ic,
                              KleeEvent *ev, int idx, const char *name)
{
    if (!proc->sandbox || !proc->sandbox->unshare_pid || !proc->sandbox->pid_map)
        return 0;

    pid_t pgid = (pid_t)ev->args[idx];
    if (pgid <= 0)
        return 0;
    pid_t real = resolve_target_pgid(proc, pgid);
    if (real <= 0) {
        KLEE_TRACE("%s: pid=%d pgid=%d not in namespace -> ESRCH", name,
                   proc->real_pid, pgid);
        return -ESRCH;
    }
    if (real != pgid) {
        klee_regs_fetch(ic, proc);
        klee_regs_set_arg(proc, idx, (uint64_t)real);
        klee_regs_push(ic, proc);
    }
    return 0;
}

/* Shared by tkill, rt_sigqueueinfo and pidfd_open: a single PID in arg0. */
static int translate_target_arg0(KleeProcess *proc, KleeInterceptor *ic,
                                 KleeEvent *ev, const char *name)
{
    return translate_pid_arg(proc, ic, ev, 0, name);
}

/* ==================== clone / unshare: what threads share ==================== */

/* Remember the flags of a clone in flight: the fork event that follows
 * uses them to share or copy the creator's cwd and fd table. */
int klee_enter_clone(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    proc->pending_clone_flags = (unsigned long)ev->args[0];
    return 0;
}

int klee_enter_clone3(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* clone3(struct clone_args *args, size): flags is the first u64 */
    uint64_t flags = 0;
    if (ev->args[0] &&
        klee_read_mem(ic, ev->pid, &flags, (const void *)(uintptr_t)ev->args[0],
                      sizeof(flags)) == 0)
        proc->pending_clone_flags = (unsigned long)flags;
    return 0;
}

int klee_enter_unshare(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    klee_process_unshare(proc, (unsigned long)ev->args[0]);
    return 0;
}

/* sched_*, prlimit64, process_vm_*, get_robust_list, move_pages,
 * migrate_pages: the target pid is arg0, 0 meaning the caller. */
int klee_enter_pid_arg0(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_pid_arg(proc, ic, ev, 0, "pid-arg");
}

int klee_enter_kcmp(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_pid_arg(proc, ic, ev, 0, "kcmp");
    if (rc < 0) return rc;
    return translate_pid_arg(proc, ic, ev, 1, "kcmp");
}

int klee_enter_perf_event_open(KleeProcess *proc, KleeInterceptor *ic,
                               KleeEvent *ev)
{
    /* perf_event_open(attr, pid, cpu, group_fd, flags); pid -1 = any */
    return translate_pid_arg(proc, ic, ev, 1, "perf_event_open");
}

int klee_enter_prio(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* setpriority/getpriority(which, who, ...) */
    int which = (int)ev->args[0];
    if (which == PRIO_PROCESS)
        return translate_pid_arg(proc, ic, ev, 1, "setpriority");
    if (which == PRIO_PGRP)
        return translate_pgid_arg(proc, ic, ev, 1, "setpriority");
    return 0;
}

int klee_enter_ioprio(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* ioprio_set/ioprio_get(which, who, ...) */
    int which = (int)ev->args[0];
    if (which == 1 /* IOPRIO_WHO_PROCESS */)
        return translate_pid_arg(proc, ic, ev, 1, "ioprio");
    if (which == 2 /* IOPRIO_WHO_PGRP */)
        return translate_pgid_arg(proc, ic, ev, 1, "ioprio");
    return 0;
}

int klee_enter_tgkill(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_tgid_tid(proc, ic, ev, "tgkill");
}

int klee_enter_tkill(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_target_arg0(proc, ic, ev, "tkill");
}

int klee_enter_rt_sigqueueinfo(KleeProcess *proc, KleeInterceptor *ic,
                               KleeEvent *ev)
{
    return translate_target_arg0(proc, ic, ev, "rt_sigqueueinfo");
}

int klee_enter_rt_tgsigqueueinfo(KleeProcess *proc, KleeInterceptor *ic,
                                 KleeEvent *ev)
{
    return translate_tgid_tid(proc, ic, ev, "rt_tgsigqueueinfo");
}

int klee_enter_pidfd_open(KleeProcess *proc, KleeInterceptor *ic,
                          KleeEvent *ev)
{
    return translate_target_arg0(proc, ic, ev, "pidfd_open");
}

/* ==================== Process Group Enter Handlers ==================== */

int klee_enter_setpgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!proc->sandbox || !proc->sandbox->unshare_pid)
        return 0;

    pid_t vpid = (pid_t)ev->args[0];
    pid_t vpgid = (pid_t)ev->args[1];
    bool modified = false;

    if (vpid != 0) {
        pid_t real = translate_pid(proc->sandbox->pid_map, vpid);
        if (real <= 0)
            return 0;
        if (real != vpid) {
            if (!modified) klee_regs_fetch(ic, proc);
            klee_regs_set_arg(proc, 0, (uint64_t)real);
            modified = true;
        }
    }

    if (vpgid != 0) {
        pid_t real = translate_pid(proc->sandbox->pid_map, vpgid);
        if (real <= 0)
            return 0;
        if (real != vpgid) {
            if (!modified) klee_regs_fetch(ic, proc);
            klee_regs_set_arg(proc, 1, (uint64_t)real);
            modified = true;
        }
    }

    if (modified)
        klee_regs_push(ic, proc);
    return 0;
}

int klee_enter_getpgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!proc->sandbox || !proc->sandbox->unshare_pid)
        return 0;

    pid_t vpid = (pid_t)ev->args[0];
    if (vpid == 0)
        return 0;

    pid_t real = translate_pid(proc->sandbox->pid_map, vpid);
    if (real <= 0)
        return 0;

    if (real != vpid) {
        klee_regs_fetch(ic, proc);
        klee_regs_set_arg(proc, 0, (uint64_t)real);
        klee_regs_push(ic, proc);
    }
    return 0;
}

int klee_enter_getsid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!proc->sandbox || !proc->sandbox->unshare_pid)
        return 0;

    pid_t vpid = (pid_t)ev->args[0];
    if (vpid == 0)
        return 0;

    pid_t real = translate_pid(proc->sandbox->pid_map, vpid);
    if (real <= 0)
        return 0;

    if (real != vpid) {
        klee_regs_fetch(ic, proc);
        klee_regs_set_arg(proc, 0, (uint64_t)real);
        klee_regs_push(ic, proc);
    }
    return 0;
}

/* ==================== ioctl Enter Handler ==================== */

int klee_enter_ioctl(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!proc->sandbox || !proc->sandbox->unshare_pid)
        return 0;

    unsigned long request = ev->args[1];

    if (request == TIOCSPGRP) {
        /* tcsetpgrp: ioctl(fd, TIOCSPGRP, &pgid)
         * The pgid is passed via pointer in arg2.  Read the virtual pgid
         * from tracee memory, translate to real, and write it back. */
        void *pgid_ptr = (void *)(uintptr_t)ev->args[2];
        pid_t vpgid;
        int rc = klee_read_mem(ic, ev->pid, &vpgid, pgid_ptr, sizeof(vpgid));
        if (rc < 0)
            return 0;

        pid_t real_pgid = translate_pid(proc->sandbox->pid_map, vpgid);
        if (real_pgid <= 0) {
            KLEE_TRACE("ioctl TIOCSPGRP: unknown vpgid %d", vpgid);
            return 0;
        }

        if (real_pgid != vpgid) {
            uint64_t scratch;
            rc = klee_scratch_write(proc, ic, &real_pgid, sizeof(real_pgid), &scratch);
            if (rc < 0)
                return rc;
            klee_regs_set_arg(proc, 2, scratch);
            return klee_regs_push(ic, proc);
        }
    }

    return 0;
}

/* ==================== UID/GID Enter Handlers ==================== */

static int emulate(KleeEvent *ev, long result)
{
    ev->emulated = true;
    ev->retval = result;
    return 0;
}

static bool virtual_ids(const KleeProcess *proc)
{
    return proc->sandbox && proc->sandbox->unshare_user && proc->id_state;
}

static uint32_t id_arg(const KleeProcess *proc, uint64_t arg)
{
    if (!(proc->sys32_flags & KLEE_SYS32_UID16))
        return (uint32_t)arg;
    uint16_t id = (uint16_t)arg;
    return id == UINT16_MAX ? UINT32_MAX : id;
}

int klee_enter_setuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!virtual_ids(proc))
        return 0;
    uid_t uid = id_arg(proc, ev->args[0]);
    if (uid == (uid_t)-1)
        return -EINVAL;
    klee_user_ns_handle_setuid(proc->id_state, uid);
    return emulate(ev, 0);
}

int klee_enter_setgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!virtual_ids(proc))
        return 0;
    gid_t gid = id_arg(proc, ev->args[0]);
    if (gid == (gid_t)-1)
        return -EINVAL;
    klee_user_ns_handle_setgid(proc->id_state, gid);
    return emulate(ev, 0);
}

int klee_enter_setreuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!virtual_ids(proc))
        return 0;
    klee_user_ns_handle_setreuid(proc->id_state, id_arg(proc, ev->args[0]),
                                  id_arg(proc, ev->args[1]));
    return emulate(ev, 0);
}

int klee_enter_setregid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!virtual_ids(proc))
        return 0;
    klee_user_ns_handle_setregid(proc->id_state, id_arg(proc, ev->args[0]),
                                  id_arg(proc, ev->args[1]));
    return emulate(ev, 0);
}

int klee_enter_setresuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!virtual_ids(proc))
        return 0;
    klee_user_ns_handle_setresuid(proc->id_state, id_arg(proc, ev->args[0]),
                                   id_arg(proc, ev->args[1]), id_arg(proc, ev->args[2]));
    return emulate(ev, 0);
}

int klee_enter_setresgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!virtual_ids(proc))
        return 0;
    klee_user_ns_handle_setresgid(proc->id_state, id_arg(proc, ev->args[0]),
                                   id_arg(proc, ev->args[1]), id_arg(proc, ev->args[2]));
    return emulate(ev, 0);
}

int klee_enter_setfsuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!virtual_ids(proc))
        return 0;
    uid_t old = proc->id_state->fsuid;
    uid_t uid = id_arg(proc, ev->args[0]);
    if (uid != (uid_t)-1)
        klee_user_ns_handle_setfsuid(proc->id_state, uid);
    return emulate(ev, klee_abi_id_result(proc, old));
}

int klee_enter_setfsgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!virtual_ids(proc))
        return 0;
    gid_t old = proc->id_state->fsgid;
    gid_t gid = id_arg(proc, ev->args[0]);
    if (gid != (gid_t)-1)
        klee_user_ns_handle_setfsgid(proc->id_state, gid);
    return emulate(ev, klee_abi_id_result(proc, old));
}

int klee_enter_setgroups(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!virtual_ids(proc))
        return 0;
    unsigned int count = (unsigned int)ev->args[0];
    if (count > NGROUPS_MAX)
        return -EINVAL;

    gid_t *groups = NULL;
    if (count) {
        groups = malloc(count * sizeof(*groups));
        if (!groups)
            return -ENOMEM;

        void *remote = (void *)(uintptr_t)ev->args[1];
        bool legacy = (proc->sys32_flags & KLEE_SYS32_UID16) != 0;
        int rc = klee_read_mem(ic, ev->pid, groups, remote,
                               count * (legacy ? sizeof(uint16_t) : sizeof(gid_t)));
        if (rc < 0) {
            free(groups);
            return -EFAULT;
        }
        if (legacy) {
            /* Expand the packed legacy IDs in reverse to avoid overlap. */
            for (unsigned int i = count; i-- > 0;) {
                uint16_t id;
                memcpy(&id, (char *)groups + i * sizeof(id), sizeof(id));
                groups[i] = id;
            }
        }
    }

    free(proc->id_state->groups);
    proc->id_state->groups = groups;
    proc->id_state->group_count = count;
    return emulate(ev, 0);
}

int klee_enter_getgroups(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!virtual_ids(proc) || proc->skip_uid_virt)
        return 0;
    size_t count = proc->id_state->group_count;
    int size = (int)ev->args[0];
    if (size == 0)
        return emulate(ev, (long)count);
    if (size < 0 || (size_t)size < count)
        return -EINVAL;
    if (count && klee_abi_write_ids(proc, ic, ev->args[1],
                                    proc->id_state->groups, count) < 0)
        return -EFAULT;
    return emulate(ev, (long)count);
}

/* ==================== UTS / IPC Enter Handlers ==================== */

int klee_enter_sethostname(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!proc->sandbox || !proc->sandbox->unshare_uts)
        return 0;

    char hostname[HOST_NAME_MAX + 1];
    size_t len = (size_t)ev->args[1];
    if (len > HOST_NAME_MAX)
        return -EINVAL;
    if (len && klee_read_mem(ic, ev->pid, hostname,
                             (void *)(uintptr_t)ev->args[0], len) < 0)
        return -EFAULT;
    hostname[len] = '\0';
    char *new_name = strdup(hostname);
    if (!new_name)
        return -ENOMEM;
    free(proc->sandbox->hostname);
    proc->sandbox->hostname = new_name;
    return emulate(ev, 0);
}

/* SysV shmget/msgget/semget: point the key argument at this sandbox's
 * private real key.  The kernel only sees the register, so it has to be
 * written back; updating ev->args alone changes nothing but klee's copy. */
static int translate_ipc_key(KleeProcess *proc, KleeInterceptor *ic,
                             KleeEvent *ev, const char *name)
{
    if (!proc->sandbox || !proc->sandbox->unshare_ipc || !proc->sandbox->ipc_ns)
        return 0;

    key_t key = (key_t)ev->args[0];
    key_t real_key = klee_ipc_ns_translate_key(proc->sandbox->ipc_ns, key);
    if (real_key != key) {
        klee_regs_fetch(ic, proc);
        klee_regs_set_arg(proc, 0, (uint64_t)(unsigned int)real_key);
        klee_regs_push(ic, proc);
        ev->args[0] = (uint64_t)(unsigned int)real_key;
    }
    KLEE_TRACE("%s: translated key %d -> %d", name, key, real_key);
    return 0;
}

int klee_enter_shmget(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_ipc_key(proc, ic, ev, "shmget");
}

int klee_enter_msgget(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_ipc_key(proc, ic, ev, "msgget");
}

int klee_enter_semget(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_ipc_key(proc, ic, ev, "semget");
}

/* ==================== Misc Enter Handlers ==================== */

int klee_enter_ptrace(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ev;
    if (ic->backend != INTERCEPT_PTRACE)
        return 0; /* seccomp_unotify backend — ptrace works normally */

    /* Child processes cannot ptrace when klee is already the tracer.
     * Deny explicitly rather than letting the kernel return a confusing
     * error after partial setup.  This is the normal situation for crash
     * reporters like crashpad running under a ptrace-based sandbox. */
    KLEE_DEBUG("ptrace: pid=%d denied (klee is tracer)", proc->real_pid);
    return -EPERM;
}

int klee_enter_prctl(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    int option = (int)ev->args[0];

    switch (option) {
    case PR_SET_MM:
    {
        int sub = (int)ev->args[1];
        if (sub == PR_SET_MM_EXE_FILE) {
            /* Look up FD and update virtual exe path, void the real syscall */
            int fd = (int)ev->args[2];
            const char *path = klee_fd_table_get(proc->fd_table, fd);
            if (path) {
                snprintf(proc->vexe, PATH_MAX, "%s", path);
                KLEE_DEBUG("prctl(PR_SET_MM_EXE_FILE) fd=%d -> vexe=%s",
                           fd, proc->vexe);
            }
            /* Void the real syscall (return success) */
            return emulate(ev, 0);
        }
        break;
    }

    case PR_CAPBSET_DROP:
        /* Under user namespace simulation, pretend capability drop succeeds.
         * Real bwrap does this via kernel namespace; we void the syscall. */
        if (proc->sandbox && proc->sandbox->unshare_user) {
            if (prctl(PR_CAPBSET_READ, ev->args[1], 0L, 0L, 0L) < 0)
                return -errno;
            return emulate(ev, 0);
        }
        break;

    case PR_SET_KEEPCAPS:
        /* Under user namespace simulation, pretend success.
         * Real bwrap uses this before dropping privileges. */
        if (proc->sandbox && proc->sandbox->unshare_user) {
            return ev->args[1] > 1 ? -EINVAL : emulate(ev, 0);
        }
        break;

    case PR_SET_CHILD_SUBREAPER:
        /* Allow passthrough - bwrap uses this for PID namespace init */
        break;

    case PR_SET_DUMPABLE:
        /* Block attempts to clear dumpable status.  Klee reads/writes
         * tracee memory via process_vm_readv/writev and PTRACE_PEEKDATA;
         * a non-dumpable process returns EIO on these calls, breaking
         * all path translation.  Programs like gpg-agent set dumpable=0
         * to protect cryptographic material, but klee already confines
         * them inside its sandbox.
         *
         * Rewrite arg from 0 (disable) to 1 (enable) so the kernel
         * executes a harmless no-op and returns success to the tracee. */
        if ((int)ev->args[1] == 0 && ic->backend == INTERCEPT_PTRACE) {
            KLEE_DEBUG("prctl(PR_SET_DUMPABLE, 0) -> 1 for pid=%d",
                       proc->real_pid);
            klee_regs_fetch(ic, proc);
            klee_regs_set_arg(proc, 1, 1);
            klee_regs_push(ic, proc);
        }
        break;

    case PR_SET_NAME:
    case PR_GET_DUMPABLE:
    case PR_SET_NO_NEW_PRIVS:
    case PR_GET_NO_NEW_PRIVS:
        /* Allow passthrough */
        break;

#ifdef PR_CAP_AMBIENT
    case PR_CAP_AMBIENT:
        /* Under user namespace simulation, void ambient cap operations */
        if (proc->sandbox && proc->sandbox->unshare_user) {
            KLEE_DEBUG("prctl(PR_CAP_AMBIENT) voided under user ns");
            return emulate(ev, 0);
        }
        break;
#endif

    default:
        /* Allow passthrough for unhandled prctl operations */
        break;
    }

    return 0;
}

int klee_enter_inotify_add_watch(KleeProcess *proc, KleeInterceptor *ic,
                                  KleeEvent *ev)
{
    if (ev->args[2] & IN_DONT_FOLLOW)
        return translate_path_arg_nofollow(proc, ic, ev, 1, -1);
    return translate_path_arg(proc, ic, ev, 1, -1);
}

/* ==================== Timestamps, xattrs, statfs, mount ids ==================== */

#ifndef FAN_MARK_DONT_FOLLOW
#define FAN_MARK_DONT_FOLLOW 0x00000004
#endif

/* A read-only check for "the file this descriptor refers to", used when a
 * path argument is NULL (utimensat(fd, NULL, ...) is futimens). */
static int check_readonly_fd(KleeProcess *proc, int fd, int syscall_nr)
{
    if (!proc->sandbox || !proc->sandbox->mount_table || !proc->fd_table)
        return 0;
    const char *vpath = klee_fd_table_get(proc->fd_table, fd);
    if (!vpath)
        return 0;
    if (klee_readonly_check_path(proc->sandbox->mount_table, vpath, syscall_nr))
        return -EROFS;
    return 0;
}

/* Translate a path argument and, for a modifying call, refuse it on a
 * read-only mount.  Handles a NULL path (operate on dirfd) too. */
static int enter_path_at(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev,
                         int path_idx, int dirfd_idx, bool nofollow, bool write)
{
    if (!ev->args[path_idx]) {
        if (write && dirfd_idx >= 0)
            return check_readonly_fd(proc, (int)ev->args[dirfd_idx],
                                     ev->syscall_nr);
        return 0;
    }
    int rc = translate_path_arg_for(proc, ic, ev, path_idx, dirfd_idx, nofollow,
                                    write ? KLEE_OV_SETATTR : KLEE_OV_READ);
    if (rc < 0) return rc;
    return write ? check_readonly(proc, ev->syscall_nr) : 0;
}

int klee_enter_utimensat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* utimensat(dirfd, path, times, flags) */
    return enter_path_at(proc, ic, ev, 1, 0,
                         (ev->args[3] & AT_SYMLINK_NOFOLLOW) != 0, true);
}

int klee_enter_utimes(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* utimes(path, times) / utime(path, buf) */
    return enter_path_at(proc, ic, ev, 0, -1, false, true);
}

int klee_enter_futimesat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* futimesat(dirfd, path, times) */
    return enter_path_at(proc, ic, ev, 1, 0, false, true);
}

int klee_enter_xattr_write(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* setxattr(path, ...), removexattr(path, ...) */
    return enter_path_at(proc, ic, ev, 0, -1, false, true);
}

int klee_enter_lxattr_write(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return enter_path_at(proc, ic, ev, 0, -1, true, true);
}

int klee_enter_xattr_read(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* getxattr(path, ...), listxattr(path, ...) */
    return enter_path_at(proc, ic, ev, 0, -1, false, false);
}

int klee_enter_lxattr_read(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return enter_path_at(proc, ic, ev, 0, -1, true, false);
}

int klee_enter_statfs(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* statfs(path, buf); i386 statfs64(path, sz, buf) lands here too */
    return enter_path_at(proc, ic, ev, 0, -1, false, false);
}

int klee_enter_fchmodat2(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* fchmodat2(dirfd, path, mode, flags) */
    return enter_path_at(proc, ic, ev, 1, 0,
                         (ev->args[3] & AT_SYMLINK_NOFOLLOW) != 0, true);
}

int klee_enter_fanotify_mark(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* fanotify_mark(fanotify_fd, flags, mask, dirfd, path) */
    return enter_path_at(proc, ic, ev, 4, 3,
                         (ev->args[1] & FAN_MARK_DONT_FOLLOW) != 0, false);
}

int klee_enter_name_to_handle_at(KleeProcess *proc, KleeInterceptor *ic,
                                 KleeEvent *ev)
{
    /* name_to_handle_at(dirfd, path, handle, mount_id, flags): the final
     * symlink is only followed with AT_SYMLINK_FOLLOW */
    return enter_path_at(proc, ic, ev, 1, 0,
                         (ev->args[4] & AT_SYMLINK_FOLLOW) == 0, false);
}

int klee_enter_open_tree(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* open_tree(dirfd, path, flags) */
    return enter_path_at(proc, ic, ev, 1, 0,
                         (ev->args[2] & AT_SYMLINK_NOFOLLOW) != 0, false);
}

int klee_enter_io_uring_setup(KleeProcess *proc, KleeInterceptor *ic,
                               KleeEvent *ev)
{
    (void)ic;
    (void)ev;
    KLEE_DEBUG("io_uring_setup blocked from pid=%d", proc->real_pid);
    return -ENOSYS;
}

/* ==================== Socket AF_UNIX Path Translation ==================== */

/* Return 1 for a staged filesystem address, 0 for an unchanged address. */
static int stage_unix_addr(KleeProcess *proc, KleeInterceptor *ic,
                            uint64_t addr, socklen_t size, bool creating,
                            uint64_t *scratch, socklen_t *staged_size)
{
    if (!proc->sandbox || !proc->sandbox->mount_table || !addr ||
        size <= offsetof(struct sockaddr_un, sun_path))
        return 0;

    const void *remote = (const void *)(uintptr_t)addr;
    sa_family_t family;
    if (klee_read_mem(ic, proc->real_pid, &family, remote, sizeof(family)) < 0 ||
        family != AF_UNIX)
        return 0;

    struct sockaddr_un sun = {0};
    if (size > sizeof(sun))
        return -EINVAL;
    if (klee_read_mem(ic, proc->real_pid, &sun, remote, size) < 0)
        return -EFAULT;
    if (!sun.sun_path[0])
        return 0;

    char guest[sizeof(sun.sun_path) + 1];
    memcpy(guest, sun.sun_path, sizeof(sun.sun_path));
    guest[sizeof(sun.sun_path)] = '\0';
    KleeResolveCtx ctx = {
        .mount_table = proc->sandbox->mount_table,
        .fd_table = proc->fd_table,
        .tracee_pid = proc->real_pid,
        .vcwd = proc->vcwd,
        .vroot = klee_mount_table_get_root(proc->sandbox->mount_table),
    };
    char resolved[PATH_MAX], host[PATH_MAX];
    int rc = creating ? klee_path_resolve_nofollow(&ctx, guest, resolved, AT_FDCWD) :
                        klee_path_resolve(&ctx, guest, resolved, AT_FDCWD);
    if (rc < 0)
        return rc;
    if (creating) {
        if (klee_mount_table_is_readonly(ctx.mount_table, resolved))
            return -EROFS;
        rc = klee_mount_table_translate_nofollow(ctx.mount_table, resolved,
                                                  host, sizeof(host), KLEE_OV_CREATE_EXCL);
        if (rc == -EEXIST)
            return -EADDRINUSE;
    } else {
        rc = klee_mount_table_translate_access(ctx.mount_table, resolved,
                                                host, sizeof(host), KLEE_OV_READ);
    }
    if (rc < 0)
        return rc;
    if (strcmp(guest, host) == 0)
        return 0;

    size_t len = strlen(host);
    if (len >= sizeof(sun.sun_path))
        return -ENAMETOOLONG;
    memcpy(sun.sun_path, host, len + 1);
    *staged_size = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + len + 1);
    rc = klee_scratch_write(proc, ic, &sun, *staged_size, scratch);
    return rc < 0 ? rc : 1;
}

static int translate_sockaddr(KleeProcess *proc, KleeInterceptor *ic,
                               const KleeEvent *ev, int index, bool creating)
{
    uint64_t addr;
    socklen_t size;
    int rc = stage_unix_addr(proc, ic, ev->args[index], (socklen_t)ev->args[index + 1],
                              creating, &addr, &size);
    if (rc <= 0)
        return rc;
    klee_regs_set_arg(proc, index, addr);
    klee_regs_set_arg(proc, index + 1, size);
    return klee_regs_push(ic, proc);
}

int klee_enter_bind(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_sockaddr(proc, ic, ev, 1, true);
}

int klee_enter_connect(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_sockaddr(proc, ic, ev, 1, false);
}

int klee_enter_sendto(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_sockaddr(proc, ic, ev, 4, false);
}

static int stage_msg_credentials(KleeProcess *proc, KleeInterceptor *ic,
                                  uint64_t address, size_t length, uint64_t *scratch)
{
    unsigned char data[4096];
    if (!address || !length || length > sizeof(data) ||
        (!proc->sandbox->unshare_pid && !virtual_ids(proc)))
        return 0;
    if (klee_read_mem(ic, proc->real_pid, data, (void *)(uintptr_t)address, length) < 0)
        return 0;

    const KleeIdState *ids = virtual_ids(proc) && !proc->skip_uid_virt ?
                             proc->id_state : NULL;
    pid_t vpid = klee_pid_map_r2v(proc->sandbox->pid_map, proc->real_tgid);
    bool changed = false;
    size_t offset = 0, begin, size;
    int level, type;
    while (klee_abi_cmsg_next(proc->abi, data, length, &offset, &level, &type,
                              &begin, &size)) {
        if (level != SOL_SOCKET || type != SCM_CREDENTIALS || size < sizeof(struct ucred))
            continue;
        struct ucred old, cred;
        memcpy(&old, data + begin, sizeof(old));
        cred = old;
        if (vpid > 0 && cred.pid == vpid)
            cred.pid = proc->real_tgid;
        if (ids && (cred.uid == ids->ruid || cred.uid == ids->euid || cred.uid == ids->suid))
            cred.uid = getuid();
        if (ids && (cred.gid == ids->rgid || cred.gid == ids->egid || cred.gid == ids->sgid))
            cred.gid = getgid();
        if (cred.pid != old.pid || cred.uid != old.uid || cred.gid != old.gid) {
            memcpy(data + begin, &cred, sizeof(cred));
            changed = true;
        }
    }
    if (!changed)
        return 0;
    int rc = klee_scratch_write(proc, ic, data, length, scratch);
    return rc < 0 ? rc : 1;
}

int klee_enter_sendmsg(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!proc->sandbox || !ev->args[1])
        return 0;

    bool compat = proc->abi == KLEE_ABI_I386;
    KleeAbiMsg msg;
    size_t msg_size = klee_abi_msg_size(proc->abi);
    if (klee_read_mem(ic, ev->pid, &msg, (const void *)(uintptr_t)ev->args[1], msg_size) < 0)
        return 0;

    uint64_t name = compat ? msg.compat.name : (uint64_t)(uintptr_t)msg.native.msg_name;
    socklen_t namelen = compat ? msg.compat.namelen : msg.native.msg_namelen;
    int name_result = stage_unix_addr(proc, ic, name, namelen, false, &name, &namelen);
    if (name_result < 0)
        return name_result;
    uint64_t control = compat ? msg.compat.control : (uint64_t)(uintptr_t)msg.native.msg_control;
    size_t controllen = compat ? msg.compat.controllen : msg.native.msg_controllen;
    int ctrl_result = stage_msg_credentials(proc, ic, control, controllen, &control);
    if (ctrl_result < 0)
        return ctrl_result;
    if (!name_result && !ctrl_result)
        return 0;

    if (compat) {
        msg.compat.name = (uint32_t)name;
        msg.compat.namelen = namelen;
        msg.compat.control = (uint32_t)control;
    } else {
        msg.native.msg_name = (void *)(uintptr_t)name;
        msg.native.msg_namelen = namelen;
        msg.native.msg_control = (void *)(uintptr_t)control;
    }
    uint64_t scratch;
    int rc = klee_scratch_write(proc, ic, &msg, msg_size, &scratch);
    if (rc < 0)
        return rc;
    klee_regs_set_arg(proc, 1, scratch);
    return klee_regs_push(ic, proc);
}
