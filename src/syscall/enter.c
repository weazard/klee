/*
 * Klee - Userspace bwrap translation layer
 * Syscall-enter handler implementations
 */
#include "syscall/enter.h"
#include "syscall/sysnum.h"
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
#include "compat/seccomp_filter.h"
#include "compat/nested.h"
#include "compat/zypak_compat.h"
#include "util/log.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <linux/openat2.h>
#include <sys/ioctl.h>
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

/* Point syscall argument arg_idx at a copy of proc->translated_path below
 * the tracee's stack.  The original buffer is left alone: the translated
 * path may be longer (e.g. symlink resolution: /lib/... → /usr/lib/...)
 * and would overflow it.  The exit stop restores the argument. */
static void stage_path_arg(KleeProcess *proc, KleeInterceptor *ic,
                           KleeEvent *ev, int arg_idx)
{
    proc->path_modified = true;
    if (ic->backend != INTERCEPT_PTRACE)
        return;

    /* Save original arg value for exit-time restore */
    proc->saved_args[arg_idx] = ev->args[arg_idx];

    /* Fetch current registers to get RSP */
    klee_regs_fetch(ic, proc);
    uint64_t rsp = klee_regs_get_sp(proc);

    /* Write translated path below the stack (past 128-byte red zone) */
    uint64_t scratch = rsp - 128 - PATH_MAX * (uint64_t)(proc->path_arg_count + 1);
    int rc = klee_write_string(ic, ev->pid, (void *)(uintptr_t)scratch,
                               proc->translated_path);
    if (rc < 0) {
        KLEE_DEBUG("failed to write translated path to scratch: %d", rc);
        return;
    }

    /* Update syscall argument register to point to scratch area */
    klee_regs_set_arg(proc, arg_idx, scratch);
    klee_regs_push(ic, proc);

    /* Track which arg was modified for exit-time restore */
    proc->path_arg_idx[proc->path_arg_count++] = arg_idx;
}

static int translate_path_arg_ex(KleeProcess *proc, KleeInterceptor *ic,
                                  KleeEvent *ev, int arg_idx, int dirfd_idx,
                                  bool nofollow, KleeOvAccess access)
{
    /* Describes this argument only, not an earlier one of the same call */
    proc->resolved_guest[0] = '\0';

    void *path_addr = (void *)(uintptr_t)ev->args[arg_idx];
    if (!path_addr)
        return 0;

    /* Read guest path */
    int rc = klee_read_path(ic, ev->pid, proc->saved_path,
                            sizeof(proc->saved_path), path_addr);
    if (rc < 0) {
        KLEE_DEBUG("failed to read path from tracee: %d", rc);
        return 0; /* pass through on failure */
    }

    /* Rewrite /proc/self and /proc/thread-self to use the tracee's real PID.
     * The kernel's /proc/self is a magic symlink to the CURRENT process's PID.
     * Since klee (not the tracee) performs path resolution, /proc/self would
     * resolve to klee's own PID, giving the tracee access to klee's /proc
     * entries instead of its own.  Always rewrite to /proc/<real_pid> so
     * the host kernel targets the correct process. */
    bool proc_self_rewritten = false;
    if (proc->sandbox) {
        pid_t target_pid = proc->real_pid;
        if (strncmp(proc->saved_path, "/proc/self/", 11) == 0) {
            char rewritten[PATH_MAX];
            snprintf(rewritten, sizeof(rewritten), "/proc/%d/%s",
                     target_pid, proc->saved_path + 11);
            snprintf(proc->saved_path, PATH_MAX, "%s", rewritten);
            proc_self_rewritten = true;
        } else if (strcmp(proc->saved_path, "/proc/self") == 0) {
            snprintf(proc->saved_path, PATH_MAX, "/proc/%d", target_pid);
            proc_self_rewritten = true;
        } else if (strncmp(proc->saved_path, "/proc/thread-self/", 18) == 0) {
            char rewritten[PATH_MAX];
            snprintf(rewritten, sizeof(rewritten), "/proc/%d/task/%d/%s",
                     target_pid, ev->pid, proc->saved_path + 18);
            snprintf(proc->saved_path, PATH_MAX, "%s", rewritten);
            proc_self_rewritten = true;
        } else if (strcmp(proc->saved_path, "/proc/thread-self") == 0) {
            snprintf(proc->saved_path, PATH_MAX, "/proc/%d/task/%d",
                     target_pid, ev->pid);
            proc_self_rewritten = true;
        }
    }

    /* Rewrite /proc/<vpid>/... to /proc/<real_pid>/... when the tracee
     * uses its virtual PID to access /proc entries.  This is necessary
     * when /proc is passthrough (no FUSE overlay) but getpid() returns
     * virtual PIDs — programs like `ps` use getpid() to construct
     * /proc/<pid>/... paths that don't exist on the host. */
    bool vpid_rewritten = false;
    pid_t proc_rewrite_real_pid = 0;  /* real PID in path after rewrite */
    if (!proc_self_rewritten && proc->sandbox &&
        proc->sandbox->unshare_pid && proc->sandbox->pid_map &&
        strncmp(proc->saved_path, "/proc/", 6) == 0) {
        const char *p = proc->saved_path + 6;
        if (*p >= '1' && *p <= '9') {
            pid_t vpid_val = 0;
            const char *q = p;
            while (*q >= '0' && *q <= '9') {
                vpid_val = vpid_val * 10 + (*q - '0');
                q++;
            }
            if (vpid_val > 0 && (*q == '/' || *q == '\0')) {
                pid_t real_pid = klee_pid_map_v2r(proc->sandbox->pid_map,
                                                   vpid_val);
                if (real_pid > 0 && real_pid != vpid_val) {
                    char rewritten[PATH_MAX];
                    snprintf(rewritten, sizeof(rewritten), "/proc/%d%s",
                             real_pid, q);
                    snprintf(proc->saved_path, PATH_MAX, "%s", rewritten);
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

    /* Also track the real PID for /proc/self rewrites */
    if (proc_self_rewritten)
        proc_rewrite_real_pid = proc->real_pid;

    /* Get dirfd for *at() variants */
    int dirfd = AT_FDCWD;
    if (dirfd_idx >= 0)
        dirfd = (int)ev->args[dirfd_idx];

    /* Build resolve context */
    KleeResolveCtx ctx = {
        .mount_table = proc->sandbox ? proc->sandbox->mount_table : NULL,
        .fd_table = proc->fd_table,
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
    if (nofollow)
        rc = klee_path_resolve_nofollow(&ctx, proc->saved_path,
                                         proc->resolved_guest, dirfd);
    else
        rc = klee_path_resolve(&ctx, proc->saved_path,
                                proc->resolved_guest, dirfd);
    if (rc < 0) {
        KLEE_DEBUG("path resolution failed for %s: %d", proc->saved_path, rc);
        proc->resolved_guest[0] = '\0';
        /* A symlink loop in the sandbox is one for the kernel too.  The raw
         * path must not go through: on the host it names something else. */
        if (rc == -ELOOP)
            return rc;
        return 0;
    }

    rc = klee_mount_table_translate_access(ctx.mount_table,
                                           proc->resolved_guest,
                                           proc->translated_path, PATH_MAX,
                                           access);
    if (rc < 0) {
        KLEE_DEBUG("path translation failed for %s: %d", proc->resolved_guest, rc);
        /* An overlay refusing the call (EEXIST, EXDEV, ENOTEMPTY...) is
         * the result; elsewhere the path goes to the kernel unchanged. */
        if (klee_mount_table_overlay_at(ctx.mount_table, proc->resolved_guest))
            return rc;
        return 0;
    }

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

    /* If /proc/self or /proc/<vpid> was rewritten, always force the write
     * even if the mount table didn't change the path further — the tracee's
     * memory still has the original path which the kernel can't resolve.
     * An unchanged path leaves path_modified alone: an earlier argument of
     * the same call may have been rewritten. */
    if (strcmp(proc->saved_path, proc->translated_path) == 0 &&
        !proc_self_rewritten && !vpid_rewritten)
        return 0;

    stage_path_arg(proc, ic, ev, arg_idx);

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
    /* creat(path, mode) is open(path, O_CREAT | O_WRONLY | O_TRUNC, mode) */
    int flags = O_CREAT | O_WRONLY | O_TRUNC;
    int rc = translate_path_arg_for(proc, ic, ev, 0, -1, false,
                                    open_access(flags));
    if (rc < 0) return rc;
    return check_readonly_open(proc, flags);
}

int klee_enter_openat2(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* openat2(dirfd, pathname, how, size) - how contains RESOLVE flags */

    /* Read struct open_how from tracee to get RESOLVE flags */
    struct open_how how;
    memset(&how, 0, sizeof(how));
    void *how_addr = (void *)(uintptr_t)ev->args[2];
    if (how_addr) {
        size_t how_size = (size_t)ev->args[3];
        if (how_size > sizeof(how))
            how_size = sizeof(how);
        klee_read_mem(ic, ev->pid, &how, how_addr, how_size);
    }

    /* Map kernel RESOLVE_* flags to Klee's internal resolve flags */
    unsigned int resolve_flags = 0;
    if (how.resolve & RESOLVE_IN_ROOT)
        resolve_flags |= KLEE_RESOLVE_IN_ROOT;
    if (how.resolve & RESOLVE_NO_SYMLINKS)
        resolve_flags |= KLEE_RESOLVE_NO_SYMLINKS;
    if (how.resolve & RESOLVE_BENEATH)
        resolve_flags |= KLEE_RESOLVE_BENEATH;
    if (how.resolve & RESOLVE_NO_XDEV)
        resolve_flags |= KLEE_RESOLVE_NO_XDEV;
    if (how.resolve & RESOLVE_NO_MAGICLINKS)
        resolve_flags |= KLEE_RESOLVE_NO_MAGICLINKS;

    /* Translate path with resolve flags applied */
    void *path_addr = (void *)(uintptr_t)ev->args[1];
    if (!path_addr)
        return 0;

    int rc = klee_read_path(ic, ev->pid, proc->saved_path,
                            sizeof(proc->saved_path), path_addr);
    if (rc < 0)
        return 0;

    int dirfd = (int)ev->args[0];

    /* For RESOLVE_BENEATH, resolve the dirfd to its path */
    const char *dirfd_path_str = NULL;
    if ((resolve_flags & KLEE_RESOLVE_BENEATH) && dirfd >= 0 &&
        dirfd != AT_FDCWD && proc->fd_table)
        dirfd_path_str = klee_fd_table_get(proc->fd_table, dirfd);

    KleeResolveCtx ctx = {
        .mount_table = proc->sandbox ? proc->sandbox->mount_table : NULL,
        .fd_table = proc->fd_table,
        .vcwd = proc->vcwd,
        .vroot = proc->sandbox ? klee_mount_table_get_root(proc->sandbox->mount_table) : "/",
        .dirfd_path = dirfd_path_str,
        .flags = resolve_flags,
    };

    if (!ctx.mount_table)
        return 0;

    int flags = (int)how.flags;
    rc = open_nofollow(flags)
         ? klee_path_resolve_nofollow(&ctx, proc->saved_path,
                                      proc->resolved_guest, dirfd)
         : klee_path_resolve(&ctx, proc->saved_path,
                             proc->resolved_guest, dirfd);
    if (rc < 0) {
        proc->resolved_guest[0] = '\0';
        return 0;
    }

    rc = klee_mount_table_translate_access(ctx.mount_table,
                                           proc->resolved_guest,
                                           proc->translated_path, PATH_MAX,
                                           open_access(flags));
    if (rc < 0)
        return klee_mount_table_overlay_at(ctx.mount_table,
                                           proc->resolved_guest) ? rc : 0;

    if (strcmp(proc->saved_path, proc->translated_path) != 0) {
        stage_path_arg(proc, ic, ev, 1);
        KLEE_TRACE("openat2: translated %s -> %s (resolve=0x%lx)",
                   proc->saved_path, proc->translated_path,
                   (unsigned long)how.resolve);
    }

    return check_readonly_open(proc, flags);
}

int klee_enter_stat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_path_arg(proc, ic, ev, 0, -1);
}

int klee_enter_lstat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_path_arg_nofollow(proc, ic, ev, 0, -1);
}

/* True when a path argument is "": with AT_EMPTY_PATH the call then works
 * on the descriptor itself and there is nothing to translate. */
static bool path_arg_empty(KleeInterceptor *ic, KleeEvent *ev, int idx)
{
    char first = 1;
    return ev->args[idx] &&
           klee_read_mem(ic, ev->pid, &first,
                         (const void *)(uintptr_t)ev->args[idx], 1) == 0 &&
           first == '\0';
}

int klee_enter_newfstatat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* newfstatat(dirfd, pathname, statbuf, flags)
     * AT_EMPTY_PATH and ""  -> fstat semantics on dirfd
     * AT_SYMLINK_NOFOLLOW -> lstat semantics
     * otherwise -> stat semantics */
    int flags = (int)ev->args[3];
    if ((flags & AT_EMPTY_PATH) && path_arg_empty(ic, ev, 1))
        return 0;
    if (flags & AT_SYMLINK_NOFOLLOW)
        return translate_path_arg_nofollow(proc, ic, ev, 1, 0);
    return translate_path_arg(proc, ic, ev, 1, 0);
}

int klee_enter_statx(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* statx(dirfd, pathname, flags, mask, statxbuf): flags as newfstatat */
    int flags = (int)ev->args[2];
    if ((flags & AT_EMPTY_PATH) && path_arg_empty(ic, ev, 1))
        return 0;
    if (flags & AT_SYMLINK_NOFOLLOW)
        return translate_path_arg_nofollow(proc, ic, ev, 1, 0);
    return translate_path_arg(proc, ic, ev, 1, 0);
}

int klee_enter_access(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_path_arg(proc, ic, ev, 0, -1);
}

int klee_enter_faccessat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_path_arg(proc, ic, ev, 1, 0);
}

/* Check if a guest path is /proc/self/exe or /proc/<pid>/exe.
 * These are magic kernel symlinks that should NOT be resolved through the
 * mount table.  When klee translates the path, it resolves /proc/self/exe
 * from klee's own perspective (producing klee's own binary path), which
 * then gets further translated through the mount table to a non-existent
 * runtime path.  Instead, let the kernel handle the readlink directly. */
static bool is_proc_exe_path(const char *path)
{
    if (strcmp(path, "/proc/self/exe") == 0)
        return true;
    if (strncmp(path, "/proc/", 6) != 0)
        return false;
    const char *p = path + 6;
    if (*p < '1' || *p > '9')
        return false;
    while (*p >= '0' && *p <= '9')
        p++;
    return strcmp(p, "/exe") == 0;
}

int klee_enter_readlink(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* Peek at the path to check for /proc/self/exe */
    void *path_addr = (void *)(uintptr_t)ev->args[0];
    if (path_addr) {
        char path[PATH_MAX];
        int rc = klee_read_path(ic, ev->pid, path, sizeof(path), path_addr);
        if (rc >= 0 && is_proc_exe_path(path)) {
            /* Save the path so the exit handler can detect this was a
             * /proc/exe readlink and rewrite the result with vexe. */
            snprintf(proc->saved_path, sizeof(proc->saved_path), "%s", path);
            return 0;  /* let kernel handle, exit handler rewrites */
        }
    }
    return translate_path_arg_nofollow(proc, ic, ev, 0, -1);
}

int klee_enter_readlinkat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* Peek at the path to check for /proc/self/exe */
    void *path_addr = (void *)(uintptr_t)ev->args[1];
    if (path_addr) {
        char path[PATH_MAX];
        int rc = klee_read_path(ic, ev->pid, path, sizeof(path), path_addr);
        if (rc >= 0 && is_proc_exe_path(path)) {
            snprintf(proc->saved_path, sizeof(proc->saved_path), "%s", path);
            return 0;
        }
    }
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

/* path_arg/argv_arg: 0/1 for execve, 1/2 for execveat. */
static int handle_exec_interp(KleeProcess *proc, KleeInterceptor *ic,
                                KleeEvent *ev, int path_arg, int argv_arg)
{
    KleeResolveCtx ctx = {
        .mount_table = proc->sandbox->mount_table,
        .fd_table = proc->fd_table,
        .vcwd = proc->vcwd,
        .vroot = klee_mount_table_get_root(proc->sandbox->mount_table),
        .flags = 0,
    };

    /* Track the host path of the file being executed */
    char current_host[PATH_MAX];
    snprintf(current_host, sizeof(current_host), "%s", proc->translated_path);

    /* If the target is /proc/<pid>/exe, resolve the symlink NOW.  After the
     * exec it points at whatever file we end up executing (a staged copy or
     * ld-linux), which is useless to re-exec. */
    if (strncmp(current_host, "/proc/", 6) == 0) {
        const char *p = current_host + 6;
        while (*p >= '0' && *p <= '9') p++;
        if (strcmp(p, "/exe") == 0) {
            char resolved[PATH_MAX];
            ssize_t len = readlink(current_host, resolved, sizeof(resolved) - 1);
            if (len > 0) {
                resolved[len] = '\0';
                KLEE_TRACE("exec: resolved %s -> %s", current_host, resolved);
                snprintf(current_host, sizeof(current_host), "%s", resolved);
            }
        }
    }

    /* Results of the chain resolution */
    char interp_host[PATH_MAX] = {0};   /* Shebang interpreter (host path) */
    char interp_guest[PATH_MAX] = {0};  /* Shebang interpreter (guest path) */
    char shebang_arg[PATH_MAX] = {0};   /* Shebang optional argument */
    char loader_host[PATH_MAX] = {0};   /* ELF PT_INTERP (host path) */
    char loader_guest[PATH_MAX] = {0};  /* ELF PT_INTERP (guest path) */

    /* Step 1: Resolve shebang chain (scripts pointing to scripts) */
    for (int depth = 0; depth < 5; depth++) {
        int fd = open(current_host, O_RDONLY | O_CLOEXEC);
        if (fd < 0) break;

        char buf[256];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n < 2) break;

        char sb_interp[PATH_MAX], sb_arg[PATH_MAX];
        if (parse_shebang(buf, n, sb_interp, sizeof(sb_interp),
                          sb_arg, sizeof(sb_arg)) != 0)
            break; /* Not a script — done with shebang chain */

        /* Translate the interpreter */
        char sb_translated[PATH_MAX];
        int rc = klee_path_guest_to_host(&ctx, sb_interp, sb_translated, AT_FDCWD);
        if (rc < 0) break;

        /* Only record the first (outermost) shebang level */
        if (depth == 0) {
            snprintf(interp_host, sizeof(interp_host), "%s", sb_translated);
            snprintf(interp_guest, sizeof(interp_guest), "%s", sb_interp);
            snprintf(shebang_arg, sizeof(shebang_arg), "%s", sb_arg);
            KLEE_TRACE("shebang: interpreter %s -> %s (script=%s)",
                       sb_interp, sb_translated, current_host);
        }

        snprintf(current_host, sizeof(current_host), "%s", sb_translated);
    }

    /* Step 2: Check the final binary's ELF PT_INTERP.  Only act when the
     * kernel's own lookup would load a different file than the one the
     * sandbox maps at that path; otherwise leave the exec alone. */
    KleeElfInfo elf;
    if (klee_elf_read_interp(current_host, &elf) == 0) {
        char pt_translated[PATH_MAX];
        int rc = klee_path_guest_to_host(&ctx, elf.interp, pt_translated, AT_FDCWD);
        if (rc == 0 && strcmp(elf.interp, pt_translated) != 0 &&
            !same_host_file(elf.interp, pt_translated)) {
            snprintf(loader_host, sizeof(loader_host), "%s", pt_translated);
            snprintf(loader_guest, sizeof(loader_guest), "%s", elf.interp);
            KLEE_TRACE("elf: PT_INTERP %s -> %s (binary=%s)",
                       elf.interp, pt_translated, current_host);
        }
    }

    bool need_loader = loader_host[0] != '\0';
    bool take_script = interp_host[0] != '\0';

    /* Step 3: If nothing needs rewriting, return */
    if (!need_loader && !take_script)
        return 0;

    /* Step 4: Choose the host path to exec.
     *
     * The filename must be a HOST path: the kernel opens it directly,
     * bypassing klee's mount table.  Its last component becomes the
     * process's comm, so exec through a symlink named like the program (or
     * the script) instead of naming a loader or interpreter directly.
     *
     * A binary that needs the sandbox's loader is run as a private copy
     * whose PT_INTERP points at that loader (exec_shim.c).  The kernel then
     * loads the loader itself and argv stays exactly as the caller built
     * it, so ps, pgrep, pidof and the program's own argv[0] all see the real
     * program.  If no copy can be made, fall back to executing ld.so with
     * the program as its first argument, which costs the loader prefix in
     * cmdline and the resolved path in argv[0]. */
    char name[NAME_MAX + 1];
    exec_comm_name(proc->saved_path, current_host, name, sizeof(name));

    KleeExecShim *shim = klee_exec_shim_get();
    char filename_host[PATH_MAX];
    bool via_ldso = false;

    if (need_loader) {
        if (klee_exec_shim_prepare(shim, current_host, &elf, loader_host, name,
                                   filename_host, sizeof(filename_host)) == 0) {
            KLEE_TRACE("exec shim: %s -> %s", current_host, filename_host);
        } else {
            via_ldso = true;
            if (klee_exec_shim_alias(shim, loader_host, name, filename_host,
                                     sizeof(filename_host)) != 0)
                snprintf(filename_host, sizeof(filename_host), "%s", loader_host);
        }
    } else if (klee_exec_shim_alias(shim, interp_host, name, filename_host,
                                    sizeof(filename_host)) != 0) {
        snprintf(filename_host, sizeof(filename_host), "%s", interp_host);
    }

    klee_regs_fetch(ic, proc);
    uint64_t rsp = klee_regs_get_sp(proc);

    uint64_t addr_filename = rsp - 128 - PATH_MAX;
    int rc = klee_write_string(ic, ev->pid, (void *)(uintptr_t)addr_filename,
                               filename_host);
    if (rc < 0) return 0;

    /* If path wasn't already modified by translate_path_arg, we need to
     * save the original path arg for exit-time restore (exec failure case)
     * and set up the register pointing to the scratch area. */
    if (!proc->path_modified) {
        proc->saved_args[path_arg] = ev->args[path_arg];
        proc->path_arg_idx[proc->path_arg_count++] = path_arg;
        proc->path_modified = true;
    }

    klee_regs_set_arg(proc, path_arg, addr_filename);
    klee_regs_push(ic, proc);

    /* A plain binary started through the shim keeps the caller's argv. */
    if (!via_ldso && !take_script) {
        KLEE_TRACE("exec: %s as %s, argv untouched", proc->resolved_guest,
                   filename_host);
        return 0;
    }

    /* Step 5: Rebuild argv.
     *
     * argv entries must be GUEST paths — the loader or interpreter runs
     * under klee's interception, so any paths it opens from argv will be
     * translated through the mount table.  Using host paths in argv would
     * cause double-translation (host path → mount table → nonexistent path).
     *
     *   argv = [loader_guest?] [interp_guest?] [shebang_arg?] script_guest [orig_argv1 ...]
     */

    /* Read original argv from tracee (4-byte pointers for a 32-bit caller) */
    size_t psz = klee_abi_ptr_size(proc->abi);
    uint64_t argv_base = ev->args[argv_arg];
    uint64_t argv_ptrs[256];
    int argc = 0;
    for (int i = 0; i < 255; i++) {
        uint64_t ptr;
        rc = klee_abi_read_ptr(ic, ev->pid, proc->abi,
                               argv_base + (uint64_t)i * psz, &ptr);
        if (rc < 0) return 0;
        argv_ptrs[i] = ptr;
        if (ptr == 0) break;
        argc++;
    }

    uint64_t scratch = rsp - 128 - PATH_MAX * 5;

    uint64_t addr_ldlinux = 0;
    uint64_t addr_interp = 0;
    uint64_t addr_shebang_arg = 0;
    uint64_t addr_script = 0;

    if (via_ldso) {
        addr_ldlinux = scratch;
        rc = klee_write_string(ic, ev->pid, (void *)(uintptr_t)addr_ldlinux, loader_guest);
        if (rc < 0) return 0;
        scratch -= PATH_MAX;
    }

    if (interp_guest[0]) {
        addr_interp = scratch;
        rc = klee_write_string(ic, ev->pid, (void *)(uintptr_t)addr_interp, interp_guest);
        if (rc < 0) return 0;
        scratch -= PATH_MAX;
    }

    if (shebang_arg[0]) {
        addr_shebang_arg = scratch;
        rc = klee_write_string(ic, ev->pid, (void *)(uintptr_t)addr_shebang_arg, shebang_arg);
        if (rc < 0) return 0;
        scratch -= PATH_MAX;
    }

    /* Script path: use the guest path so bash/python/etc. can open it
     * through klee's mount table translation. */
    addr_script = scratch;
    rc = klee_write_string(ic, ev->pid, (void *)(uintptr_t)addr_script,
                           proc->resolved_guest);
    if (rc < 0) return 0;
    scratch -= PATH_MAX;

    /* Build new argv array */
    uint64_t new_argv[260];
    int new_argc = 0;

    if (addr_ldlinux)
        new_argv[new_argc++] = addr_ldlinux;
    if (addr_interp)
        new_argv[new_argc++] = addr_interp;
    if (addr_shebang_arg)
        new_argv[new_argc++] = addr_shebang_arg;
    new_argv[new_argc++] = addr_script;

    /* Copy original argv[1..] */
    for (int i = 1; i < argc && new_argc < 259; i++)
        new_argv[new_argc++] = argv_ptrs[i];
    new_argv[new_argc] = 0; /* NULL terminator */

    /* Write new argv array to scratch area, in the caller's pointer size */
    uint64_t argv_addr = (scratch - (uint64_t)(new_argc + 1) * psz) & ~7ULL;
    if (psz == 4) {
        uint32_t new_argv32[260];
        for (int i = 0; i <= new_argc; i++)
            new_argv32[i] = (uint32_t)new_argv[i];
        rc = klee_write_mem(ic, ev->pid, (void *)(uintptr_t)argv_addr,
                            new_argv32, (size_t)(new_argc + 1) * sizeof(uint32_t));
    } else {
        rc = klee_write_mem(ic, ev->pid, (void *)(uintptr_t)argv_addr,
                            new_argv, (size_t)(new_argc + 1) * sizeof(uint64_t));
    }
    if (rc < 0) return 0;

    /* filename (rdi) = host path (already set above).
     * argv (rsi) = new array with guest paths. */
    klee_regs_set_arg(proc, argv_arg, argv_addr);
    klee_regs_push(ic, proc);

    /* Save original argv pointer for exit-time restore (exec failure case) */
    proc->saved_args[argv_arg] = ev->args[argv_arg];
    proc->path_arg_idx[proc->path_arg_count++] = argv_arg;

    KLEE_TRACE("exec interp: filename=%s argv=[%s%s%s %s ...]",
               filename_host,
               via_ldso ? loader_guest : "",
               via_ldso ? ", " : "",
               interp_guest[0] ? interp_guest : "",
               proc->resolved_guest);
    return 0;
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

    /* If the tracee exec'd /proc/self/exe (or /proc/<vpid>/exe),
     * translate_path_arg rewrote /proc/self → /proc/<real_pid>/exe.
     * But the kernel's /proc/<pid>/exe symlink points to ld-linux
     * (from PT_INTERP rewriting), not the actual program.  Chromium
     * re-execs via /proc/self/exe to spawn --type=utility children;
     * without this fix ld-linux receives --type=utility and errors.
     *
     * Substitute with vexe (the guest exe path) translated through
     * the mount table, and overwrite the scratch area that
     * translate_path_arg already allocated. */
    if (proc->vexe[0] && proc->sandbox && proc->sandbox->mount_table &&
        is_proc_exe_path(proc->saved_path) && proc->path_modified &&
        ic->backend == INTERCEPT_PTRACE) {

        KleeResolveCtx ctx = {
            .mount_table = proc->sandbox->mount_table,
            .fd_table = proc->fd_table,
            .vcwd = proc->vcwd,
            .vroot = klee_mount_table_get_root(proc->sandbox->mount_table),
            .flags = 0,
        };

        char host_path[PATH_MAX];
        rc = klee_path_guest_to_host(&ctx, proc->vexe, host_path, AT_FDCWD);
        if (rc >= 0) {
            KLEE_DEBUG("execve /proc/*/exe -> %s (host: %s)",
                       proc->vexe, host_path);
            snprintf(proc->saved_path, PATH_MAX, "%s", proc->vexe);
            snprintf(proc->resolved_guest, PATH_MAX, "%s", proc->vexe);
            snprintf(proc->translated_path, PATH_MAX, "%s", host_path);
            uint64_t arg0_scratch = klee_regs_get_arg(proc, 0);
            klee_write_string(ic, ev->pid,
                              (void *)(uintptr_t)arg0_scratch, host_path);
        }
    }

    /* Check for nested bwrap invocation — parse inline and rewrite */
    if (klee_nested_is_bwrap(proc->saved_path)) {
        if (klee_nested_handle_exec(proc, ic, ev) == 0)
            return 0; /* handler sets vexe and manipulates registers */
        /* Fall through on failure — let original exec proceed */
    }

    /* Check for flatpak-spawn (Zypak mimic strategy) — intercept and
     * run target command directly inside klee's process tree */
    if (proc->sandbox && proc->sandbox->zypak_detected &&
        klee_zypak_is_flatpak_spawn(proc->saved_path)) {
        if (klee_zypak_handle_flatpak_spawn(proc, ic, ev) == 0) {
            ev->args[1] = klee_regs_get_arg(proc, 1);
            /* Fall through to handle_exec_interp for PT_INTERP translation */
        }
        /* Fall through on failure — let original exec proceed */
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
        uint64_t argv_addr = ev->args[1];
        uint64_t argv1_ptr = 0;
        int csrc = klee_read_mem(ic, ev->pid, &argv1_ptr,
                            (const void *)(uintptr_t)(argv_addr + 8),
                            sizeof(argv1_ptr));
        if (csrc == 0 && argv1_ptr != 0) {
            char target_guest[PATH_MAX];
            csrc = klee_read_string(ic, ev->pid, target_guest,
                                    sizeof(target_guest),
                                    (const void *)(uintptr_t)argv1_ptr);
            if (csrc >= 0 && target_guest[0]) {
                /* Translate target through mount table */
                char target_host[PATH_MAX];
                snprintf(target_host, PATH_MAX, "%s", target_guest);
                if (proc->sandbox->mount_table) {
                    KleeResolveCtx ctx = {
                        .mount_table = proc->sandbox->mount_table,
                        .fd_table = proc->fd_table,
                        .vcwd = proc->vcwd,
                        .vroot = klee_mount_table_get_root(
                                     proc->sandbox->mount_table),
                        .flags = 0,
                    };
                    if (klee_path_guest_to_host(&ctx, target_guest,
                                                target_host, AT_FDCWD) < 0)
                        snprintf(target_host, PATH_MAX, "%s", target_guest);
                }

                KLEE_INFO("zypak: chrome-sandbox bypass: %s -> %s",
                          target_guest, target_host);

                /* Overwrite exec path with target host path */
                klee_regs_fetch(ic, proc);
                if (proc->path_modified) {
                    uint64_t arg0_scratch = klee_regs_get_arg(proc, 0);
                    klee_write_string(ic, ev->pid,
                                      (void *)(uintptr_t)arg0_scratch,
                                      target_host);
                } else {
                    uint64_t rsp = klee_regs_get_sp(proc);
                    uint64_t scratch = rsp - 128 - PATH_MAX;
                    klee_write_string(ic, ev->pid,
                                      (void *)(uintptr_t)scratch,
                                      target_host);
                    klee_regs_set_arg(proc, 0, scratch);
                    proc->saved_args[0] = ev->args[0];
                    proc->path_arg_idx[proc->path_arg_count++] = 0;
                    proc->path_modified = true;
                }

                /* Shift argv to skip chrome-sandbox entry:
                 * [chrome-sandbox, target, args...] → [target, args...] */
                klee_regs_set_arg(proc, 1, argv_addr + 8);
                klee_regs_push(ic, proc);
                ev->args[1] = argv_addr + 8;

                /* Update proc paths for downstream handlers */
                snprintf(proc->saved_path, PATH_MAX, "%s", target_guest);
                snprintf(proc->resolved_guest, PATH_MAX, "%s", target_guest);
                snprintf(proc->translated_path, PATH_MAX, "%s", target_host);

                /* Nullify CHROME_DEVEL_SANDBOX in tracee envp */
                klee_zypak_nullify_sandbox_env(ic, ev->pid, ev->args[2]);
            }
        }
        /* Fall through to shebang/interp handling for the target binary */
    }

    /* Handle shebang scripts and ELF PT_INTERP: detect interpreters that
     * the kernel would resolve on the host filesystem and rewrite execve
     * to use the correctly translated versions.
     *
     * Note: we intentionally do NOT gate on proc->path_modified.  A tracee
     * can exec a host filesystem path (e.g. from "realpath $0" in a script
     * where $0 leaked the host path via shebang rewriting).  In that case
     * the mount table won't change the path, but the binary's PT_INTERP
     * may still need translation to avoid an ABI mismatch between the
     * host's ld-linux and the runtime's libc. */
    if (proc->sandbox && proc->sandbox->mount_table &&
        ic->backend == INTERCEPT_PTRACE) {
        handle_exec_interp(proc, ic, ev, 0, 1);
    }

    /* Save exe path for vexe update on exit */
    snprintf(proc->vexe, PATH_MAX, "%s", proc->saved_path);

    /* Per-process UID virtualization for Zypak: on exec, determine whether
     * this process should skip UID virtualization.  Processes with --no-sandbox
     * (Chrome main, GPU) skip it so getuid() returns real uid=0 for D-Bus
     * AUTH EXTERNAL.  Processes without it (zygote, utility) keep virtual
     * uid to pass Chrome's root check. */
    if (proc->sandbox && proc->sandbox->zypak_detected) {
        proc->skip_uid_virt = tracee_argv_has_no_sandbox(ic, ev->pid, proc->abi, ev->args[1]);
        KLEE_DEBUG("execve pid=%d %s: skip_uid_virt=%d",
                   proc->real_pid, proc->saved_path, proc->skip_uid_virt);
    }

    return 0;
}

int klee_enter_execveat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* execveat(dirfd, pathname, argv, envp, flags) */
    int rc = translate_path_arg(proc, ic, ev, 1, 0);
    if (rc < 0) return rc;

    char guest_exe[PATH_MAX];
    snprintf(guest_exe, sizeof(guest_exe), "%s", proc->saved_path);

    if ((ev->args[4] & AT_EMPTY_PATH) && proc->saved_path[0] == '\0') {
        /* fexecve(): the program is dirfd itself.  Its host file is
         * reachable through /proc, which works for reading the ELF, for
         * staging a copy and, if nothing needs rewriting, for the exec. */
        int fd = (int)ev->args[0];
        snprintf(proc->translated_path, PATH_MAX, "/proc/%d/fd/%d",
                 proc->real_pid, fd);
        const char *vpath = proc->fd_table ? klee_fd_table_get(proc->fd_table, fd) : NULL;
        snprintf(proc->resolved_guest, PATH_MAX, "%s", vpath ? vpath : "");
        snprintf(guest_exe, sizeof(guest_exe), "%s", vpath ? vpath : "");
    }

    /* Interpreter/loader handling as for execve.  A rewritten filename is
     * absolute, so the kernel ignores dirfd and AT_EMPTY_PATH for it. */
    if (proc->sandbox && proc->sandbox->mount_table &&
        ic->backend == INTERCEPT_PTRACE &&
        (proc->translated_path[0] == '/'))
        handle_exec_interp(proc, ic, ev, 1, 2);

    snprintf(proc->vexe, PATH_MAX, "%s", guest_exe);

    if (proc->sandbox && proc->sandbox->zypak_detected)
        proc->skip_uid_virt = tracee_argv_has_no_sandbox(ic, ev->pid, proc->abi, ev->args[2]);

    return 0;
}

/* The overlay the last translated path is in, or NULL */
static KleeOverlayMount *overlay_of_path(KleeProcess *proc)
{
    if (!proc->resolved_guest[0] || !proc->sandbox ||
        !proc->sandbox->mount_table)
        return NULL;
    return klee_mount_table_overlay_at(proc->sandbox->mount_table,
                                       proc->resolved_guest);
}

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif

/* rename, renameat, renameat2.  Moving a name into or out of an overlay
 * crosses a mount, which the kernel refuses with EXDEV. */
static int enter_rename(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev,
                        int old_idx, int olddir_idx, int new_idx,
                        int newdir_idx, unsigned int flags)
{
    int rc = translate_path_arg_for(proc, ic, ev, old_idx, olddir_idx, true,
                                    KLEE_OV_RENAME_SRC);
    if (rc < 0) return rc;
    rc = check_readonly(proc, ev->syscall_nr);
    if (rc < 0) return rc;
    KleeOverlayMount *ov = overlay_of_path(proc);

    /* An overlay prepares the destination for what is moved there.  With
     * no source the kernel fails the call and nothing may be prepared. */
    struct stat st;
    KleeOvAccess dst = KLEE_OV_UNUSED;
    if (proc->resolved_guest[0] && lstat(proc->translated_path, &st) == 0)
        dst = (flags & RENAME_EXCHANGE) ? KLEE_OV_RENAME_SRC
            : (flags & RENAME_NOREPLACE) ? KLEE_OV_CREATE_EXCL
            : S_ISDIR(st.st_mode) ? KLEE_OV_RENAME_DST_DIR
            : KLEE_OV_RENAME_DST;

    rc = translate_path_arg_for(proc, ic, ev, new_idx, newdir_idx, true, dst);
    if (rc < 0) return rc;
    if (overlay_of_path(proc) != ov)
        return -EXDEV;
    return check_readonly(proc, ev->syscall_nr);
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

int klee_enter_rmdir(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_for(proc, ic, ev, 0, -1, true, KLEE_OV_RMDIR);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_unlink(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_for(proc, ic, ev, 0, -1, true, KLEE_OV_UNLINK);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_unlinkat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* unlinkat(dirfd, path, flags) */
    KleeOvAccess access = (ev->args[2] & AT_REMOVEDIR) ? KLEE_OV_RMDIR
                                                       : KLEE_OV_UNLINK;
    int rc = translate_path_arg_for(proc, ic, ev, 1, 0, true, access);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

/* /proc/<pid>/fd/<n>, also below task/<tid>: a magic link to an open file */
static bool is_proc_fd_link(const char *path)
{
    if (strncmp(path, "/proc/", 6) != 0)
        return false;
    const char *p = path + 6;
    for (int round = 0; round < 2; round++) {
        if (*p < '0' || *p > '9')
            return false;
        while (*p >= '0' && *p <= '9')
            p++;
        if (strncmp(p, "/task/", 6) != 0)
            break;
        p += 6;
    }
    if (strncmp(p, "/fd/", 4) != 0)
        return false;
    p += 4;
    if (*p < '0' || *p > '9')
        return false;
    while (*p >= '0' && *p <= '9')
        p++;
    return *p == '\0';
}

/* Linking the file behind a descriptor (proc_link names it) to a name in
 * dst_ov.  Only a file of that overlay's upper layer may get a name there:
 * a name for a file of a lower layer would be a way to write to it, and
 * anything else is on another mount. */
static int check_link_by_fd(KleeProcess *proc, const char *proc_link,
                            KleeOverlayMount *dst_ov)
{
    char host[PATH_MAX];
    KleeOverlayMount *src_ov = NULL;
    KleeOvHostLayer layer = KLEE_OV_HOST_NONE;
    ssize_t len = readlink(proc_link, host, sizeof(host) - 1);
    if (len > 0) {
        host[len] = '\0';
        layer = klee_mount_table_host_layer(proc->sandbox->mount_table, host,
                                            &src_ov);
    }
    if (layer == KLEE_OV_HOST_LOWER)
        return -EXDEV;
    if (layer == KLEE_OV_HOST_UPPER ? src_ov != dst_ov : dst_ov != NULL)
        return -EXDEV;
    return 0;
}

/* link, linkat.  An overlay copies the source up, so the new name never
 * shares an inode with a lower layer. */
static int enter_link(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev,
                      int old_idx, int olddir_idx, int new_idx,
                      int newdir_idx, int flags)
{
    char fd_link[64] = "";       /* the source is an open file */
    KleeOverlayMount *src_ov = NULL;
    bool src_gone = false, src_dir = false;
    struct stat st;

    if (olddir_idx >= 0 && (flags & AT_EMPTY_PATH) &&
        path_arg_empty(ic, ev, old_idx)) {
        /* With AT_EMPTY_PATH and "" the source is olddirfd itself */
        snprintf(fd_link, sizeof(fd_link), "/proc/%d/fd/%d", (int)ev->pid,
                 (int)ev->args[olddir_idx]);
    } else {
        int rc = translate_path_arg_for(proc, ic, ev, old_idx, olddir_idx,
                                        !(flags & AT_SYMLINK_FOLLOW),
                                        KLEE_OV_LINK_SRC);
        if (rc < 0) return rc;
        src_ov = overlay_of_path(proc);
        if ((flags & AT_SYMLINK_FOLLOW) && is_proc_fd_link(proc->resolved_guest))
            snprintf(fd_link, sizeof(fd_link), "%.63s", proc->resolved_guest);
        else if (proc->resolved_guest[0] &&
                 lstat(proc->translated_path, &st) < 0)
            src_gone = true;
        else if (proc->resolved_guest[0])
            src_dir = S_ISDIR(st.st_mode);
    }

    /* Without a source the kernel fails the call: nothing is prepared */
    int rc = translate_path_arg_for(proc, ic, ev, new_idx, newdir_idx, true,
                                    src_gone ? KLEE_OV_UNUSED
                                             : KLEE_OV_CREATE_EXCL);
    if (rc < 0) return rc;
    if (src_gone)
        return 0;
    /* An existing name is EEXIST, which the kernel reports before the rest */
    if (proc->resolved_guest[0] && lstat(proc->translated_path, &st) == 0)
        return 0;

    KleeOverlayMount *dst_ov = overlay_of_path(proc);
    if (fd_link[0] && proc->sandbox && proc->sandbox->mount_table)
        rc = check_link_by_fd(proc, fd_link, dst_ov);
    else
        rc = src_ov != dst_ov ? -EXDEV : 0;
    if (rc < 0) return rc;
    /* The layers of an overlay may be different file systems, for which
     * the kernel would answer EXDEV before it refuses a directory */
    if (src_dir && dst_ov)
        return -EPERM;
    return check_readonly(proc, ev->syscall_nr);
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
            ic->write_mem(ic, ev->pid, pgid_ptr, &real_pgid, sizeof(real_pgid));
            /* Save original vpgid so exit handler can restore it */
            proc->saved_args[2] = (uint64_t)(uintptr_t)vpgid;
        }
    }

    return 0;
}

/* ==================== UID/GID Enter Handlers ==================== */

int klee_enter_setuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user)
        return 0;
    return klee_user_ns_handle_setuid(proc->id_state, (uid_t)ev->args[0]);
}

int klee_enter_setgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user)
        return 0;
    return klee_user_ns_handle_setgid(proc->id_state, (gid_t)ev->args[0]);
}

int klee_enter_setreuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user)
        return 0;
    return klee_user_ns_handle_setreuid(proc->id_state,
                                         (uid_t)ev->args[0], (uid_t)ev->args[1]);
}

int klee_enter_setregid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user)
        return 0;
    return klee_user_ns_handle_setregid(proc->id_state,
                                         (gid_t)ev->args[0], (gid_t)ev->args[1]);
}

int klee_enter_setresuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user)
        return 0;
    return klee_user_ns_handle_setresuid(proc->id_state,
                                          (uid_t)ev->args[0], (uid_t)ev->args[1],
                                          (uid_t)ev->args[2]);
}

int klee_enter_setresgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user)
        return 0;
    return klee_user_ns_handle_setresgid(proc->id_state,
                                          (gid_t)ev->args[0], (gid_t)ev->args[1],
                                          (gid_t)ev->args[2]);
}

int klee_enter_setfsuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user)
        return 0;
    return klee_user_ns_handle_setfsuid(proc->id_state, (uid_t)ev->args[0]);
}

int klee_enter_setfsgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user)
        return 0;
    return klee_user_ns_handle_setfsgid(proc->id_state, (gid_t)ev->args[0]);
}

int klee_enter_setgroups(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic; (void)ev;
    if (!proc->sandbox || !proc->sandbox->unshare_user)
        return 0;
    /* Void the syscall and return success */
    return 0;
}

/* ==================== UTS / IPC Enter Handlers ==================== */

int klee_enter_sethostname(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!proc->sandbox || !proc->sandbox->unshare_uts)
        return 0;

    char hostname[256];
    size_t len = (size_t)ev->args[1];
    if (len >= sizeof(hostname))
        return -EINVAL;

    int rc = klee_read_mem(ic, ev->pid, hostname, (void *)(uintptr_t)ev->args[0], len);
    if (rc < 0)
        return 0;
    hostname[len] = '\0';

    klee_uts_set_hostname(proc->sandbox->hostname ? NULL : proc->sandbox, hostname);
    /* Void the real syscall, return success */
    return -0;
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
            return -0;
        }
        break;
    }

    case PR_CAPBSET_DROP:
        /* Under user namespace simulation, pretend capability drop succeeds.
         * Real bwrap does this via kernel namespace; we void the syscall. */
        if (proc->sandbox && proc->sandbox->unshare_user) {
            KLEE_DEBUG("prctl(PR_CAPBSET_DROP, %lu) voided under user ns",
                       (unsigned long)ev->args[1]);
            return -0;
        }
        break;

    case PR_SET_KEEPCAPS:
        /* Under user namespace simulation, pretend success.
         * Real bwrap uses this before dropping privileges. */
        if (proc->sandbox && proc->sandbox->unshare_user) {
            KLEE_DEBUG("prctl(PR_SET_KEEPCAPS, %lu) voided under user ns",
                       (unsigned long)ev->args[1]);
            return -0;
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
            return -0;
        }
        break;
#endif

    default:
        /* Allow passthrough for unhandled prctl operations */
        break;
    }

    return 0;
}

int klee_enter_seccomp(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    unsigned int operation = (unsigned int)ev->args[0];

    if (operation == SECCOMP_SET_MODE_FILTER) {
        uint64_t fprog_addr = ev->args[2];

        if (fprog_addr) {
            uint16_t len = 0;
            uint64_t filter = 0;
            int rc = klee_abi_read_fprog(ic, ev->pid, proc->abi, fprog_addr,
                                         &len, &filter);
            if (rc == 0 && filter && len > 0) {
                /* The rewriter stages its filter below the stack: use the
                 * stack pointer of this stop, not a stale one. */
                klee_regs_fetch(ic, proc);
                klee_compat_handle_seccomp_filter(ic, ev->pid, proc->abi,
                                                   len, filter, fprog_addr,
                                                   klee_regs_get_sp(proc));
            }
        }
        return 0;
    }
    return 0;
}

int klee_enter_inotify_add_watch(KleeProcess *proc, KleeInterceptor *ic,
                                  KleeEvent *ev)
{
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

/*
 * Helper: translate the sun_path inside a sockaddr_un for bind/connect.
 *
 * For AF_UNIX sockets, the path embedded in the sockaddr_un goes through
 * the same mount table translation as regular filesystem paths.  Without
 * this, a tracee that mkdir'd "/tmp/foo" (translated to e.g.
 * "/tmp/klee-PID-1/foo") would then bind() to "/tmp/foo/sock" which the
 * kernel sees as a non-existent directory — ENOENT.
 *
 * Layout: bind/connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
 *         args[0]=sockfd, args[1]=addr, args[2]=addrlen
 */
static int translate_sockaddr_arg(KleeProcess *proc, KleeInterceptor *ic,
                                   KleeEvent *ev, KleeOvAccess access)
{
    if (!proc->sandbox || !proc->sandbox->mount_table)
        return 0;

    void *addr_ptr = (void *)(uintptr_t)ev->args[1];
    socklen_t addrlen = (socklen_t)ev->args[2];

    if (!addr_ptr || addrlen < sizeof(sa_family_t))
        return 0;

    /* Read sa_family to check if this is AF_UNIX */
    sa_family_t family;
    int rc = klee_read_mem(ic, ev->pid, &family, addr_ptr, sizeof(family));
    if (rc < 0 || family != AF_UNIX)
        return 0;

    /* Read full sockaddr_un from tracee */
    struct sockaddr_un sun;
    size_t to_read = addrlen;
    if (to_read > sizeof(sun))
        to_read = sizeof(sun);
    memset(&sun, 0, sizeof(sun));
    rc = klee_read_mem(ic, ev->pid, &sun, addr_ptr, to_read);
    if (rc < 0)
        return 0;

    /* Skip abstract sockets (sun_path[0] == '\0') — they live in a
     * kernel namespace, not the filesystem */
    if (sun.sun_path[0] == '\0') {
        size_t abs_off = offsetof(struct sockaddr_un, sun_path);
        size_t abs_len = to_read > abs_off + 1 ? to_read - abs_off - 1 : 0;
        if (abs_len > 0) {
            char abs_name[108];
            size_t n = abs_len < sizeof(abs_name)-1 ? abs_len : sizeof(abs_name)-1;
            memcpy(abs_name, sun.sun_path + 1, n);
            abs_name[n] = '\0';
            KLEE_TRACE("socket: abstract @%s (pid=%d)", abs_name, ev->pid);
        }
        return 0;
    }

    /* Ensure null termination for path extraction.
     * addrlen typically includes the trailing NUL in the count, but some
     * callers pass the exact strlen (no NUL).  We already memset sun to 0,
     * so the only risk is addrlen covering the full sun_path with no room
     * for a NUL — clamp in that case. */
    size_t path_offset = offsetof(struct sockaddr_un, sun_path);
    size_t path_max = to_read > path_offset ? to_read - path_offset : 0;
    if (path_max == 0)
        return 0;
    if (path_max >= sizeof(sun.sun_path))
        sun.sun_path[sizeof(sun.sun_path) - 1] = '\0';

    /* Save original path */
    snprintf(proc->saved_path, sizeof(proc->saved_path), "%s", sun.sun_path);

    /* Translate through mount table */
    KleeResolveCtx ctx = {
        .mount_table = proc->sandbox->mount_table,
        .fd_table = proc->fd_table,
        .vcwd = proc->vcwd,
        .vroot = klee_mount_table_get_root(proc->sandbox->mount_table),
        .flags = 0,
        .ov_access = access,
    };

    rc = klee_path_guest_to_host(&ctx, proc->saved_path,
                                  proc->translated_path, AT_FDCWD);
    if (rc < 0)
        return 0;

    if (strcmp(proc->saved_path, proc->translated_path) == 0) {
        KLEE_TRACE("socket: unchanged %s (pid=%d)", proc->saved_path, ev->pid);
        proc->path_modified = false;
        return 0;
    }

    /* Check translated path fits in sun_path (108 bytes) */
    if (strlen(proc->translated_path) >= sizeof(sun.sun_path))
        return 0;

    /* Build new sockaddr_un with translated path */
    struct sockaddr_un new_sun;
    memset(&new_sun, 0, sizeof(new_sun));
    new_sun.sun_family = AF_UNIX;
    strncpy(new_sun.sun_path, proc->translated_path,
            sizeof(new_sun.sun_path) - 1);
    socklen_t new_addrlen = (socklen_t)(path_offset +
                             strlen(proc->translated_path) + 1);

    proc->path_modified = true;

    if (ic->backend == INTERCEPT_PTRACE) {
        /* Save original arg values for exit-time restore */
        proc->saved_args[1] = ev->args[1];
        proc->saved_args[2] = ev->args[2];

        klee_regs_fetch(ic, proc);
        uint64_t rsp = klee_regs_get_sp(proc);

        /* Write new sockaddr_un below the stack (past 128-byte red zone) */
        uint64_t scratch = rsp - 128 - PATH_MAX;
        rc = klee_write_mem(ic, ev->pid, (void *)(uintptr_t)scratch,
                            &new_sun, new_addrlen);
        if (rc < 0) {
            proc->path_modified = false;
            return 0;
        }

        /* Update arg1 (addr) and arg2 (addrlen) */
        klee_regs_set_arg(proc, 1, scratch);
        klee_regs_set_arg(proc, 2, (uint64_t)new_addrlen);
        klee_regs_push(ic, proc);

        /* Track both modified args for exit-time restore */
        proc->path_arg_idx[proc->path_arg_count++] = 1;
        proc->path_arg_idx[proc->path_arg_count++] = 2;
    }

    KLEE_TRACE("socket: translated %s -> %s",
               proc->saved_path, proc->translated_path);
    return 0;
}

int klee_enter_bind(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* bind() creates the socket file */
    return translate_sockaddr_arg(proc, ic, ev, KLEE_OV_CREATE);
}

int klee_enter_connect(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_sockaddr_arg(proc, ic, ev, KLEE_OV_READ);
}

/* ==================== Socket Credential Translation ==================== */

/*
 * Intercept sendmsg() to fix SCM_CREDENTIALS ancillary data.
 *
 * When klee virtualizes PID/UID/GID (unshare_pid / unshare_user), the
 * tracee's getpid/getuid/getgid return virtual values.  Libraries like
 * GLib cache these and include them in SCM_CREDENTIALS when authenticating
 * D-Bus connections.  The kernel rejects credentials that don't match
 * the caller's real identity → EPERM.
 *
 * Fix: read the msghdr control data, find SCM_CREDENTIALS entries, and
 * rewrite virtual PID/UID/GID to real values before the kernel checks.
 */
int klee_enter_sendmsg(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!proc->sandbox ||
        (!proc->sandbox->unshare_pid && !proc->sandbox->unshare_user))
        return 0;

    /* sendmsg(int sockfd, const struct msghdr *msg, int flags) */
    if (!ev->args[1])
        return 0;

    uint64_t ctrl_addr = 0;
    size_t ctrllen = 0;
    if (klee_abi_read_msg_control(ic, ev->pid, proc->abi, ev->args[1],
                                  &ctrl_addr, &ctrllen) < 0)
        return 0;
    if (!ctrl_addr || ctrllen == 0 || ctrllen > 4096)
        return 0;

    uint8_t ctrl_buf[4096];
    int rc = klee_read_mem(ic, ev->pid, ctrl_buf,
                           (const void *)(uintptr_t)ctrl_addr, ctrllen);
    if (rc < 0)
        return 0;

    /* Walk cmsghdr entries (in the tracee's layout) looking for SCM_CREDENTIALS */
    bool modified = false;
    size_t off = 0, data_off, data_len;
    int level, type;
    while (klee_abi_cmsg_next(proc->abi, ctrl_buf, ctrllen, &off,
                              &level, &type, &data_off, &data_len)) {
        if (level != SOL_SOCKET || type != SCM_CREDENTIALS ||
            data_len < sizeof(struct ucred))
            continue;
        struct ucred cred;
        memcpy(&cred, ctrl_buf + data_off, sizeof(cred));

        /* Translate credentials: the guest process sends its virtual
         * pid/uid/gid, but the kernel validates against real values.
         * Rewrite to the real pid and the klee host process's actual
         * uid/gid (what the kernel expects); the virtual uid/gid are
         * purely for in-sandbox presentation. */
        uid_t host_uid = getuid();
        gid_t host_gid = getgid();

        KLEE_TRACE("sendmsg SCM_CREDENTIALS: pid=%d uid=%d gid=%d -> "
                   "pid=%d uid=%d gid=%d",
                   cred.pid, cred.uid, cred.gid,
                   proc->real_pid, host_uid, host_gid);

        cred.pid = proc->real_pid;
        cred.uid = host_uid;
        cred.gid = host_gid;
        memcpy(ctrl_buf + data_off, &cred, sizeof(cred));
        modified = true;
    }

    if (!modified)
        return 0;

    /* Write modified control data back to tracee (same address, same size) */
    rc = klee_write_mem(ic, ev->pid, (void *)(uintptr_t)ctrl_addr, ctrl_buf,
                        ctrllen);
    if (rc < 0)
        KLEE_DEBUG("sendmsg: failed to write back SCM_CREDENTIALS: %d", rc);

    return 0;
}
