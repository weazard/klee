/*
 * Klee - Userspace bwrap translation layer
 * Syscall-enter handler implementations
 */
#include "syscall/enter.h"
#include "syscall/sysnum.h"
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
#include "util/log.h"

#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/seccomp.h>
#include <linux/openat2.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
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
                                 bool nofollow);

static int translate_path_arg(KleeProcess *proc, KleeInterceptor *ic,
                               KleeEvent *ev, int arg_idx, int dirfd_idx)
{
    return translate_path_arg_ex(proc, ic, ev, arg_idx, dirfd_idx, false);
}

/* Like translate_path_arg but does not follow the final symlink.
 * Used by lstat, unlink, readlink, symlink(linkpath), rename, rmdir, etc. */
static int translate_path_arg_nofollow(KleeProcess *proc, KleeInterceptor *ic,
                                        KleeEvent *ev, int arg_idx,
                                        int dirfd_idx)
{
    return translate_path_arg_ex(proc, ic, ev, arg_idx, dirfd_idx, true);
}

static int translate_path_arg_ex(KleeProcess *proc, KleeInterceptor *ic,
                                  KleeEvent *ev, int arg_idx, int dirfd_idx,
                                  bool nofollow)
{
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
        return 0;
    }

    rc = klee_mount_table_translate(ctx.mount_table, proc->resolved_guest,
                                     proc->translated_path, PATH_MAX);
    if (rc < 0) {
        KLEE_DEBUG("path translation failed for %s: %d", proc->resolved_guest, rc);
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
     * memory still has the original path which the kernel can't resolve. */
    if (strcmp(proc->saved_path, proc->translated_path) == 0 &&
        !proc_self_rewritten && !vpid_rewritten) {
        proc->path_modified = false;
        return 0;
    }

    proc->path_modified = true;

    /* Write translated path to tracee via stack scratch area.
     * We must NOT write to the original buffer because the translated
     * path may be longer (e.g. symlink resolution: /lib/... → /usr/lib/...),
     * which would overflow the buffer and corrupt adjacent heap memory.
     * Instead, write to a scratch area below the tracee's stack pointer
     * and update the syscall argument register to point there. */
    if (ic->backend == INTERCEPT_PTRACE) {
        /* Save original arg value for exit-time restore */
        proc->saved_args[arg_idx] = ev->args[arg_idx];

        /* Fetch current registers to get RSP */
        klee_regs_fetch(ic, proc);
        uint64_t rsp = klee_regs_get_sp(proc);

        /* Write translated path below the stack (past 128-byte red zone) */
        uint64_t scratch = rsp - 128 - PATH_MAX * (uint64_t)(proc->path_arg_count + 1);
        rc = klee_write_string(ic, ev->pid, (void *)(uintptr_t)scratch,
                               proc->translated_path);
        if (rc < 0) {
            KLEE_DEBUG("failed to write translated path to scratch: %d", rc);
            proc->path_modified = false;
            return 0;
        }

        /* Update syscall argument register to point to scratch area */
        klee_regs_set_arg(proc, arg_idx, scratch);
        klee_regs_push(ic, proc);

        /* Track which arg was modified for exit-time restore */
        proc->path_arg_idx[proc->path_arg_count++] = arg_idx;
    }

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
                                  proc->resolved_guest, flags))
        return -EROFS;
    return 0;
}

/* ==================== Filesystem Enter Handlers ==================== */

int klee_enter_open(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg(proc, ic, ev, 0, -1);
    if (rc < 0) return rc;
    return check_readonly_open(proc, (int)ev->args[1]);
}

int klee_enter_openat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg(proc, ic, ev, 1, 0);
    if (rc < 0) return rc;
    return check_readonly_open(proc, (int)ev->args[2]);
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

    rc = klee_path_guest_to_host(&ctx, proc->saved_path,
                                  proc->translated_path, dirfd);
    if (rc < 0)
        return 0;

    if (strcmp(proc->saved_path, proc->translated_path) == 0) {
        proc->path_modified = false;
        return 0;
    }

    proc->path_modified = true;

    if (ic->backend == INTERCEPT_PTRACE) {
        rc = klee_write_string(ic, ev->pid, path_addr, proc->translated_path);
        if (rc < 0) {
            proc->path_modified = false;
            return 0;
        }
    }

    KLEE_TRACE("openat2: translated %s -> %s (resolve=0x%lx)",
               proc->saved_path, proc->translated_path,
               (unsigned long)how.resolve);

    return check_readonly_open(proc, (int)how.flags);
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
    /* newfstatat(dirfd, pathname, statbuf, flags)
     * AT_EMPTY_PATH  -> fstat semantics on dirfd, no path to translate
     * AT_SYMLINK_NOFOLLOW -> lstat semantics
     * otherwise -> stat semantics */
    int flags = (int)ev->args[3];
    if (flags & AT_EMPTY_PATH)
        return 0;
    if (flags & AT_SYMLINK_NOFOLLOW)
        return translate_path_arg_nofollow(proc, ic, ev, 1, 0);
    return translate_path_arg(proc, ic, ev, 1, 0);
}

int klee_enter_statx(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
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

#include <elf.h>

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

/*
 * Read PT_INTERP from an ELF file.
 * Returns 0 if found, -1 otherwise.
 */
static int read_elf_interp(const char *host_path, char *interp_out, size_t size)
{
    int fd = open(host_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != (ssize_t)sizeof(ehdr) ||
        memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
        ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        close(fd);
        return -1;
    }

    int found = -1;
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (pread(fd, &phdr, sizeof(phdr),
                  (off_t)(ehdr.e_phoff + (uint64_t)i * ehdr.e_phentsize))
            != (ssize_t)sizeof(phdr))
            break;
        if (phdr.p_type == PT_INTERP && phdr.p_filesz > 0 &&
            phdr.p_filesz < size) {
            ssize_t r = pread(fd, interp_out, phdr.p_filesz, (off_t)phdr.p_offset);
            if (r == (ssize_t)phdr.p_filesz) {
                interp_out[phdr.p_filesz] = '\0';
                found = 0;
            }
            break;
        }
    }

    close(fd);
    return found;
}

static int handle_exec_interp(KleeProcess *proc, KleeInterceptor *ic,
                                KleeEvent *ev)
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

    /* If the target is /proc/<pid>/exe, resolve the symlink NOW.
     * After exec, /proc/<pid>/exe will point to ld-linux (the new binary),
     * making the original symlink useless.  ld-linux would try to load
     * itself and fail with exit code 127. */
    bool resolved_proc_exe = false;
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
                resolved_proc_exe = true;
            }
        }
    }

    /* Results of the chain resolution */
    char interp_host[PATH_MAX] = {0};   /* Shebang interpreter (translated) */
    char shebang_arg[PATH_MAX] = {0};   /* Shebang optional argument */
    char ldlinux_host[PATH_MAX] = {0};  /* ELF PT_INTERP (translated) */

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
            snprintf(shebang_arg, sizeof(shebang_arg), "%s", sb_arg);
            KLEE_TRACE("shebang: interpreter %s -> %s (script=%s)",
                       sb_interp, sb_translated, current_host);
        }

        snprintf(current_host, sizeof(current_host), "%s", sb_translated);
    }

    /* Step 2: Check final binary for ELF PT_INTERP */
    char pt_interp[PATH_MAX];
    if (read_elf_interp(current_host, pt_interp, sizeof(pt_interp)) == 0) {
        char pt_translated[PATH_MAX];
        int rc = klee_path_guest_to_host(&ctx, pt_interp, pt_translated, AT_FDCWD);
        if (rc == 0 && strcmp(pt_interp, pt_translated) != 0) {
            snprintf(ldlinux_host, sizeof(ldlinux_host), "%s", pt_translated);
            KLEE_TRACE("elf: PT_INTERP %s -> %s (binary=%s)",
                       pt_interp, pt_translated, current_host);
        }
    }

    /* Step 3: If nothing needs rewriting, return */
    if (!interp_host[0] && !ldlinux_host[0])
        return 0;

    /* Step 4: Build the final execve command.
     *
     * The kernel expects: execve(filename, argv, env)
     *
     * Original:  execve(translated_script, [argv0, argv1, ...], env)
     *
     * Final argv layout (outermost to innermost):
     *   [ldlinux_host?] [interp_host?] [shebang_arg?] translated_script [orig_argv1 ...]
     *
     * filename = first element of new argv (ld-linux if present, else interpreter)
     */

    /* Read original argv from tracee */
    uint64_t argv_base = ev->args[1];
    uint64_t argv_ptrs[256];
    int argc = 0;
    for (int i = 0; i < 255; i++) {
        uint64_t ptr;
        int rc = klee_read_mem(ic, ev->pid, &ptr,
                               (void *)(uintptr_t)(argv_base + (unsigned)i * sizeof(uint64_t)),
                               sizeof(uint64_t));
        if (rc < 0) return 0;
        argv_ptrs[i] = ptr;
        if (ptr == 0) break;
        argc++;
    }

    klee_regs_fetch(ic, proc);
    uint64_t rsp = klee_regs_get_sp(proc);

    /* Ensure the translated script/binary host path is in the scratch area.
     * translate_path_arg writes it when path_modified=true, but we may also
     * reach here when path_modified=false (e.g. a script resolved $0 to a
     * host filesystem path via realpath).  Always write to be safe. */
    uint64_t addr_script = rsp - 128 - PATH_MAX;
    int rc;
    rc = klee_write_string(ic, ev->pid, (void *)(uintptr_t)addr_script,
                           resolved_proc_exe ? current_host : proc->translated_path);
    if (rc < 0) return 0;

    /* If path wasn't already modified by translate_path_arg, we need to
     * save the original arg[0] for exit-time restore (exec failure case)
     * and set up the register pointing to the scratch area. */
    if (!proc->path_modified) {
        proc->saved_args[0] = ev->args[0];
        klee_regs_set_arg(proc, 0, addr_script);
        klee_regs_push(ic, proc);
        proc->path_arg_idx[proc->path_arg_count++] = 0;
        proc->path_modified = true;
    } else if (resolved_proc_exe) {
        /* Path was already modified, but we need to update the script path
         * with the resolved /proc/PID/exe target (already written above). */
    }

    /* Write additional strings to scratch area below translate_path_arg's area */
    uint64_t scratch = rsp - 128 - PATH_MAX * 5;

    uint64_t addr_ldlinux = 0;
    uint64_t addr_interp = 0;
    uint64_t addr_shebang_arg = 0;

    if (ldlinux_host[0]) {
        addr_ldlinux = scratch;
        rc = klee_write_string(ic, ev->pid, (void *)(uintptr_t)addr_ldlinux, ldlinux_host);
        if (rc < 0) return 0;
        scratch -= PATH_MAX;
    }

    if (interp_host[0]) {
        addr_interp = scratch;
        rc = klee_write_string(ic, ev->pid, (void *)(uintptr_t)addr_interp, interp_host);
        if (rc < 0) return 0;
        scratch -= PATH_MAX;
    }

    if (shebang_arg[0]) {
        addr_shebang_arg = scratch;
        rc = klee_write_string(ic, ev->pid, (void *)(uintptr_t)addr_shebang_arg, shebang_arg);
        if (rc < 0) return 0;
        scratch -= PATH_MAX;
    }

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

    /* Write new argv array to scratch area */
    uint64_t argv_addr = (scratch - (uint64_t)(new_argc + 1) * sizeof(uint64_t)) & ~7ULL;
    rc = klee_write_mem(ic, ev->pid, (void *)(uintptr_t)argv_addr,
                        new_argv, (size_t)(new_argc + 1) * sizeof(uint64_t));
    if (rc < 0) return 0;

    /* Update registers: filename = first argv element, argv = new array */
    klee_regs_set_arg(proc, 0, new_argv[0]);
    klee_regs_set_arg(proc, 1, argv_addr);
    klee_regs_push(ic, proc);

    /* Save original argv pointer for exit-time restore (exec failure case) */
    proc->saved_args[1] = ev->args[1];
    proc->path_arg_idx[proc->path_arg_count++] = 1;

    KLEE_TRACE("exec interp: rewritten to %s%s%s %s",
               ldlinux_host[0] ? ldlinux_host : "",
               ldlinux_host[0] ? " -> " : "",
               interp_host[0] ? interp_host : current_host,
               proc->translated_path);
    return 0;
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
            snprintf(proc->translated_path, PATH_MAX, "%s", host_path);
            klee_write_string(ic, ev->pid,
                              (void *)(uintptr_t)ev->args[0], host_path);
        }
    }

    /* Check for nested bwrap invocation — parse inline and rewrite */
    if (klee_nested_is_bwrap(proc->saved_path)) {
        if (klee_nested_handle_exec(proc, ic, ev) == 0)
            return 0; /* handler sets vexe and manipulates registers */
        /* Fall through on failure — let original exec proceed */
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
        handle_exec_interp(proc, ic, ev);
    }

    /* Save exe path for vexe update on exit */
    snprintf(proc->vexe, PATH_MAX, "%s", proc->saved_path);
    return 0;
}

int klee_enter_execveat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg(proc, ic, ev, 1, 0);
    if (rc < 0) return rc;
    snprintf(proc->vexe, PATH_MAX, "%s", proc->saved_path);
    return 0;
}

int klee_enter_rename(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_nofollow(proc, ic, ev, 0, -1);
    if (rc < 0) return rc;
    rc = check_readonly(proc, ev->syscall_nr);
    if (rc < 0) return rc;
    /* Also translate dest path (arg 1) - need a second translate */
    return translate_path_arg_nofollow(proc, ic, ev, 1, -1);
}

int klee_enter_renameat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_nofollow(proc, ic, ev, 1, 0);
    if (rc < 0) return rc;
    rc = check_readonly(proc, ev->syscall_nr);
    if (rc < 0) return rc;
    return translate_path_arg_nofollow(proc, ic, ev, 3, 2);
}

int klee_enter_renameat2(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return klee_enter_renameat(proc, ic, ev);
}

int klee_enter_mkdir(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg(proc, ic, ev, 0, -1);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_mkdirat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg(proc, ic, ev, 1, 0);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_rmdir(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_nofollow(proc, ic, ev, 0, -1);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_unlink(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_nofollow(proc, ic, ev, 0, -1);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_unlinkat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg_nofollow(proc, ic, ev, 1, 0);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_link(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* link(oldpath, newpath) - oldpath should not follow final symlink */
    int rc = translate_path_arg_nofollow(proc, ic, ev, 0, -1);
    if (rc < 0) return rc;
    return translate_path_arg_nofollow(proc, ic, ev, 1, -1);
}

int klee_enter_linkat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* linkat(olddirfd, oldpath, newdirfd, newpath, flags)
     * Default: don't follow on oldpath. AT_SYMLINK_FOLLOW changes this. */
    int rc = translate_path_arg_nofollow(proc, ic, ev, 1, 0);
    if (rc < 0) return rc;
    return translate_path_arg_nofollow(proc, ic, ev, 3, 2);
}

int klee_enter_symlink(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* symlink(target, linkpath) - translate linkpath (arg 1), nofollow */
    int rc = translate_path_arg_nofollow(proc, ic, ev, 1, -1);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_symlinkat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    /* symlinkat(target, dirfd, linkpath) - translate linkpath (arg 2), nofollow */
    int rc = translate_path_arg_nofollow(proc, ic, ev, 2, 1);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_chmod(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg(proc, ic, ev, 0, -1);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_fchmodat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg(proc, ic, ev, 1, 0);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_chown(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_path_arg(proc, ic, ev, 0, -1);
}

int klee_enter_lchown(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_path_arg_nofollow(proc, ic, ev, 0, -1);
}

int klee_enter_fchownat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_path_arg(proc, ic, ev, 1, 0);
}

int klee_enter_truncate(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg(proc, ic, ev, 0, -1);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_mknod(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg(proc, ic, ev, 0, -1);
    if (rc < 0) return rc;
    return check_readonly(proc, ev->syscall_nr);
}

int klee_enter_mknodat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    int rc = translate_path_arg(proc, ic, ev, 1, 0);
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

int klee_enter_kill(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!proc->sandbox || !proc->sandbox->unshare_pid)
        return 0;

    pid_t vpid = (pid_t)ev->args[0];
    if (vpid <= 0)
        return 0; /* Process group or special PIDs pass through */

    pid_t real = translate_pid(proc->sandbox->pid_map, vpid);
    if (real <= 0) {
        /* PID not in the map — likely an exited process or a real PID
         * cached by glibc.  Pass through and let the kernel decide
         * (returns ESRCH for truly dead processes). */
        KLEE_TRACE("kill: pid=%d target vpid=%d not in map, passthrough",
                    proc->real_pid, vpid);
        return 0;
    }

    if (real != vpid) {
        klee_regs_fetch(ic, proc);
        klee_regs_set_arg(proc, 0, (uint64_t)real);
        klee_regs_push(ic, proc);
    }
    return 0;
}

int klee_enter_tgkill(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!proc->sandbox || !proc->sandbox->unshare_pid)
        return 0;

    pid_t vtgid = (pid_t)ev->args[0];
    pid_t vtid = (pid_t)ev->args[1];

    pid_t real_tgid = translate_pid(proc->sandbox->pid_map, vtgid);
    pid_t real_tid = translate_pid(proc->sandbox->pid_map, vtid);

    if (real_tgid <= 0 || real_tid <= 0) {
        /* PID/TID not in the map.  Pass through to kernel rather than
         * denying — handles glibc-cached real TIDs (raise/abort pattern)
         * and already-exited threads (crashpad cleanup). */
        KLEE_TRACE("tgkill: pid=%d tgid=%d tid=%d not fully mapped, passthrough",
                    proc->real_pid, vtgid, vtid);
        return 0;
    }

    if (real_tgid != vtgid || real_tid != vtid) {
        klee_regs_fetch(ic, proc);
        klee_regs_set_arg(proc, 0, (uint64_t)real_tgid);
        klee_regs_set_arg(proc, 1, (uint64_t)real_tid);
        klee_regs_push(ic, proc);
    }
    return 0;
}

int klee_enter_tkill(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!proc->sandbox || !proc->sandbox->unshare_pid)
        return 0;

    pid_t vpid = (pid_t)ev->args[0];
    pid_t real = translate_pid(proc->sandbox->pid_map, vpid);
    if (real <= 0) {
        KLEE_TRACE("tkill: pid=%d target=%d not in map, passthrough",
                    proc->real_pid, vpid);
        return 0;
    }

    if (real != vpid) {
        klee_regs_fetch(ic, proc);
        klee_regs_set_arg(proc, 0, (uint64_t)real);
        klee_regs_push(ic, proc);
    }
    return 0;
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

int klee_enter_shmget(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_ipc || !proc->sandbox->ipc_ns)
        return 0;

    key_t key = (key_t)ev->args[0];
    key_t real_key = klee_ipc_ns_translate_key(proc->sandbox->ipc_ns, key);
    ev->args[0] = (uint64_t)(unsigned int)real_key;
    KLEE_TRACE("shmget: translated key %d -> %d", key, real_key);
    return 0;
}

int klee_enter_msgget(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_ipc || !proc->sandbox->ipc_ns)
        return 0;

    key_t key = (key_t)ev->args[0];
    key_t real_key = klee_ipc_ns_translate_key(proc->sandbox->ipc_ns, key);
    ev->args[0] = (uint64_t)(unsigned int)real_key;
    KLEE_TRACE("msgget: translated key %d -> %d", key, real_key);
    return 0;
}

int klee_enter_semget(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_ipc || !proc->sandbox->ipc_ns)
        return 0;

    key_t key = (key_t)ev->args[0];
    key_t real_key = klee_ipc_ns_translate_key(proc->sandbox->ipc_ns, key);
    ev->args[0] = (uint64_t)(unsigned int)real_key;
    KLEE_TRACE("semget: translated key %d -> %d", key, real_key);
    return 0;
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
        /* bwrap actively sets dumpable after dropping privs.
         * Allow passthrough to kernel. */
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
        KLEE_DEBUG("child seccomp(SET_MODE_FILTER) from pid=%d", proc->real_pid);

        /* Read sock_fprog from tracee at args[2] */
        void *fprog_addr = (void *)(uintptr_t)ev->args[2];
        if (fprog_addr) {
            struct sock_fprog fprog;
            int rc = klee_read_mem(ic, ev->pid, &fprog, fprog_addr, sizeof(fprog));
            if (rc == 0 && fprog.filter && fprog.len > 0) {
                klee_compat_handle_seccomp_filter(ic, ev->pid, &fprog);
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
                                   KleeEvent *ev)
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
    if (sun.sun_path[0] == '\0')
        return 0;

    /* Ensure null termination for path extraction */
    size_t path_offset = offsetof(struct sockaddr_un, sun_path);
    size_t path_max = to_read > path_offset ? to_read - path_offset : 0;
    if (path_max == 0)
        return 0;
    if (path_max > sizeof(sun.sun_path))
        path_max = sizeof(sun.sun_path);
    sun.sun_path[path_max - 1] = '\0';

    /* Save original path */
    snprintf(proc->saved_path, sizeof(proc->saved_path), "%s", sun.sun_path);

    /* Translate through mount table */
    KleeResolveCtx ctx = {
        .mount_table = proc->sandbox->mount_table,
        .fd_table = proc->fd_table,
        .vcwd = proc->vcwd,
        .vroot = klee_mount_table_get_root(proc->sandbox->mount_table),
        .flags = 0,
    };

    rc = klee_path_guest_to_host(&ctx, proc->saved_path,
                                  proc->translated_path, AT_FDCWD);
    if (rc < 0)
        return 0;

    if (strcmp(proc->saved_path, proc->translated_path) == 0) {
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
    return translate_sockaddr_arg(proc, ic, ev);
}

int klee_enter_connect(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return translate_sockaddr_arg(proc, ic, ev);
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
    void *msg_addr = (void *)(uintptr_t)ev->args[1];
    if (!msg_addr)
        return 0;

    /* Read msghdr from tracee */
    struct msghdr msg;
    int rc = klee_read_mem(ic, ev->pid, &msg, msg_addr, sizeof(msg));
    if (rc < 0)
        return 0;

    if (!msg.msg_control || msg.msg_controllen == 0)
        return 0;

    /* Sanity limit on control data size */
    size_t ctrllen = msg.msg_controllen;
    if (ctrllen > 4096)
        return 0;

    /* Read control data from tracee */
    char ctrl_buf[4096];
    void *ctrl_addr = msg.msg_control;
    rc = klee_read_mem(ic, ev->pid, ctrl_buf, ctrl_addr, ctrllen);
    if (rc < 0)
        return 0;

    /* Walk cmsghdr entries looking for SCM_CREDENTIALS */
    bool modified = false;
    struct msghdr local_msg;
    memset(&local_msg, 0, sizeof(local_msg));
    local_msg.msg_control = ctrl_buf;
    local_msg.msg_controllen = ctrllen;

    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&local_msg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&local_msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET &&
            cmsg->cmsg_type == SCM_CREDENTIALS &&
            cmsg->cmsg_len >= CMSG_LEN(sizeof(struct ucred))) {
            struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);

            /* Translate credentials: the guest process sends its
             * virtual pid/uid/gid, but the kernel validates against
             * real values.  Rewrite to real pid and the klee host
             * process's actual uid/gid (what the kernel expects).
             *
             * Use the host uid/gid (not virtual ones from id_state)
             * because the kernel checks that SCM_CREDENTIALS match
             * the sending process's real credentials.  The virtual
             * uid/gid are purely for in-sandbox presentation. */
            uid_t host_uid = getuid();
            gid_t host_gid = getgid();

            KLEE_TRACE("sendmsg SCM_CREDENTIALS: pid=%d uid=%d gid=%d -> "
                       "pid=%d uid=%d gid=%d",
                       cred->pid, cred->uid, cred->gid,
                       proc->real_pid, host_uid, host_gid);

            cred->pid = proc->real_pid;
            cred->uid = host_uid;
            cred->gid = host_gid;
            modified = true;
        }
    }

    if (!modified)
        return 0;

    /* Write modified control data back to tracee (same address, same size) */
    rc = klee_write_mem(ic, ev->pid, ctrl_addr, ctrl_buf, ctrllen);
    if (rc < 0)
        KLEE_DEBUG("sendmsg: failed to write back SCM_CREDENTIALS: %d", rc);

    return 0;
}
