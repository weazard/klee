/*
 * Klee - Userspace bwrap translation layer
 * Syscall-exit handler implementations
 */
#include "syscall/exit.h"
#include "syscall/sysnum.h"
#include "process/memory.h"
#include "process/regs.h"
#include "ns/pid_ns.h"
#include "ns/user_ns.h"
#include "ns/uts_ns.h"
#include "util/log.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/prctl.h>

/* ==================== Filesystem Exit Handlers ==================== */

int klee_exit_open(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;

    /* Track new FD if open succeeded */
    if (ev->retval >= 0) {
        int fd = (int)ev->retval;
        bool cloexec = false;

        /* Check O_CLOEXEC in flags */
        int syscall_nr = ev->syscall_nr;
        int flags = 0;
        if (syscall_nr == KLEE_SYS_open)
            flags = (int)ev->args[1];
        else if (syscall_nr == KLEE_SYS_openat)
            flags = (int)ev->args[2];
        cloexec = !!(flags & O_CLOEXEC);

        /* Use the resolved absolute guest path so that fchdir() and
         * other lookups get a proper absolute path, not a relative one. */
        klee_fd_table_set(proc->fd_table, fd,
                          proc->resolved_guest[0] ? proc->resolved_guest
                                                   : proc->saved_path,
                          cloexec);
    }
    return 0;
}

int klee_exit_stat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (ev->retval < 0)
        return 0;

    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;

    /* Rewrite uid/gid in stat buffer.
     * stat/lstat/fstat: statbuf is args[1]
     * newfstatat:       statbuf is args[2] (dirfd, path, statbuf, flags) */
    void *stat_addr;
#ifdef KLEE_SYS_newfstatat
    if (ev->syscall_nr == KLEE_SYS_newfstatat)
        stat_addr = (void *)(uintptr_t)ev->args[2];
    else
#endif
        stat_addr = (void *)(uintptr_t)ev->args[1];

    struct stat st;
    int rc = klee_read_mem(ic, ev->pid, &st, stat_addr, sizeof(st));
    if (rc < 0)
        return 0;

    /* If the file is owned by us in reality, show it as owned by virtual uid */
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();

    if (st.st_uid == real_uid)
        st.st_uid = proc->id_state->euid;
    if (st.st_gid == real_gid)
        st.st_gid = proc->id_state->egid;

    ic->write_mem(ic, ev->pid, stat_addr, &st, sizeof(st));
    return 0;
}

int klee_exit_statx(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (ev->retval < 0)
        return 0;

    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;

    /* statx struct has uid/gid at known offsets */
    /* struct statx { ... uint32_t stx_uid; uint32_t stx_gid; ... } */
    /* We'll read the whole struct and rewrite */
    void *statx_addr = (void *)(uintptr_t)ev->args[4];

    /* statx uid is at offset 0x1c (28), gid at 0x20 (32) */
    uint32_t uid_val, gid_val;
    const size_t uid_off = 28;
    const size_t gid_off = 32;

    int rc = klee_read_mem(ic, ev->pid, &uid_val,
                           (char *)statx_addr + uid_off, sizeof(uid_val));
    if (rc < 0) return 0;

    rc = klee_read_mem(ic, ev->pid, &gid_val,
                       (char *)statx_addr + gid_off, sizeof(gid_val));
    if (rc < 0) return 0;

    uid_t real_uid = getuid();
    gid_t real_gid = getgid();

    if (uid_val == (uint32_t)real_uid)
        uid_val = proc->id_state->euid;
    if (gid_val == (uint32_t)real_gid)
        gid_val = proc->id_state->egid;

    ic->write_mem(ic, ev->pid, (char *)statx_addr + uid_off, &uid_val, sizeof(uid_val));
    ic->write_mem(ic, ev->pid, (char *)statx_addr + gid_off, &gid_val, sizeof(gid_val));
    return 0;
}

/* Check if a saved path is /proc/self/exe or /proc/<pid>/exe */
static bool is_proc_exe_readlink(const char *path)
{
    if (strncmp(path, "/proc/", 6) != 0)
        return false;
    const char *p = path + 6;
    if (strcmp(p, "self/exe") == 0)
        return true;
    /* /proc/<pid>/exe */
    if (*p >= '1' && *p <= '9') {
        while (*p >= '0' && *p <= '9')
            p++;
        return strcmp(p, "/exe") == 0;
    }
    return false;
}

int klee_exit_readlink(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (ev->retval <= 0)
        return 0;

    /* If this was a /proc/self/exe or /proc/<pid>/exe readlink, rewrite
     * the result with the virtual exe path (proc->vexe).
     *
     * The exec interpreter handler rewrites execve to invoke ld-linux as
     * the actual binary, so the kernel's /proc/self/exe points to ld-linux
     * instead of the real program.  This breaks programs like Chromium that
     * use readlink("/proc/self/exe") to find their data directory. */
    if (proc->vexe[0] && proc->sandbox &&
        is_proc_exe_readlink(proc->saved_path)) {
        void *buf_addr;
        size_t bufsiz;
        if (ev->syscall_nr == KLEE_SYS_readlink) {
            buf_addr = (void *)(uintptr_t)ev->args[1];
            bufsiz = (size_t)ev->args[2];
        } else { /* readlinkat */
            buf_addr = (void *)(uintptr_t)ev->args[2];
            bufsiz = (size_t)ev->args[3];
        }

        size_t vexe_len = strlen(proc->vexe);
        if (vexe_len > bufsiz)
            vexe_len = bufsiz;

        int rc = klee_write_mem(ic, ev->pid, buf_addr, proc->vexe, vexe_len);
        if (rc == 0) {
            ev->retval = (long)vexe_len;
            KLEE_TRACE("readlink exe: rewritten to %s", proc->vexe);
            return 1; /* retval modified */
        }
    }

    return 0;
}

int klee_exit_chdir(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (ev->retval == 0) {
        /* Update virtual CWD from the resolved absolute guest path,
         * not the raw (possibly relative) tracee path in saved_path. */
        snprintf(proc->vcwd, PATH_MAX, "%s", proc->resolved_guest);
        KLEE_DEBUG("chdir: vcwd now %s", proc->vcwd);
    }
    return 0;
}

int klee_exit_fchdir(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (ev->retval == 0) {
        int fd = (int)ev->args[0];
        const char *path = klee_fd_table_get(proc->fd_table, fd);
        if (path) {
            snprintf(proc->vcwd, PATH_MAX, "%s", path);
            KLEE_DEBUG("fchdir: vcwd now %s", proc->vcwd);
        }
    }
    return 0;
}

int klee_exit_getcwd(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (ev->retval <= 0)
        return 0;

    /* Overwrite the returned CWD with our virtual CWD */
    void *buf = (void *)(uintptr_t)ev->args[0];
    size_t buf_len = (size_t)ev->args[1];

    size_t vcwd_len = strlen(proc->vcwd) + 1;
    if (vcwd_len > buf_len)
        return 0; /* Buffer too small */

    ic->write_mem(ic, ev->pid, buf, proc->vcwd, vcwd_len);
    return 0;
}

/* ==================== FD Tracking Exit Handlers ==================== */

int klee_exit_dup(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (ev->retval >= 0) {
        int old_fd = (int)ev->args[0];
        int new_fd = (int)ev->retval;
        klee_fd_table_dup(proc->fd_table, old_fd, new_fd, false);
    }
    return 0;
}

int klee_exit_dup2(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (ev->retval >= 0) {
        int old_fd = (int)ev->args[0];
        int new_fd = (int)ev->args[1];
        klee_fd_table_dup(proc->fd_table, old_fd, new_fd, false);
    }
    return 0;
}

int klee_exit_dup3(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (ev->retval >= 0) {
        int old_fd = (int)ev->args[0];
        int new_fd = (int)ev->args[1];
        int flags = (int)ev->args[2];
        klee_fd_table_dup(proc->fd_table, old_fd, new_fd,
                          !!(flags & O_CLOEXEC));
    }
    return 0;
}

int klee_exit_fcntl(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    int fd = (int)ev->args[0];
    int cmd = (int)ev->args[1];

    if (ev->retval < 0)
        return 0;

    switch (cmd) {
    case F_DUPFD:
    case F_DUPFD_CLOEXEC:
        klee_fd_table_dup(proc->fd_table, fd, (int)ev->retval,
                          cmd == F_DUPFD_CLOEXEC);
        break;
    case F_SETFD:
        klee_fd_table_set_cloexec(proc->fd_table, fd,
                                   !!((int)ev->args[2] & FD_CLOEXEC));
        break;
    }
    return 0;
}

/* ==================== PID Namespace Exit Handlers ==================== */

int klee_exit_getpid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_pid)
        return 0;

    /* The kernel returns the real TGID.  Map it through the PID namespace.
     * For threads, this correctly returns the thread group leader's vpid
     * (not the thread's own vpid), matching Linux getpid() semantics. */
    if (proc->sandbox->pid_map) {
        pid_t real_tgid = (pid_t)ev->retval;
        pid_t vpid = klee_pid_map_r2v(proc->sandbox->pid_map, real_tgid);
        if (vpid > 0) {
            ev->retval = vpid;
            return 1;
        }
    }

    ev->retval = proc->virtual_pid;
    return 1;
}

int klee_exit_getppid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_pid)
        return 0;

    /* The kernel returns the real parent TGID.  Map through PID namespace. */
    if (proc->sandbox->pid_map) {
        pid_t real_ppid = (pid_t)ev->retval;
        pid_t vpid = klee_pid_map_r2v(proc->sandbox->pid_map, real_ppid);
        if (vpid > 0) {
            ev->retval = vpid;
            return 1;
        }
    }

    ev->retval = proc->virtual_ppid;
    return 1;
}

int klee_exit_gettid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_pid)
        return 0;
    /* For the main thread, tid == pid */
    ev->retval = proc->virtual_pid;
    return 1;
}

/* ==================== UID/GID Exit Handlers ==================== */

int klee_exit_getuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;
    ev->retval = proc->id_state->ruid;
    return 1;
}

int klee_exit_geteuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;
    ev->retval = proc->id_state->euid;
    return 1;
}

int klee_exit_getgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;
    ev->retval = proc->id_state->rgid;
    return 1;
}

int klee_exit_getegid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;
    ev->retval = proc->id_state->egid;
    return 1;
}

int klee_exit_getresuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (ev->retval < 0)
        return 0;
    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;

    /* Write virtual UIDs to tracee pointers */
    uid_t ruid = proc->id_state->ruid;
    uid_t euid = proc->id_state->euid;
    uid_t suid = proc->id_state->suid;

    ic->write_mem(ic, ev->pid, (void *)(uintptr_t)ev->args[0], &ruid, sizeof(ruid));
    ic->write_mem(ic, ev->pid, (void *)(uintptr_t)ev->args[1], &euid, sizeof(euid));
    ic->write_mem(ic, ev->pid, (void *)(uintptr_t)ev->args[2], &suid, sizeof(suid));
    return 0;
}

int klee_exit_getresgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (ev->retval < 0)
        return 0;
    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;

    gid_t rgid = proc->id_state->rgid;
    gid_t egid = proc->id_state->egid;
    gid_t sgid = proc->id_state->sgid;

    ic->write_mem(ic, ev->pid, (void *)(uintptr_t)ev->args[0], &rgid, sizeof(rgid));
    ic->write_mem(ic, ev->pid, (void *)(uintptr_t)ev->args[1], &egid, sizeof(egid));
    ic->write_mem(ic, ev->pid, (void *)(uintptr_t)ev->args[2], &sgid, sizeof(sgid));
    return 0;
}

int klee_exit_getgroups(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user)
        return 0;
    /* Return single group matching virtual gid */
    ev->retval = 1;
    return 1;
}

/* ==================== UTS Namespace Exit Handler ==================== */

int klee_exit_uname(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (ev->retval < 0)
        return 0;
    if (!proc->sandbox || !proc->sandbox->unshare_uts || !proc->sandbox->hostname)
        return 0;

    /* Read utsname struct, overwrite nodename field */
    struct utsname uts;
    void *buf = (void *)(uintptr_t)ev->args[0];

    int rc = klee_read_mem(ic, ev->pid, &uts, buf, sizeof(uts));
    if (rc < 0)
        return 0;

    snprintf(uts.nodename, sizeof(uts.nodename), "%s", proc->sandbox->hostname);

    ic->write_mem(ic, ev->pid, buf, &uts, sizeof(uts));
    return 0;
}

/* ==================== Misc Exit Handlers ==================== */

int klee_exit_prctl(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    int option = (int)ev->args[0];

    /* Fake capability support */
    if (option == PR_CAPBSET_READ) {
        if (proc->sandbox && proc->sandbox->unshare_user) {
            ev->retval = 1; /* All capabilities present */
            return 1;
        }
    }
    return 0;
}

int klee_exit_getsockopt(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (ev->retval < 0)
        return 0;
    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;

    int level = (int)ev->args[1];
    int optname = (int)ev->args[2];

    /* Rewrite SO_PEERCRED */
    if (level == SOL_SOCKET && optname == SO_PEERCRED) {
        struct ucred cred;
        void *optval = (void *)(uintptr_t)ev->args[3];

        int rc = klee_read_mem(ic, ev->pid, &cred, optval, sizeof(cred));
        if (rc < 0)
            return 0;

        /* Translate PID and UID/GID */
        if (proc->sandbox->unshare_pid && proc->sandbox->pid_map) {
            pid_t vpid = klee_pid_map_r2v(proc->sandbox->pid_map, cred.pid);
            if (vpid > 0) {
                cred.pid = vpid;
            } else if (cred.pid > 0) {
                /* Peer PID not in our namespace map — this peer is outside
                 * the sandbox.  Present as 0 (unknown) rather than leaking
                 * the real host PID to the guest. */
                KLEE_TRACE("getsockopt SO_PEERCRED: peer pid=%d not in "
                           "namespace, presenting as 0", cred.pid);
                cred.pid = 0;
            }
        }

        uid_t real_uid = getuid();
        gid_t real_gid = getgid();
        if (cred.uid == real_uid)
            cred.uid = proc->id_state->euid;
        if (cred.gid == real_gid)
            cred.gid = proc->id_state->egid;

        ic->write_mem(ic, ev->pid, optval, &cred, sizeof(cred));
    }
    return 0;
}
