/*
 * Klee - Userspace bwrap translation layer
 * Syscall-exit handler implementations
 */
#include "syscall/exit.h"
#include "syscall/sysnum.h"
#include "syscall/sysnum32.h"
#include "syscall/abi.h"
#include "process/memory.h"
#include "process/regs.h"
#include "fs/fd_table.h"
#include "ns/pid_ns.h"
#include "ns/user_ns.h"
#include "ns/uts_ns.h"
#include "ns/ipc_ns.h"
#include "compat/zypak_compat.h"
#include "util/log.h"

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
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
         * other lookups get a proper absolute path, not a relative one.
         * Without one (the path was not resolved) the descriptor is left
         * untracked: *at() calls on it then go to the kernel as they are. */
        const char *vpath = proc->resolved_guest[0] ? proc->resolved_guest
                                                    : proc->saved_path;
        if (vpath[0] == '/')
            klee_fd_table_set(proc->fd_table, fd, vpath, cloexec);
        else
            klee_fd_table_remove(proc->fd_table, fd);
    }
    return 0;
}

/* Owner and mode klee shows for a file the kernel reported with these
 * values; shared by stat and statx. */
static void virt_file_ids(KleeProcess *proc, uint32_t *mode, uint32_t *uid,
                          uint32_t *gid)
{
    /* If the file is owned by us in reality, show it as owned by virtual uid */
    if (*uid == (uint32_t)getuid())
        *uid = proc->id_state->euid;
    if (*gid == (uint32_t)getgid())
        *gid = proc->id_state->egid;

    /* Fake SUID ownership for chrome-sandbox when zypak is active.
     * Chrome stat()s the sandbox helper before exec and requires
     * root ownership + setuid bit. */
    if (proc->sandbox->zypak_detected &&
        klee_zypak_is_chrome_sandbox(proc->saved_path)) {
        *uid = 0;
        *mode |= S_ISUID | S_IXUSR | S_IXGRP | S_IXOTH;
        KLEE_DEBUG("stat: faked SUID for chrome-sandbox: %s",
                   proc->saved_path);
    }
}

int klee_exit_stat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (ev->retval < 0)
        return 0;

    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;

    /* The legacy i386 stat/oldstat buffers have 16-bit ids at other
     * offsets; nothing modern issues them, leave them alone. */
    if (proc->sys32_flags & KLEE_SYS32_OLDSTRUCT)
        return 0;

    /* Rewrite uid/gid in stat buffer.
     * stat/lstat/fstat: statbuf is args[1]
     * newfstatat:       statbuf is args[2] (dirfd, path, statbuf, flags) */
    uint64_t stat_addr;
#ifdef KLEE_SYS_newfstatat
    if (ev->syscall_nr == KLEE_SYS_newfstatat)
        stat_addr = ev->args[2];
    else
#endif
        stat_addr = ev->args[1];

    /* Only the fields klee may change, at the offsets of the tracee's
     * struct (struct stat on x86_64, struct stat64 for a 32-bit tracee). */
    size_t mode_off, uid_off, gid_off;
    klee_abi_stat_layout(proc->abi, &mode_off, &uid_off, &gid_off);

    uint32_t mode, uid, gid;
    if (klee_read_mem(ic, ev->pid, &mode, (void *)(uintptr_t)(stat_addr + mode_off), sizeof(mode)) < 0 ||
        klee_read_mem(ic, ev->pid, &uid, (void *)(uintptr_t)(stat_addr + uid_off), sizeof(uid)) < 0 ||
        klee_read_mem(ic, ev->pid, &gid, (void *)(uintptr_t)(stat_addr + gid_off), sizeof(gid)) < 0)
        return 0;

    uint32_t new_mode = mode, new_uid = uid, new_gid = gid;
    virt_file_ids(proc, &new_mode, &new_uid, &new_gid);

    if (new_mode != mode)
        ic->write_mem(ic, ev->pid, (void *)(uintptr_t)(stat_addr + mode_off), &new_mode, sizeof(new_mode));
    if (new_uid != uid)
        ic->write_mem(ic, ev->pid, (void *)(uintptr_t)(stat_addr + uid_off), &new_uid, sizeof(new_uid));
    if (new_gid != gid)
        ic->write_mem(ic, ev->pid, (void *)(uintptr_t)(stat_addr + gid_off), &new_gid, sizeof(new_gid));
    return 0;
}

/* struct statx has one layout for every ABI (include/uapi/linux/stat.h).
 * Its uid/gid are not where struct stat keeps them on x86_64. */
#define KLEE_STATX_MASK_OFF 0
#define KLEE_STATX_UID_OFF  20
#define KLEE_STATX_GID_OFF  24
#define KLEE_STATX_MODE_OFF 28   /* __u16 */
#ifndef STATX_MODE
#define STATX_MODE 0x00000002U
#define STATX_UID  0x00000008U
#define STATX_GID  0x00000010U
#else
_Static_assert(offsetof(struct statx, stx_mask) == KLEE_STATX_MASK_OFF, "statx layout");
_Static_assert(offsetof(struct statx, stx_uid) == KLEE_STATX_UID_OFF, "statx layout");
_Static_assert(offsetof(struct statx, stx_gid) == KLEE_STATX_GID_OFF, "statx layout");
_Static_assert(offsetof(struct statx, stx_mode) == KLEE_STATX_MODE_OFF, "statx layout");
#endif

int klee_exit_statx(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (ev->retval < 0)
        return 0;

    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;

    /* statx(dirfd, pathname, flags, mask, statxbuf) */
    char *statx_addr = (char *)(uintptr_t)ev->args[4];

    uint8_t head[KLEE_STATX_MODE_OFF + 2];
    if (klee_read_mem(ic, ev->pid, head, statx_addr, sizeof(head)) < 0)
        return 0;

    uint32_t mask, uid, gid;
    uint16_t mode16;
    memcpy(&mask, head + KLEE_STATX_MASK_OFF, sizeof(mask));
    memcpy(&uid, head + KLEE_STATX_UID_OFF, sizeof(uid));
    memcpy(&gid, head + KLEE_STATX_GID_OFF, sizeof(gid));
    memcpy(&mode16, head + KLEE_STATX_MODE_OFF, sizeof(mode16));

    uint32_t mode = mode16, new_mode = mode, new_uid = uid, new_gid = gid;
    virt_file_ids(proc, &new_mode, &new_uid, &new_gid);

    /* Only fields the kernel reported as filled in */
    if ((mask & STATX_UID) && new_uid != uid)
        ic->write_mem(ic, ev->pid, statx_addr + KLEE_STATX_UID_OFF,
                      &new_uid, sizeof(new_uid));
    if ((mask & STATX_GID) && new_gid != gid)
        ic->write_mem(ic, ev->pid, statx_addr + KLEE_STATX_GID_OFF,
                      &new_gid, sizeof(new_gid));
    if ((mask & STATX_MODE) && new_mode != mode) {
        uint16_t m = (uint16_t)new_mode;
        ic->write_mem(ic, ev->pid, statx_addr + KLEE_STATX_MODE_OFF,
                      &m, sizeof(m));
    }
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

    /* The parent is outside the namespace.  For init (any of its threads)
     * that is expected and reads as 0; any other process has been orphaned
     * and reparented to klee, the subreaper, which in a real namespace
     * makes it init's. */
    pid_t tgid = proc->real_pid;
    klee_proc_status_ids(proc->real_pid, &tgid, NULL);
    ev->retval = klee_pid_map_is_init(proc->sandbox->pid_map, tgid) ? 0 : 1;
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

/* ==================== Process Group Exit Handlers ==================== */

int klee_exit_getpgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_pid)
        return 0;
    if (ev->retval < 0)
        return 0;

    if (proc->sandbox->pid_map) {
        pid_t real_pgid = (pid_t)ev->retval;
        pid_t vpid = klee_pid_map_r2v(proc->sandbox->pid_map, real_pgid);
        if (vpid > 0) {
            ev->retval = vpid;
            return 1;
        }
    }
    return 0;
}

int klee_exit_getpgrp(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return klee_exit_getpgid(proc, ic, ev);
}

int klee_exit_setsid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return klee_exit_getpgid(proc, ic, ev);
}

int klee_exit_getsid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    return klee_exit_getpgid(proc, ic, ev);
}

/* ==================== ioctl Exit Handler ==================== */

int klee_exit_ioctl(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (!proc->sandbox || !proc->sandbox->unshare_pid)
        return 0;

    unsigned long request = ev->args[1];

    if (request == TIOCSPGRP) {
        /* Restore the original virtual pgid in tracee memory so the
         * tracee's copy isn't left containing the real pgid. */
        void *pgid_ptr = (void *)(uintptr_t)ev->args[2];
        pid_t vpgid = (pid_t)(uintptr_t)proc->saved_args[2];
        if (vpgid > 0)
            ic->write_mem(ic, ev->pid, pgid_ptr, &vpgid, sizeof(vpgid));
    } else if (request == TIOCGPGRP || request == TIOCGSID) {
        /* tcgetpgrp / TIOCGSID: kernel wrote a real pgid/sid into the
         * tracee's buffer.  Translate it to a virtual PID. */
        if (ev->retval < 0)
            return 0;

        void *pid_ptr = (void *)(uintptr_t)ev->args[2];
        pid_t real_pid;
        int rc = klee_read_mem(ic, ev->pid, &real_pid, pid_ptr, sizeof(real_pid));
        if (rc < 0)
            return 0;

        if (proc->sandbox->pid_map) {
            pid_t vpid = klee_pid_map_r2v(proc->sandbox->pid_map, real_pid);
            if (vpid > 0 && vpid != real_pid)
                ic->write_mem(ic, ev->pid, pid_ptr, &vpid, sizeof(vpid));
        }
    }

    return 0;
}

/* ==================== /proc getdents64 Filtering ==================== */

int klee_exit_getdents64(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (ev->retval <= 0)
        return 0;

    if (!proc->sandbox || !proc->sandbox->unshare_pid || !proc->sandbox->pid_map)
        return 0;

    /* Only filter the top-level /proc directory */
    int dirfd = (int)ev->args[0];
    const char *vpath = klee_fd_table_get(proc->fd_table, dirfd);
    if (!vpath || strcmp(vpath, "/proc") != 0)
        return 0;

    size_t buf_len = (size_t)ev->retval;
    if (buf_len > 65536)
        return 0;

    void *dirp_addr = (void *)(uintptr_t)ev->args[1];

    uint8_t *in_buf = malloc(buf_len);
    uint8_t *out_buf = malloc(buf_len);
    if (!in_buf || !out_buf) {
        free(in_buf);
        free(out_buf);
        return 0;
    }

    int rc = klee_read_mem(ic, ev->pid, in_buf, dirp_addr, buf_len);
    if (rc < 0) {
        free(in_buf);
        free(out_buf);
        return 0;
    }

    /*
     * linux_dirent64 layout:
     *   uint64_t d_ino;      (0)
     *   int64_t  d_off;      (8)
     *   uint16_t d_reclen;   (16)
     *   uint8_t  d_type;     (18)
     *   char     d_name[];   (19)
     */
    size_t in_pos = 0;
    size_t out_pos = 0;

    while (in_pos + 19 < buf_len) {
        uint16_t reclen;
        memcpy(&reclen, in_buf + in_pos + 16, 2);
        if (reclen < 19 || in_pos + reclen > buf_len)
            break;

        char *d_name = (char *)(in_buf + in_pos + 19);
        size_t name_max = reclen - 19;

        /* Check if entry name is purely numeric (a PID directory) */
        bool is_numeric = (d_name[0] != '\0');
        for (size_t i = 0; i < name_max && d_name[i]; i++) {
            if (!isdigit((unsigned char)d_name[i])) {
                is_numeric = false;
                break;
            }
        }

        if (!is_numeric) {
            /* Non-PID entry: copy as-is */
            memcpy(out_buf + out_pos, in_buf + in_pos, reclen);
            out_pos += reclen;
        } else {
            pid_t real_pid = (pid_t)atoi(d_name);
            pid_t vpid = klee_pid_map_r2v(proc->sandbox->pid_map, real_pid);

            if (vpid > 0) {
                /* Translate: rewrite name to virtual PID */
                char vpid_str[16];
                int vpid_len = snprintf(vpid_str, sizeof(vpid_str), "%d", vpid);

                /* New reclen: header(19) + name + null, 8-byte aligned */
                size_t new_reclen = (19 + (size_t)vpid_len + 1 + 7) & ~(size_t)7;

                if (out_pos + new_reclen <= buf_len) {
                    memset(out_buf + out_pos, 0, new_reclen);
                    /* Copy header (d_ino, d_off, d_type) */
                    memcpy(out_buf + out_pos, in_buf + in_pos, 18);
                    out_buf[out_pos + 18] = in_buf[in_pos + 18]; /* d_type */
                    /* Write new reclen */
                    uint16_t nr = (uint16_t)new_reclen;
                    memcpy(out_buf + out_pos + 16, &nr, 2);
                    /* Write translated name */
                    memcpy(out_buf + out_pos + 19, vpid_str, (size_t)vpid_len + 1);
                    out_pos += new_reclen;
                }
            }
            /* else: PID not in namespace, filter out */
        }

        in_pos += reclen;
    }

    /* Write filtered buffer back to tracee */
    if (out_pos > 0) {
        rc = klee_write_mem(ic, ev->pid, dirp_addr, out_buf, out_pos);
        if (rc < 0) {
            free(in_buf);
            free(out_buf);
            return 0;
        }
    }

    ev->retval = (long)out_pos;
    free(in_buf);
    free(out_buf);
    return 1;
}

/* ==================== UID/GID Exit Handlers ==================== */

int klee_exit_getuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;
    if (proc->skip_uid_virt)
        return 0;
    ev->retval = proc->id_state->ruid;
    return 1;
}

int klee_exit_geteuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;
    if (proc->skip_uid_virt)
        return 0;
    ev->retval = proc->id_state->euid;
    return 1;
}

int klee_exit_getgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;
    if (proc->skip_uid_virt)
        return 0;
    ev->retval = proc->id_state->rgid;
    return 1;
}

int klee_exit_getegid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    if (!proc->sandbox || !proc->sandbox->unshare_user || !proc->id_state)
        return 0;
    if (proc->skip_uid_virt)
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
    if (proc->skip_uid_virt)
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
    if (proc->skip_uid_virt)
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
    if (proc->skip_uid_virt)
        return 0;
    /* Return single group matching virtual gid */
    ev->retval = 1;
    return 1;
}

/* ==================== UTS Namespace Exit Handler ==================== */

int klee_exit_uname(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (proc->sys32_flags & KLEE_SYS32_OLDSTRUCT)
        return 0;   /* oldolduname: 9-byte fields, leave it alone */
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

/* ==================== IPC Namespace Exit Handlers ==================== */

/* Record SysV objects created inside the sandbox so they are removed when
 * it exits.  arg0 still holds the real key written by the enter handler. */
static int track_ipc_object(KleeProcess *proc, KleeEvent *ev,
                            KleeIpcType type, int flags_arg)
{
    if (ev->retval < 0 || !proc->sandbox || !proc->sandbox->unshare_ipc ||
        !proc->sandbox->ipc_ns)
        return 0;

    key_t real_key = (key_t)ev->args[0];
    int flags = (int)ev->args[flags_arg];
    if (real_key == IPC_PRIVATE || (flags & IPC_CREAT))
        klee_ipc_ns_track_segment(proc->sandbox->ipc_ns, type,
                                  (int)ev->retval, real_key);
    return 0;
}

int klee_exit_shmget(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    return track_ipc_object(proc, ev, KLEE_IPC_SHM, 2);
}

int klee_exit_msgget(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    return track_ipc_object(proc, ev, KLEE_IPC_MSG, 1);
}

int klee_exit_semget(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    (void)ic;
    return track_ipc_object(proc, ev, KLEE_IPC_SEM, 2);
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
    /* Processes with skip_uid_virt expect real UID/GID everywhere.
     * Rewriting SO_PEERCRED to virtual values would cause mismatches. */
    if (proc->skip_uid_virt)
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

/* ==================== recvmsg SCM_CREDENTIALS Translation ==================== */

/*
 * Intercept recvmsg() exit to fix received SCM_CREDENTIALS.
 *
 * When klee virtualizes UID/GID (unshare_user), the kernel fills
 * SCM_CREDENTIALS with the sender's REAL pid/uid/gid.  If the sender
 * is another klee-traced process with UID virtualization, the receiver
 * sees the real UID (e.g. 0) instead of the virtual UID (e.g. 1000).
 *
 * This breaks D-Bus EXTERNAL authentication: the D-Bus server compares
 * the AUTH EXTERNAL uid (virtual, from getuid()) against the credentials
 * from SCM_CREDENTIALS (real, from kernel).  By translating the received
 * credentials to match the virtual UID, D-Bus auth succeeds.
 */
int klee_exit_recvmsg(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev)
{
    if (ev->retval < 0)
        return 0;
    if (!proc->id_state || !proc->sandbox)
        return 0;
    /* Processes with skip_uid_virt expect real UID/GID everywhere.
     * Rewriting SCM_CREDENTIALS to virtual values would break them. */
    if (proc->skip_uid_virt)
        return 0;

    /* recvmsg(int sockfd, struct msghdr *msg, int flags) */
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

    bool modified = false;
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();

    size_t off = 0, data_off, data_len;
    int level, type;
    while (klee_abi_cmsg_next(proc->abi, ctrl_buf, ctrllen, &off,
                              &level, &type, &data_off, &data_len)) {
        if (level != SOL_SOCKET || type != SCM_CREDENTIALS ||
            data_len < sizeof(struct ucred))
            continue;
        struct ucred cred;
        memcpy(&cred, ctrl_buf + data_off, sizeof(cred));
        if (cred.uid != real_uid && cred.gid != real_gid)
            continue;

        KLEE_TRACE("recvmsg SCM_CREDENTIALS: pid=%d uid=%d gid=%d -> "
                   "uid=%d gid=%d",
                   cred.pid, cred.uid, cred.gid,
                   proc->id_state->euid, proc->id_state->egid);

        if (cred.uid == real_uid)
            cred.uid = proc->id_state->euid;
        if (cred.gid == real_gid)
            cred.gid = proc->id_state->egid;

        /* Translate PID if PID namespace is active */
        if (proc->sandbox->unshare_pid && proc->sandbox->pid_map) {
            pid_t vpid = klee_pid_map_r2v(proc->sandbox->pid_map, cred.pid);
            if (vpid > 0)
                cred.pid = vpid;
            else if (cred.pid > 0)
                cred.pid = 0;
        }

        memcpy(ctrl_buf + data_off, &cred, sizeof(cred));
        modified = true;
    }

    if (!modified)
        return 0;

    rc = klee_write_mem(ic, ev->pid, (void *)(uintptr_t)ctrl_addr, ctrl_buf,
                        ctrllen);
    if (rc < 0)
        KLEE_DEBUG("recvmsg: failed to write back SCM_CREDENTIALS: %d", rc);

    return 0;
}
