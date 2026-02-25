/*
 * Klee - Userspace bwrap translation layer
 * Table-driven syscall dispatch implementation
 */
#include "syscall/dispatch.h"
#include "syscall/enter.h"
#include "syscall/exit.h"
#include "syscall/handlers.h"
#include "syscall/sysnum.h"
#include "util/log.h"

#include <string.h>

/* Dispatch table: indexed by syscall number for fast lookup */
#define MAX_SYSCALL_NR 512

static KleeSyscallHandler dispatch_table[MAX_SYSCALL_NR];
static bool dispatch_initialized = false;

static void register_handler(int nr, const char *name,
                              klee_syscall_enter_fn enter,
                              klee_syscall_exit_fn exit_fn)
{
    if (nr >= 0 && nr < MAX_SYSCALL_NR) {
        dispatch_table[nr].syscall_nr = nr;
        dispatch_table[nr].name = name;
        dispatch_table[nr].enter = enter;
        dispatch_table[nr].exit = exit_fn;
    }
}

void klee_dispatch_init(void)
{
    if (dispatch_initialized)
        return;

    memset(dispatch_table, 0, sizeof(dispatch_table));

    /* Filesystem path-rewriting syscalls (enter handlers) */
    register_handler(KLEE_SYS_open,      "open",      klee_enter_open, klee_exit_open);
    register_handler(KLEE_SYS_openat,    "openat",    klee_enter_openat, klee_exit_open);
#ifdef KLEE_SYS_openat2
    register_handler(KLEE_SYS_openat2,   "openat2",   klee_enter_openat2, klee_exit_open);
#endif
    register_handler(KLEE_SYS_stat,      "stat",      klee_enter_stat, klee_exit_stat);
    register_handler(KLEE_SYS_lstat,     "lstat",     klee_enter_lstat, klee_exit_stat);
    register_handler(KLEE_SYS_fstat,     "fstat",     NULL, klee_exit_stat);
#ifdef KLEE_SYS_newfstatat
    register_handler(KLEE_SYS_newfstatat,"newfstatat", klee_enter_newfstatat, klee_exit_stat);
#endif
#ifdef KLEE_SYS_statx
    register_handler(KLEE_SYS_statx,     "statx",     klee_enter_statx, klee_exit_statx);
#endif
    register_handler(KLEE_SYS_access,    "access",    klee_enter_access, NULL);
    register_handler(KLEE_SYS_faccessat, "faccessat", klee_enter_faccessat, NULL);
#ifdef KLEE_SYS_faccessat2
    register_handler(KLEE_SYS_faccessat2,"faccessat2",klee_enter_faccessat, NULL);
#endif
    register_handler(KLEE_SYS_readlink,  "readlink",  klee_enter_readlink, klee_exit_readlink);
    register_handler(KLEE_SYS_readlinkat,"readlinkat", klee_enter_readlinkat, klee_exit_readlink);
    register_handler(KLEE_SYS_execve,    "execve",    klee_enter_execve, NULL);
    register_handler(KLEE_SYS_execveat,  "execveat",  klee_enter_execveat, NULL);

    register_handler(KLEE_SYS_rename,    "rename",    klee_enter_rename, NULL);
    register_handler(KLEE_SYS_renameat,  "renameat",  klee_enter_renameat, NULL);
    register_handler(KLEE_SYS_renameat2, "renameat2", klee_enter_renameat2, NULL);
    register_handler(KLEE_SYS_mkdir,     "mkdir",     klee_enter_mkdir, NULL);
    register_handler(KLEE_SYS_mkdirat,   "mkdirat",   klee_enter_mkdirat, NULL);
    register_handler(KLEE_SYS_rmdir,     "rmdir",     klee_enter_rmdir, NULL);
    register_handler(KLEE_SYS_unlink,    "unlink",    klee_enter_unlink, NULL);
    register_handler(KLEE_SYS_unlinkat,  "unlinkat",  klee_enter_unlinkat, NULL);
    register_handler(KLEE_SYS_link,      "link",      klee_enter_link, NULL);
    register_handler(KLEE_SYS_linkat,    "linkat",    klee_enter_linkat, NULL);
    register_handler(KLEE_SYS_symlink,   "symlink",   klee_enter_symlink, NULL);
    register_handler(KLEE_SYS_symlinkat, "symlinkat", klee_enter_symlinkat, NULL);
    register_handler(KLEE_SYS_chmod,     "chmod",     klee_enter_chmod, NULL);
    register_handler(KLEE_SYS_fchmodat,  "fchmodat",  klee_enter_fchmodat, NULL);
    register_handler(KLEE_SYS_chown,     "chown",     klee_enter_chown, NULL);
    register_handler(KLEE_SYS_lchown,    "lchown",    klee_enter_lchown, NULL);
    register_handler(KLEE_SYS_fchownat,  "fchownat",  klee_enter_fchownat, NULL);
    register_handler(KLEE_SYS_truncate,  "truncate",  klee_enter_truncate, NULL);
    register_handler(KLEE_SYS_mknod,     "mknod",     klee_enter_mknod, NULL);
    register_handler(KLEE_SYS_mknodat,   "mknodat",   klee_enter_mknodat, NULL);

    register_handler(KLEE_SYS_chdir,     "chdir",     klee_enter_chdir, klee_exit_chdir);
    register_handler(KLEE_SYS_fchdir,    "fchdir",    NULL, klee_exit_fchdir);
    register_handler(KLEE_SYS_getcwd,    "getcwd",    NULL, klee_exit_getcwd);
    register_handler(KLEE_SYS_chroot,    "chroot",    klee_enter_chroot, NULL);
    register_handler(KLEE_SYS_mount,     "mount",     klee_enter_mount, NULL);
    register_handler(KLEE_SYS_umount2,   "umount2",   klee_enter_umount, NULL);

    /* FD tracking */
    register_handler(KLEE_SYS_close,     "close",     klee_enter_close, NULL);
    register_handler(KLEE_SYS_dup,       "dup",       NULL, klee_exit_dup);
    register_handler(KLEE_SYS_dup2,      "dup2",      NULL, klee_exit_dup2);
    register_handler(KLEE_SYS_dup3,      "dup3",      NULL, klee_exit_dup3);
    register_handler(KLEE_SYS_fcntl,     "fcntl",     NULL, klee_exit_fcntl);
    register_handler(KLEE_SYS_getdents64, "getdents64", NULL, klee_exit_getdents64);

    /* PID namespace */
    register_handler(KLEE_SYS_getpid,    "getpid",    NULL, klee_exit_getpid);
    register_handler(KLEE_SYS_getppid,   "getppid",   NULL, klee_exit_getppid);
    register_handler(KLEE_SYS_gettid,    "gettid",    NULL, klee_exit_gettid);
    register_handler(KLEE_SYS_kill,      "kill",      klee_enter_kill, NULL);
    register_handler(KLEE_SYS_tgkill,    "tgkill",    klee_enter_tgkill, NULL);
    register_handler(KLEE_SYS_tkill,     "tkill",     klee_enter_tkill, NULL);
    register_handler(KLEE_SYS_setpgid,   "setpgid",   klee_enter_setpgid, NULL);
    register_handler(KLEE_SYS_getpgid,   "getpgid",   klee_enter_getpgid, klee_exit_getpgid);
    register_handler(KLEE_SYS_getpgrp,   "getpgrp",   NULL, klee_exit_getpgrp);
    register_handler(KLEE_SYS_setsid,    "setsid",    NULL, klee_exit_setsid);
    register_handler(KLEE_SYS_getsid,    "getsid",    klee_enter_getsid, klee_exit_getsid);
    register_handler(KLEE_SYS_ioctl,    "ioctl",     klee_enter_ioctl, klee_exit_ioctl);

    /* UID/GID */
    register_handler(KLEE_SYS_getuid,    "getuid",    NULL, klee_exit_getuid);
    register_handler(KLEE_SYS_geteuid,   "geteuid",   NULL, klee_exit_geteuid);
    register_handler(KLEE_SYS_getgid,    "getgid",    NULL, klee_exit_getgid);
    register_handler(KLEE_SYS_getegid,   "getegid",   NULL, klee_exit_getegid);
    register_handler(KLEE_SYS_getresuid, "getresuid", NULL, klee_exit_getresuid);
    register_handler(KLEE_SYS_getresgid, "getresgid", NULL, klee_exit_getresgid);
    register_handler(KLEE_SYS_setuid,    "setuid",    klee_enter_setuid, NULL);
    register_handler(KLEE_SYS_setgid,    "setgid",    klee_enter_setgid, NULL);
    register_handler(KLEE_SYS_setreuid,  "setreuid",  klee_enter_setreuid, NULL);
    register_handler(KLEE_SYS_setregid,  "setregid",  klee_enter_setregid, NULL);
    register_handler(KLEE_SYS_setresuid, "setresuid", klee_enter_setresuid, NULL);
    register_handler(KLEE_SYS_setresgid, "setresgid", klee_enter_setresgid, NULL);
    register_handler(KLEE_SYS_setfsuid,  "setfsuid",  klee_enter_setfsuid, NULL);
    register_handler(KLEE_SYS_setfsgid,  "setfsgid",  klee_enter_setfsgid, NULL);
    register_handler(KLEE_SYS_setgroups, "setgroups", klee_enter_setgroups, NULL);
    register_handler(KLEE_SYS_getgroups, "getgroups", NULL, klee_exit_getgroups);

    /* UTS namespace */
    register_handler(KLEE_SYS_uname,     "uname",     NULL, klee_exit_uname);
    register_handler(KLEE_SYS_sethostname,"sethostname", klee_enter_sethostname, NULL);

    /* IPC namespace */
    register_handler(KLEE_SYS_shmget,    "shmget",    klee_enter_shmget, NULL);
    register_handler(KLEE_SYS_msgget,    "msgget",    klee_enter_msgget, NULL);
    register_handler(KLEE_SYS_semget,    "semget",    klee_enter_semget, NULL);

    /* Socket AF_UNIX path translation */
    register_handler(KLEE_SYS_bind,      "bind",      klee_enter_bind, NULL);
    register_handler(KLEE_SYS_connect,   "connect",   klee_enter_connect, NULL);
    register_handler(KLEE_SYS_sendmsg,   "sendmsg",   klee_enter_sendmsg, NULL);

    /* Misc */
    register_handler(KLEE_SYS_ptrace,    "ptrace",    klee_enter_ptrace, NULL);
    register_handler(KLEE_SYS_prctl,     "prctl",     klee_enter_prctl, klee_exit_prctl);
    register_handler(KLEE_SYS_seccomp,   "seccomp",   klee_enter_seccomp, NULL);
    register_handler(KLEE_SYS_getsockopt,"getsockopt", NULL, klee_exit_getsockopt);
    register_handler(KLEE_SYS_inotify_add_watch, "inotify_add_watch",
                     klee_enter_inotify_add_watch, NULL);

#ifdef KLEE_SYS_io_uring_setup
    register_handler(KLEE_SYS_io_uring_setup, "io_uring_setup",
                     klee_enter_io_uring_setup, NULL);
#endif

    dispatch_initialized = true;
    KLEE_DEBUG("dispatch table initialized");
}

int klee_dispatch_enter(KleeProcess *proc, KleeInterceptor *ic,
                         KleeEvent *event)
{
    int nr = event->syscall_nr;
    if (nr < 0 || nr >= MAX_SYSCALL_NR)
        return 0;

    const KleeSyscallHandler *h = &dispatch_table[nr];
    if (!h->enter)
        return 0;

    KLEE_TRACE("enter: pid=%d syscall=%s(%d)", proc->real_pid, h->name, nr);
    return h->enter(proc, ic, event);
}

int klee_dispatch_exit(KleeProcess *proc, KleeInterceptor *ic,
                        KleeEvent *event)
{
    int nr = event->syscall_nr;
    if (nr < 0 || nr >= MAX_SYSCALL_NR)
        return 0;

    const KleeSyscallHandler *h = &dispatch_table[nr];
    if (!h->exit)
        return 0;

    KLEE_TRACE("exit: pid=%d syscall=%s(%d) ret=%ld",
               proc->real_pid, h->name, nr, event->retval);
    return h->exit(proc, ic, event);
}

const KleeSyscallHandler *klee_dispatch_get(int syscall_nr)
{
    if (syscall_nr < 0 || syscall_nr >= MAX_SYSCALL_NR)
        return NULL;
    if (!dispatch_table[syscall_nr].name)
        return NULL;
    return &dispatch_table[syscall_nr];
}
