/*
 * Klee - Userspace bwrap translation layer
 * Per-syscall handler registration
 */
#include "syscall/handlers.h"
#include "syscall/sysnum.h"

int klee_get_intercepted_syscalls(int *out, size_t max_count)
{
    static const int syscalls[] = {
        /* Filesystem */
        KLEE_SYS_open,
        KLEE_SYS_openat,
        KLEE_SYS_stat,
        KLEE_SYS_lstat,
        KLEE_SYS_fstat,
        KLEE_SYS_access,
        KLEE_SYS_faccessat,
        KLEE_SYS_readlink,
        KLEE_SYS_readlinkat,
        KLEE_SYS_execve,
        KLEE_SYS_execveat,
        KLEE_SYS_rename,
        KLEE_SYS_renameat,
        KLEE_SYS_renameat2,
        KLEE_SYS_mkdir,
        KLEE_SYS_mkdirat,
        KLEE_SYS_rmdir,
        KLEE_SYS_unlink,
        KLEE_SYS_unlinkat,
        KLEE_SYS_link,
        KLEE_SYS_linkat,
        KLEE_SYS_symlink,
        KLEE_SYS_symlinkat,
        KLEE_SYS_chmod,
        KLEE_SYS_fchmodat,
        KLEE_SYS_chown,
        KLEE_SYS_lchown,
        KLEE_SYS_fchownat,
        KLEE_SYS_chdir,
        KLEE_SYS_fchdir,
        KLEE_SYS_chroot,
        KLEE_SYS_mount,
        KLEE_SYS_umount2,
        KLEE_SYS_mknod,
        KLEE_SYS_mknodat,
        KLEE_SYS_truncate,
        KLEE_SYS_creat,
        KLEE_SYS_getcwd,
        KLEE_SYS_getdents64,
        KLEE_SYS_inotify_add_watch,

        /* FD tracking */
        KLEE_SYS_close,
        KLEE_SYS_dup,
        KLEE_SYS_dup2,
        KLEE_SYS_dup3,
        KLEE_SYS_fcntl,

        /* PID namespace */
        KLEE_SYS_getpid,
        KLEE_SYS_getppid,
        KLEE_SYS_gettid,
        KLEE_SYS_kill,
        KLEE_SYS_tgkill,
        KLEE_SYS_tkill,
        KLEE_SYS_clone,
        KLEE_SYS_fork,
        KLEE_SYS_vfork,
        KLEE_SYS_wait4,
        KLEE_SYS_waitid,
        KLEE_SYS_setpgid,
        KLEE_SYS_getpgid,
        KLEE_SYS_getpgrp,
        KLEE_SYS_setsid,
        KLEE_SYS_getsid,

        /* UID/GID */
        KLEE_SYS_getuid,
        KLEE_SYS_geteuid,
        KLEE_SYS_getgid,
        KLEE_SYS_getegid,
        KLEE_SYS_getresuid,
        KLEE_SYS_getresgid,
        KLEE_SYS_setuid,
        KLEE_SYS_setgid,
        KLEE_SYS_setreuid,
        KLEE_SYS_setregid,
        KLEE_SYS_setresuid,
        KLEE_SYS_setresgid,
        KLEE_SYS_setfsuid,
        KLEE_SYS_setfsgid,
        KLEE_SYS_setgroups,
        KLEE_SYS_getgroups,

        /* UTS */
        KLEE_SYS_uname,
        KLEE_SYS_sethostname,

        /* IPC */
        KLEE_SYS_shmget,
        KLEE_SYS_msgget,
        KLEE_SYS_semget,

        /* Socket */
        KLEE_SYS_bind,
        KLEE_SYS_connect,
        KLEE_SYS_sendmsg,
        KLEE_SYS_recvmsg,
        KLEE_SYS_recvfrom,

        /* Terminal/ioctl */
        KLEE_SYS_ioctl,

        /* Misc */
        KLEE_SYS_prctl,
        KLEE_SYS_seccomp,
        KLEE_SYS_getsockopt,
        KLEE_SYS_memfd_create,

#ifdef KLEE_SYS_newfstatat
        KLEE_SYS_newfstatat,
#endif
#ifdef KLEE_SYS_statx
        KLEE_SYS_statx,
#endif
#ifdef KLEE_SYS_openat2
        KLEE_SYS_openat2,
#endif
#ifdef KLEE_SYS_faccessat2
        KLEE_SYS_faccessat2,
#endif
#ifdef KLEE_SYS_clone3
        KLEE_SYS_clone3,
#endif
#ifdef KLEE_SYS_io_uring_setup
        KLEE_SYS_io_uring_setup,
#endif
    };

    size_t count = sizeof(syscalls) / sizeof(syscalls[0]);
    if (count > max_count)
        count = max_count;

    for (size_t i = 0; i < count; i++)
        out[i] = syscalls[i];

    return (int)count;
}
