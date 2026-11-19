/*
 * Klee - Userspace bwrap translation layer
 * Per-syscall handler registration
 */
#include "syscall/handlers.h"
#include "syscall/sysnum.h"

#include <errno.h>

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
        KLEE_SYS_getdents,
        KLEE_SYS_getdents64,
        KLEE_SYS_inotify_add_watch,

        /* FD tracking */
        KLEE_SYS_close,
        KLEE_SYS_close_range,
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
        KLEE_SYS_sendto,
        KLEE_SYS_sendmsg,
        KLEE_SYS_recvmsg,
        KLEE_SYS_recvfrom,

        /* Terminal/ioctl */
        KLEE_SYS_ioctl,

        /* Misc */
        KLEE_SYS_prctl,
        KLEE_SYS_getsockopt,

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

        /* PID-targeting signal/pidfd calls. */
        KLEE_SYS_rt_sigqueueinfo,
        KLEE_SYS_rt_tgsigqueueinfo,
#ifdef KLEE_SYS_pidfd_open
        KLEE_SYS_pidfd_open,
#endif

        /* Path-taking syscalls that used to reach the host filesystem
         * untranslated (timestamps, xattrs, statfs, mount-id lookups). */
        KLEE_SYS_utimensat,
        KLEE_SYS_utimes,
        KLEE_SYS_utime,
        KLEE_SYS_futimesat,
        KLEE_SYS_setxattr,
        KLEE_SYS_lsetxattr,
        KLEE_SYS_getxattr,
        KLEE_SYS_lgetxattr,
        KLEE_SYS_listxattr,
        KLEE_SYS_llistxattr,
        KLEE_SYS_removexattr,
        KLEE_SYS_lremovexattr,
        KLEE_SYS_statfs,
        KLEE_SYS_fchmodat2,
        KLEE_SYS_fanotify_mark,
        KLEE_SYS_name_to_handle_at,
        KLEE_SYS_open_tree,

        /* PID-targeting syscalls: translate the pid and keep host
         * processes out of reach. */
        KLEE_SYS_sched_setaffinity,
        KLEE_SYS_sched_getaffinity,
        KLEE_SYS_sched_setscheduler,
        KLEE_SYS_sched_getscheduler,
        KLEE_SYS_sched_setparam,
        KLEE_SYS_sched_getparam,
        KLEE_SYS_sched_rr_get_interval,
        KLEE_SYS_sched_setattr,
        KLEE_SYS_sched_getattr,
        KLEE_SYS_prlimit64,
        KLEE_SYS_process_vm_readv,
        KLEE_SYS_process_vm_writev,
        KLEE_SYS_get_robust_list,
        KLEE_SYS_move_pages,
        KLEE_SYS_migrate_pages,
        KLEE_SYS_kcmp,
        KLEE_SYS_perf_event_open,
        KLEE_SYS_setpriority,
        KLEE_SYS_getpriority,
        KLEE_SYS_ioprio_set,
        KLEE_SYS_ioprio_get,

        /* What threads share: unshare() splits cwd/fd tables again */
        KLEE_SYS_unshare,
    };

    size_t count = sizeof(syscalls) / sizeof(syscalls[0]);
    if (count > max_count)
        return -E2BIG;

    for (size_t i = 0; i < count; i++)
        out[i] = syscalls[i];

    return (int)count;
}
