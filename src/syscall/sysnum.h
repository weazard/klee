/*
 * Klee - Userspace bwrap translation layer
 * x86_64 syscall number constants
 */
#ifndef KLEE_SYSNUM_H
#define KLEE_SYSNUM_H

#include <sys/syscall.h>
#include <stddef.h>

/* Filesystem syscalls */
#define KLEE_SYS_open            SYS_open
#define KLEE_SYS_openat          SYS_openat
#define KLEE_SYS_stat            SYS_stat
#define KLEE_SYS_lstat           SYS_lstat
#define KLEE_SYS_fstat           SYS_fstat
#define KLEE_SYS_access          SYS_access
#define KLEE_SYS_faccessat       SYS_faccessat
#ifdef SYS_faccessat2
#define KLEE_SYS_faccessat2      SYS_faccessat2
#endif
#define KLEE_SYS_readlink        SYS_readlink
#define KLEE_SYS_readlinkat      SYS_readlinkat
#define KLEE_SYS_execve          SYS_execve
#define KLEE_SYS_execveat        SYS_execveat
#define KLEE_SYS_rename          SYS_rename
#define KLEE_SYS_renameat        SYS_renameat
#define KLEE_SYS_renameat2       SYS_renameat2
#define KLEE_SYS_mkdir           SYS_mkdir
#define KLEE_SYS_mkdirat         SYS_mkdirat
#define KLEE_SYS_rmdir           SYS_rmdir
#define KLEE_SYS_unlink          SYS_unlink
#define KLEE_SYS_unlinkat        SYS_unlinkat
#define KLEE_SYS_link            SYS_link
#define KLEE_SYS_linkat          SYS_linkat
#define KLEE_SYS_symlink         SYS_symlink
#define KLEE_SYS_symlinkat       SYS_symlinkat
#define KLEE_SYS_chmod           SYS_chmod
#define KLEE_SYS_fchmod          SYS_fchmod
#define KLEE_SYS_fchmodat        SYS_fchmodat
#define KLEE_SYS_chown           SYS_chown
#define KLEE_SYS_lchown          SYS_lchown
#define KLEE_SYS_fchown          SYS_fchown
#define KLEE_SYS_fchownat        SYS_fchownat
#define KLEE_SYS_chdir           SYS_chdir
#define KLEE_SYS_fchdir          SYS_fchdir
#define KLEE_SYS_chroot          SYS_chroot
#define KLEE_SYS_mount           SYS_mount
#define KLEE_SYS_umount2         SYS_umount2
#define KLEE_SYS_mknod           SYS_mknod
#define KLEE_SYS_mknodat         SYS_mknodat
#define KLEE_SYS_getdents64      SYS_getdents64
#define KLEE_SYS_truncate        SYS_truncate
#define KLEE_SYS_creat           SYS_creat
#define KLEE_SYS_close           SYS_close
#define KLEE_SYS_dup             SYS_dup
#define KLEE_SYS_dup2            SYS_dup2
#define KLEE_SYS_dup3            SYS_dup3
#define KLEE_SYS_fcntl           SYS_fcntl
#define KLEE_SYS_getcwd          SYS_getcwd
#ifdef SYS_newfstatat
#define KLEE_SYS_newfstatat      SYS_newfstatat
#endif
#ifdef SYS_statx
#define KLEE_SYS_statx           SYS_statx
#endif
#ifdef SYS_openat2
#define KLEE_SYS_openat2         SYS_openat2
#endif
#ifdef SYS_name_to_handle_at
#define KLEE_SYS_name_to_handle_at SYS_name_to_handle_at
#endif
#ifdef SYS_open_by_handle_at
#define KLEE_SYS_open_by_handle_at SYS_open_by_handle_at
#endif

/* /proc-related */
#define KLEE_SYS_getdents        SYS_getdents

/* Process syscalls */
#define KLEE_SYS_fork            SYS_fork
#define KLEE_SYS_vfork           SYS_vfork
#define KLEE_SYS_clone           SYS_clone
#ifdef SYS_clone3
#define KLEE_SYS_clone3          SYS_clone3
#endif
#define KLEE_SYS_getpid          SYS_getpid
#define KLEE_SYS_getppid         SYS_getppid
#define KLEE_SYS_gettid          SYS_gettid
#define KLEE_SYS_kill            SYS_kill
#define KLEE_SYS_tgkill          SYS_tgkill
#define KLEE_SYS_tkill           SYS_tkill
#define KLEE_SYS_setpgid         SYS_setpgid
#define KLEE_SYS_getpgid         SYS_getpgid
#define KLEE_SYS_getpgrp         SYS_getpgrp
#define KLEE_SYS_setsid          SYS_setsid
#define KLEE_SYS_getsid          SYS_getsid
#define KLEE_SYS_wait4           SYS_wait4
#define KLEE_SYS_waitid          SYS_waitid
#define KLEE_SYS_exit            SYS_exit
#define KLEE_SYS_exit_group      SYS_exit_group

/* UID/GID syscalls */
#define KLEE_SYS_getuid          SYS_getuid
#define KLEE_SYS_geteuid         SYS_geteuid
#define KLEE_SYS_getgid          SYS_getgid
#define KLEE_SYS_getegid         SYS_getegid
#define KLEE_SYS_getresuid       SYS_getresuid
#define KLEE_SYS_getresgid       SYS_getresgid
#define KLEE_SYS_setuid          SYS_setuid
#define KLEE_SYS_seteuid         SYS_seteuid
#define KLEE_SYS_setgid          SYS_setgid
#define KLEE_SYS_setegid         SYS_setegid
#define KLEE_SYS_setreuid        SYS_setreuid
#define KLEE_SYS_setregid        SYS_setregid
#define KLEE_SYS_setresuid       SYS_setresuid
#define KLEE_SYS_setresgid       SYS_setresgid
#define KLEE_SYS_setfsuid        SYS_setfsuid
#define KLEE_SYS_setfsgid        SYS_setfsgid
#define KLEE_SYS_setgroups       SYS_setgroups
#define KLEE_SYS_getgroups       SYS_getgroups

/* UTS/IPC */
#define KLEE_SYS_uname           SYS_uname
#define KLEE_SYS_sethostname     SYS_sethostname
#define KLEE_SYS_setdomainname   SYS_setdomainname
#define KLEE_SYS_shmget          SYS_shmget
#define KLEE_SYS_msgget          SYS_msgget
#define KLEE_SYS_semget          SYS_semget

/* Socket */
#define KLEE_SYS_getsockopt      SYS_getsockopt
#define KLEE_SYS_connect         SYS_connect
#define KLEE_SYS_bind            SYS_bind
#define KLEE_SYS_sendmsg         SYS_sendmsg
#define KLEE_SYS_recvmsg         SYS_recvmsg
#define KLEE_SYS_recvfrom        SYS_recvfrom

/* Terminal/ioctl */
#define KLEE_SYS_ioctl           SYS_ioctl

/* Misc */
#define KLEE_SYS_ptrace          SYS_ptrace
#define KLEE_SYS_prctl           SYS_prctl
#define KLEE_SYS_seccomp         SYS_seccomp
#define KLEE_SYS_inotify_add_watch SYS_inotify_add_watch
#define KLEE_SYS_memfd_create    SYS_memfd_create
#ifdef SYS_io_uring_setup
#define KLEE_SYS_io_uring_setup  SYS_io_uring_setup
#endif
#ifdef SYS_io_uring_enter
#define KLEE_SYS_io_uring_enter  SYS_io_uring_enter
#endif

/* Total number of syscalls we intercept (must be >= actual count in handlers.c) */
#define KLEE_INTERCEPTED_SYSCALL_COUNT 128

/* Get the list of all syscall numbers to intercept */
int klee_get_intercepted_syscalls(int *out, size_t max_count);

#endif /* KLEE_SYSNUM_H */
