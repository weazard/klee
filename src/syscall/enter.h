/*
 * Klee - Userspace bwrap translation layer
 * Syscall-enter handlers (path rewriting, RO enforcement)
 */
#ifndef KLEE_ENTER_H
#define KLEE_ENTER_H

#include "process/process.h"
#include "intercept/intercept.h"

/* Filesystem path-rewriting enter handlers */
int klee_enter_open(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_openat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_openat2(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_stat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_lstat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_newfstatat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_statx(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_access(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_faccessat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_readlink(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_readlinkat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_execve(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_execveat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

int klee_enter_rename(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_renameat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_renameat2(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_mkdir(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_mkdirat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_rmdir(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_unlink(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_unlinkat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_link(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_linkat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_symlink(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_symlinkat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_chmod(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_fchmodat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_chown(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_lchown(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_fchownat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_truncate(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_mknod(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_mknodat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

int klee_enter_chdir(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_chroot(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_mount(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_umount(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_close(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

/* unotify enter-time handlers (for exit-only syscalls under seccomp_unotify) */
int klee_enter_fstat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_getpid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_getppid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_gettid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_getcwd(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_getuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_geteuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_getgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_getegid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_getresuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_getresgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_getgroups(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_uname(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_getpgrp(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_fchdir(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

/* PID namespace */
int klee_enter_kill(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_tgkill(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_tkill(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_setpgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_getpgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_getsid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_ioctl(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

/* UID/GID */
int klee_enter_setuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_setgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_setreuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_setregid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_setresuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_setresgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_setfsuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_setfsgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_setgroups(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

/* UTS / IPC */
int klee_enter_sethostname(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_shmget(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_msgget(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_semget(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

/* Socket AF_UNIX path translation */
int klee_enter_bind(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_connect(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

/* Socket credential translation */
int klee_enter_sendmsg(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

/* Misc */
int klee_enter_ptrace(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_prctl(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_seccomp(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_inotify_add_watch(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_enter_io_uring_setup(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

#endif /* KLEE_ENTER_H */
