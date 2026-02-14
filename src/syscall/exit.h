/*
 * Klee - Userspace bwrap translation layer
 * Syscall-exit handlers (stat/readlink rewriting, PID/UID virtualization)
 */
#ifndef KLEE_EXIT_H
#define KLEE_EXIT_H

#include "process/process.h"
#include "intercept/intercept.h"

/* Filesystem exit handlers */
int klee_exit_open(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_stat(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_statx(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_readlink(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_chdir(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_fchdir(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_getcwd(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

/* FD tracking exit handlers */
int klee_exit_dup(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_dup2(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_dup3(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_fcntl(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

/* PID namespace exit handlers */
int klee_exit_getpid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_getppid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_gettid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

/* UID/GID exit handlers */
int klee_exit_getuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_geteuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_getgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_getegid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_getresuid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_getresgid(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_getgroups(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

/* UTS namespace */
int klee_exit_uname(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

/* Misc */
int klee_exit_prctl(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);
int klee_exit_getsockopt(KleeProcess *proc, KleeInterceptor *ic, KleeEvent *ev);

#endif /* KLEE_EXIT_H */
