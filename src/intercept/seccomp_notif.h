/*
 * Klee - Userspace bwrap translation layer
 * seccomp_unotify backend
 */
#ifndef KLEE_SECCOMP_NOTIF_H
#define KLEE_SECCOMP_NOTIF_H

#include "intercept.h"

/* Create a seccomp_unotify backend interceptor */
KleeInterceptor *klee_seccomp_notif_create(void);

/* Check if seccomp_unotify is available on this kernel */
int klee_seccomp_notif_available(void);

/* Respond by returning a specific value (skip the real syscall).
 * Used when an enter handler fully handles the syscall for unotify
 * (e.g., getpid returning a virtual PID). */
int klee_seccomp_notif_respond_value(KleeInterceptor *ic, KleeEvent *event,
                                      long retval);

/* Transfer the seccomp listener FD from child to parent */
int klee_seccomp_notif_send_fd(KleeInterceptor *ic, int listener_fd);
int klee_seccomp_notif_recv_fd(KleeInterceptor *ic);

#endif /* KLEE_SECCOMP_NOTIF_H */
