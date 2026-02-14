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

#endif /* KLEE_SECCOMP_NOTIF_H */
