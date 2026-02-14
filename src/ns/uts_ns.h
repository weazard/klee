/*
 * Klee - Userspace bwrap translation layer
 * UTS namespace (uname/hostname)
 */
#ifndef KLEE_UTS_NS_H
#define KLEE_UTS_NS_H

#include "process/process.h"

/* Set the virtual hostname for a sandbox */
void klee_uts_set_hostname(KleeSandbox *sb, const char *hostname);

/* Get the virtual hostname */
const char *klee_uts_get_hostname(const KleeSandbox *sb);

#endif /* KLEE_UTS_NS_H */
