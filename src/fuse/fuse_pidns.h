/*
 * Klee - Userspace bwrap translation layer
 * /proc/[pid] directory filtering
 */
#ifndef KLEE_FUSE_PIDNS_H
#define KLEE_FUSE_PIDNS_H

#include "ns/pid_ns.h"
#include <stdbool.h>

/* Check if a /proc directory entry should be visible in the PID namespace */
bool klee_pidns_filter_proc_entry(const KleePidMap *pm, const char *name);

#endif /* KLEE_FUSE_PIDNS_H */
