/*
 * Klee - Userspace bwrap translation layer
 * pivot_root simulation
 */
#ifndef KLEE_PIVOT_H
#define KLEE_PIVOT_H

#include "fs/mount_table.h"

/* Simulate pivot_root by setting the virtual root prefix.
 * All absolute paths in the guest will be prefixed with new_root. */
int klee_pivot_root(KleeMountTable *mt, const char *new_root,
                     const char *put_old);

#endif /* KLEE_PIVOT_H */
