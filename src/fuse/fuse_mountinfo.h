/*
 * Klee - Userspace bwrap translation layer
 * /proc/self/mountinfo generation
 */
#ifndef KLEE_FUSE_MOUNTINFO_H
#define KLEE_FUSE_MOUNTINFO_H

#include "fs/mount_table.h"
#include <stddef.h>

/* Generate synthetic /proc/self/mountinfo content from mount table */
int klee_gen_mountinfo(const KleeMountTable *mt, char *buf, size_t buf_size);

#endif /* KLEE_FUSE_MOUNTINFO_H */
