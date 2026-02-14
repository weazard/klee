/*
 * Klee - Userspace bwrap translation layer
 * Read-only mount enforcement
 */
#ifndef KLEE_READONLY_H
#define KLEE_READONLY_H

#include "fs/mount_table.h"
#include <stdbool.h>

/* Check if a syscall on the given path should be blocked due to read-only mount.
 * Returns true if the operation should be denied with EROFS. */
bool klee_readonly_check_path(const KleeMountTable *mt, const char *guest_path,
                               int syscall_nr);

/* Check if an open() with the given flags should be blocked */
bool klee_readonly_check_open(const KleeMountTable *mt, const char *guest_path,
                               int flags);

#endif /* KLEE_READONLY_H */
