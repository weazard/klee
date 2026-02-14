/*
 * Klee - Userspace bwrap translation layer
 * Tracee memory read/write utilities
 */
#ifndef KLEE_MEMORY_H
#define KLEE_MEMORY_H

#include "intercept/intercept.h"
#include <sys/types.h>
#include <stddef.h>
#include <linux/limits.h>

/* Read a NUL-terminated string from tracee memory.
 * Returns length read (excluding NUL), or negative errno. */
int klee_read_string(KleeInterceptor *ic, pid_t pid,
                     char *buf, size_t buf_size, const void *remote_addr);

/* Write a NUL-terminated string to tracee memory.
 * Returns 0 on success, negative errno on failure. */
int klee_write_string(KleeInterceptor *ic, pid_t pid,
                      void *remote_addr, const char *str);

/* Read raw bytes from tracee */
static inline int klee_read_mem(KleeInterceptor *ic, pid_t pid,
                                void *local, const void *remote, size_t len)
{
    return ic->read_mem(ic, pid, local, remote, len);
}

/* Write raw bytes to tracee */
static inline int klee_write_mem(KleeInterceptor *ic, pid_t pid,
                                 const void *remote, const void *local, size_t len)
{
    return ic->write_mem(ic, pid, remote, local, len);
}

/* Read a path argument from tracee at the given address.
 * Handles dirfd-relative paths (AT_FDCWD, etc.).
 * Returns 0 on success with path in buf. */
int klee_read_path(KleeInterceptor *ic, pid_t pid,
                   char *buf, size_t buf_size, const void *remote_addr);

#endif /* KLEE_MEMORY_H */
