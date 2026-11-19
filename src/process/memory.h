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

struct klee_process;

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

/* Read a path argument. Returns its length excluding NUL or negative errno. */
int klee_read_path(KleeInterceptor *ic, pid_t pid,
                   char *buf, size_t buf_size, const void *remote_addr);

/* Stage arguments below the tracee's red zone within its stack mapping. */
int klee_scratch_write(struct klee_process *proc, KleeInterceptor *ic,
                        const void *data, size_t len, uint64_t *addr);
int klee_scratch_string(struct klee_process *proc, KleeInterceptor *ic,
                         const char *str, uint64_t *addr);

#endif /* KLEE_MEMORY_H */
