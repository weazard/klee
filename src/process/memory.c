/*
 * Klee - Userspace bwrap translation layer
 * Tracee memory read/write implementation
 */
#include "process/memory.h"
#include "util/log.h"

#include <string.h>
#include <errno.h>

/*
 * Read a NUL-terminated string from tracee memory one word at a time.
 * Using sizeof(long)-sized reads avoids page-crossing failures that
 * happen when a large chunk spans a mapped/unmapped boundary.
 */
int klee_read_string(KleeInterceptor *ic, pid_t pid,
                     char *buf, size_t buf_size, const void *remote_addr)
{
    if (!buf || buf_size == 0 || !remote_addr)
        return -EINVAL;

    size_t total = 0;
    const char *remote = remote_addr;

    while (total < buf_size - 1) {
        size_t chunk = sizeof(long);
        if (total + chunk >= buf_size)
            chunk = buf_size - 1 - total;

        int rc = ic->read_mem(ic, pid, buf + total, remote + total, chunk);
        if (rc < 0) {
            /* If we already read something, NUL-terminate and return it */
            if (total > 0) {
                buf[total] = '\0';
                return (int)total;
            }
            KLEE_DEBUG("read_string: read_mem failed at offset %zu: %d",
                       total, rc);
            return rc;
        }

        /* Check for NUL terminator in this chunk */
        for (size_t i = 0; i < chunk; i++) {
            if (buf[total + i] == '\0')
                return (int)(total + i);
        }
        total += chunk;
    }

    buf[buf_size - 1] = '\0';
    return (int)(buf_size - 1);
}

int klee_write_string(KleeInterceptor *ic, pid_t pid,
                      void *remote_addr, const char *str)
{
    if (!str || !remote_addr)
        return -EINVAL;

    size_t len = strlen(str) + 1;
    return ic->write_mem(ic, pid, remote_addr, str, len);
}

int klee_read_path(KleeInterceptor *ic, pid_t pid,
                   char *buf, size_t buf_size, const void *remote_addr)
{
    return klee_read_string(ic, pid, buf, buf_size, remote_addr);
}
