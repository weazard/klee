/*
 * Klee - Userspace bwrap translation layer
 * Tracee memory read/write implementation
 */
#include "process/memory.h"
#include "process/regs.h"

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <inttypes.h>

int klee_read_string(KleeInterceptor *ic, pid_t pid,
                     char *buf, size_t buf_size, const void *remote_addr)
{
    if (!buf || buf_size == 0)
        return -EINVAL;
    buf[0] = '\0';
    if (!remote_addr)
        return -EFAULT;

    size_t total = 0;
    uintptr_t remote = (uintptr_t)remote_addr;
    if (buf_size > UINTPTR_MAX - remote)
        return -EFAULT;
    while (total < buf_size) {
        /* Aligned chunks never cross an x86 page boundary. */
#ifdef HAVE_PROCESS_VM
        size_t granularity = 128;
#else
        size_t granularity = sizeof(long);
#endif
        size_t chunk = granularity - (remote + total) % granularity;
        if (chunk > buf_size - total)
            chunk = buf_size - total;

        int rc = ic->read_mem(ic, pid, buf + total,
                              (const void *)(remote + total), chunk);
        if (rc < 0) {
            buf[0] = '\0';
            return rc == -EIO ? -EFAULT : rc;
        }

        char *end = memchr(buf + total, '\0', chunk);
        if (end)
            return (int)(end - buf);
        total += chunk;
    }

    buf[0] = '\0';
    return -ENAMETOOLONG;
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

static int find_stack_mapping(KleeProcess *proc, uint64_t sp)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", proc->real_pid);
    FILE *maps = fopen(path, "re");
    if (!maps)
        return -errno;

    uint64_t start, end;
    char line[512], perms[5];
    int rc = -EFAULT;
    while (fgets(line, sizeof(line), maps)) {
        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %4s", &start, &end, perms) != 3)
            continue;
        if (sp - 1 < start || sp - 1 >= end)
            continue;
        if (perms[1] == 'w') {
            proc->stack_start = start;
            proc->stack_end = end;
            rc = 0;
        }
        break;
    }
    fclose(maps);
    return rc;
}

int klee_scratch_write(KleeProcess *proc, KleeInterceptor *ic,
                        const void *data, size_t len, uint64_t *addr)
{
    if (!proc->scratch_top) {
        int rc = klee_regs_fetch(ic, proc);
        if (rc < 0)
            return rc;
        uint64_t sp = klee_regs_get_sp(proc);
        if (sp <= 128 || (proc->abi == KLEE_ABI_I386 && sp > UINT32_MAX))
            return -EFAULT;
        proc->scratch_top = sp;
        proc->scratch_cursor = sp - 128;
    }
    if (len >= proc->scratch_cursor)
        return -EFAULT;
    uint64_t target = (proc->scratch_cursor - len) & ~(uint64_t)7;
    uint64_t sp = proc->scratch_top;
    if (target / 4096 != (sp - 1) / 4096 &&
        (target < proc->stack_start || sp > proc->stack_end ||
         sp <= proc->stack_start)) {
        int rc = find_stack_mapping(proc, sp);
        if (rc < 0 || target < proc->stack_start)
            return rc < 0 ? rc : -EFAULT;
    }
    int rc = klee_write_mem(ic, proc->real_pid, (void *)(uintptr_t)target, data, len);
    if (rc < 0)
        return rc == -EIO ? -EFAULT : rc;
    proc->scratch_cursor = target;
    *addr = target;
    return 0;
}

int klee_scratch_string(KleeProcess *proc, KleeInterceptor *ic,
                         const char *str, uint64_t *addr)
{
    return klee_scratch_write(proc, ic, str, strlen(str) + 1, addr);
}
