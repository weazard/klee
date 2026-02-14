/*
 * Klee - Userspace bwrap translation layer
 * Edge case handling implementation
 */
#include "compat/edge_cases.h"
#include "process/memory.h"
#include "fs/path_resolve.h"
#include "util/log.h"

#include <errno.h>
#include <string.h>
#include <linux/limits.h>

int klee_compat_handle_openat2(KleeProcess *proc, KleeInterceptor *ic,
                                KleeEvent *ev)
{
    (void)proc;
    (void)ic;
    (void)ev;

    /* openat2 RESOLVE flags are now handled in klee_enter_openat2().
     * This handler is retained for exit-side processing if needed. */
    return 0;
}

int klee_compat_handle_name_to_handle(KleeProcess *proc, KleeInterceptor *ic,
                                       KleeEvent *ev)
{
    /* name_to_handle_at(dirfd, pathname, handle, mount_id, flags)
     * Translate pathname (arg 1 with dirfd arg 0) so the kernel handle
     * references the translated host path. */
    void *path_addr = (void *)(uintptr_t)ev->args[1];
    if (!path_addr)
        return 0;

    char saved_path[PATH_MAX];
    char translated_path[PATH_MAX];
    int rc = klee_read_path(ic, ev->pid, saved_path, sizeof(saved_path), path_addr);
    if (rc < 0)
        return 0;

    if (!proc->sandbox || !proc->sandbox->mount_table)
        return 0;

    int dirfd = (int)ev->args[0];
    KleeResolveCtx ctx = {
        .mount_table = proc->sandbox->mount_table,
        .fd_table = proc->fd_table,
        .vcwd = proc->vcwd,
        .vroot = klee_mount_table_get_root(proc->sandbox->mount_table),
        .flags = 0,
    };

    rc = klee_path_guest_to_host(&ctx, saved_path, translated_path, dirfd);
    if (rc < 0)
        return 0;

    if (strcmp(saved_path, translated_path) != 0) {
        if (ic->backend == INTERCEPT_PTRACE)
            klee_write_string(ic, ev->pid, path_addr, translated_path);
        KLEE_TRACE("name_to_handle_at: translated %s -> %s",
                   saved_path, translated_path);
    }
    return 0;
}

int klee_compat_handle_open_by_handle(KleeProcess *proc, KleeInterceptor *ic,
                                       KleeEvent *ev)
{
    (void)proc;
    (void)ic;
    (void)ev;

    /* open_by_handle_at(mount_fd, handle, flags)
     * Handles are opaque kernel objects. Since they reference host paths
     * (from a translated name_to_handle_at), they could bypass sandbox
     * isolation. Block with -EOPNOTSUPP for safety. */
    KLEE_DEBUG("open_by_handle_at: blocked with EOPNOTSUPP from pid=%d",
               proc->real_pid);
    return -EOPNOTSUPP;
}

int klee_compat_handle_memfd_create(KleeProcess *proc, KleeInterceptor *ic,
                                     KleeEvent *ev)
{
    (void)ic;

    if (ev->retval >= 0) {
        int fd = (int)ev->retval;
        /* Track memfd in FD table with synthetic path */
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/memfd:%d", fd);
        klee_fd_table_set(proc->fd_table, fd, path, false);
        KLEE_TRACE("memfd_create: tracking fd=%d", fd);
    }
    return 0;
}
