/*
 * Klee - Userspace bwrap translation layer
 * Read-only mount enforcement implementation
 */
#include "fs/readonly.h"
#include "syscall/sysnum.h"
#include "util/log.h"

#include <fcntl.h>
#include <stdbool.h>
#include <sys/syscall.h>

/* Syscalls that modify filesystem content */
static bool is_write_syscall(int syscall_nr)
{
    switch (syscall_nr) {
    case KLEE_SYS_unlink:
    case KLEE_SYS_unlinkat:
    case KLEE_SYS_rmdir:
    case KLEE_SYS_rename:
    case KLEE_SYS_renameat:
    case KLEE_SYS_renameat2:
    case KLEE_SYS_mkdir:
    case KLEE_SYS_mkdirat:
    case KLEE_SYS_symlink:
    case KLEE_SYS_symlinkat:
    case KLEE_SYS_link:
    case KLEE_SYS_linkat:
    case KLEE_SYS_chmod:
    case KLEE_SYS_fchmodat:
    case KLEE_SYS_chown:
    case KLEE_SYS_lchown:
    case KLEE_SYS_fchownat:
    case KLEE_SYS_truncate:
    case KLEE_SYS_creat:
    case KLEE_SYS_mknod:
    case KLEE_SYS_mknodat:
        return true;
    default:
        return false;
    }
}

bool klee_readonly_check_path(const KleeMountTable *mt, const char *guest_path,
                               int syscall_nr)
{
    if (!klee_mount_table_is_readonly(mt, guest_path))
        return false;

    if (is_write_syscall(syscall_nr)) {
        KLEE_DEBUG("readonly: blocking %d on %s", syscall_nr, guest_path);
        return true;
    }

    return false;
}

bool klee_readonly_check_open(const KleeMountTable *mt, const char *guest_path,
                               int flags)
{
    if (!klee_mount_table_is_readonly(mt, guest_path))
        return false;

    int accmode = flags & O_ACCMODE;
    if (accmode == O_WRONLY || accmode == O_RDWR) {
        KLEE_DEBUG("readonly: blocking open(write) on %s", guest_path);
        return true;
    }

    if (flags & (O_CREAT | O_TRUNC | O_APPEND)) {
        KLEE_DEBUG("readonly: blocking open(create/trunc/append) on %s",
                   guest_path);
        return true;
    }

    return false;
}
