/*
 * Klee - Userspace bwrap translation layer
 * pivot_root simulation implementation
 */
#include "fs/pivot.h"
#include "util/log.h"

#include <string.h>
#include <errno.h>

int klee_pivot_root(KleeMountTable *mt, const char *new_root,
                     const char *put_old)
{
    if (!mt || !new_root)
        return -EINVAL;

    KLEE_INFO("pivot_root: new_root=%s put_old=%s",
              new_root, put_old ? put_old : "(null)");

    klee_mount_table_set_root(mt, new_root);
    return 0;
}
