/*
 * Klee - Userspace bwrap translation layer
 * /proc/[pid] directory filtering implementation
 */
#include "fuse/fuse_pidns.h"

#include <stdlib.h>
#include <ctype.h>

bool klee_pidns_filter_proc_entry(const KleePidMap *pm, const char *name)
{
    if (!pm || !name)
        return true;

    /* Check if name is a numeric PID directory */
    const char *p = name;
    while (*p) {
        if (!isdigit((unsigned char)*p))
            return true; /* Not a PID directory, always show */
        p++;
    }

    /* It's a PID directory - check if the PID is in our namespace */
    pid_t real_pid = (pid_t)atoi(name);
    pid_t vpid = klee_pid_map_r2v(pm, real_pid);
    return vpid > 0; /* Only show if PID is in our namespace */
}
