/*
 * Klee - Userspace bwrap translation layer
 * UTS namespace implementation
 */
#include "ns/uts_ns.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>

void klee_uts_set_hostname(KleeSandbox *sb, const char *hostname)
{
    if (!sb || !hostname)
        return;

    /* Linux HOST_NAME_MAX is 64 (including NUL).  Truncate to match
     * kernel behavior and prevent unbounded allocation. */
    size_t len = strlen(hostname);
    if (len >= 64) {
        KLEE_WARN("uts: hostname too long (%zu bytes), truncating to 63",
                  len);
        len = 63;
    }

    free(sb->hostname);
    sb->hostname = strndup(hostname, len);
    KLEE_DEBUG("uts: hostname set to '%s'", sb->hostname);
}

const char *klee_uts_get_hostname(const KleeSandbox *sb)
{
    return sb ? sb->hostname : NULL;
}
