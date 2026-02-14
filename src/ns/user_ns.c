/*
 * Klee - Userspace bwrap translation layer
 * UID/GID simulation implementation
 *
 * Reference: proot/src/extension/fake_id0/fake_id0.c
 */
#include "ns/user_ns.h"

#include <stdlib.h>
#include <string.h>

KleeIdState *klee_id_state_create(uid_t uid, gid_t gid)
{
    KleeIdState *ids = calloc(1, sizeof(KleeIdState));
    if (!ids)
        return NULL;

    ids->ruid = ids->euid = ids->suid = ids->fsuid = uid;
    ids->rgid = ids->egid = ids->sgid = ids->fsgid = gid;
    return ids;
}

KleeIdState *klee_id_state_clone(const KleeIdState *src)
{
    if (!src)
        return NULL;
    KleeIdState *ids = malloc(sizeof(KleeIdState));
    if (ids)
        memcpy(ids, src, sizeof(KleeIdState));
    return ids;
}

void klee_id_state_destroy(KleeIdState *ids)
{
    free(ids);
}

/*
 * These handlers emulate the Linux kernel's set*id logic but
 * always succeed (as if the caller has CAP_SETUID/CAP_SETGID).
 */

int klee_user_ns_handle_setuid(KleeIdState *ids, uid_t uid)
{
    if (!ids) return -1;
    /* With capabilities: sets all three UIDs */
    ids->ruid = uid;
    ids->euid = uid;
    ids->suid = uid;
    ids->fsuid = uid;
    return 0;
}

int klee_user_ns_handle_setgid(KleeIdState *ids, gid_t gid)
{
    if (!ids) return -1;
    ids->rgid = gid;
    ids->egid = gid;
    ids->sgid = gid;
    ids->fsgid = gid;
    return 0;
}

int klee_user_ns_handle_setreuid(KleeIdState *ids, uid_t ruid, uid_t euid)
{
    if (!ids) return -1;
    if (ruid != (uid_t)-1)
        ids->ruid = ruid;
    if (euid != (uid_t)-1)
        ids->euid = euid;
    /* If ruid was set or euid was set, suid is set to new euid */
    ids->suid = ids->euid;
    ids->fsuid = ids->euid;
    return 0;
}

int klee_user_ns_handle_setregid(KleeIdState *ids, gid_t rgid, gid_t egid)
{
    if (!ids) return -1;
    if (rgid != (gid_t)-1)
        ids->rgid = rgid;
    if (egid != (gid_t)-1)
        ids->egid = egid;
    ids->sgid = ids->egid;
    ids->fsgid = ids->egid;
    return 0;
}

int klee_user_ns_handle_setresuid(KleeIdState *ids, uid_t ruid, uid_t euid,
                                   uid_t suid)
{
    if (!ids) return -1;
    if (ruid != (uid_t)-1)
        ids->ruid = ruid;
    if (euid != (uid_t)-1)
        ids->euid = euid;
    if (suid != (uid_t)-1)
        ids->suid = suid;
    ids->fsuid = ids->euid;
    return 0;
}

int klee_user_ns_handle_setresgid(KleeIdState *ids, gid_t rgid, gid_t egid,
                                   gid_t sgid)
{
    if (!ids) return -1;
    if (rgid != (gid_t)-1)
        ids->rgid = rgid;
    if (egid != (gid_t)-1)
        ids->egid = egid;
    if (sgid != (gid_t)-1)
        ids->sgid = sgid;
    ids->fsgid = ids->egid;
    return 0;
}

int klee_user_ns_handle_setfsuid(KleeIdState *ids, uid_t fsuid)
{
    if (!ids) return -1;
    ids->fsuid = fsuid;
    return 0;
}

int klee_user_ns_handle_setfsgid(KleeIdState *ids, gid_t fsgid)
{
    if (!ids) return -1;
    ids->fsgid = fsgid;
    return 0;
}
