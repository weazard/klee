/*
 * Klee - Userspace bwrap translation layer
 * IPC namespace implementation
 *
 * Provides key-space isolation for SysV IPC (shmget, msgget, semget).
 * Each sandbox gets unique base keys to prevent inter-sandbox collision.
 * Tracks created segments for cleanup on sandbox exit.
 */
#include "ns/ipc_ns.h"
#include "util/log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <sys/sem.h>

/* IPC segment types for cleanup */
#define IPC_TYPE_SHM 0
#define IPC_TYPE_MSG 1
#define IPC_TYPE_SEM 2

/* Pack type + id for segment tracking */
static uint64_t pack_seg(int type, int id)
{
    return ((uint64_t)(unsigned int)type << 32) | (uint64_t)(unsigned int)id;
}

static KleeIpcNs *ipc_ns_create_with_base(unsigned int base_key)
{
    KleeIpcNs *ipc = calloc(1, sizeof(KleeIpcNs));
    if (!ipc)
        return NULL;

    ipc->key_map = klee_ht_create();
    if (!ipc->key_map) {
        free(ipc);
        return NULL;
    }

    ipc->rev_map = klee_ht_create();
    if (!ipc->rev_map) {
        klee_ht_destroy(ipc->key_map);
        free(ipc);
        return NULL;
    }

    ipc->seg_ids = klee_ht_create();
    if (!ipc->seg_ids) {
        klee_ht_destroy(ipc->rev_map);
        klee_ht_destroy(ipc->key_map);
        free(ipc);
        return NULL;
    }

    ipc->next_key = base_key;
    return ipc;
}

KleeIpcNs *klee_ipc_ns_create(void)
{
    return ipc_ns_create_with_base(0x4B4C4545); /* "KLEE" in hex */
}

KleeIpcNs *klee_ipc_ns_create_unique(unsigned long sandbox_id)
{
    /* Generate a unique base key by mixing sandbox identity.
     * Use a simple hash to spread values across key space. */
    unsigned int hash = (unsigned int)sandbox_id;
    hash ^= hash >> 16;
    hash *= 0x45d9f3b;
    hash ^= hash >> 16;

    /* Keep in a range that avoids common application keys (0-0xFFFF)
     * and kernel-reserved keys */
    unsigned int base = 0x4B4C0000 | (hash & 0xFFFF);
    return ipc_ns_create_with_base(base);
}

static int cleanup_segment(uint64_t key, void *val, void *ctx)
{
    (void)val; (void)ctx;
    int type = (int)(key >> 32);
    int id = (int)(key & 0xFFFFFFFF);
    int rc;
    switch (type) {
    case IPC_TYPE_SHM:
        rc = shmctl(id, IPC_RMID, NULL);
        if (rc == 0)
            KLEE_DEBUG("ipc cleanup: removed shm %d", id);
        else
            KLEE_WARN("ipc cleanup: failed to remove shm %d: %s",
                      id, strerror(errno));
        break;
    case IPC_TYPE_MSG:
        rc = msgctl(id, IPC_RMID, NULL);
        if (rc == 0)
            KLEE_DEBUG("ipc cleanup: removed msg %d", id);
        else
            KLEE_WARN("ipc cleanup: failed to remove msg %d: %s",
                      id, strerror(errno));
        break;
    case IPC_TYPE_SEM:
        rc = semctl(id, 0, IPC_RMID);
        if (rc == 0)
            KLEE_DEBUG("ipc cleanup: removed sem %d", id);
        else
            KLEE_WARN("ipc cleanup: failed to remove sem %d: %s",
                      id, strerror(errno));
        break;
    }
    return 0;
}

void klee_ipc_ns_destroy(KleeIpcNs *ipc)
{
    if (!ipc)
        return;

    /* Clean up tracked IPC segments to prevent orphans */
    if (ipc->seg_ids) {
        klee_ht_foreach(ipc->seg_ids, cleanup_segment, NULL);
        klee_ht_destroy(ipc->seg_ids);
    }

    klee_ht_destroy(ipc->rev_map);
    klee_ht_destroy(ipc->key_map);
    free(ipc);
}

key_t klee_ipc_ns_translate_key(KleeIpcNs *ipc, key_t virtual_key)
{
    if (!ipc)
        return virtual_key;

    /* IPC_PRIVATE is always private */
    if (virtual_key == IPC_PRIVATE)
        return IPC_PRIVATE;

    /* Check existing mapping */
    void *val = klee_ht_get(ipc->key_map, (uint64_t)(unsigned int)virtual_key);
    if (val)
        return (key_t)(uintptr_t)val;

    /* Create new mapping using a private key.
     * Guard against wraparound: if next_key wraps back to the base range
     * or into common application key space, log a warning. */
    key_t real_key = (key_t)ipc->next_key++;
    if (ipc->next_key == 0) {
        KLEE_WARN("ipc: key counter wrapped to 0 — potential key collisions");
        ipc->next_key = 0x4B4C0000; /* reset to safe range */
    }
    klee_ht_put(ipc->key_map, (uint64_t)(unsigned int)virtual_key,
                (void *)(uintptr_t)real_key);
    klee_ht_put(ipc->rev_map, (uint64_t)(unsigned int)real_key,
                (void *)(uintptr_t)virtual_key);

    KLEE_DEBUG("ipc: mapped key %d -> %d", virtual_key, real_key);
    return real_key;
}

key_t klee_ipc_ns_reverse_key(const KleeIpcNs *ipc, key_t real_key)
{
    if (!ipc)
        return real_key;

    void *val = klee_ht_get(ipc->rev_map, (uint64_t)(unsigned int)real_key);
    if (val)
        return (key_t)(uintptr_t)val;

    /* No reverse mapping found — this real key did not originate from this
     * sandbox's key translation.  Log a warning rather than silently
     * returning the raw host key, which could leak cross-sandbox state. */
    KLEE_DEBUG("ipc: reverse key %d not in map, returning as-is", real_key);
    return real_key;
}

void klee_ipc_ns_track_segment(KleeIpcNs *ipc, int type, int seg_id)
{
    if (!ipc || !ipc->seg_ids)
        return;
    uint64_t packed = pack_seg(type, seg_id);
    klee_ht_put(ipc->seg_ids, packed, (void *)1);
    KLEE_DEBUG("ipc: tracking segment type=%d id=%d", type, seg_id);
}
