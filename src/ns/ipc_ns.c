/*
 * Klee - Userspace bwrap translation layer
 * IPC namespace implementation
 *
 * Provides key-space isolation for SysV IPC (shmget, msgget, semget).
 * Each virtual key maps to a random real key private to the sandbox, and
 * objects created inside the sandbox are removed when it exits, as they
 * would be when a real IPC namespace is torn down.
 */
#include "ns/ipc_ns.h"
#include "util/log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/random.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <sys/sem.h>

union klee_semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

/* Pack type + id for segment tracking */
static uint64_t pack_seg(int type, int id)
{
    return ((uint64_t)(unsigned int)type << 32) | (uint64_t)(unsigned int)id;
}

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static KleeIpcNs *ipc_ns_create_with_seed(uint64_t seed)
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

    ipc->rng_state = seed;
    return ipc;
}

KleeIpcNs *klee_ipc_ns_create(void)
{
    return ipc_ns_create_with_seed(0x4B4C4545); /* "KLEE" in hex */
}

KleeIpcNs *klee_ipc_ns_create_unique(unsigned long sandbox_id)
{
    uint64_t seed = 0;
    if (getrandom(&seed, sizeof(seed), GRND_NONBLOCK) != (ssize_t)sizeof(seed)) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        seed = ((uint64_t)getpid() << 32) ^ (uint64_t)ts.tv_nsec ^
               (uint64_t)ts.tv_sec;
    }
    seed ^= (uint64_t)sandbox_id * 0x9E3779B97F4A7C15ULL;
    return ipc_ns_create_with_seed(seed);
}

/* Current key of an IPC object, or -errno if it can't be inspected. */
static int ipc_object_key(int type, int id, key_t *key)
{
    switch (type) {
    case KLEE_IPC_SHM: {
        struct shmid_ds ds;
        if (shmctl(id, IPC_STAT, &ds) < 0)
            return -errno;
        *key = ds.shm_perm.__key;
        return 0;
    }
    case KLEE_IPC_MSG: {
        struct msqid_ds ds;
        if (msgctl(id, IPC_STAT, &ds) < 0)
            return -errno;
        *key = ds.msg_perm.__key;
        return 0;
    }
    case KLEE_IPC_SEM: {
        struct semid_ds ds;
        union klee_semun arg = { .buf = &ds };
        if (semctl(id, 0, IPC_STAT, arg) < 0)
            return -errno;
        *key = ds.sem_perm.__key;
        return 0;
    }
    }
    return -EINVAL;
}

static int cleanup_segment(uint64_t packed, void *val, void *ctx)
{
    (void)ctx;
    int type = (int)(packed >> 32);
    int id = (int)(packed & 0xFFFFFFFF);
    key_t created_key = (key_t)(uint32_t)(uintptr_t)val;

    /* Only remove the object if it is still the one created here: the
     * sandbox may have removed it already and the id been reused. */
    key_t cur_key = created_key;
    int rc = ipc_object_key(type, id, &cur_key);
    if (rc < 0 && rc != -EACCES)
        return 0; /* already gone */
    if (cur_key != created_key)
        return 0;

    switch (type) {
    case KLEE_IPC_SHM:
        rc = shmctl(id, IPC_RMID, NULL);
        break;
    case KLEE_IPC_MSG:
        rc = msgctl(id, IPC_RMID, NULL);
        break;
    case KLEE_IPC_SEM:
        rc = semctl(id, 0, IPC_RMID);
        break;
    default:
        return 0;
    }
    if (rc == 0)
        KLEE_DEBUG("ipc cleanup: removed type=%d id=%d", type, id);
    else
        KLEE_WARN("ipc cleanup: failed to remove type=%d id=%d: %s",
                  type, id, strerror(errno));
    return 0;
}

void klee_ipc_ns_destroy(KleeIpcNs *ipc)
{
    if (!ipc)
        return;

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

    /* Random real keys keep sandboxes (and the host) apart except with
     * negligible probability; a per-sandbox base plus counter overlapped
     * whenever two bases were close. */
    key_t real_key;
    do {
        real_key = (key_t)(uint32_t)splitmix64(&ipc->rng_state);
    } while (real_key == IPC_PRIVATE ||
             klee_ht_get(ipc->rev_map, (uint64_t)(unsigned int)real_key));

    klee_ht_put(ipc->key_map, (uint64_t)(unsigned int)virtual_key,
                (void *)(uintptr_t)real_key);
    klee_ht_put(ipc->rev_map, (uint64_t)(unsigned int)real_key,
                (void *)(uintptr_t)virtual_key);

    KLEE_DEBUG("ipc: mapped key %#x -> %#x", (unsigned)virtual_key,
               (unsigned)real_key);
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
     * sandbox's key translation. */
    KLEE_DEBUG("ipc: reverse key %d not in map, returning as-is", real_key);
    return real_key;
}

void klee_ipc_ns_track_segment(KleeIpcNs *ipc, KleeIpcType type, int seg_id,
                               key_t real_key)
{
    if (!ipc || !ipc->seg_ids || seg_id < 0)
        return;
    /* Bit 32 keeps the stored value non-NULL for IPC_PRIVATE (key 0). */
    uint64_t val = (1ULL << 32) | (uint32_t)real_key;
    klee_ht_put(ipc->seg_ids, pack_seg(type, seg_id), (void *)(uintptr_t)val);
    KLEE_DEBUG("ipc: tracking type=%d id=%d key=%#x", type, seg_id,
               (unsigned)real_key);
}
