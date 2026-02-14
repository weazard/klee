/*
 * Klee - Userspace bwrap translation layer
 * PID namespace simulation implementation
 */
#include "ns/pid_ns.h"
#include "util/hash_table.h"
#include "util/log.h"

#include <stdlib.h>
#include <stdint.h>

KleePidMap *klee_pid_map_create(void)
{
    KleePidMap *pm = calloc(1, sizeof(KleePidMap));
    if (!pm)
        return NULL;

    pm->real_to_virtual = klee_ht_create();
    pm->virtual_to_real = klee_ht_create();

    if (!pm->real_to_virtual || !pm->virtual_to_real) {
        klee_ht_destroy(pm->real_to_virtual);
        klee_ht_destroy(pm->virtual_to_real);
        free(pm);
        return NULL;
    }

    pm->next_vpid = 1;
    pm->init_real_pid = 0;
    return pm;
}

void klee_pid_map_destroy(KleePidMap *pm)
{
    if (!pm)
        return;
    klee_ht_destroy(pm->real_to_virtual);
    klee_ht_destroy(pm->virtual_to_real);
    free(pm);
}

pid_t klee_pid_map_add(KleePidMap *pm, pid_t real_pid)
{
    if (!pm)
        return 0;

    /* Check if already mapped */
    pid_t existing = klee_pid_map_r2v(pm, real_pid);
    if (existing > 0)
        return existing;

    pid_t vpid = pm->next_vpid;

    /* Guard against wraparound: pid_t is signed 32-bit, valid range 1..INT_MAX.
     * Exhausting 2 billion PIDs is practically impossible, but defend against
     * corruption or bugs that skip large ranges. */
    if (vpid <= 0 || vpid >= (pid_t)0x7FFFFFFF) {
        KLEE_WARN("pid_map: virtual PID counter exhausted (next=%d), "
                  "wrapping to 1 — PID collisions may occur", vpid);
        vpid = 1;
        /* Skip over any existing mappings to avoid collision */
        while (klee_ht_get(pm->virtual_to_real, (uint64_t)vpid) && vpid < 0x7FFFFFFF)
            vpid++;
    }
    pm->next_vpid = vpid + 1;

    /* Store as (uintptr_t) value in hash table since it stores void* */
    klee_ht_put(pm->real_to_virtual, (uint64_t)real_pid,
                (void *)(uintptr_t)vpid);
    klee_ht_put(pm->virtual_to_real, (uint64_t)vpid,
                (void *)(uintptr_t)real_pid);

    if (vpid == 1)
        pm->init_real_pid = real_pid;

    KLEE_DEBUG("pid_map: real=%d -> virtual=%d", real_pid, vpid);
    return vpid;
}

int klee_pid_map_add_explicit(KleePidMap *pm, pid_t real_pid, pid_t virtual_pid)
{
    if (!pm)
        return -1;

    klee_ht_put(pm->real_to_virtual, (uint64_t)real_pid,
                (void *)(uintptr_t)virtual_pid);
    klee_ht_put(pm->virtual_to_real, (uint64_t)virtual_pid,
                (void *)(uintptr_t)real_pid);

    if (virtual_pid == 1)
        pm->init_real_pid = real_pid;

    if (virtual_pid >= pm->next_vpid)
        pm->next_vpid = virtual_pid + 1;

    return 0;
}

void klee_pid_map_remove(KleePidMap *pm, pid_t real_pid)
{
    if (!pm)
        return;

    void *val = klee_ht_remove(pm->real_to_virtual, (uint64_t)real_pid);
    if (val) {
        pid_t vpid = (pid_t)(uintptr_t)val;
        klee_ht_remove(pm->virtual_to_real, (uint64_t)vpid);
        KLEE_DEBUG("pid_map: removed real=%d virtual=%d", real_pid, vpid);
    }
}

pid_t klee_pid_map_r2v(const KleePidMap *pm, pid_t real_pid)
{
    if (!pm)
        return 0;
    void *val = klee_ht_get(pm->real_to_virtual, (uint64_t)real_pid);
    return val ? (pid_t)(uintptr_t)val : 0;
}

pid_t klee_pid_map_v2r(const KleePidMap *pm, pid_t virtual_pid)
{
    if (!pm)
        return 0;
    void *val = klee_ht_get(pm->virtual_to_real, (uint64_t)virtual_pid);
    return val ? (pid_t)(uintptr_t)val : 0;
}

bool klee_pid_map_is_init(const KleePidMap *pm, pid_t real_pid)
{
    return pm && pm->init_real_pid == real_pid;
}

pid_t klee_pid_map_get_init(const KleePidMap *pm)
{
    return pm ? pm->init_real_pid : 0;
}

size_t klee_pid_map_count(const KleePidMap *pm)
{
    return pm ? klee_ht_size(pm->real_to_virtual) : 0;
}
