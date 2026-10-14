/*
 * Klee - Userspace bwrap translation layer
 * IPC namespace (virtual keys)
 */
#ifndef KLEE_IPC_NS_H
#define KLEE_IPC_NS_H

#include "util/hash_table.h"
#include <stdint.h>
#include <sys/types.h>

/* SysV IPC object kinds (separate key and id spaces in the kernel) */
typedef enum {
    KLEE_IPC_SHM = 0,
    KLEE_IPC_MSG = 1,
    KLEE_IPC_SEM = 2,
} KleeIpcType;

typedef struct klee_ipc_ns {
    KleeHashTable *key_map;      /* virtual_key → real_key */
    KleeHashTable *rev_map;      /* real_key → virtual_key (for /proc display) */
    KleeHashTable *seg_ids;      /* (type, id) → real key, for cleanup */
    uint64_t rng_state;          /* real-key generator state */
} KleeIpcNs;

/* Create IPC namespace whose real keys are unique to this sandbox */
KleeIpcNs *klee_ipc_ns_create_unique(unsigned long sandbox_id);

/* Create IPC namespace (legacy, deterministic key sequence) */
KleeIpcNs *klee_ipc_ns_create(void);

/* Destroy IPC namespace and remove the IPC objects created inside it */
void klee_ipc_ns_destroy(KleeIpcNs *ipc);

/* Translate a virtual IPC key to a real key.
 * If the key doesn't exist, creates a new mapping.
 * Returns the real key. */
key_t klee_ipc_ns_translate_key(KleeIpcNs *ipc, key_t virtual_key);

/* Reverse-translate a real IPC key back to virtual key.
 * Returns the virtual key, or real_key if no mapping exists. */
key_t klee_ipc_ns_reverse_key(const KleeIpcNs *ipc, key_t real_key);

/* Record an IPC object created inside the sandbox so it is removed when
 * the namespace is destroyed.  real_key is the key it was created with. */
void klee_ipc_ns_track_segment(KleeIpcNs *ipc, KleeIpcType type, int seg_id,
                               key_t real_key);

#endif /* KLEE_IPC_NS_H */
