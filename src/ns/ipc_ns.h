/*
 * Klee - Userspace bwrap translation layer
 * IPC namespace (virtual keys)
 */
#ifndef KLEE_IPC_NS_H
#define KLEE_IPC_NS_H

#include "util/hash_table.h"
#include <sys/types.h>

typedef struct klee_ipc_ns {
    KleeHashTable *key_map;      /* virtual_key → real_key */
    KleeHashTable *rev_map;      /* real_key → virtual_key (for /proc display) */
    KleeHashTable *seg_ids;      /* tracks real segment IDs for cleanup */
    unsigned int next_key;
} KleeIpcNs;

/* Create IPC namespace with unique base key derived from sandbox identity */
KleeIpcNs *klee_ipc_ns_create_unique(unsigned long sandbox_id);

/* Create IPC namespace (legacy, deterministic base key) */
KleeIpcNs *klee_ipc_ns_create(void);

/* Destroy IPC namespace and clean up tracked IPC segments */
void klee_ipc_ns_destroy(KleeIpcNs *ipc);

/* Translate a virtual IPC key to a real key.
 * If the key doesn't exist, creates a new mapping.
 * Returns the real key. */
key_t klee_ipc_ns_translate_key(KleeIpcNs *ipc, key_t virtual_key);

/* Reverse-translate a real IPC key back to virtual key.
 * Returns the virtual key, or real_key if no mapping exists. */
key_t klee_ipc_ns_reverse_key(const KleeIpcNs *ipc, key_t real_key);

/* Track a segment ID for cleanup on destroy */
void klee_ipc_ns_track_segment(KleeIpcNs *ipc, int type, int seg_id);

#endif /* KLEE_IPC_NS_H */
