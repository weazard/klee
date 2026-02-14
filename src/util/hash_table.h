/*
 * Klee - Userspace bwrap translation layer
 * Generic open-addressing hash table with uint64 keys
 */
#ifndef KLEE_HASH_TABLE_H
#define KLEE_HASH_TABLE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define KLEE_HT_INITIAL_CAPACITY 16
#define KLEE_HT_MAX_LOAD_FACTOR  0.7

typedef struct klee_ht_entry {
    uint64_t key;
    void *value;
    bool occupied;
    bool deleted;
} KleeHTEntry;

typedef struct klee_hash_table {
    KleeHTEntry *entries;
    size_t capacity;
    size_t count;       /* number of live entries */
    size_t tombstones;  /* number of deleted entries */
} KleeHashTable;

/* Create a new hash table */
KleeHashTable *klee_ht_create(void);

/* Create with initial capacity hint */
KleeHashTable *klee_ht_create_sized(size_t capacity);

/* Destroy hash table (does NOT free values) */
void klee_ht_destroy(KleeHashTable *ht);

/* Insert or update key→value. Returns previous value or NULL */
void *klee_ht_put(KleeHashTable *ht, uint64_t key, void *value);

/* Lookup key. Returns value or NULL */
void *klee_ht_get(const KleeHashTable *ht, uint64_t key);

/* Check if key exists */
bool klee_ht_contains(const KleeHashTable *ht, uint64_t key);

/* Remove key. Returns removed value or NULL */
void *klee_ht_remove(KleeHashTable *ht, uint64_t key);

/* Get number of entries */
size_t klee_ht_size(const KleeHashTable *ht);

/* Iteration: call fn for each (key, value). Return non-zero from fn to stop. */
typedef int (*klee_ht_iter_fn)(uint64_t key, void *value, void *ctx);
int klee_ht_foreach(const KleeHashTable *ht, klee_ht_iter_fn fn, void *ctx);

/* Clear all entries (does NOT free values) */
void klee_ht_clear(KleeHashTable *ht);

#endif /* KLEE_HASH_TABLE_H */
