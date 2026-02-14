/*
 * Klee - Userspace bwrap translation layer
 * Open-addressing hash table implementation
 */
#include "util/hash_table.h"
#include <stdlib.h>
#include <string.h>

/* FNV-1a inspired mixing for uint64 keys */
static inline size_t hash_key(uint64_t key)
{
    key = (~key) + (key << 21);
    key = key ^ (key >> 24);
    key = (key + (key << 3)) + (key << 8);
    key = key ^ (key >> 14);
    key = (key + (key << 2)) + (key << 4);
    key = key ^ (key >> 28);
    key = key + (key << 31);
    return (size_t)key;
}

static size_t next_power_of_2(size_t n)
{
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;
    return n + 1;
}

KleeHashTable *klee_ht_create(void)
{
    return klee_ht_create_sized(KLEE_HT_INITIAL_CAPACITY);
}

KleeHashTable *klee_ht_create_sized(size_t capacity)
{
    KleeHashTable *ht = malloc(sizeof(KleeHashTable));
    if (!ht)
        return NULL;

    if (capacity < KLEE_HT_INITIAL_CAPACITY)
        capacity = KLEE_HT_INITIAL_CAPACITY;
    capacity = next_power_of_2(capacity);

    ht->entries = calloc(capacity, sizeof(KleeHTEntry));
    if (!ht->entries) {
        free(ht);
        return NULL;
    }

    ht->capacity = capacity;
    ht->count = 0;
    ht->tombstones = 0;
    return ht;
}

void klee_ht_destroy(KleeHashTable *ht)
{
    if (!ht)
        return;
    free(ht->entries);
    free(ht);
}

static int ht_resize(KleeHashTable *ht, size_t new_cap)
{
    KleeHTEntry *old_entries = ht->entries;
    size_t old_cap = ht->capacity;

    KleeHTEntry *new_entries = calloc(new_cap, sizeof(KleeHTEntry));
    if (!new_entries)
        return -1;

    ht->entries = new_entries;
    ht->capacity = new_cap;
    ht->count = 0;
    ht->tombstones = 0;

    for (size_t i = 0; i < old_cap; i++) {
        if (old_entries[i].occupied && !old_entries[i].deleted)
            klee_ht_put(ht, old_entries[i].key, old_entries[i].value);
    }

    free(old_entries);
    return 0;
}

void *klee_ht_put(KleeHashTable *ht, uint64_t key, void *value)
{
    if (!ht)
        return NULL;

    /* Check load factor */
    if ((ht->count + ht->tombstones + 1) > (size_t)(ht->capacity * KLEE_HT_MAX_LOAD_FACTOR)) {
        if (ht_resize(ht, ht->capacity * 2) < 0)
            return NULL;
    }

    size_t mask = ht->capacity - 1;
    size_t idx = hash_key(key) & mask;
    size_t first_tombstone = (size_t)-1;

    for (size_t i = 0; i < ht->capacity; i++) {
        size_t probe = (idx + i) & mask;
        KleeHTEntry *e = &ht->entries[probe];

        if (!e->occupied && !e->deleted) {
            /* Empty slot */
            size_t insert = (first_tombstone != (size_t)-1) ? first_tombstone : probe;
            KleeHTEntry *ie = &ht->entries[insert];
            if (ie->deleted)
                ht->tombstones--;
            ie->key = key;
            ie->value = value;
            ie->occupied = true;
            ie->deleted = false;
            ht->count++;
            return NULL;
        }

        if (e->deleted) {
            if (first_tombstone == (size_t)-1)
                first_tombstone = probe;
            continue;
        }

        if (e->key == key) {
            void *old = e->value;
            e->value = value;
            return old;
        }
    }

    /* Table is full (shouldn't happen with proper load factor) */
    return NULL;
}

void *klee_ht_get(const KleeHashTable *ht, uint64_t key)
{
    if (!ht || ht->count == 0)
        return NULL;

    size_t mask = ht->capacity - 1;
    size_t idx = hash_key(key) & mask;

    for (size_t i = 0; i < ht->capacity; i++) {
        size_t probe = (idx + i) & mask;
        const KleeHTEntry *e = &ht->entries[probe];

        if (!e->occupied && !e->deleted)
            return NULL;
        if (e->occupied && !e->deleted && e->key == key)
            return e->value;
    }
    return NULL;
}

bool klee_ht_contains(const KleeHashTable *ht, uint64_t key)
{
    if (!ht || ht->count == 0)
        return false;

    size_t mask = ht->capacity - 1;
    size_t idx = hash_key(key) & mask;

    for (size_t i = 0; i < ht->capacity; i++) {
        size_t probe = (idx + i) & mask;
        const KleeHTEntry *e = &ht->entries[probe];

        if (!e->occupied && !e->deleted)
            return false;
        if (e->occupied && !e->deleted && e->key == key)
            return true;
    }
    return false;
}

void *klee_ht_remove(KleeHashTable *ht, uint64_t key)
{
    if (!ht || ht->count == 0)
        return NULL;

    size_t mask = ht->capacity - 1;
    size_t idx = hash_key(key) & mask;

    for (size_t i = 0; i < ht->capacity; i++) {
        size_t probe = (idx + i) & mask;
        KleeHTEntry *e = &ht->entries[probe];

        if (!e->occupied && !e->deleted)
            return NULL;

        if (e->occupied && !e->deleted && e->key == key) {
            void *old = e->value;
            e->deleted = true;
            e->occupied = false;
            ht->count--;
            ht->tombstones++;
            return old;
        }
    }
    return NULL;
}

size_t klee_ht_size(const KleeHashTable *ht)
{
    return ht ? ht->count : 0;
}

int klee_ht_foreach(const KleeHashTable *ht, klee_ht_iter_fn fn, void *ctx)
{
    if (!ht || !fn)
        return 0;

    for (size_t i = 0; i < ht->capacity; i++) {
        const KleeHTEntry *e = &ht->entries[i];
        if (e->occupied && !e->deleted) {
            int rc = fn(e->key, e->value, ctx);
            if (rc != 0)
                return rc;
        }
    }
    return 0;
}

void klee_ht_clear(KleeHashTable *ht)
{
    if (!ht)
        return;
    memset(ht->entries, 0, ht->capacity * sizeof(KleeHTEntry));
    ht->count = 0;
    ht->tombstones = 0;
}
