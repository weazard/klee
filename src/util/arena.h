/*
 * Klee - Userspace bwrap translation layer
 * Pool-based arena allocator
 */
#ifndef KLEE_ARENA_H
#define KLEE_ARENA_H

#include <stddef.h>

#define KLEE_ARENA_DEFAULT_BLOCK_SIZE 4096

typedef struct klee_arena_block {
    struct klee_arena_block *next;
    size_t size;
    size_t used;
    char data[];    /* flexible array member */
} KleeArenaBlock;

typedef struct klee_arena {
    KleeArenaBlock *current;
    KleeArenaBlock *blocks;     /* all blocks for freeing */
    size_t default_block_size;
    size_t total_allocated;
} KleeArena;

/* Create a new arena with the given default block size (0 = use default) */
KleeArena *klee_arena_create(size_t block_size);

/* Allocate memory from the arena (8-byte aligned) */
void *klee_arena_alloc(KleeArena *arena, size_t size);

/* Allocate zeroed memory from the arena */
void *klee_arena_calloc(KleeArena *arena, size_t count, size_t size);

/* Duplicate a string into the arena */
char *klee_arena_strdup(KleeArena *arena, const char *s);

/* Duplicate a string with length limit into the arena */
char *klee_arena_strndup(KleeArena *arena, const char *s, size_t n);

/* Reset arena: mark all blocks as unused without freeing memory */
void klee_arena_reset(KleeArena *arena);

/* Destroy arena: free all blocks */
void klee_arena_destroy(KleeArena *arena);

/* Get total bytes allocated from system */
size_t klee_arena_total(const KleeArena *arena);

#endif /* KLEE_ARENA_H */
