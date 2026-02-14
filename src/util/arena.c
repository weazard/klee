/*
 * Klee - Userspace bwrap translation layer
 * Pool-based arena allocator implementation
 */
#include "util/arena.h"
#include <stdlib.h>
#include <string.h>

#define ALIGN_UP(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define ARENA_ALIGNMENT 8

static KleeArenaBlock *arena_new_block(size_t min_size)
{
    size_t size = min_size < KLEE_ARENA_DEFAULT_BLOCK_SIZE
                  ? KLEE_ARENA_DEFAULT_BLOCK_SIZE
                  : min_size;
    KleeArenaBlock *block = malloc(sizeof(KleeArenaBlock) + size);
    if (!block)
        return NULL;
    block->next = NULL;
    block->size = size;
    block->used = 0;
    return block;
}

KleeArena *klee_arena_create(size_t block_size)
{
    KleeArena *arena = malloc(sizeof(KleeArena));
    if (!arena)
        return NULL;

    if (block_size == 0)
        block_size = KLEE_ARENA_DEFAULT_BLOCK_SIZE;

    arena->default_block_size = block_size;
    arena->total_allocated = 0;

    KleeArenaBlock *block = arena_new_block(block_size);
    if (!block) {
        free(arena);
        return NULL;
    }

    arena->current = block;
    arena->blocks = block;
    arena->total_allocated = sizeof(KleeArenaBlock) + block->size;
    return arena;
}

void *klee_arena_alloc(KleeArena *arena, size_t size)
{
    if (!arena || size == 0)
        return NULL;

    size = ALIGN_UP(size, ARENA_ALIGNMENT);

    KleeArenaBlock *block = arena->current;
    if (block->used + size > block->size) {
        /* Need a new block */
        size_t new_size = arena->default_block_size;
        if (size > new_size)
            new_size = size;

        KleeArenaBlock *new_block = arena_new_block(new_size);
        if (!new_block)
            return NULL;

        /* Insert at head of block list and make current */
        new_block->next = arena->blocks;
        arena->blocks = new_block;
        arena->current = new_block;
        arena->total_allocated += sizeof(KleeArenaBlock) + new_block->size;
        block = new_block;
    }

    void *ptr = block->data + block->used;
    block->used += size;
    return ptr;
}

void *klee_arena_calloc(KleeArena *arena, size_t count, size_t size)
{
    size_t total = count * size;
    void *ptr = klee_arena_alloc(arena, total);
    if (ptr)
        memset(ptr, 0, total);
    return ptr;
}

char *klee_arena_strdup(KleeArena *arena, const char *s)
{
    if (!s)
        return NULL;
    size_t len = strlen(s) + 1;
    char *dup = klee_arena_alloc(arena, len);
    if (dup)
        memcpy(dup, s, len);
    return dup;
}

char *klee_arena_strndup(KleeArena *arena, const char *s, size_t n)
{
    if (!s)
        return NULL;
    size_t len = strnlen(s, n);
    char *dup = klee_arena_alloc(arena, len + 1);
    if (dup) {
        memcpy(dup, s, len);
        dup[len] = '\0';
    }
    return dup;
}

void klee_arena_reset(KleeArena *arena)
{
    if (!arena)
        return;

    /* Reset all blocks to unused, keep the first one as current */
    for (KleeArenaBlock *b = arena->blocks; b; b = b->next)
        b->used = 0;

    arena->current = arena->blocks;
}

void klee_arena_destroy(KleeArena *arena)
{
    if (!arena)
        return;

    KleeArenaBlock *block = arena->blocks;
    while (block) {
        KleeArenaBlock *next = block->next;
        free(block);
        block = next;
    }
    free(arena);
}

size_t klee_arena_total(const KleeArena *arena)
{
    return arena ? arena->total_allocated : 0;
}
