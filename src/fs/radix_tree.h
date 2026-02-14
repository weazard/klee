/*
 * Klee - Userspace bwrap translation layer
 * Compressed trie (radix tree) for path lookups
 */
#ifndef KLEE_RADIX_TREE_H
#define KLEE_RADIX_TREE_H

#include <stddef.h>
#include <stdbool.h>
#include "util/arena.h"

/* Forward declaration */
typedef struct klee_mount KleeMount;

typedef struct radix_node {
    char *component;         /* path component (e.g., "usr", "lib") */
    size_t component_len;
    struct radix_node *children;   /* first child */
    struct radix_node *sibling;    /* next sibling */
    KleeMount *mount;              /* non-NULL if this is a mountpoint */
} RadixNode;

typedef struct klee_radix_tree {
    RadixNode *root;
    KleeArena *arena;
    size_t num_nodes;
} KleeRadixTree;

/* Create a new radix tree */
KleeRadixTree *klee_radix_create(KleeArena *arena);

/* Insert a mount at the given path.
 * Path must be absolute (start with /).
 * Returns the node where mount was inserted, or NULL on failure. */
RadixNode *klee_radix_insert(KleeRadixTree *tree, const char *path,
                              KleeMount *mount);

/* Lookup: find the longest prefix match for the given path.
 * Returns the deepest node that has a mount entry.
 * If match_len is non-NULL, it receives the length of the matched prefix.
 * If remainder is non-NULL, it points to the unmatched suffix. */
RadixNode *klee_radix_lookup(const KleeRadixTree *tree, const char *path,
                              size_t *match_len, const char **remainder);

/* Exact lookup: find node for exact path match */
RadixNode *klee_radix_find_exact(const KleeRadixTree *tree, const char *path);

/* Walk all mount entries, calling fn(path, mount, ctx) for each */
typedef void (*klee_radix_walk_fn)(const char *path, KleeMount *mount, void *ctx);
void klee_radix_walk(const KleeRadixTree *tree, klee_radix_walk_fn fn, void *ctx);

/* Debug: print the tree structure */
void klee_radix_dump(const KleeRadixTree *tree);

#endif /* KLEE_RADIX_TREE_H */
