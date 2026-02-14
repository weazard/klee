/*
 * Klee - Userspace bwrap translation layer
 * Compressed trie for O(path-length) lookups
 */
#include "fs/radix_tree.h"
#include "fs/mount_table.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <linux/limits.h>

KleeRadixTree *klee_radix_create(KleeArena *arena)
{
    KleeRadixTree *tree;

    if (arena) {
        tree = klee_arena_calloc(arena, 1, sizeof(KleeRadixTree));
    } else {
        tree = calloc(1, sizeof(KleeRadixTree));
    }
    if (!tree)
        return NULL;

    tree->arena = arena;

    /* Create root node for "/" */
    RadixNode *root;
    if (arena) {
        root = klee_arena_calloc(arena, 1, sizeof(RadixNode));
        root->component = klee_arena_strdup(arena, "");
    } else {
        root = calloc(1, sizeof(RadixNode));
        root->component = strdup("");
    }
    root->component_len = 0;
    tree->root = root;
    tree->num_nodes = 1;

    return tree;
}

/* Get next path component, skipping leading slashes.
 * Returns pointer to component start, sets *len to component length.
 * Returns NULL when no more components. */
static const char *next_component(const char *path, size_t *len)
{
    while (*path == '/')
        path++;
    if (*path == '\0')
        return NULL;

    const char *end = path;
    while (*end != '\0' && *end != '/')
        end++;
    *len = (size_t)(end - path);
    return path;
}

/* Find or create a child node with the given component */
static RadixNode *find_or_create_child(KleeRadixTree *tree, RadixNode *parent,
                                        const char *component, size_t len)
{
    /* Search existing children */
    for (RadixNode *child = parent->children; child; child = child->sibling) {
        if (child->component_len == len &&
            memcmp(child->component, component, len) == 0) {
            return child;
        }
    }

    /* Create new child */
    RadixNode *node;
    if (tree->arena) {
        node = klee_arena_calloc(tree->arena, 1, sizeof(RadixNode));
        node->component = klee_arena_strndup(tree->arena, component, len);
    } else {
        node = calloc(1, sizeof(RadixNode));
        node->component = strndup(component, len);
    }
    if (!node)
        return NULL;

    node->component_len = len;

    /* Prepend to children list */
    node->sibling = parent->children;
    parent->children = node;
    tree->num_nodes++;

    return node;
}

RadixNode *klee_radix_insert(KleeRadixTree *tree, const char *path,
                              KleeMount *mount)
{
    if (!tree || !path || path[0] != '/')
        return NULL;

    RadixNode *current = tree->root;
    const char *p = path;
    size_t comp_len;

    /* For root path "/" */
    const char *comp = next_component(p, &comp_len);
    if (!comp) {
        /* Mounting at root */
        current->mount = mount;
        return current;
    }

    while (comp) {
        current = find_or_create_child(tree, current, comp, comp_len);
        if (!current)
            return NULL;

        p = comp + comp_len;
        comp = next_component(p, &comp_len);
    }

    /* Set mount at this node */
    if (mount) {
        /* Stack: new mount shadows previous */
        if (current->mount) {
            mount->stacked = current->mount;
        }
        current->mount = mount;
    }

    return current;
}

RadixNode *klee_radix_lookup(const KleeRadixTree *tree, const char *path,
                              size_t *match_len, const char **remainder)
{
    if (!tree || !path)
        return NULL;

    RadixNode *current = tree->root;
    RadixNode *best_match = NULL;
    size_t best_len = 0;
    size_t pos = 0;

    /* Check root mount */
    if (current->mount) {
        best_match = current;
        best_len = 0;
    }

    const char *p = path;
    size_t comp_len;
    const char *comp = next_component(p, &comp_len);

    while (comp) {
        /* Search children */
        RadixNode *found = NULL;
        for (RadixNode *child = current->children; child; child = child->sibling) {
            if (child->component_len == comp_len &&
                memcmp(child->component, comp, comp_len) == 0) {
                found = child;
                break;
            }
        }

        if (!found)
            break;

        current = found;
        pos = (size_t)(comp + comp_len - path);

        if (current->mount) {
            best_match = current;
            best_len = pos;
        }

        p = comp + comp_len;
        comp = next_component(p, &comp_len);
    }

    if (match_len)
        *match_len = best_len;
    if (remainder)
        *remainder = path + best_len;

    return best_match;
}

RadixNode *klee_radix_find_exact(const KleeRadixTree *tree, const char *path)
{
    if (!tree || !path)
        return NULL;

    RadixNode *current = tree->root;
    const char *p = path;
    size_t comp_len;
    const char *comp = next_component(p, &comp_len);

    if (!comp) {
        /* Looking for root */
        return current;
    }

    while (comp) {
        RadixNode *found = NULL;
        for (RadixNode *child = current->children; child; child = child->sibling) {
            if (child->component_len == comp_len &&
                memcmp(child->component, comp, comp_len) == 0) {
                found = child;
                break;
            }
        }

        if (!found)
            return NULL;

        current = found;
        p = comp + comp_len;
        comp = next_component(p, &comp_len);
    }

    return current;
}

static void walk_node(const RadixNode *node, const char *prefix,
                       klee_radix_walk_fn fn, void *ctx)
{
    char path[PATH_MAX];
    if (node->component_len > 0)
        snprintf(path, sizeof(path), "%s/%.*s", prefix,
                 (int)node->component_len, node->component);
    else
        snprintf(path, sizeof(path), "%s", prefix);

    if (node->mount) {
        const char *cb_path = path[0] ? path : "/";
        fn(cb_path, node->mount, ctx);
    }

    for (RadixNode *child = node->children; child; child = child->sibling)
        walk_node(child, path, fn, ctx);
}

void klee_radix_walk(const KleeRadixTree *tree, klee_radix_walk_fn fn, void *ctx)
{
    if (!tree || !tree->root || !fn)
        return;
    walk_node(tree->root, "", fn, ctx);
}

static void dump_node(const RadixNode *node, int depth)
{
    for (int i = 0; i < depth; i++)
        fprintf(stderr, "  ");

    fprintf(stderr, "/%.*s", (int)node->component_len, node->component);
    if (node->mount)
        fprintf(stderr, " [MOUNT: src=%s]",
                node->mount->source ? node->mount->source : "(null)");
    fprintf(stderr, "\n");

    for (RadixNode *child = node->children; child; child = child->sibling)
        dump_node(child, depth + 1);
}

void klee_radix_dump(const KleeRadixTree *tree)
{
    if (!tree || !tree->root)
        return;
    fprintf(stderr, "=== Radix Tree (%zu nodes) ===\n", tree->num_nodes);
    dump_node(tree->root, 0);
}
