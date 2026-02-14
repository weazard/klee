/*
 * Klee - Radix tree unit tests
 */
#include "fs/radix_tree.h"
#include "fs/mount_table.h"
#include "util/arena.h"
#include "util/log.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define TEST(name) static void test_##name(void)
#define RUN(name) do { printf("  %s... ", #name); test_##name(); printf("OK\n"); } while(0)

static KleeMount *make_mount(KleeArena *arena, const char *src, const char *dest)
{
    KleeMount *m = klee_arena_calloc(arena, 1, sizeof(KleeMount));
    m->source = klee_arena_strdup(arena, src);
    m->dest = klee_arena_strdup(arena, dest);
    m->type = MOUNT_BIND_RW;
    return m;
}

TEST(create_empty)
{
    KleeArena *arena = klee_arena_create(0);
    KleeRadixTree *tree = klee_radix_create(arena);
    assert(tree != NULL);
    assert(tree->root != NULL);
    assert(tree->num_nodes == 1);
    klee_arena_destroy(arena);
}

TEST(insert_root)
{
    KleeArena *arena = klee_arena_create(0);
    KleeRadixTree *tree = klee_radix_create(arena);
    KleeMount *m = make_mount(arena, "/host", "/");
    RadixNode *node = klee_radix_insert(tree, "/", m);
    assert(node != NULL);
    assert(node->mount == m);
    klee_arena_destroy(arena);
}

TEST(insert_simple_path)
{
    KleeArena *arena = klee_arena_create(0);
    KleeRadixTree *tree = klee_radix_create(arena);
    KleeMount *m = make_mount(arena, "/host/tmp", "/tmp");
    RadixNode *node = klee_radix_insert(tree, "/tmp", m);
    assert(node != NULL);
    assert(node->mount == m);
    klee_arena_destroy(arena);
}

TEST(insert_deep_path)
{
    KleeArena *arena = klee_arena_create(0);
    KleeRadixTree *tree = klee_radix_create(arena);
    KleeMount *m = make_mount(arena, "/host/usr/lib", "/usr/lib");
    RadixNode *node = klee_radix_insert(tree, "/usr/lib", m);
    assert(node != NULL);
    assert(node->mount == m);
    assert(tree->num_nodes == 3); /* root, usr, lib */
    klee_arena_destroy(arena);
}

TEST(lookup_exact)
{
    KleeArena *arena = klee_arena_create(0);
    KleeRadixTree *tree = klee_radix_create(arena);
    KleeMount *m = make_mount(arena, "/h", "/tmp");
    klee_radix_insert(tree, "/tmp", m);

    size_t match_len;
    RadixNode *found = klee_radix_lookup(tree, "/tmp", &match_len, NULL);
    assert(found != NULL);
    assert(found->mount == m);
    assert(match_len == 4); /* "/tmp" */
    klee_arena_destroy(arena);
}

TEST(lookup_prefix)
{
    KleeArena *arena = klee_arena_create(0);
    KleeRadixTree *tree = klee_radix_create(arena);
    KleeMount *m = make_mount(arena, "/h", "/usr");
    klee_radix_insert(tree, "/usr", m);

    size_t match_len;
    const char *remainder;
    RadixNode *found = klee_radix_lookup(tree, "/usr/lib/foo.so",
                                          &match_len, &remainder);
    assert(found != NULL);
    assert(found->mount == m);
    klee_arena_destroy(arena);
}

TEST(lookup_no_match)
{
    KleeArena *arena = klee_arena_create(0);
    KleeRadixTree *tree = klee_radix_create(arena);
    KleeMount *m = make_mount(arena, "/h", "/usr");
    klee_radix_insert(tree, "/usr", m);

    size_t match_len;
    RadixNode *found = klee_radix_lookup(tree, "/var/log", &match_len, NULL);
    /* Should return NULL since no root mount */
    assert(found == NULL);
    klee_arena_destroy(arena);
}

TEST(lookup_root_fallback)
{
    KleeArena *arena = klee_arena_create(0);
    KleeRadixTree *tree = klee_radix_create(arena);
    KleeMount *root_m = make_mount(arena, "/", "/");
    KleeMount *usr_m = make_mount(arena, "/h-usr", "/usr");
    klee_radix_insert(tree, "/", root_m);
    klee_radix_insert(tree, "/usr", usr_m);

    size_t match_len;
    /* /var should match root */
    RadixNode *found = klee_radix_lookup(tree, "/var/log", &match_len, NULL);
    assert(found != NULL);
    assert(found->mount == root_m);

    /* /usr/lib should match /usr */
    found = klee_radix_lookup(tree, "/usr/lib", &match_len, NULL);
    assert(found != NULL);
    assert(found->mount == usr_m);
    klee_arena_destroy(arena);
}

TEST(longest_prefix_match)
{
    KleeArena *arena = klee_arena_create(0);
    KleeRadixTree *tree = klee_radix_create(arena);
    KleeMount *root_m = make_mount(arena, "/", "/");
    KleeMount *usr_m = make_mount(arena, "/h-usr", "/usr");
    KleeMount *lib_m = make_mount(arena, "/h-lib", "/usr/lib");
    klee_radix_insert(tree, "/", root_m);
    klee_radix_insert(tree, "/usr", usr_m);
    klee_radix_insert(tree, "/usr/lib", lib_m);

    size_t match_len;
    /* /usr/lib/x86_64 should match /usr/lib (longest) */
    RadixNode *found = klee_radix_lookup(tree, "/usr/lib/x86_64",
                                          &match_len, NULL);
    assert(found != NULL);
    assert(found->mount == lib_m);

    /* /usr/bin should match /usr */
    found = klee_radix_lookup(tree, "/usr/bin", &match_len, NULL);
    assert(found != NULL);
    assert(found->mount == usr_m);
    klee_arena_destroy(arena);
}

TEST(find_exact)
{
    KleeArena *arena = klee_arena_create(0);
    KleeRadixTree *tree = klee_radix_create(arena);
    KleeMount *m = make_mount(arena, "/h", "/usr/lib");
    klee_radix_insert(tree, "/usr/lib", m);

    RadixNode *found = klee_radix_find_exact(tree, "/usr/lib");
    assert(found != NULL);
    assert(found->mount == m);

    found = klee_radix_find_exact(tree, "/usr");
    assert(found != NULL);
    assert(found->mount == NULL); /* /usr exists as node but no mount */

    found = klee_radix_find_exact(tree, "/var");
    assert(found == NULL);
    klee_arena_destroy(arena);
}

TEST(mount_stacking)
{
    KleeArena *arena = klee_arena_create(0);
    KleeRadixTree *tree = klee_radix_create(arena);
    KleeMount *m1 = make_mount(arena, "/first", "/mnt");
    KleeMount *m2 = make_mount(arena, "/second", "/mnt");
    klee_radix_insert(tree, "/mnt", m1);
    klee_radix_insert(tree, "/mnt", m2);

    /* m2 should shadow m1 */
    RadixNode *found = klee_radix_find_exact(tree, "/mnt");
    assert(found != NULL);
    assert(found->mount == m2);
    assert(found->mount->stacked == m1);
    klee_arena_destroy(arena);
}

int main(void)
{
    klee_log_init(LOG_ERROR);
    printf("=== Radix Tree Tests ===\n");
    RUN(create_empty);
    RUN(insert_root);
    RUN(insert_simple_path);
    RUN(insert_deep_path);
    RUN(lookup_exact);
    RUN(lookup_prefix);
    RUN(lookup_no_match);
    RUN(lookup_root_fallback);
    RUN(longest_prefix_match);
    RUN(find_exact);
    RUN(mount_stacking);
    printf("All radix tree tests passed!\n");
    return 0;
}
