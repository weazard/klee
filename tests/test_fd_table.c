/*
 * Klee - FD table unit tests
 */
#include "fs/fd_table.h"
#include "util/log.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define TEST(name) static void test_##name(void)
#define RUN(name) do { printf("  %s... ", #name); test_##name(); printf("OK\n"); } while(0)

TEST(create_destroy)
{
    KleeFdTable *ft = klee_fd_table_create();
    assert(ft != NULL);
    assert(ft->count == 0);
    klee_fd_table_destroy(ft);
}

TEST(set_and_get)
{
    KleeFdTable *ft = klee_fd_table_create();
    klee_fd_table_set(ft, 3, "/etc/passwd", false);
    const char *path = klee_fd_table_get(ft, 3);
    assert(path != NULL);
    assert(strcmp(path, "/etc/passwd") == 0);
    assert(ft->count == 1);
    klee_fd_table_destroy(ft);
}

TEST(remove_fd)
{
    KleeFdTable *ft = klee_fd_table_create();
    klee_fd_table_set(ft, 3, "/etc/passwd", false);
    klee_fd_table_remove(ft, 3);
    assert(klee_fd_table_get(ft, 3) == NULL);
    assert(ft->count == 0);
    klee_fd_table_destroy(ft);
}

TEST(dup_fd)
{
    KleeFdTable *ft = klee_fd_table_create();
    klee_fd_table_set(ft, 3, "/etc/passwd", false);
    klee_fd_table_dup(ft, 3, 4, false);
    const char *path = klee_fd_table_get(ft, 4);
    assert(path != NULL);
    assert(strcmp(path, "/etc/passwd") == 0);
    assert(ft->count == 2);
    klee_fd_table_destroy(ft);
}

TEST(cloexec)
{
    KleeFdTable *ft = klee_fd_table_create();
    klee_fd_table_set(ft, 3, "/test", true);
    klee_fd_table_set(ft, 4, "/keep", false);
    assert(klee_fd_table_is_cloexec(ft, 3) == true);
    assert(klee_fd_table_is_cloexec(ft, 4) == false);

    klee_fd_table_exec(ft);
    assert(klee_fd_table_get(ft, 3) == NULL); /* removed */
    assert(klee_fd_table_get(ft, 4) != NULL); /* kept */
    assert(ft->count == 1);
    klee_fd_table_destroy(ft);
}

TEST(clone_table)
{
    KleeFdTable *ft = klee_fd_table_create();
    klee_fd_table_set(ft, 3, "/test1", false);
    klee_fd_table_set(ft, 4, "/test2", true);

    KleeFdTable *clone = klee_fd_table_clone(ft);
    assert(clone != NULL);
    assert(clone->count == 2);
    assert(strcmp(klee_fd_table_get(clone, 3), "/test1") == 0);
    assert(strcmp(klee_fd_table_get(clone, 4), "/test2") == 0);
    assert(klee_fd_table_is_cloexec(clone, 4) == true);

    /* Modify clone shouldn't affect original */
    klee_fd_table_remove(clone, 3);
    assert(klee_fd_table_get(ft, 3) != NULL);
    assert(klee_fd_table_get(clone, 3) == NULL);

    klee_fd_table_destroy(ft);
    klee_fd_table_destroy(clone);
}

TEST(overwrite_fd)
{
    KleeFdTable *ft = klee_fd_table_create();
    klee_fd_table_set(ft, 3, "/old", false);
    klee_fd_table_set(ft, 3, "/new", true);
    assert(ft->count == 1);
    assert(strcmp(klee_fd_table_get(ft, 3), "/new") == 0);
    assert(klee_fd_table_is_cloexec(ft, 3) == true);
    klee_fd_table_destroy(ft);
}

TEST(set_cloexec)
{
    KleeFdTable *ft = klee_fd_table_create();
    klee_fd_table_set(ft, 3, "/test", false);
    assert(klee_fd_table_is_cloexec(ft, 3) == false);
    klee_fd_table_set_cloexec(ft, 3, true);
    assert(klee_fd_table_is_cloexec(ft, 3) == true);
    klee_fd_table_destroy(ft);
}

TEST(many_fds)
{
    KleeFdTable *ft = klee_fd_table_create();
    for (int i = 0; i < 200; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/fd/%d", i);
        klee_fd_table_set(ft, i, path, i % 2 == 0);
    }
    assert(ft->count == 200);

    for (int i = 0; i < 200; i++) {
        char expected[64];
        snprintf(expected, sizeof(expected), "/fd/%d", i);
        assert(strcmp(klee_fd_table_get(ft, i), expected) == 0);
    }
    klee_fd_table_destroy(ft);
}

int main(void)
{
    klee_log_init(LOG_ERROR);
    printf("=== FD Table Tests ===\n");
    RUN(create_destroy);
    RUN(set_and_get);
    RUN(remove_fd);
    RUN(dup_fd);
    RUN(cloexec);
    RUN(clone_table);
    RUN(overwrite_fd);
    RUN(set_cloexec);
    RUN(many_fds);
    printf("All FD table tests passed!\n");
    return 0;
}
