/*
 * Klee - Process table unit tests
 *
 * Allocation failures are injected with -Wl,--wrap=malloc,--wrap=calloc
 * (see the Makefile rule).
 */
#include "process/process.h"
#include "fs/fd_table.h"
#include "util/hash_table.h"
#include "util/log.h"
#include <assert.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST(name) static void test_##name(void)
#define RUN(name) do { printf("  %s... ", #name); test_##name(); printf("OK\n"); } while(0)

static size_t fail_malloc_size;                   /* malloc of this size fails */
static size_t fail_calloc_nmemb, fail_calloc_size; /* calloc of this shape fails */

void *__real_malloc(size_t size);
void *__real_calloc(size_t nmemb, size_t size);

void *__wrap_malloc(size_t size)
{
    if (fail_malloc_size && size == fail_malloc_size)
        return NULL;
    return __real_malloc(size);
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
    if (fail_calloc_nmemb && nmemb == fail_calloc_nmemb &&
        size == fail_calloc_size)
        return NULL;
    return __real_calloc(nmemb, size);
}

#define PARENT 1000
#define CHILD  1001

static KleeProcessTable *table_with_parent(KleeProcess **parent)
{
    KleeProcessTable *pt = klee_proctable_create();
    assert(pt != NULL);
    *parent = klee_process_create(pt, PARENT, NULL);
    assert(*parent != NULL);
    assert(klee_fd_table_set((*parent)->fd_table, 3, "/etc", false) == 0);
    return pt;
}

static void destroy(KleeProcessTable *pt)
{
    klee_process_remove(pt, CHILD);
    klee_process_remove(pt, PARENT);
    klee_proctable_destroy(pt);
}

TEST(fork_copies_fd_table)
{
    KleeProcess *parent;
    KleeProcessTable *pt = table_with_parent(&parent);
    KleeProcess *child = klee_process_fork(pt, parent, CHILD, 0);
    assert(child != NULL);
    assert(klee_process_find(pt, CHILD) == child && pt->count == 2);
    assert(child->fd_table != NULL && child->fd_table != parent->fd_table);
    assert(strcmp(klee_fd_table_get(child->fd_table, 3), "/etc") == 0);
    destroy(pt);
}

TEST(fork_shares_fd_table)
{
    KleeProcess *parent;
    KleeProcessTable *pt = table_with_parent(&parent);
    KleeProcess *child = klee_process_fork(pt, parent, CHILD,
                                           CLONE_FILES | CLONE_FS);
    assert(child != NULL);
    assert(child->fd_table == parent->fd_table);
    assert(parent->fd_table->refs == 2);
    assert(child->fs == parent->fs);
    destroy(pt);
}

/* The copy of the FD table runs out of memory: no child, nothing changed */
TEST(fork_copy_fails)
{
    KleeProcess *parent;
    KleeProcessTable *pt = table_with_parent(&parent);
    KleeFdTable *table = parent->fd_table;

    fail_malloc_size = sizeof(KleeFdEntry);
    KleeProcess *child = klee_process_fork(pt, parent, CHILD, 0);
    fail_malloc_size = 0;

    assert(child == NULL);
    assert(klee_process_find(pt, CHILD) == NULL && pt->count == 1);
    assert(parent->fd_table == table && table->refs == 1);
    assert(parent->first_child == NULL);
    destroy(pt);
}

/* The process table cannot grow: no process half registered */
TEST(create_table_full)
{
    KleeProcessTable *pt = klee_proctable_create();
    assert(pt != NULL);
    size_t cap = pt->by_pid->capacity;
    pid_t pid = 2000;
    while (pt->by_pid->count + 1 <=
           (size_t)(cap * KLEE_HT_MAX_LOAD_FACTOR))
        assert(klee_process_create(pt, pid++, NULL) != NULL);

    /* The next insert must grow the table */
    fail_calloc_nmemb = cap * 2;
    fail_calloc_size = sizeof(KleeHTEntry);
    KleeProcess *proc = klee_process_create(pt, pid, NULL);
    fail_calloc_nmemb = fail_calloc_size = 0;

    assert(proc == NULL);
    assert(klee_process_find(pt, pid) == NULL);
    assert(pt->count == pt->by_pid->count);

    for (pid_t p = 2000; p < pid; p++)
        klee_process_remove(pt, p);
    klee_proctable_destroy(pt);
}

int main(void)
{
    klee_log_init(LOG_ERROR);
    printf("=== Process Table Tests ===\n");
    RUN(fork_copies_fd_table);
    RUN(fork_shares_fd_table);
    RUN(fork_copy_fails);
    RUN(create_table_full);
    printf("All process table tests passed!\n");
    return 0;
}
