/*
 * Klee - PID namespace unit tests
 */
#include "ns/pid_ns.h"
#include "util/log.h"
#include <stdio.h>
#include <assert.h>

#define TEST(name) static void test_##name(void)
#define RUN(name) do { printf("  %s... ", #name); test_##name(); printf("OK\n"); } while(0)

TEST(create_destroy)
{
    KleePidMap *pm = klee_pid_map_create();
    assert(pm != NULL);
    assert(klee_pid_map_count(pm) == 0);
    klee_pid_map_destroy(pm);
}

TEST(first_is_pid1)
{
    KleePidMap *pm = klee_pid_map_create();
    pid_t vpid = klee_pid_map_add(pm, 42);
    assert(vpid == 1);
    assert(klee_pid_map_is_init(pm, 42));
    assert(klee_pid_map_get_init(pm) == 42);
    klee_pid_map_destroy(pm);
}

TEST(sequential_assignment)
{
    KleePidMap *pm = klee_pid_map_create();
    pid_t v1 = klee_pid_map_add(pm, 100);
    pid_t v2 = klee_pid_map_add(pm, 200);
    pid_t v3 = klee_pid_map_add(pm, 300);
    assert(v1 == 1);
    assert(v2 == 2);
    assert(v3 == 3);
    assert(klee_pid_map_count(pm) == 3);
    klee_pid_map_destroy(pm);
}

TEST(bidirectional_lookup)
{
    KleePidMap *pm = klee_pid_map_create();
    klee_pid_map_add(pm, 100);  /* vpid 1 */
    klee_pid_map_add(pm, 200);  /* vpid 2 */

    assert(klee_pid_map_r2v(pm, 100) == 1);
    assert(klee_pid_map_r2v(pm, 200) == 2);
    assert(klee_pid_map_v2r(pm, 1) == 100);
    assert(klee_pid_map_v2r(pm, 2) == 200);
    assert(klee_pid_map_r2v(pm, 999) == 0);
    assert(klee_pid_map_v2r(pm, 999) == 0);
    klee_pid_map_destroy(pm);
}

TEST(remove_process)
{
    KleePidMap *pm = klee_pid_map_create();
    klee_pid_map_add(pm, 100);
    klee_pid_map_add(pm, 200);
    assert(klee_pid_map_count(pm) == 2);

    klee_pid_map_remove(pm, 100);
    assert(klee_pid_map_count(pm) == 1);
    assert(klee_pid_map_r2v(pm, 100) == 0);
    assert(klee_pid_map_v2r(pm, 1) == 0);
    assert(klee_pid_map_r2v(pm, 200) == 2);
    klee_pid_map_destroy(pm);
}

TEST(duplicate_add)
{
    KleePidMap *pm = klee_pid_map_create();
    pid_t v1 = klee_pid_map_add(pm, 100);
    pid_t v2 = klee_pid_map_add(pm, 100);
    assert(v1 == v2);
    assert(klee_pid_map_count(pm) == 1);
    klee_pid_map_destroy(pm);
}

TEST(explicit_add)
{
    KleePidMap *pm = klee_pid_map_create();
    int rc = klee_pid_map_add_explicit(pm, 42, 1);
    assert(rc == 0);
    assert(klee_pid_map_r2v(pm, 42) == 1);
    assert(klee_pid_map_v2r(pm, 1) == 42);
    assert(klee_pid_map_is_init(pm, 42));
    klee_pid_map_destroy(pm);
}

int main(void)
{
    klee_log_init(LOG_ERROR);
    printf("=== PID Namespace Tests ===\n");
    RUN(create_destroy);
    RUN(first_is_pid1);
    RUN(sequential_assignment);
    RUN(bidirectional_lookup);
    RUN(remove_process);
    RUN(duplicate_add);
    RUN(explicit_add);
    printf("All PID namespace tests passed!\n");
    return 0;
}
