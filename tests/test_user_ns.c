/*
 * Klee - UID/GID simulation unit tests
 */
#include "ns/user_ns.h"
#include "util/log.h"
#include <stdio.h>
#include <assert.h>

#define TEST(name) static void test_##name(void)
#define RUN(name) do { printf("  %s... ", #name); test_##name(); printf("OK\n"); } while(0)

TEST(create_with_uid0)
{
    KleeIdState *ids = klee_id_state_create(0, 0);
    assert(ids != NULL);
    assert(ids->ruid == 0);
    assert(ids->euid == 0);
    assert(ids->suid == 0);
    assert(ids->fsuid == 0);
    assert(ids->rgid == 0);
    assert(ids->egid == 0);
    klee_id_state_destroy(ids);
}

TEST(setuid)
{
    KleeIdState *ids = klee_id_state_create(0, 0);
    int rc = klee_user_ns_handle_setuid(ids, 1000);
    assert(rc == 0);
    assert(ids->ruid == 1000);
    assert(ids->euid == 1000);
    assert(ids->suid == 1000);
    assert(ids->fsuid == 1000);
    klee_id_state_destroy(ids);
}

TEST(setgid)
{
    KleeIdState *ids = klee_id_state_create(0, 0);
    int rc = klee_user_ns_handle_setgid(ids, 1000);
    assert(rc == 0);
    assert(ids->rgid == 1000);
    assert(ids->egid == 1000);
    assert(ids->sgid == 1000);
    assert(ids->fsgid == 1000);
    klee_id_state_destroy(ids);
}

TEST(setreuid)
{
    KleeIdState *ids = klee_id_state_create(0, 0);
    int rc = klee_user_ns_handle_setreuid(ids, 1000, 2000);
    assert(rc == 0);
    assert(ids->ruid == 1000);
    assert(ids->euid == 2000);
    assert(ids->suid == 2000);
    klee_id_state_destroy(ids);
}

TEST(setreuid_minus1)
{
    KleeIdState *ids = klee_id_state_create(0, 0);
    int rc = klee_user_ns_handle_setreuid(ids, (uid_t)-1, 1000);
    assert(rc == 0);
    assert(ids->ruid == 0);  /* unchanged */
    assert(ids->euid == 1000);
    klee_id_state_destroy(ids);
}

TEST(setresuid)
{
    KleeIdState *ids = klee_id_state_create(0, 0);
    int rc = klee_user_ns_handle_setresuid(ids, 100, 200, 300);
    assert(rc == 0);
    assert(ids->ruid == 100);
    assert(ids->euid == 200);
    assert(ids->suid == 300);
    assert(ids->fsuid == 200); /* follows euid */
    klee_id_state_destroy(ids);
}

TEST(setfsuid)
{
    KleeIdState *ids = klee_id_state_create(0, 0);
    int rc = klee_user_ns_handle_setfsuid(ids, 999);
    assert(rc == 0);
    assert(ids->fsuid == 999);
    assert(ids->euid == 0); /* unchanged */
    klee_id_state_destroy(ids);
}

TEST(clone_state)
{
    KleeIdState *ids = klee_id_state_create(0, 0);
    klee_user_ns_handle_setuid(ids, 42);

    KleeIdState *clone = klee_id_state_clone(ids);
    assert(clone != NULL);
    assert(clone->ruid == 42);
    assert(clone->euid == 42);

    /* Modifying clone shouldn't affect original */
    klee_user_ns_handle_setuid(clone, 99);
    assert(ids->ruid == 42);
    assert(clone->ruid == 99);

    klee_id_state_destroy(ids);
    klee_id_state_destroy(clone);
}

int main(void)
{
    klee_log_init(LOG_ERROR);
    printf("=== User NS Tests ===\n");
    RUN(create_with_uid0);
    RUN(setuid);
    RUN(setgid);
    RUN(setreuid);
    RUN(setreuid_minus1);
    RUN(setresuid);
    RUN(setfsuid);
    RUN(clone_state);
    printf("All user NS tests passed!\n");
    return 0;
}
