/*
 * Klee - Path resolution unit tests
 */
#include "fs/path_resolve.h"
#include "fs/mount_table.h"
#include "fs/fd_table.h"
#include "util/log.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>

#define TEST(name) static void test_##name(void)
#define RUN(name) do { printf("  %s... ", #name); test_##name(); printf("OK\n"); } while(0)

static KleeMountTable *make_mt(void)
{
    KleeMountTable *mt = klee_mount_table_create();
    klee_mount_table_add(mt, MOUNT_BIND_RW, "/", "/", false, 0755);
    return mt;
}

TEST(absolute_path)
{
    KleeMountTable *mt = make_mt();
    KleeResolveCtx ctx = { .mount_table = mt, .vcwd = "/", .vroot = "/" };
    char resolved[PATH_MAX];

    int rc = klee_path_resolve(&ctx, "/usr/lib", resolved, AT_FDCWD);
    assert(rc == 0);
    assert(strcmp(resolved, "/usr/lib") == 0);
    klee_mount_table_destroy(mt);
}

TEST(relative_path)
{
    KleeMountTable *mt = make_mt();
    KleeResolveCtx ctx = { .mount_table = mt, .vcwd = "/home/user", .vroot = "/" };
    char resolved[PATH_MAX];

    int rc = klee_path_resolve(&ctx, "docs/file.txt", resolved, AT_FDCWD);
    assert(rc == 0);
    assert(strcmp(resolved, "/home/user/docs/file.txt") == 0);
    klee_mount_table_destroy(mt);
}

TEST(dot_components)
{
    KleeMountTable *mt = make_mt();
    KleeResolveCtx ctx = { .mount_table = mt, .vcwd = "/", .vroot = "/" };
    char resolved[PATH_MAX];

    int rc = klee_path_resolve(&ctx, "/usr/./lib/./test", resolved, AT_FDCWD);
    assert(rc == 0);
    assert(strcmp(resolved, "/usr/lib/test") == 0);
    klee_mount_table_destroy(mt);
}

TEST(dotdot_components)
{
    KleeMountTable *mt = make_mt();
    KleeResolveCtx ctx = { .mount_table = mt, .vcwd = "/", .vroot = "/" };
    char resolved[PATH_MAX];

    int rc = klee_path_resolve(&ctx, "/usr/lib/../bin/test", resolved, AT_FDCWD);
    assert(rc == 0);
    assert(strcmp(resolved, "/usr/bin/test") == 0);
    klee_mount_table_destroy(mt);
}

TEST(dotdot_at_root)
{
    KleeMountTable *mt = make_mt();
    KleeResolveCtx ctx = { .mount_table = mt, .vcwd = "/", .vroot = "/" };
    char resolved[PATH_MAX];

    int rc = klee_path_resolve(&ctx, "/../../../etc/passwd", resolved, AT_FDCWD);
    assert(rc == 0);
    assert(strcmp(resolved, "/etc/passwd") == 0);
    klee_mount_table_destroy(mt);
}

TEST(trailing_slashes)
{
    KleeMountTable *mt = make_mt();
    KleeResolveCtx ctx = { .mount_table = mt, .vcwd = "/", .vroot = "/" };
    char resolved[PATH_MAX];

    int rc = klee_path_resolve(&ctx, "/usr///lib///", resolved, AT_FDCWD);
    assert(rc == 0);
    assert(strcmp(resolved, "/usr/lib") == 0);
    klee_mount_table_destroy(mt);
}

TEST(root_path)
{
    KleeMountTable *mt = make_mt();
    KleeResolveCtx ctx = { .mount_table = mt, .vcwd = "/", .vroot = "/" };
    char resolved[PATH_MAX];

    int rc = klee_path_resolve(&ctx, "/", resolved, AT_FDCWD);
    assert(rc == 0);
    assert(strcmp(resolved, "/") == 0);
    klee_mount_table_destroy(mt);
}

TEST(guest_to_host)
{
    KleeMountTable *mt = klee_mount_table_create();
    klee_mount_table_add(mt, MOUNT_BIND_RW, "/real/root", "/", false, 0755);

    KleeResolveCtx ctx = { .mount_table = mt, .vcwd = "/", .vroot = "/" };
    char host_path[PATH_MAX];

    int rc = klee_path_guest_to_host(&ctx, "/etc/passwd", host_path, AT_FDCWD);
    assert(rc == 0);
    assert(strcmp(host_path, "/real/root/etc/passwd") == 0);
    klee_mount_table_destroy(mt);
}

int main(void)
{
    klee_log_init(LOG_ERROR);
    printf("=== Path Resolve Tests ===\n");
    RUN(absolute_path);
    RUN(relative_path);
    RUN(dot_components);
    RUN(dotdot_components);
    RUN(dotdot_at_root);
    RUN(trailing_slashes);
    RUN(root_path);
    RUN(guest_to_host);
    printf("All path resolve tests passed!\n");
    return 0;
}
