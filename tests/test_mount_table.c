/*
 * Klee - Mount table unit tests
 */
#include "fs/mount_table.h"
#include "fs/overlay.h"
#include "config.h"
#include "util/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>

#define TEST(name) static void test_##name(void)
#define RUN(name) do { printf("  %s... ", #name); test_##name(); printf("OK\n"); } while(0)

TEST(create_destroy)
{
    KleeMountTable *mt = klee_mount_table_create();
    assert(mt != NULL);
    klee_mount_table_destroy(mt);
}

TEST(add_and_resolve)
{
    KleeMountTable *mt = klee_mount_table_create();
    klee_mount_table_add(mt, MOUNT_BIND_RW, "/host/src", "/src", false, 0755);

    KleeMount *m = klee_mount_table_resolve(mt, "/src");
    assert(m != NULL);
    assert(strcmp(m->source, "/host/src") == 0);
    klee_mount_table_destroy(mt);
}

TEST(translate_bind)
{
    KleeMountTable *mt = klee_mount_table_create();
    klee_mount_table_add(mt, MOUNT_BIND_RW, "/host", "/guest", false, 0755);

    char host_path[PATH_MAX];
    int rc = klee_mount_table_translate(mt, "/guest/sub/file.txt",
                                         host_path, sizeof(host_path));
    assert(rc == 0);
    assert(strcmp(host_path, "/host/sub/file.txt") == 0);
    klee_mount_table_destroy(mt);
}

TEST(translate_root_bind)
{
    KleeMountTable *mt = klee_mount_table_create();
    klee_mount_table_add(mt, MOUNT_BIND_RW, "/", "/", false, 0755);

    char host_path[PATH_MAX];
    int rc = klee_mount_table_translate(mt, "/usr/lib/test.so",
                                         host_path, sizeof(host_path));
    assert(rc == 0);
    assert(strcmp(host_path, "/usr/lib/test.so") == 0);
    klee_mount_table_destroy(mt);
}

TEST(readonly_check)
{
    KleeMountTable *mt = klee_mount_table_create();
    klee_mount_table_add(mt, MOUNT_BIND_RO, "/host", "/ro", true, 0755);
    klee_mount_table_add(mt, MOUNT_BIND_RW, "/host/rw", "/rw", false, 0755);

    assert(klee_mount_table_is_readonly(mt, "/ro/file") == true);
    assert(klee_mount_table_is_readonly(mt, "/rw/file") == false);
    klee_mount_table_destroy(mt);
}

TEST(populate_from_config)
{
    KleeConfig cfg;
    klee_config_init(&cfg);

    klee_config_add_mount(&cfg, MOUNT_BIND_RW, "/", "/");
    klee_config_add_mount(&cfg, MOUNT_BIND_RO, "/etc", "/etc");

    KleeMountTable *mt = klee_mount_table_create();
    int rc = klee_mount_table_populate(mt, &cfg);
    assert(rc == 0);
    assert(mt->num_mounts >= 2);

    assert(klee_mount_table_is_readonly(mt, "/etc/passwd") == true);
    assert(klee_mount_table_is_readonly(mt, "/tmp/foo") == false);

    klee_mount_table_destroy(mt);
    klee_config_destroy(&cfg);
}

TEST(no_mount_passthrough)
{
    KleeMountTable *mt = klee_mount_table_create();
    /* No mounts added */

    char host_path[PATH_MAX];
    int rc = klee_mount_table_translate(mt, "/etc/passwd",
                                         host_path, sizeof(host_path));
    assert(rc == 0);
    assert(strcmp(host_path, "/etc/passwd") == 0);
    klee_mount_table_destroy(mt);
}

TEST(overlay_create_destroy)
{
    /* Create temp directories for lower layers */
    char lower1[] = "/tmp/klee-test-lower1-XXXXXX";
    char lower2[] = "/tmp/klee-test-lower2-XXXXXX";
    assert(mkdtemp(lower1) != NULL);
    assert(mkdtemp(lower2) != NULL);

    /* Create a file in lower1 */
    char file1[PATH_MAX];
    snprintf(file1, sizeof(file1), "%s/file1.txt", lower1);
    FILE *f = fopen(file1, "w");
    assert(f != NULL);
    fputs("hello", f);
    fclose(f);

    /* Create a file in lower2 */
    char file2[PATH_MAX];
    snprintf(file2, sizeof(file2), "%s/file2.txt", lower2);
    f = fopen(file2, "w");
    assert(f != NULL);
    fputs("world", f);
    fclose(f);

    char *lowers[] = { lower1, lower2 };
    KleeOverlayMount *ov = klee_overlay_create("/test-overlay", NULL, lowers, 2, false);
    assert(ov != NULL);
    assert(ov->merged_dir != NULL);
    assert(ov->upper_dir != NULL);
    assert(ov->lower_count == 2);
    assert(ov->readonly == false);

    klee_overlay_destroy(ov);

    /* Cleanup */
    unlink(file1);
    unlink(file2);
    rmdir(lower1);
    rmdir(lower2);
}

TEST(overlay_resolve_read)
{
    char lower1[] = "/tmp/klee-test-ovr-XXXXXX";
    assert(mkdtemp(lower1) != NULL);

    char file1[PATH_MAX];
    snprintf(file1, sizeof(file1), "%s/test.txt", lower1);
    FILE *f = fopen(file1, "w");
    assert(f != NULL);
    fputs("data", f);
    fclose(f);

    char *lowers[] = { lower1 };
    KleeOverlayMount *ov = klee_overlay_create("/test-ov", NULL, lowers, 1, false);
    assert(ov != NULL);

    /* Resolve a read for a file from the lower layer */
    char host_path[PATH_MAX];
    int rc = klee_overlay_resolve(ov, "test.txt", host_path, sizeof(host_path), false);
    assert(rc == 0);
    /* Should resolve to merged dir which has a symlink to the lower file */
    struct stat st;
    assert(lstat(host_path, &st) == 0);

    klee_overlay_destroy(ov);
    unlink(file1);
    rmdir(lower1);
}

TEST(overlay_resolve_write)
{
    char lower1[] = "/tmp/klee-test-ovw-XXXXXX";
    assert(mkdtemp(lower1) != NULL);

    char *lowers[] = { lower1 };
    KleeOverlayMount *ov = klee_overlay_create("/test-ow", NULL, lowers, 1, false);
    assert(ov != NULL);
    assert(ov->upper_dir != NULL);

    /* Write resolve should go to upper dir */
    char host_path[PATH_MAX];
    int rc = klee_overlay_resolve(ov, "new_file.txt", host_path, sizeof(host_path), true);
    assert(rc == 0);
    assert(strstr(host_path, ov->upper_dir) != NULL);

    klee_overlay_destroy(ov);
    rmdir(lower1);
}

TEST(overlay_readonly)
{
    char lower1[] = "/tmp/klee-test-ovro-XXXXXX";
    assert(mkdtemp(lower1) != NULL);

    char *lowers[] = { lower1 };
    KleeOverlayMount *ov = klee_overlay_create("/test-ro", NULL, lowers, 1, true);
    assert(ov != NULL);
    assert(ov->upper_dir == NULL);
    assert(ov->readonly == true);

    /* Write to readonly overlay should fail with EROFS */
    char host_path[PATH_MAX];
    int rc = klee_overlay_resolve(ov, "file.txt", host_path, sizeof(host_path), true);
    assert(rc == -EROFS);

    /* Read should succeed */
    rc = klee_overlay_resolve(ov, "", host_path, sizeof(host_path), false);
    assert(rc == 0);

    klee_overlay_destroy(ov);
    rmdir(lower1);
}

TEST(gen_mountinfo)
{
    KleeMountTable *mt = klee_mount_table_create();
    klee_mount_table_add(mt, MOUNT_BIND_RW, "/host", "/guest", false, 0755);
    klee_mount_table_add(mt, MOUNT_TMPFS, "/tmp/klee-tmp", "/tmp", false, 01777);

    char buf[4096];
    int len = klee_mount_table_gen_mountinfo(mt, buf, sizeof(buf));
    assert(len > 0);
    /* Should contain mount entries */
    assert(strstr(buf, "/guest") != NULL || strstr(buf, "/tmp") != NULL);

    klee_mount_table_destroy(mt);
}

/* ==== Runtime mutation API tests (mount(2)/umount2(2) emulation) ==== */

TEST(runtime_mount_umount)
{
    KleeMountTable *mt = klee_mount_table_create();
    klee_mount_table_add(mt, MOUNT_BIND_RW, "/", "/", false, 0755);

    /* Runtime mount */
    KleeMount *m = NULL;
    int rc = klee_mount_table_mount(mt, MOUNT_BIND_RW, "/host/data",
                                     "/mnt", false, 0, &m);
    assert(rc == 0);
    assert(m != NULL);

    char host_path[PATH_MAX];
    rc = klee_mount_table_translate(mt, "/mnt/file", host_path, PATH_MAX);
    assert(rc == 0);
    assert(strcmp(host_path, "/host/data/file") == 0);

    /* Umount restores passthrough (root bind) */
    rc = klee_mount_table_umount(mt, "/mnt", false);
    assert(rc == 0);
    rc = klee_mount_table_translate(mt, "/mnt/file", host_path, PATH_MAX);
    assert(rc == 0);
    assert(strcmp(host_path, "/mnt/file") == 0);

    /* Umount of non-mountpoint → -EINVAL */
    rc = klee_mount_table_umount(mt, "/mnt", false);
    assert(rc == -EINVAL);
    rc = klee_mount_table_umount(mt, "/not/mounted", false);
    assert(rc == -EINVAL);

    klee_mount_table_destroy(mt);
}

TEST(runtime_mount_stacking)
{
    KleeMountTable *mt = klee_mount_table_create();

    /* Stack two mounts on the same mountpoint */
    assert(klee_mount_table_mount(mt, MOUNT_BIND_RW, "/host/a",
                                   "/mnt", false, 0, NULL) == 0);
    assert(klee_mount_table_mount(mt, MOUNT_BIND_RW, "/host/b",
                                   "/mnt", false, 0, NULL) == 0);

    char host_path[PATH_MAX];
    assert(klee_mount_table_translate(mt, "/mnt/x", host_path,
                                       PATH_MAX) == 0);
    assert(strcmp(host_path, "/host/b/x") == 0); /* top of stack wins */

    /* Umount pops the stack, revealing /host/a */
    assert(klee_mount_table_umount(mt, "/mnt", false) == 0);
    assert(klee_mount_table_translate(mt, "/mnt/x", host_path,
                                       PATH_MAX) == 0);
    assert(strcmp(host_path, "/host/a/x") == 0);

    klee_mount_table_destroy(mt);
}

TEST(runtime_umount_busy)
{
    KleeMountTable *mt = klee_mount_table_create();

    assert(klee_mount_table_mount(mt, MOUNT_BIND_RW, "/host/a",
                                   "/mnt", false, 0, NULL) == 0);
    assert(klee_mount_table_mount(mt, MOUNT_BIND_RW, "/host/b",
                                   "/mnt/sub", false, 0, NULL) == 0);

    /* Child mount beneath → -EBUSY without MNT_DETACH */
    assert(klee_mount_table_umount(mt, "/mnt", false) == -EBUSY);

    /* MNT_DETACH removes the subtree */
    assert(klee_mount_table_umount(mt, "/mnt", true) == 0);
    char host_path[PATH_MAX];
    assert(klee_mount_table_translate(mt, "/mnt/sub/x", host_path,
                                       PATH_MAX) == 0);
    assert(strcmp(host_path, "/mnt/sub/x") == 0); /* passthrough again */

    klee_mount_table_destroy(mt);
}

TEST(runtime_remount)
{
    KleeMountTable *mt = klee_mount_table_create();

    assert(klee_mount_table_mount(mt, MOUNT_BIND_RW, "/host/a",
                                   "/mnt", false, 0, NULL) == 0);
    assert(klee_mount_table_is_readonly(mt, "/mnt/file") == false);

    /* Remount read-only */
    assert(klee_mount_table_remount(mt, "/mnt", true) == 0);
    assert(klee_mount_table_is_readonly(mt, "/mnt/file") == true);

    /* Remount read-write */
    assert(klee_mount_table_remount(mt, "/mnt", false) == 0);
    assert(klee_mount_table_is_readonly(mt, "/mnt/file") == false);

    /* Remount non-mountpoint → -EINVAL */
    assert(klee_mount_table_remount(mt, "/nope", true) == -EINVAL);

    klee_mount_table_destroy(mt);
}

TEST(runtime_move)
{
    KleeMountTable *mt = klee_mount_table_create();

    assert(klee_mount_table_mount(mt, MOUNT_BIND_RW, "/host/a",
                                   "/old", false, 0, NULL) == 0);
    assert(klee_mount_table_mount(mt, MOUNT_BIND_RW, "/host/sub",
                                   "/old/nested", false, 0, NULL) == 0);

    /* Move /old → /new, nested mount comes along */
    assert(klee_mount_table_move(mt, "/old", "/new") == 0);

    char host_path[PATH_MAX];
    assert(klee_mount_table_translate(mt, "/new/x", host_path,
                                       PATH_MAX) == 0);
    assert(strcmp(host_path, "/host/a/x") == 0);
    assert(klee_mount_table_translate(mt, "/new/nested/y", host_path,
                                       PATH_MAX) == 0);
    assert(strcmp(host_path, "/host/sub/y") == 0);

    /* Old location is passthrough */
    assert(klee_mount_table_translate(mt, "/old/x", host_path,
                                       PATH_MAX) == 0);
    assert(strcmp(host_path, "/old/x") == 0);

    /* Move of non-mountpoint → -EINVAL */
    assert(klee_mount_table_move(mt, "/old", "/other") == -EINVAL);
    /* Move under itself → -EINVAL */
    assert(klee_mount_table_move(mt, "/new", "/new/inside") == -EINVAL);

    klee_mount_table_destroy(mt);
}

TEST(runtime_propagation)
{
    KleeMountTable *mt = klee_mount_table_create();

    assert(klee_mount_table_mount(mt, MOUNT_BIND_RW, "/host/a",
                                   "/mnt", false, 0, NULL) == 0);
    assert(klee_mount_table_mount(mt, MOUNT_BIND_RW, "/host/b",
                                   "/mnt/sub", false, 0, NULL) == 0);

    /* Non-recursive: only /mnt */
    assert(klee_mount_table_set_propagation(mt, "/mnt",
                                             KLEE_PROP_SHARED,
                                             false) == 0);
    KleeMount *m = klee_mount_table_find_exact(mt, "/mnt");
    assert(m && m->propagation == KLEE_PROP_SHARED && m->peer_group > 0);
    KleeMount *sub = klee_mount_table_find_exact(mt, "/mnt/sub");
    assert(sub && sub->propagation == KLEE_PROP_PRIVATE);

    /* Recursive: /mnt/sub too */
    assert(klee_mount_table_set_propagation(mt, "/mnt",
                                             KLEE_PROP_SLAVE, true) == 0);
    sub = klee_mount_table_find_exact(mt, "/mnt/sub");
    assert(sub && sub->propagation == KLEE_PROP_SLAVE);

    /* Propagation in mountinfo optional fields */
    assert(klee_mount_table_set_propagation(mt, "/mnt",
                                             KLEE_PROP_SHARED,
                                             false) == 0);
    char buf[4096];
    int len = klee_mount_table_gen_mountinfo(mt, buf, sizeof(buf));
    assert(len > 0);
    assert(strstr(buf, "shared:") != NULL);

    /* Non-mountpoint → -EINVAL */
    assert(klee_mount_table_set_propagation(mt, "/nope",
                                             KLEE_PROP_SHARED,
                                             false) == -EINVAL);

    klee_mount_table_destroy(mt);
}

TEST(runtime_find_exact)
{
    KleeMountTable *mt = klee_mount_table_create();
    assert(klee_mount_table_mount(mt, MOUNT_BIND_RW, "/host/a",
                                   "/mnt", false, 0, NULL) == 0);

    assert(klee_mount_table_find_exact(mt, "/mnt") != NULL);
    /* Prefix paths are NOT exact matches */
    assert(klee_mount_table_find_exact(mt, "/mnt/sub") == NULL);
    assert(klee_mount_table_find_exact(mt, "/m") == NULL);

    klee_mount_table_destroy(mt);
}

int main(void)
{
    klee_log_init(LOG_ERROR);
    printf("=== Mount Table Tests ===\n");
    RUN(create_destroy);
    RUN(add_and_resolve);
    RUN(translate_bind);
    RUN(translate_root_bind);
    RUN(readonly_check);
    RUN(populate_from_config);
    RUN(no_mount_passthrough);
    RUN(overlay_create_destroy);
    RUN(overlay_resolve_read);
    RUN(overlay_resolve_write);
    RUN(overlay_readonly);
    RUN(gen_mountinfo);
    RUN(runtime_mount_umount);
    RUN(runtime_mount_stacking);
    RUN(runtime_umount_busy);
    RUN(runtime_remount);
    RUN(runtime_move);
    RUN(runtime_propagation);
    RUN(runtime_find_exact);
    printf("All mount table tests passed!\n");
    return 0;
}
