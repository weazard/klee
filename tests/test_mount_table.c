/*
 * Klee - Mount table unit tests
 */
#include "fs/mount_table.h"
#include "fs/overlay.h"
#include "fs/tmpfs.h"
#include "config.h"
#include "util/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <stdbool.h>
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

/* ---- overlay fixtures ---- */

static void write_file(const char *path, const char *data)
{
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    fputs(data, f);
    fclose(f);
}

static const char *read_file(const char *path)
{
    static char buf[256];
    FILE *f = fopen(path, "r");
    if (!f)
        return "(missing)";
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static bool exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

static int cmp_name(const void *a, const void *b)
{
    return strcmp(a, b);
}

/* Sorted entries of a directory, "name/" for subdirectories */
static const char *listing(const char *dir)
{
    static char out[1024];
    char names[64][64];
    int n = 0;
    DIR *d = opendir(dir);
    assert(d != NULL);
    struct dirent *de;
    while ((de = readdir(d)) != NULL && n < 64) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        snprintf(names[n++], sizeof(names[0]), "%.60s%s", de->d_name,
                 de->d_type == DT_DIR ? "/" : "");
    }
    closedir(d);
    qsort(names, (size_t)n, sizeof(names[0]), cmp_name);
    out[0] = '\0';
    for (int i = 0; i < n; i++) {
        if (i)
            strcat(out, " ");
        strcat(out, names[i]);
    }
    return out;
}

static int rm_entry(const char *path, const struct stat *st, int flag,
                    struct FTW *ftw)
{
    (void)st; (void)flag; (void)ftw;
    return remove(path);
}

static void rm_rf(const char *path)
{
    nftw(path, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
}

/* lower1: a, shared ("lower1"), sub/inner;  lower2: b, shared ("lower2") */
typedef struct {
    char l1[64], l2[64];
    KleeOverlayMount *ov;
} OvFixture;

static void ov_setup(OvFixture *fx, bool ro)
{
    char p[PATH_MAX];
    strcpy(fx->l1, "/tmp/klee-test-ov1-XXXXXX");
    strcpy(fx->l2, "/tmp/klee-test-ov2-XXXXXX");
    assert(mkdtemp(fx->l1) != NULL && mkdtemp(fx->l2) != NULL);
    snprintf(p, sizeof(p), "%s/a", fx->l1);         write_file(p, "a1");
    snprintf(p, sizeof(p), "%s/shared", fx->l1);    write_file(p, "lower1");
    snprintf(p, sizeof(p), "%s/sub", fx->l1);       assert(mkdir(p, 0755) == 0);
    snprintf(p, sizeof(p), "%s/sub/inner", fx->l1); write_file(p, "inner");
    snprintf(p, sizeof(p), "%s/b", fx->l2);         write_file(p, "b2");
    snprintf(p, sizeof(p), "%s/shared", fx->l2);    write_file(p, "lower2");

    char *lowers[] = { fx->l1, fx->l2 };
    fx->ov = klee_overlay_create("/test-ov", NULL, lowers, 2, ro);
    assert(fx->ov != NULL);
}

static void ov_teardown(OvFixture *fx)
{
    klee_overlay_destroy(fx->ov);
    rm_rf(fx->l1);
    rm_rf(fx->l2);
}

static bool in_upper(const OvFixture *fx, const char *host)
{
    return strncmp(host, fx->ov->upper_dir, strlen(fx->ov->upper_dir)) == 0;
}

TEST(overlay_read_and_list)
{
    OvFixture fx;
    ov_setup(&fx, false);
    char host[PATH_MAX];

    /* The topmost layer wins */
    assert(klee_overlay_resolve(fx.ov, "shared", host, sizeof(host), KLEE_OV_READ) == 0);
    assert(strcmp(read_file(host), "lower2") == 0);
    assert(klee_overlay_resolve(fx.ov, "/a", host, sizeof(host), KLEE_OV_READ) == 0);
    assert(strcmp(read_file(host), "a1") == 0);

    /* Listings show the union, the overlay root included */
    assert(klee_overlay_resolve(fx.ov, "", host, sizeof(host), KLEE_OV_LIST) == 0);
    assert(strcmp(listing(host), "a b shared sub/") == 0);
    assert(klee_overlay_resolve(fx.ov, "sub", host, sizeof(host), KLEE_OV_LIST) == 0);
    assert(strcmp(listing(host), "inner") == 0);

    assert(klee_overlay_resolve(fx.ov, "nope", host, sizeof(host), KLEE_OV_READ) == 0);
    assert(!exists(host));
    ov_teardown(&fx);
}

TEST(overlay_write_copies_up)
{
    OvFixture fx;
    ov_setup(&fx, false);
    char host[PATH_MAX], lower[PATH_MAX], p[PATH_MAX];
    snprintf(lower, sizeof(lower), "%s/sub/inner", fx.l1);

    assert(klee_overlay_resolve(fx.ov, "sub/inner", host, sizeof(host), KLEE_OV_WRITE) == 0);
    assert(in_upper(&fx, host));
    assert(strcmp(read_file(host), "inner") == 0);
    write_file(host, "changed");                 /* what the syscall does */
    assert(strcmp(read_file(lower), "inner") == 0);
    assert(klee_overlay_resolve(fx.ov, "sub/inner", host, sizeof(host), KLEE_OV_READ) == 0);
    assert(strcmp(read_file(host), "changed") == 0);

    /* The upper copy of sub has the mode of the directory it shadows */
    struct stat up, low;
    snprintf(p, sizeof(p), "%s/sub", fx.ov->upper_dir);
    assert(stat(p, &up) == 0);
    snprintf(p, sizeof(p), "%s/sub", fx.l1);
    assert(stat(p, &low) == 0);
    assert((up.st_mode & 07777) == (low.st_mode & 07777));
    ov_teardown(&fx);
}

TEST(overlay_create)
{
    OvFixture fx;
    ov_setup(&fx, false);
    char host[PATH_MAX], p[PATH_MAX];

    assert(klee_overlay_resolve(fx.ov, "a", host, sizeof(host), KLEE_OV_CREATE_EXCL) == -EEXIST);
    assert(klee_overlay_resolve(fx.ov, "sub", host, sizeof(host), KLEE_OV_CREATE_EXCL) == -EEXIST);

    assert(klee_overlay_resolve(fx.ov, "sub/new", host, sizeof(host), KLEE_OV_CREATE_EXCL) == 0);
    assert(in_upper(&fx, host));
    write_file(host, "new");
    assert(klee_overlay_resolve(fx.ov, "sub", host, sizeof(host), KLEE_OV_LIST) == 0);
    assert(strcmp(listing(host), "inner new") == 0);
    snprintf(p, sizeof(p), "%s/sub/new", fx.l1);
    assert(!exists(p));

    /* No parent in the union: nothing is made for it */
    assert(klee_overlay_resolve(fx.ov, "nodir/x", host, sizeof(host), KLEE_OV_CREATE_EXCL) == 0);
    snprintf(p, sizeof(p), "%s/nodir", fx.ov->upper_dir);
    assert(!exists(p));
    ov_teardown(&fx);
}

TEST(overlay_unlink)
{
    OvFixture fx;
    ov_setup(&fx, false);
    char host[PATH_MAX], lower[PATH_MAX];

    assert(klee_overlay_resolve(fx.ov, "sub", host, sizeof(host), KLEE_OV_UNLINK) == -EISDIR);
    assert(klee_overlay_resolve(fx.ov, "nope", host, sizeof(host), KLEE_OV_UNLINK) == -ENOENT);

    /* Only in a lower layer: whited out, and the syscall removes an upper
     * stand-in */
    assert(klee_overlay_resolve(fx.ov, "a", host, sizeof(host), KLEE_OV_UNLINK) == 0);
    assert(in_upper(&fx, host));
    assert(unlink(host) == 0);
    snprintf(lower, sizeof(lower), "%s/a", fx.l1);
    assert(exists(lower));
    assert(klee_overlay_is_whiteout(fx.ov, "a"));
    assert(klee_overlay_resolve(fx.ov, "a", host, sizeof(host), KLEE_OV_READ) == 0);
    assert(!exists(host));
    assert(klee_overlay_resolve(fx.ov, "a", host, sizeof(host), KLEE_OV_UNLINK) == -ENOENT);

    /* In both lower layers: hidden in both */
    assert(klee_overlay_resolve(fx.ov, "shared", host, sizeof(host), KLEE_OV_UNLINK) == 0);
    assert(unlink(host) == 0);
    assert(klee_overlay_resolve(fx.ov, "", host, sizeof(host), KLEE_OV_LIST) == 0);
    assert(strcmp(listing(host), "b sub/") == 0);

    /* Created again: shown again */
    assert(klee_overlay_resolve(fx.ov, "a", host, sizeof(host), KLEE_OV_CREATE_EXCL) == 0);
    write_file(host, "again");
    assert(klee_overlay_resolve(fx.ov, "a", host, sizeof(host), KLEE_OV_READ) == 0);
    assert(strcmp(read_file(host), "again") == 0);
    ov_teardown(&fx);
}

TEST(overlay_rmdir)
{
    OvFixture fx;
    ov_setup(&fx, false);
    char host[PATH_MAX], lower[PATH_MAX];

    assert(klee_overlay_resolve(fx.ov, "sub", host, sizeof(host), KLEE_OV_RMDIR) == -ENOTEMPTY);
    assert(klee_overlay_resolve(fx.ov, "a", host, sizeof(host), KLEE_OV_RMDIR) == -ENOTDIR);
    assert(klee_overlay_resolve(fx.ov, "", host, sizeof(host), KLEE_OV_RMDIR) == -EBUSY);

    assert(klee_overlay_resolve(fx.ov, "sub/inner", host, sizeof(host), KLEE_OV_UNLINK) == 0);
    assert(unlink(host) == 0);
    assert(klee_overlay_resolve(fx.ov, "sub", host, sizeof(host), KLEE_OV_RMDIR) == 0);
    assert(rmdir(host) == 0);
    assert(klee_overlay_resolve(fx.ov, "sub", host, sizeof(host), KLEE_OV_READ) == 0);
    assert(!exists(host));
    snprintf(lower, sizeof(lower), "%s/sub/inner", fx.l1);
    assert(exists(lower));

    /* Made again, it is empty: the lower contents stay deleted */
    assert(klee_overlay_resolve(fx.ov, "sub", host, sizeof(host), KLEE_OV_CREATE_EXCL) == 0);
    assert(mkdir(host, 0755) == 0);
    assert(klee_overlay_resolve(fx.ov, "sub", host, sizeof(host), KLEE_OV_LIST) == 0);
    assert(strcmp(listing(host), "") == 0);
    assert(klee_overlay_resolve(fx.ov, "sub/inner", host, sizeof(host), KLEE_OV_READ) == 0);
    assert(!exists(host));
    ov_teardown(&fx);
}

TEST(overlay_rename)
{
    OvFixture fx;
    ov_setup(&fx, false);
    char src[PATH_MAX], dst[PATH_MAX], lower[PATH_MAX];

    /* A directory a lower layer has: EXDEV, as with overlayfs */
    assert(klee_overlay_resolve(fx.ov, "sub", src, sizeof(src), KLEE_OV_RENAME_SRC) == -EXDEV);
    assert(klee_overlay_resolve(fx.ov, "sub", dst, sizeof(dst), KLEE_OV_RENAME_DST) == -EXDEV);

    /* A file is copied up, and the kernel moves the copy */
    assert(klee_overlay_resolve(fx.ov, "a", src, sizeof(src), KLEE_OV_RENAME_SRC) == 0);
    assert(klee_overlay_resolve(fx.ov, "sub/moved", dst, sizeof(dst), KLEE_OV_RENAME_DST) == 0);
    assert(in_upper(&fx, src) && in_upper(&fx, dst));
    assert(rename(src, dst) == 0);
    snprintf(lower, sizeof(lower), "%s/a", fx.l1);
    assert(exists(lower));
    assert(klee_overlay_resolve(fx.ov, "a", src, sizeof(src), KLEE_OV_READ) == 0);
    assert(!exists(src));
    assert(klee_overlay_resolve(fx.ov, "sub/moved", dst, sizeof(dst), KLEE_OV_READ) == 0);
    assert(strcmp(read_file(dst), "a1") == 0);
    ov_teardown(&fx);
}

TEST(overlay_link)
{
    OvFixture fx;
    ov_setup(&fx, false);
    char src[PATH_MAX], dst[PATH_MAX], lower[PATH_MAX];

    assert(klee_overlay_resolve(fx.ov, "sub", src, sizeof(src), KLEE_OV_LINK_SRC) == -EPERM);
    /* The new name links to an upper copy, never to the lower inode */
    assert(klee_overlay_resolve(fx.ov, "b", src, sizeof(src), KLEE_OV_LINK_SRC) == 0);
    assert(klee_overlay_resolve(fx.ov, "b-link", dst, sizeof(dst), KLEE_OV_CREATE_EXCL) == 0);
    assert(link(src, dst) == 0);
    write_file(dst, "through the link");
    snprintf(lower, sizeof(lower), "%s/b", fx.l2);
    assert(strcmp(read_file(lower), "b2") == 0);
    ov_teardown(&fx);
}

TEST(overlay_readonly)
{
    OvFixture fx;
    ov_setup(&fx, true);
    assert(fx.ov->upper_dir == NULL);
    assert(fx.ov->readonly == true);
    char host[PATH_MAX], lower[PATH_MAX];
    snprintf(lower, sizeof(lower), "%s/a", fx.l1);

    /* Nothing is prepared or recorded: the read-only checks refuse these */
    assert(klee_overlay_resolve(fx.ov, "a", host, sizeof(host), KLEE_OV_WRITE) == 0);
    assert(strcmp(host, lower) == 0);
    assert(klee_overlay_resolve(fx.ov, "a", host, sizeof(host), KLEE_OV_UNLINK) == 0);
    assert(strcmp(host, lower) == 0);
    assert(!klee_overlay_is_whiteout(fx.ov, "a"));

    assert(klee_overlay_resolve(fx.ov, "", host, sizeof(host), KLEE_OV_LIST) == 0);
    assert(strcmp(listing(host), "a b shared sub/") == 0);
    ov_teardown(&fx);
}

/* Through the mount table: a remounted read-only overlay is not changed */
TEST(overlay_mount_table)
{
    OvFixture fx;
    ov_setup(&fx, false);
    KleeMountTable *mt = klee_mount_table_create();
    assert(klee_mount_table_add(mt, MOUNT_TMP_OVERLAY, fx.ov->merged_dir,
                                "/ov", false, 0755) == 0);
    KleeMount *m = klee_mount_table_resolve(mt, "/ov");
    assert(m != NULL);
    m->overlay = fx.ov;
    assert(klee_mount_table_overlay_at(mt, "/ov/a") == fx.ov);
    assert(klee_mount_table_overlay_at(mt, "/elsewhere") == NULL);

    char host[PATH_MAX], lower[PATH_MAX];
    snprintf(lower, sizeof(lower), "%s/a", fx.l1);
    m->is_readonly = true;
    assert(klee_mount_table_translate_access(mt, "/ov/a", host, sizeof(host), KLEE_OV_WRITE) == 0);
    assert(strcmp(host, lower) == 0);
    m->is_readonly = false;
    assert(klee_mount_table_translate_access(mt, "/ov/a", host, sizeof(host), KLEE_OV_WRITE) == 0);
    assert(in_upper(&fx, host));

    m->overlay = NULL;
    klee_mount_table_destroy(mt);
    ov_teardown(&fx);
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
    RUN(overlay_read_and_list);
    RUN(overlay_write_copies_up);
    RUN(overlay_create);
    RUN(overlay_unlink);
    RUN(overlay_rmdir);
    RUN(overlay_rename);
    RUN(overlay_link);
    RUN(overlay_readonly);
    RUN(overlay_mount_table);
    RUN(gen_mountinfo);
    klee_tmpfs_cleanup();
    printf("All mount table tests passed!\n");
    return 0;
}
