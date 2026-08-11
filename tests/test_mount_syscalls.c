/*
 * Klee - mount(2)/umount2(2)/chroot(2) end-to-end syscall tests.
 *
 * This binary is executed INSIDE klee by tests/test_integration.sh.
 * It exercises the emulated syscalls exactly as a real program would
 * and verifies both results and errno values against kernel semantics.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifndef MNT_DETACH
#define MNT_DETACH 2
#endif

static int failures = 0;

#define CHECK(cond, name) do { \
    if (cond) { \
        printf("  PASS: %s\n", name); \
    } else { \
        printf("  FAIL: %s (errno=%d %s)\n", name, errno, strerror(errno)); \
        failures++; \
    } \
} while (0)

static void write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    if (f) {
        fputs(content, f);
        fclose(f);
    }
}

static int read_file_eq(const char *path, const char *expect)
{
    char buf[256] = "";
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);
    return strcmp(buf, expect) == 0;
}

static void test_tmpfs_mount(void)
{
    printf("tmpfs mount:\n");
    mkdir("/tmp/mnt-tmpfs", 0755);

    int rc = mount("tmpfs", "/tmp/mnt-tmpfs", "tmpfs", 0, NULL);
    CHECK(rc == 0, "mount tmpfs returns 0");

    /* The mount must have full effect: files land in the new fs */
    write_file("/tmp/mnt-tmpfs/probe.txt", "in-tmpfs");
    CHECK(read_file_eq("/tmp/mnt-tmpfs/probe.txt", "in-tmpfs"),
          "file written into tmpfs is readable");

    rc = umount2("/tmp/mnt-tmpfs", 0);
    CHECK(rc == 0, "umount2 tmpfs returns 0");

    /* After umount the file must be gone (underlying dir shows through) */
    CHECK(access("/tmp/mnt-tmpfs/probe.txt", F_OK) != 0,
          "tmpfs contents gone after umount");
}

static void test_bind_mount(void)
{
    printf("bind mount:\n");
    mkdir("/tmp/bind-src", 0755);
    mkdir("/tmp/bind-dst", 0755);
    write_file("/tmp/bind-src/data.txt", "bound");

    int rc = mount("/tmp/bind-src", "/tmp/bind-dst", NULL, MS_BIND, NULL);
    CHECK(rc == 0, "bind mount returns 0");
    CHECK(read_file_eq("/tmp/bind-dst/data.txt", "bound"),
          "bind target shows source contents");

    /* Writes through the bind land in the source */
    write_file("/tmp/bind-dst/new.txt", "via-bind");
    CHECK(read_file_eq("/tmp/bind-src/new.txt", "via-bind"),
          "write via bind lands in source");

    rc = umount2("/tmp/bind-dst", 0);
    CHECK(rc == 0, "umount2 bind returns 0");
    CHECK(access("/tmp/bind-dst/data.txt", F_OK) != 0,
          "bind contents gone after umount");
}

static void test_ro_bind_and_remount(void)
{
    printf("ro bind + remount:\n");
    mkdir("/tmp/ro-src", 0755);
    mkdir("/tmp/ro-dst", 0755);
    write_file("/tmp/ro-src/f.txt", "x");

    int rc = mount("/tmp/ro-src", "/tmp/ro-dst", NULL,
                   MS_BIND | MS_RDONLY, NULL);
    CHECK(rc == 0, "ro bind mount returns 0");

    errno = 0;
    int fd = open("/tmp/ro-dst/f.txt", O_WRONLY);
    CHECK(fd < 0 && errno == EROFS, "write to ro bind fails with EROFS");
    if (fd >= 0)
        close(fd);

    /* Remount read-write */
    rc = mount(NULL, "/tmp/ro-dst", NULL, MS_REMOUNT, NULL);
    CHECK(rc == 0, "remount rw returns 0");
    fd = open("/tmp/ro-dst/f.txt", O_WRONLY);
    CHECK(fd >= 0, "write allowed after remount rw");
    if (fd >= 0)
        close(fd);

    /* Remount read-only again */
    rc = mount(NULL, "/tmp/ro-dst", NULL, MS_REMOUNT | MS_RDONLY, NULL);
    CHECK(rc == 0, "remount ro returns 0");
    errno = 0;
    fd = open("/tmp/ro-dst/f.txt", O_WRONLY);
    CHECK(fd < 0 && errno == EROFS, "write blocked after remount ro");
    if (fd >= 0)
        close(fd);

    umount2("/tmp/ro-dst", 0);
}

static void test_mount_stacking(void)
{
    printf("mount stacking:\n");
    mkdir("/tmp/stack-a", 0755);
    mkdir("/tmp/stack-b", 0755);
    mkdir("/tmp/stack-dst", 0755);
    write_file("/tmp/stack-a/who.txt", "a");
    write_file("/tmp/stack-b/who.txt", "b");

    CHECK(mount("/tmp/stack-a", "/tmp/stack-dst", NULL, MS_BIND, NULL) == 0,
          "first mount returns 0");
    CHECK(mount("/tmp/stack-b", "/tmp/stack-dst", NULL, MS_BIND, NULL) == 0,
          "second (stacked) mount returns 0");
    CHECK(read_file_eq("/tmp/stack-dst/who.txt", "b"),
          "top of stack shadows");

    CHECK(umount2("/tmp/stack-dst", 0) == 0, "pop top of stack");
    CHECK(read_file_eq("/tmp/stack-dst/who.txt", "a"),
          "previous mount revealed");

    CHECK(umount2("/tmp/stack-dst", 0) == 0, "pop bottom of stack");
    CHECK(access("/tmp/stack-dst/who.txt", F_OK) != 0,
          "underlying dir revealed");
}

static void test_ms_move(void)
{
    printf("MS_MOVE:\n");
    mkdir("/tmp/move-src-backing", 0755);
    mkdir("/tmp/move-old", 0755);
    mkdir("/tmp/move-new", 0755);
    write_file("/tmp/move-src-backing/m.txt", "moved");

    CHECK(mount("/tmp/move-src-backing", "/tmp/move-old", NULL,
                MS_BIND, NULL) == 0, "setup bind returns 0");
    CHECK(mount("/tmp/move-old", "/tmp/move-new", NULL, MS_MOVE, NULL) == 0,
          "MS_MOVE returns 0");
    CHECK(read_file_eq("/tmp/move-new/m.txt", "moved"),
          "contents visible at new location");
    CHECK(access("/tmp/move-old/m.txt", F_OK) != 0,
          "old location empty after move");

    umount2("/tmp/move-new", 0);
}

static void test_propagation(void)
{
    printf("propagation flags:\n");
    mkdir("/tmp/prop-src", 0755);
    mkdir("/tmp/prop-dst", 0755);

    CHECK(mount("/tmp/prop-src", "/tmp/prop-dst", NULL, MS_BIND, NULL) == 0,
          "setup bind returns 0");
    CHECK(mount(NULL, "/tmp/prop-dst", NULL, MS_PRIVATE, NULL) == 0,
          "MS_PRIVATE returns 0");
    CHECK(mount(NULL, "/tmp/prop-dst", NULL, MS_SHARED, NULL) == 0,
          "MS_SHARED returns 0");
    CHECK(mount(NULL, "/tmp/prop-dst", NULL, MS_SLAVE | MS_REC, NULL) == 0,
          "MS_SLAVE|MS_REC returns 0");

    /* Two propagation types at once → EINVAL */
    errno = 0;
    CHECK(mount(NULL, "/tmp/prop-dst", NULL, MS_SHARED | MS_PRIVATE,
                NULL) < 0 && errno == EINVAL,
          "conflicting propagation flags → EINVAL");

    /* Propagation on non-mountpoint → EINVAL */
    errno = 0;
    CHECK(mount(NULL, "/tmp/prop-src", NULL, MS_SHARED, NULL) < 0 &&
          errno == EINVAL, "propagation on non-mountpoint → EINVAL");

    umount2("/tmp/prop-dst", 0);
}

static void test_error_codes(void)
{
    printf("kernel error codes:\n");
    mkdir("/tmp/err-dir", 0755);
    write_file("/tmp/err-file", "f");

    /* Unknown fstype → ENODEV */
    errno = 0;
    CHECK(mount("none", "/tmp/err-dir", "nosuchfs", 0, NULL) < 0 &&
          errno == ENODEV, "unknown fstype → ENODEV");

    /* Missing target → ENOENT */
    errno = 0;
    CHECK(mount("tmpfs", "/tmp/no/such/dir", "tmpfs", 0, NULL) < 0 &&
          errno == ENOENT, "missing target → ENOENT");

    /* tmpfs on a file → ENOTDIR */
    errno = 0;
    CHECK(mount("tmpfs", "/tmp/err-file", "tmpfs", 0, NULL) < 0 &&
          errno == ENOTDIR, "tmpfs on file → ENOTDIR");

    /* Bind dir onto file → ENOTDIR */
    errno = 0;
    CHECK(mount("/tmp/err-dir", "/tmp/err-file", NULL, MS_BIND, NULL) < 0 &&
          errno == ENOTDIR, "bind dir onto file → ENOTDIR");

    /* umount non-mountpoint → EINVAL */
    errno = 0;
    CHECK(umount2("/tmp/err-dir", 0) < 0 && errno == EINVAL,
          "umount non-mountpoint → EINVAL");

    /* umount bad flags → EINVAL */
    errno = 0;
    CHECK(umount2("/tmp/err-dir", 0x1000) < 0 && errno == EINVAL,
          "umount bad flags → EINVAL");

    /* umount root → EBUSY */
    errno = 0;
    CHECK(umount2("/", 0) < 0 && (errno == EBUSY || errno == EINVAL),
          "umount / → EBUSY/EINVAL");
}

static void test_umount_busy_detach(void)
{
    printf("umount EBUSY / MNT_DETACH:\n");
    mkdir("/tmp/busy-a", 0755);
    mkdir("/tmp/busy-dst", 0755);

    CHECK(mount("/tmp/busy-a", "/tmp/busy-dst", NULL, MS_BIND, NULL) == 0,
          "outer mount returns 0");
    mkdir("/tmp/busy-dst/inner", 0755);
    CHECK(mount("tmpfs", "/tmp/busy-dst/inner", "tmpfs", 0, NULL) == 0,
          "inner mount returns 0");

    errno = 0;
    CHECK(umount2("/tmp/busy-dst", 0) < 0 && errno == EBUSY,
          "umount with child → EBUSY");
    CHECK(umount2("/tmp/busy-dst", MNT_DETACH) == 0,
          "MNT_DETACH succeeds");
}

static void test_chroot(void)
{
    printf("chroot:\n");
    mkdir("/tmp/jail", 0755);
    mkdir("/tmp/jail/etc", 0755);
    mkdir("/tmp/jail/data", 0755);
    write_file("/tmp/jail/etc/inside.txt", "jailed");
    write_file("/tmp/outside.txt", "free");

    /* chroot on a file → ENOTDIR */
    errno = 0;
    CHECK(chroot("/tmp/outside.txt") < 0 && errno == ENOTDIR,
          "chroot on file → ENOTDIR");

    /* chroot on missing dir → ENOENT */
    errno = 0;
    CHECK(chroot("/tmp/no-such-jail") < 0 && errno == ENOENT,
          "chroot on missing dir → ENOENT");

    /* Do the chroot in a child so this process's view stays intact */
    pid_t pid = fork();
    if (pid == 0) {
        if (chroot("/tmp/jail") != 0)
            _exit(1);
        if (chdir("/") != 0)
            _exit(2);
        /* Path resolution must now be relative to the jail */
        char buf[64] = "";
        FILE *f = fopen("/etc/inside.txt", "r");
        if (!f)
            _exit(3);
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        fclose(f);
        if (strcmp(buf, "jailed") != 0)
            _exit(4);
        /* Outside file must NOT be visible */
        if (access("/outside.txt", F_OK) == 0)
            _exit(5);
        /* getcwd must report the in-jail view */
        char cwd[256];
        if (!getcwd(cwd, sizeof(cwd)))
            _exit(6);
        if (strcmp(cwd, "/") != 0)
            _exit(7);
        /* Writes inside the jail must land in the jail dir */
        FILE *w = fopen("/data/out.txt", "w");
        if (!w)
            _exit(8);
        fputs("written", w);
        fclose(w);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    if (code != 0)
        printf("  (child exit code %d)\n", code);
    CHECK(code == 0, "chroot child: resolution, isolation, getcwd, write");

    /* Child's write really landed inside the jail */
    CHECK(read_file_eq("/tmp/jail/data/out.txt", "written"),
          "chroot write landed in jail dir");

    /* Parent was not affected by child's chroot */
    CHECK(access("/tmp/outside.txt", F_OK) == 0,
          "parent unaffected by child chroot");
}

static void test_chroot_inherit(void)
{
    printf("chroot inheritance:\n");
    mkdir("/tmp/jail2", 0755);
    write_file("/tmp/jail2/marker.txt", "j2");

    pid_t pid = fork();
    if (pid == 0) {
        if (chroot("/tmp/jail2") != 0)
            _exit(1);
        if (chdir("/") != 0)
            _exit(2);
        /* Grandchild must inherit the chroot */
        pid_t gpid = fork();
        if (gpid == 0)
            _exit(access("/marker.txt", F_OK) == 0 ? 0 : 3);
        int gstatus = 0;
        waitpid(gpid, &gstatus, 0);
        _exit(WIFEXITED(gstatus) ? WEXITSTATUS(gstatus) : 4);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "fork inherits chroot");
}

int main(void)
{
    printf("=== mount/umount/chroot end-to-end tests (inside klee) ===\n");

    test_tmpfs_mount();
    test_bind_mount();
    test_ro_bind_and_remount();
    test_mount_stacking();
    test_ms_move();
    test_propagation();
    test_error_codes();
    test_umount_busy_detach();
    test_chroot();
    test_chroot_inherit();

    if (failures) {
        printf("=== %d FAILURE(S) ===\n", failures);
        return 1;
    }
    printf("=== all mount/chroot syscall tests passed ===\n");
    return 0;
}
