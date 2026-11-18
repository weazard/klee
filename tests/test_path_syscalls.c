#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Use the syscall numbers directly so the test covers the intended handlers
 * even when libc implements creat() or fstatat() with another syscall. */
static void test_creat(const char *path, const char *readonly_path)
{
    umask(0);
    int fd = syscall(SYS_creat, path, 0640);
    assert(fd >= 0);
    assert(write(fd, "x", 1) == 1);
    assert(close(fd) == 0);

    fd = syscall(SYS_creat, path, 0600);
    assert(fd >= 0);
    struct stat st;
    assert(fstat(fd, &st) == 0);
    assert(st.st_size == 0);
    assert((st.st_mode & 0777) == 0640);
    assert(close(fd) == 0);

    assert(syscall(SYS_creat, readonly_path, 0600) == -1);
    assert(errno == EROFS);
}

static void assert_same_file(const struct stat *expected, const struct stat *actual)
{
    assert(expected->st_dev == actual->st_dev);
    assert(expected->st_ino == actual->st_ino);
}

static void test_fstatat(const char *directory, const char *path)
{
    int fd = open(path, O_RDONLY);
    assert(fd >= 0);
    struct stat expected, actual;
    assert(fstat(fd, &expected) == 0);
    assert(syscall(SYS_newfstatat, fd, "", &actual, AT_EMPTY_PATH) == 0);
    assert_same_file(&expected, &actual);
    assert(close(fd) == 0);

    assert(syscall(SYS_newfstatat, AT_FDCWD, path, &actual, AT_EMPTY_PATH) == 0);
    assert_same_file(&expected, &actual);

    int dirfd = open(directory, O_RDONLY | O_DIRECTORY);
    assert(dirfd >= 0);
    assert(syscall(SYS_newfstatat, dirfd, "entry", &actual, AT_EMPTY_PATH) == 0);
    assert_same_file(&expected, &actual);
    assert(syscall(SYS_newfstatat, dirfd, "link", &actual,
                   AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) == 0);
    assert(S_ISLNK(actual.st_mode));
    assert(close(dirfd) == 0);
}

int main(int argc, char **argv)
{
    if (argc != 4)
        return 2;
    if (strcmp(argv[1], "creat") == 0)
        test_creat(argv[2], argv[3]);
    else if (strcmp(argv[1], "fstatat") == 0)
        test_fstatat(argv[2], argv[3]);
    else
        return 2;
    return 0;
}
