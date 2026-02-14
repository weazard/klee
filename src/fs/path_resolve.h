/*
 * Klee - Userspace bwrap translation layer
 * Path canonicalization in virtual context
 */
#ifndef KLEE_PATH_RESOLVE_H
#define KLEE_PATH_RESOLVE_H

#include "fs/mount_table.h"
#include "fs/fd_table.h"
#include <linux/limits.h>
#include <sys/types.h>

/* Resolve flags (matching openat2 RESOLVE_* flags) */
#define KLEE_RESOLVE_IN_ROOT       0x01
#define KLEE_RESOLVE_NO_SYMLINKS   0x02
#define KLEE_RESOLVE_BENEATH       0x04
#define KLEE_RESOLVE_NO_XDEV       0x08
#define KLEE_RESOLVE_NO_MAGICLINKS 0x10

/* Internal flag: don't follow the final path component if it's a symlink.
 * Used for syscalls like lstat, unlink, readlink, rename that operate on
 * the directory entry (symlink itself) rather than the symlink target. */
#define KLEE_RESOLVE_NOFOLLOW_LAST 0x100

/* Maximum symlink follow depth */
#define KLEE_MAX_SYMLINK_DEPTH 40

typedef struct klee_resolve_ctx {
    const KleeMountTable *mount_table;
    const KleeFdTable *fd_table;
    const char *vcwd;        /* virtual current working directory */
    const char *vroot;       /* virtual root (/) */
    const char *dirfd_path;  /* resolved dirfd path for RESOLVE_BENEATH */
    unsigned int flags;
    int symlink_depth;
} KleeResolveCtx;

/* Canonicalize a guest path.
 * Handles: relative→absolute via vcwd, "." skip, ".." pop,
 * symlink dereference, mount boundary crossing.
 *
 * guest_path: input path (may be relative)
 * resolved: output buffer (PATH_MAX)
 * dirfd: AT_FDCWD or an open directory FD
 *
 * Returns 0 on success, negative errno on failure. */
int klee_path_resolve(KleeResolveCtx *ctx, const char *guest_path,
                       char *resolved, int dirfd);

/* Translate a guest path all the way to a host path.
 * First canonicalizes, then translates through mount table.
 * Returns 0 on success. */
int klee_path_guest_to_host(KleeResolveCtx *ctx, const char *guest_path,
                             char *host_path, int dirfd);

/* Canonicalize and check path components.
 * Does not follow final symlink (like lstat). */
int klee_path_resolve_nofollow(KleeResolveCtx *ctx, const char *guest_path,
                                char *resolved, int dirfd);

/* Like klee_path_guest_to_host but does not follow the final symlink.
 * Used by lstat, unlink, readlink, symlink (linkpath), rename, etc. */
int klee_path_guest_to_host_nofollow(KleeResolveCtx *ctx, const char *guest_path,
                                      char *host_path, int dirfd);

#endif /* KLEE_PATH_RESOLVE_H */
