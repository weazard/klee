/*
 * Klee - Userspace bwrap translation layer
 * Userspace overlay mount support
 *
 * Matches kernel overlayfs behavior:
 * - Lower layers are never modified
 * - Copy-on-write from lower to upper on first write
 * - Whiteout tracking for deleted files
 * - Directory listings show the union of all layers
 */
#ifndef KLEE_OVERLAY_H
#define KLEE_OVERLAY_H

#include "util/hash_table.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct klee_overlay_mount {
    char *merged_dir;       /* tmpfs-backed listing view of directories */
    char *upper_dir;        /* writable layer (NULL for ro-overlay) */
    char **lower_dirs;      /* array of lower layer paths, bottom to top */
    int lower_count;
    bool readonly;
    KleeHashTable *whiteouts;  /* hashes of relative paths deleted in the sandbox */
} KleeOverlayMount;

/* What the syscall being translated does with the path */
typedef enum {
    KLEE_OV_LOOKUP = 0,   /* path walk: the topmost entry, directories included */
    KLEE_OV_READ,         /* non-modifying call: directories show the merged view */
    KLEE_OV_LIST,         /* open: like READ, and a directory's listing is resynced */
    KLEE_OV_WRITE,        /* changes contents or metadata: copy up first */
    KLEE_OV_WRITE_CREATE, /* like WRITE, or creates the name when missing */
    KLEE_OV_CREATE,       /* creates the name when missing, else only opens it */
    KLEE_OV_CREATE_EXCL,  /* creates the name: EEXIST if it exists */
    KLEE_OV_UNLINK,
    KLEE_OV_RMDIR,
    KLEE_OV_RENAME_SRC,   /* rename source, or either side of RENAME_EXCHANGE */
    KLEE_OV_RENAME_DST,
    KLEE_OV_LINK_SRC,
} KleeOvAccess;

/* Create a userspace overlay.
 * dest: guest mount point path (used for tmpfs naming)
 * upper: writable upper directory path (NULL for a tmpfs upper or ro overlay)
 * lowers: array of lower layer paths (bottom to top)
 * lower_count: number of lower layers
 * ro: true for read-only overlay
 * Returns overlay mount struct, or NULL on failure. */
KleeOverlayMount *klee_overlay_create(const char *dest, const char *upper,
                                        char **lowers, int lower_count, bool ro);

/* Resolve a path within the overlay to the host path the syscall should use,
 * preparing the upper layer for what the call does (copy-up, parent
 * directories, whiteouts).  A read-only overlay is never changed: every
 * access resolves like KLEE_OV_READ and the read-only checks refuse writes.
 * remainder: path relative to overlay mount point
 * Returns 0 on success, negative errno for the syscall to fail with. */
int klee_overlay_resolve(KleeOverlayMount *ov, const char *remainder,
                          char *host_path_out, size_t out_size,
                          KleeOvAccess access);

/* Record a whiteout (deletion) for a path in the overlay. */
void klee_overlay_whiteout(KleeOverlayMount *ov, const char *remainder);

/* Check if a path has been whited out (deleted), itself or by an ancestor. */
bool klee_overlay_is_whiteout(const KleeOverlayMount *ov, const char *remainder);

/* Destroy an overlay mount and free resources. */
void klee_overlay_destroy(KleeOverlayMount *ov);

#endif /* KLEE_OVERLAY_H */
