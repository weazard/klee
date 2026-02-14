/*
 * Klee - Userspace bwrap translation layer
 * Userspace overlay mount support
 *
 * Matches kernel overlayfs behavior:
 * - Files appear as regular files (not symlinks) via resolve
 * - Whiteout tracking for deleted files
 * - Copy-on-write from lower to upper on first write
 */
#ifndef KLEE_OVERLAY_H
#define KLEE_OVERLAY_H

#include "util/hash_table.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct klee_overlay_mount {
    char *merged_dir;       /* tmpfs-backed merged view (symlinks internally) */
    char *upper_dir;        /* writable layer (NULL for ro-overlay) */
    char **lower_dirs;      /* array of lower layer paths */
    int lower_count;
    bool readonly;
    KleeHashTable *whiteouts;  /* set of deleted relative paths */
} KleeOverlayMount;

/* Create a userspace overlay.
 * dest: guest mount point path (used for tmpfs naming)
 * upper: writable upper directory path (NULL for read-only overlay)
 * lowers: array of lower layer paths (bottom to top)
 * lower_count: number of lower layers
 * ro: true for read-only overlay
 * Returns overlay mount struct, or NULL on failure. */
KleeOverlayMount *klee_overlay_create(const char *dest, const char *upper,
                                        char **lowers, int lower_count, bool ro);

/* Resolve a path within the overlay to a host path.
 * remainder: path relative to overlay mount point
 * host_path_out: output buffer for resolved host path
 * out_size: size of output buffer
 * for_write: true if the path is being accessed for writing
 * Returns 0 on success, negative errno on failure. */
int klee_overlay_resolve(const KleeOverlayMount *ov, const char *remainder,
                          char *host_path_out, size_t out_size, bool for_write);

/* Record a whiteout (deletion) for a path in the overlay.
 * Called when unlink/rmdir targets an overlay path. */
void klee_overlay_whiteout(KleeOverlayMount *ov, const char *remainder);

/* Check if a path has been whited out (deleted). */
bool klee_overlay_is_whiteout(const KleeOverlayMount *ov, const char *remainder);

/* Destroy an overlay mount and free resources. */
void klee_overlay_destroy(KleeOverlayMount *ov);

#endif /* KLEE_OVERLAY_H */
