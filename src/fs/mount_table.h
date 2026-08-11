/*
 * Klee - Userspace bwrap translation layer
 * Virtual mount table management
 */
#ifndef KLEE_MOUNT_TABLE_H
#define KLEE_MOUNT_TABLE_H

#include "fs/radix_tree.h"
#include "config.h"
#include "util/arena.h"
#include <stdbool.h>
#include <sys/types.h>
#include <linux/limits.h>

/* Forward declaration */
typedef struct klee_overlay_mount KleeOverlayMount;

/* Mount propagation (recorded for mountinfo faithfulness; semantically a
 * no-op since klee models a single mount namespace) */
typedef enum {
    KLEE_PROP_PRIVATE = 0,
    KLEE_PROP_SHARED,
    KLEE_PROP_SLAVE,
    KLEE_PROP_UNBINDABLE,
} KleePropagation;

typedef struct klee_mount {
    MountType type;
    char *source;       /* host path (for binds) */
    char *dest;         /* guest path */
    unsigned long flags;
    bool is_readonly;
    int perms;
    KleePropagation propagation;  /* MS_SHARED/PRIVATE/SLAVE/UNBINDABLE */
    int peer_group;               /* shared:N id for mountinfo */
    bool expire_pending;          /* MNT_EXPIRE mark (two-phase umount) */
    struct klee_mount *stacked;  /* shadow stack for overlapping mounts */
    KleeOverlayMount *overlay;  /* overlay state (for overlay mounts) */
} KleeMount;

typedef struct klee_mount_table {
    KleeRadixTree *tree;
    size_t num_mounts;
    char *virtual_root;    /* pivot_root prefix, default "/" */
    KleeArena *arena;
} KleeMountTable;

/* Create a new mount table */
KleeMountTable *klee_mount_table_create(void);

/* Destroy mount table */
void klee_mount_table_destroy(KleeMountTable *mt);

/* Populate mount table from config mount ops */
int klee_mount_table_populate(KleeMountTable *mt, const KleeConfig *cfg);

/* Add a single mount entry */
int klee_mount_table_add(KleeMountTable *mt, MountType type,
                          const char *source, const char *dest,
                          bool readonly, int perms);

/* ==== Runtime mutation APIs (mount(2)/umount2(2) emulation) ==== */

/* Runtime mount: like add, but returns the created mount via out (optional).
 * Mounting over an existing mountpoint stacks (kernel shadow semantics). */
int klee_mount_table_mount(KleeMountTable *mt, MountType type,
                            const char *source, const char *dest,
                            bool readonly, int perms, KleeMount **out);

/* Runtime umount at an exact mountpoint.
 * - Not a mountpoint → -EINVAL
 * - Mounts exist beneath it and !detach_children → -EBUSY
 * - Stacked mount → pop, revealing the previous mount
 * detach_children (MNT_DETACH) also removes every mount beneath dest. */
int klee_mount_table_umount(KleeMountTable *mt, const char *dest,
                             bool detach_children);

/* Runtime remount: toggle read-only flag on an existing mountpoint.
 * Not a mountpoint → -EINVAL. */
int klee_mount_table_remount(KleeMountTable *mt, const char *dest,
                              bool readonly);

/* Runtime MS_MOVE: relocate a mountpoint (and every mount beneath it)
 * from src to dest.  src not a mountpoint → -EINVAL. */
int klee_mount_table_move(KleeMountTable *mt, const char *src,
                           const char *dest);

/* Set propagation type on an existing mountpoint (recursive per MS_REC).
 * Not a mountpoint → -EINVAL. */
int klee_mount_table_set_propagation(KleeMountTable *mt, const char *dest,
                                      KleePropagation prop, bool recursive);

/* Exact-mountpoint lookup (no prefix matching). NULL if dest is not a
 * mountpoint. */
KleeMount *klee_mount_table_find_exact(const KleeMountTable *mt,
                                        const char *dest);

/* Resolve a guest path to the best matching mount.
 * Returns the mount entry, or NULL if no mount matches. */
KleeMount *klee_mount_table_resolve(const KleeMountTable *mt,
                                     const char *guest_path);

/* Translate a guest path to a host path.
 * Performs prefix substitution based on the best matching mount.
 * Returns 0 on success, negative errno on failure.
 * host_path_out must be at least PATH_MAX bytes. */
int klee_mount_table_translate(const KleeMountTable *mt,
                                const char *guest_path,
                                char *host_path_out, size_t out_size);

/* Check if a guest path is on a read-only mount */
bool klee_mount_table_is_readonly(const KleeMountTable *mt,
                                   const char *guest_path);

/* Set the virtual root prefix (for pivot_root simulation) */
void klee_mount_table_set_root(KleeMountTable *mt, const char *root);

/* Get virtual root */
const char *klee_mount_table_get_root(const KleeMountTable *mt);

/* Generate /proc/self/mountinfo content */
int klee_mount_table_gen_mountinfo(const KleeMountTable *mt,
                                    char *buf, size_t buf_size);

/* Create host-side mirrors for /run/host mounts.
 * Needed so the kernel can follow host-side symlinks that reference
 * guest paths (e.g. pressure-vessel runtime overlays). */
void klee_mount_table_create_host_mirrors(const KleeMountTable *mt);

/* Apply pressure-vessel overrides as explicit mount entries.
 * Scans the overrides directory and adds individual MOUNT_SYMLINK/BIND
 * entries so they take precedence over the general /usr bind mount,
 * emulating what overlayfs would do in a real bwrap container. */
void klee_mount_table_apply_pv_overrides(KleeMountTable *mt);

/* Apply Flatpak GL extension library symlinks.
 * Scans GL extension lib/ directories and adds MOUNT_SYMLINK entries
 * at the parent library directory so the dynamic linker can find
 * GL libraries (libGLX_mesa.so.0, libEGL_mesa.so.0, etc.) at the
 * standard search paths. */
void klee_mount_table_apply_gl_extensions(KleeMountTable *mt);

/* Debug dump */
void klee_mount_table_dump(const KleeMountTable *mt);

#endif /* KLEE_MOUNT_TABLE_H */
