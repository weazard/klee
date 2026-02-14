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

typedef struct klee_mount {
    MountType type;
    char *source;       /* host path (for binds) */
    char *dest;         /* guest path */
    unsigned long flags;
    bool is_readonly;
    int perms;
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
