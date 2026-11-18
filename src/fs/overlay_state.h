#ifndef KLEE_OVERLAY_STATE_H
#define KLEE_OVERLAY_STATE_H

#include "util/hash_table.h"
#include <linux/limits.h>
#include <sys/stat.h>

#define KLEE_OVERLAY_STATE_DIR ".klee-overlay"
#define KLEE_OVERLAY_STAGE_SOURCE "source"
#define KLEE_OVERLAY_STAGE_TARGET "target"

typedef enum {
    KLEE_OVERLAY_MASK = 1,
    KLEE_OVERLAY_REMOVE,
    KLEE_OVERLAY_RENAME,
    KLEE_OVERLAY_EXCHANGE,
    KLEE_OVERLAY_LINK,
} KleeOverlayOperation;

enum {
    KLEE_OVERLAY_MASK_SOURCE = 1,
    KLEE_OVERLAY_MASK_TARGET = 2,
    KLEE_OVERLAY_STAGE_OLD = 4,
    KLEE_OVERLAY_STAGE_NEW = 8,
};

typedef struct {
    uint64_t device;
    uint64_t inode;
} KleeOverlayInode;

typedef struct {
    uint32_t operation;
    uint32_t flags;
    KleeOverlayInode old_inode;
    KleeOverlayInode new_inode;
    char old_path[PATH_MAX];
    char new_path[PATH_MAX];
} KleeOverlayChange;

typedef struct klee_overlay_state {
    int upper_fd;
    int directory_fd;
    bool durable;
    bool faulted;
    uint64_t next_record;
    KleeHashTable *whiteouts;
} KleeOverlayState;

int klee_overlay_state_open(const char *upper, bool durable, KleeOverlayState **out);
void klee_overlay_state_close(KleeOverlayState *state);
bool klee_overlay_state_has(const KleeOverlayState *state, const char *path,
                            size_t length);
bool klee_overlay_state_path(const char *relative);
KleeOverlayInode klee_overlay_inode(const struct stat *st);
int klee_overlay_open_parent(int root_fd, const char *path, const char **name);

/* The supervisor serializes operations. Prepared files live in the state
 * directory. For an exchange, install staged entries only after begin(). */
int klee_overlay_state_begin(KleeOverlayState *state, const KleeOverlayChange *change);
int klee_overlay_state_sync(KleeOverlayState *state, const KleeOverlayChange *change);
int klee_overlay_state_finish(KleeOverlayState *state, const KleeOverlayChange *change,
                               bool committed);
int klee_overlay_state_clear_stage(KleeOverlayState *state);

#endif
