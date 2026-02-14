/*
 * Klee - Userspace bwrap translation layer
 * Configuration structures
 */
#ifndef KLEE_CONFIG_H
#define KLEE_CONFIG_H

#include <stdbool.h>
#include <sys/types.h>
#include <linux/limits.h>

typedef enum {
    MOUNT_BIND_RW,
    MOUNT_BIND_RO,
    MOUNT_BIND_TRY,
    MOUNT_BIND_RO_TRY,
    MOUNT_DEV_BIND,
    MOUNT_DEV_BIND_TRY,
    MOUNT_TMPFS,
    MOUNT_PROC,
    MOUNT_DEV,
    MOUNT_DIR,
    MOUNT_SYMLINK,
    MOUNT_FILE,
    MOUNT_BIND_DATA,
    MOUNT_RO_BIND_DATA,
    MOUNT_REMOUNT_RO,
    MOUNT_CHMOD,
    MOUNT_OVERLAY_SRC,
    MOUNT_OVERLAY,
    MOUNT_TMP_OVERLAY,
    MOUNT_RO_OVERLAY,
    MOUNT_MQUEUE,
    MOUNT_BIND_FD,
    MOUNT_RO_BIND_FD,
} MountType;

typedef struct klee_mount_op {
    MountType type;
    char *source;
    char *dest;
    unsigned long flags;
    int perms;
    size_t size;            /* for --size */
    int fd;                 /* for --bind-data, --ro-bind-data, --file */
    char **overlay_srcs;    /* for --overlay */
    int overlay_src_count;
    struct klee_mount_op *next;
} KleeMountOp;

typedef enum {
    ENV_OP_SET,
    ENV_OP_UNSET,
    ENV_OP_CLEAR,
} EnvOpType;

typedef struct klee_env_op {
    EnvOpType type;
    char *key;
    char *value;     /* only for ENV_OP_SET */
    struct klee_env_op *next;
} KleeEnvOp;

/* Legacy compat - still used in some places */
typedef struct klee_setenv_pair {
    char *key;
    char *value;
} KleeSetenvPair;

typedef struct klee_config {
    /* Namespace flags */
    bool unshare_user;
    bool unshare_pid;
    bool unshare_ipc;
    bool unshare_uts;
    bool unshare_net;
    bool unshare_cgroup;

    /* User identity */
    uid_t uid;
    gid_t gid;
    bool uid_set;
    bool gid_set;

    /* Hostname */
    char *hostname;

    /* Mount operations (ordered linked list) */
    KleeMountOp *mount_ops;
    KleeMountOp *mount_ops_tail;

    /* Working directory */
    char *chdir_path;

    /* Process flags */
    bool new_session;
    bool die_with_parent;
    bool as_pid1;

    /* File descriptors */
    int seccomp_fd;
    int *add_seccomp_fds;
    int add_seccomp_fd_count;
    int info_fd;
    int json_status_fd;
    int sync_fd;
    int block_fd;
    int userns_fd;
    int userns2_fd;
    int pidns_fd;

    /* Lock files */
    char **lock_files;
    int lock_file_count;

    /* Environment (ordered operations list - applied in order) */
    KleeEnvOp *env_ops;
    KleeEnvOp *env_ops_tail;

    /* Legacy fields kept for compat */
    KleeSetenvPair *setenv_pairs;
    int setenv_count;
    char **unsetenv_keys;
    int unsetenv_count;
    bool clearenv;

    /* Capabilities */
    char **cap_add;
    int cap_add_count;
    char **cap_drop;
    int cap_drop_count;

    /* Pending state for --perms and --size (apply to next mount op) */
    int pending_perms;
    bool pending_perms_set;
    size_t pending_size;
    bool pending_size_set;

    /* Pending overlay sources */
    char **pending_overlay_srcs;
    int pending_overlay_src_count;

    /* Child command */
    int argc;
    char **argv;
    char *argv0;             /* --argv0 override */

    /* Share net (overrides unshare_net) */
    bool share_net;

    /* Disable userns */
    bool disable_userns;

    /* Assert userns disabled */
    bool assert_userns_disabled;

    /* User namespace block fd */
    int userns_block_fd;

    /* SELinux labels */
    char *exec_label;
    char *file_label;

    /* Diagnostic */
    bool level_prefix;
} KleeConfig;

/* Initialize config with defaults */
void klee_config_init(KleeConfig *cfg);

/* Free config resources */
void klee_config_destroy(KleeConfig *cfg);

/* Add a mount operation to the config */
KleeMountOp *klee_config_add_mount(KleeConfig *cfg, MountType type,
                                    const char *source, const char *dest);

/* Debug dump config */
void klee_config_dump(const KleeConfig *cfg);

#endif /* KLEE_CONFIG_H */
