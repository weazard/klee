/*
 * Klee - Userspace bwrap translation layer
 * Configuration implementation
 */
#include "config.h"
#include "util/log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void klee_config_init(KleeConfig *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->seccomp_fd = -1;
    cfg->info_fd = -1;
    cfg->json_status_fd = -1;
    cfg->sync_fd = -1;
    cfg->block_fd = -1;
    cfg->userns_fd = -1;
    cfg->userns2_fd = -1;
    cfg->pidns_fd = -1;
    cfg->userns_block_fd = -1;
    cfg->uid = (uid_t)-1;
    cfg->gid = (gid_t)-1;
    cfg->pending_perms = 0755;
}

void klee_config_destroy(KleeConfig *cfg)
{
    if (!cfg)
        return;

    KleeMountOp *op = cfg->mount_ops;
    while (op) {
        KleeMountOp *next = op->next;
        free(op->source);
        free(op->dest);
        if (op->overlay_srcs) {
            for (int i = 0; i < op->overlay_src_count; i++)
                free(op->overlay_srcs[i]);
            free(op->overlay_srcs);
        }
        free(op);
        op = next;
    }

    free(cfg->hostname);
    free(cfg->chdir_path);

    /* Free ordered environment ops list */
    KleeEnvOp *env_op = cfg->env_ops;
    while (env_op) {
        KleeEnvOp *next = env_op->next;
        free(env_op->key);
        free(env_op->value);
        free(env_op);
        env_op = next;
    }

    for (int i = 0; i < cfg->setenv_count; i++) {
        free(cfg->setenv_pairs[i].key);
        free(cfg->setenv_pairs[i].value);
    }
    free(cfg->setenv_pairs);

    for (int i = 0; i < cfg->unsetenv_count; i++)
        free(cfg->unsetenv_keys[i]);
    free(cfg->unsetenv_keys);

    for (int i = 0; i < cfg->lock_file_count; i++)
        free(cfg->lock_files[i]);
    free(cfg->lock_files);

    for (int i = 0; i < cfg->cap_add_count; i++)
        free(cfg->cap_add[i]);
    free(cfg->cap_add);

    for (int i = 0; i < cfg->cap_drop_count; i++)
        free(cfg->cap_drop[i]);
    free(cfg->cap_drop);

    free(cfg->add_seccomp_fds);

    for (int i = 0; i < cfg->pending_overlay_src_count; i++)
        free(cfg->pending_overlay_srcs[i]);
    free(cfg->pending_overlay_srcs);

    free(cfg->argv0);
    free(cfg->exec_label);
    free(cfg->file_label);
}

KleeMountOp *klee_config_add_mount(KleeConfig *cfg, MountType type,
                                    const char *source, const char *dest)
{
    KleeMountOp *op = calloc(1, sizeof(KleeMountOp));
    if (!op)
        return NULL;

    op->type = type;
    op->source = source ? strdup(source) : NULL;
    op->dest = dest ? strdup(dest) : NULL;
    /* Per-type default permissions matching bwrap:
     * --file defaults to 0666, --bind-data/--ro-bind-data to 0600,
     * everything else defaults to 0755. */
    if (cfg->pending_perms_set) {
        op->perms = cfg->pending_perms;
    } else {
        switch (type) {
        case MOUNT_FILE:
            op->perms = 0666;
            break;
        case MOUNT_BIND_DATA:
        case MOUNT_RO_BIND_DATA:
            op->perms = 0600;
            break;
        default:
            op->perms = 0755;
            break;
        }
    }
    op->size = cfg->pending_size_set ? cfg->pending_size : 0u;

    if (cfg->pending_overlay_src_count > 0) {
        op->overlay_srcs = cfg->pending_overlay_srcs;
        op->overlay_src_count = cfg->pending_overlay_src_count;
        cfg->pending_overlay_srcs = NULL;
        cfg->pending_overlay_src_count = 0;
    }

    /* Reset pending state */
    cfg->pending_perms_set = false;
    cfg->pending_size_set = false;

    /* Append to tail */
    op->next = NULL;
    if (cfg->mount_ops_tail) {
        cfg->mount_ops_tail->next = op;
        cfg->mount_ops_tail = op;
    } else {
        cfg->mount_ops = op;
        cfg->mount_ops_tail = op;
    }

    return op;
}

static const char *mount_type_str(MountType type)
{
    switch (type) {
    case MOUNT_BIND_RW:       return "bind";
    case MOUNT_BIND_RO:       return "ro-bind";
    case MOUNT_BIND_TRY:      return "bind-try";
    case MOUNT_BIND_RO_TRY:   return "ro-bind-try";
    case MOUNT_DEV_BIND:      return "dev-bind";
    case MOUNT_DEV_BIND_TRY:  return "dev-bind-try";
    case MOUNT_TMPFS:         return "tmpfs";
    case MOUNT_PROC:          return "proc";
    case MOUNT_DEV:           return "dev";
    case MOUNT_DIR:           return "dir";
    case MOUNT_SYMLINK:       return "symlink";
    case MOUNT_FILE:          return "file";
    case MOUNT_BIND_DATA:     return "bind-data";
    case MOUNT_RO_BIND_DATA:  return "ro-bind-data";
    case MOUNT_REMOUNT_RO:    return "remount-ro";
    case MOUNT_CHMOD:         return "chmod";
    case MOUNT_OVERLAY_SRC:   return "overlay-src";
    case MOUNT_OVERLAY:       return "overlay";
    case MOUNT_TMP_OVERLAY:   return "tmp-overlay";
    case MOUNT_RO_OVERLAY:    return "ro-overlay";
    case MOUNT_MQUEUE:        return "mqueue";
    case MOUNT_BIND_FD:       return "bind-fd";
    case MOUNT_RO_BIND_FD:    return "ro-bind-fd";
    }
    return "unknown";
}

void klee_config_dump(const KleeConfig *cfg)
{
    fprintf(stderr, "=== KleeConfig ===\n");
    fprintf(stderr, "unshare: user=%d pid=%d ipc=%d uts=%d net=%d cgroup=%d\n",
            cfg->unshare_user, cfg->unshare_pid, cfg->unshare_ipc,
            cfg->unshare_uts, cfg->unshare_net, cfg->unshare_cgroup);
    if (cfg->uid_set)
        fprintf(stderr, "uid: %d\n", cfg->uid);
    if (cfg->gid_set)
        fprintf(stderr, "gid: %d\n", cfg->gid);
    if (cfg->hostname)
        fprintf(stderr, "hostname: %s\n", cfg->hostname);
    if (cfg->chdir_path)
        fprintf(stderr, "chdir: %s\n", cfg->chdir_path);
    fprintf(stderr, "new_session=%d die_with_parent=%d as_pid1=%d\n",
            cfg->new_session, cfg->die_with_parent, cfg->as_pid1);

    int n = 0;
    for (KleeMountOp *op = cfg->mount_ops; op; op = op->next, n++) {
        fprintf(stderr, "  mount[%d]: %s src=%s dest=%s perms=%04o\n",
                n, mount_type_str(op->type),
                op->source ? op->source : "(null)",
                op->dest ? op->dest : "(null)",
                op->perms);
    }

    if (cfg->argc > 0) {
        fprintf(stderr, "argv:");
        for (int i = 0; i < cfg->argc; i++)
            fprintf(stderr, " %s", cfg->argv[i]);
        fprintf(stderr, "\n");
    }
}
