/*
 * Klee - Userspace bwrap translation layer
 * bwrap CLI argument parser implementation
 *
 * Order-sensitive: mount operations are applied in the order specified.
 */
#include "cli.h"
#include "util/log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#define MAX_ARGS 4096

static int need_args(int i, int argc, int count, const char *opt)
{
    if (i + count >= argc) {
        KLEE_ERROR("option %s requires %d argument(s)", opt, count);
        return -EINVAL;
    }
    return 0;
}

static int parse_int(const char *s, int *out)
{
    char *end;
    long val = strtol(s, &end, 0);
    if (*end != '\0' || end == s) {
        KLEE_ERROR("invalid integer: %s", s);
        return -EINVAL;
    }
    *out = (int)val;
    return 0;
}

static int parse_octal(const char *s, int *out)
{
    char *end;
    unsigned long val = strtoul(s, &end, 8);
    if (*end != '\0' || end == s) {
        KLEE_ERROR("invalid octal: %s", s);
        return -EINVAL;
    }
    if (val > 07777) {
        KLEE_ERROR("permissions too large: %s (max 07777)", s);
        return -EINVAL;
    }
    *out = (int)val;
    return 0;
}

static int add_env_op(KleeConfig *cfg, EnvOpType type,
                      const char *key, const char *value)
{
    KleeEnvOp *op = calloc(1, sizeof(KleeEnvOp));
    if (!op)
        return -ENOMEM;
    op->type = type;
    op->key = key ? strdup(key) : NULL;
    op->value = value ? strdup(value) : NULL;
    op->next = NULL;
    if (cfg->env_ops_tail) {
        cfg->env_ops_tail->next = op;
        cfg->env_ops_tail = op;
    } else {
        cfg->env_ops = op;
        cfg->env_ops_tail = op;
    }
    return 0;
}

static int add_setenv(KleeConfig *cfg, const char *key, const char *value)
{
    return add_env_op(cfg, ENV_OP_SET, key, value);
}

static int add_unsetenv(KleeConfig *cfg, const char *key)
{
    return add_env_op(cfg, ENV_OP_UNSET, key, NULL);
}

static int add_lock_file(KleeConfig *cfg, const char *path)
{
    int n = cfg->lock_file_count + 1;
    char **files = realloc(cfg->lock_files, n * sizeof(char *));
    if (!files)
        return -ENOMEM;
    files[n - 1] = strdup(path);
    cfg->lock_files = files;
    cfg->lock_file_count = n;
    return 0;
}

static int add_seccomp_fd(KleeConfig *cfg, int fd)
{
    int n = cfg->add_seccomp_fd_count + 1;
    int *fds = realloc(cfg->add_seccomp_fds, n * sizeof(int));
    if (!fds)
        return -ENOMEM;
    fds[n - 1] = fd;
    cfg->add_seccomp_fds = fds;
    cfg->add_seccomp_fd_count = n;
    return 0;
}

static int add_cap(char ***list, int *count, const char *cap)
{
    int n = *count + 1;
    char **new_list = realloc(*list, n * sizeof(char *));
    if (!new_list)
        return -ENOMEM;
    new_list[n - 1] = strdup(cap);
    *list = new_list;
    *count = n;
    return 0;
}

static int add_overlay_src(KleeConfig *cfg, const char *path)
{
    int n = cfg->pending_overlay_src_count + 1;
    char **srcs = realloc(cfg->pending_overlay_srcs, n * sizeof(char *));
    if (!srcs)
        return -ENOMEM;
    srcs[n - 1] = strdup(path);
    cfg->pending_overlay_srcs = srcs;
    cfg->pending_overlay_src_count = n;
    return 0;
}

static int klee_cli_parse_recurse(KleeConfig *cfg, int argc, char **argv,
                                   bool from_args_fd);

/* Parse NUL-separated arguments from a file descriptor (--args FD) */
static int parse_args_fd(KleeConfig *cfg, int fd)
{
    /* Read entire content */
    char *buf = NULL;
    size_t buf_size = 0;
    size_t buf_len = 0;
    char tmp[4096];
    ssize_t n;

    while ((n = read(fd, tmp, sizeof(tmp))) > 0) {
        char *new_buf = realloc(buf, buf_size + (size_t)n + 1);
        if (!new_buf) {
            free(buf);
            return -ENOMEM;
        }
        buf = new_buf;
        memcpy(buf + buf_len, tmp, (size_t)n);
        buf_len += (size_t)n;
        buf_size = buf_len + 1;
    }

    if (!buf || buf_len == 0) {
        free(buf);
        return 0;
    }
    buf[buf_len] = '\0';

    /* Split on NUL bytes into argv array */
    int new_argc = 0;
    char **new_argv = NULL;

    for (size_t pos = 0; pos < buf_len; ) {
        size_t slen = strlen(buf + pos);
        if (slen == 0 && pos + 1 >= buf_len)
            break;
        if (new_argc >= MAX_ARGS) {
            KLEE_ERROR("--args: too many arguments");
            free(new_argv);
            free(buf);
            return -E2BIG;
        }
        char **tmp_argv = realloc(new_argv, ((size_t)new_argc + 1) * sizeof(char *));
        if (!tmp_argv) {
            free(new_argv);
            free(buf);
            return -ENOMEM;
        }
        new_argv = tmp_argv;
        new_argv[new_argc++] = buf + pos;
        pos += slen + 1;
    }

    if (new_argc > 0) {
        KLEE_INFO("--args FD: read %d arguments", new_argc);
        for (int j = 0; j < new_argc; j++)
            KLEE_DEBUG("  args[%d] = %s", j, new_argv[j]);
        int rc = klee_cli_parse_recurse(cfg, new_argc, new_argv, true);
        free(new_argv);
        free(buf);
        return rc;
    }

    free(new_argv);
    free(buf);
    return 0;
}

int klee_cli_parse(KleeConfig *cfg, int argc, char **argv)
{
    return klee_cli_parse_recurse(cfg, argc, argv, false);
}

static int klee_cli_parse_recurse(KleeConfig *cfg, int argc, char **argv,
                                   bool from_args_fd)
{
    int i = 0;
    int rc;

    while (i < argc) {
        const char *arg = argv[i];

        /* "--" separates klee options from child command */
        if (strcmp(arg, "--") == 0) {
            i++;
            break;
        }

        /* If it doesn't start with --, it's the start of the command */
        if (strncmp(arg, "--", 2) != 0) {
            break;
        }

        /* ==================== Mount operations ==================== */
        if (strcmp(arg, "--bind") == 0) {
            if ((rc = need_args(i, argc, 2, arg)) < 0) return rc;
            klee_config_add_mount(cfg, MOUNT_BIND_RW, argv[i+1], argv[i+2]);
            i += 3;
        }
        else if (strcmp(arg, "--bind-try") == 0) {
            if ((rc = need_args(i, argc, 2, arg)) < 0) return rc;
            klee_config_add_mount(cfg, MOUNT_BIND_TRY, argv[i+1], argv[i+2]);
            i += 3;
        }
        else if (strcmp(arg, "--ro-bind") == 0) {
            if ((rc = need_args(i, argc, 2, arg)) < 0) return rc;
            klee_config_add_mount(cfg, MOUNT_BIND_RO, argv[i+1], argv[i+2]);
            i += 3;
        }
        else if (strcmp(arg, "--ro-bind-try") == 0) {
            if ((rc = need_args(i, argc, 2, arg)) < 0) return rc;
            klee_config_add_mount(cfg, MOUNT_BIND_RO_TRY, argv[i+1], argv[i+2]);
            i += 3;
        }
        else if (strcmp(arg, "--dev-bind") == 0) {
            if ((rc = need_args(i, argc, 2, arg)) < 0) return rc;
            klee_config_add_mount(cfg, MOUNT_DEV_BIND, argv[i+1], argv[i+2]);
            i += 3;
        }
        else if (strcmp(arg, "--dev-bind-try") == 0) {
            if ((rc = need_args(i, argc, 2, arg)) < 0) return rc;
            klee_config_add_mount(cfg, MOUNT_DEV_BIND_TRY, argv[i+1], argv[i+2]);
            i += 3;
        }
        else if (strcmp(arg, "--bind-fd") == 0) {
            if ((rc = need_args(i, argc, 2, arg)) < 0) return rc;
            int fd;
            if ((rc = parse_int(argv[i+1], &fd)) < 0) return rc;
            KleeMountOp *op = klee_config_add_mount(cfg, MOUNT_BIND_FD, NULL, argv[i+2]);
            if (op) op->fd = fd;
            i += 3;
        }
        else if (strcmp(arg, "--ro-bind-fd") == 0) {
            if ((rc = need_args(i, argc, 2, arg)) < 0) return rc;
            int fd;
            if ((rc = parse_int(argv[i+1], &fd)) < 0) return rc;
            KleeMountOp *op = klee_config_add_mount(cfg, MOUNT_RO_BIND_FD, NULL, argv[i+2]);
            if (op) op->fd = fd;
            i += 3;
        }
        else if (strcmp(arg, "--tmpfs") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            klee_config_add_mount(cfg, MOUNT_TMPFS, NULL, argv[i+1]);
            i += 2;
        }
        else if (strcmp(arg, "--proc") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            klee_config_add_mount(cfg, MOUNT_PROC, NULL, argv[i+1]);
            i += 2;
        }
        else if (strcmp(arg, "--dev") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            klee_config_add_mount(cfg, MOUNT_DEV, NULL, argv[i+1]);
            i += 2;
        }
        else if (strcmp(arg, "--dir") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            klee_config_add_mount(cfg, MOUNT_DIR, NULL, argv[i+1]);
            i += 2;
        }
        else if (strcmp(arg, "--mqueue") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            klee_config_add_mount(cfg, MOUNT_MQUEUE, NULL, argv[i+1]);
            i += 2;
        }
        else if (strcmp(arg, "--symlink") == 0) {
            if ((rc = need_args(i, argc, 2, arg)) < 0) return rc;
            klee_config_add_mount(cfg, MOUNT_SYMLINK, argv[i+1], argv[i+2]);
            i += 3;
        }
        else if (strcmp(arg, "--file") == 0) {
            if ((rc = need_args(i, argc, 2, arg)) < 0) return rc;
            int fd;
            if ((rc = parse_int(argv[i+1], &fd)) < 0) return rc;
            KleeMountOp *op = klee_config_add_mount(cfg, MOUNT_FILE, NULL, argv[i+2]);
            if (op) op->fd = fd;
            i += 3;
        }
        else if (strcmp(arg, "--bind-data") == 0) {
            if ((rc = need_args(i, argc, 2, arg)) < 0) return rc;
            int fd;
            if ((rc = parse_int(argv[i+1], &fd)) < 0) return rc;
            KleeMountOp *op = klee_config_add_mount(cfg, MOUNT_BIND_DATA, NULL, argv[i+2]);
            if (op) op->fd = fd;
            i += 3;
        }
        else if (strcmp(arg, "--ro-bind-data") == 0) {
            if ((rc = need_args(i, argc, 2, arg)) < 0) return rc;
            int fd;
            if ((rc = parse_int(argv[i+1], &fd)) < 0) return rc;
            KleeMountOp *op = klee_config_add_mount(cfg, MOUNT_RO_BIND_DATA, NULL, argv[i+2]);
            if (op) op->fd = fd;
            i += 3;
        }
        else if (strcmp(arg, "--remount-ro") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            klee_config_add_mount(cfg, MOUNT_REMOUNT_RO, NULL, argv[i+1]);
            i += 2;
        }
        else if (strcmp(arg, "--chmod") == 0) {
            if ((rc = need_args(i, argc, 2, arg)) < 0) return rc;
            int mode;
            if ((rc = parse_octal(argv[i+1], &mode)) < 0) return rc;
            KleeMountOp *op = klee_config_add_mount(cfg, MOUNT_CHMOD, NULL, argv[i+2]);
            if (op) op->perms = mode;
            i += 3;
        }
        /* ==================== Overlay operations ==================== */
        else if (strcmp(arg, "--overlay-src") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            add_overlay_src(cfg, argv[i+1]);
            i += 2;
        }
        else if (strcmp(arg, "--overlay") == 0) {
            if ((rc = need_args(i, argc, 3, arg)) < 0) return rc;
            if (cfg->pending_overlay_src_count < 1) {
                KLEE_ERROR("--overlay requires at least one --overlay-src");
                return -EINVAL;
            }
            KleeMountOp *op = klee_config_add_mount(cfg, MOUNT_OVERLAY, argv[i+1], argv[i+3]);
            if (op) {
                free(op->source);
                op->source = strdup(argv[i+1]);
            }
            i += 4;
        }
        else if (strcmp(arg, "--tmp-overlay") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            if (cfg->pending_overlay_src_count < 1) {
                KLEE_ERROR("--tmp-overlay requires at least one --overlay-src");
                return -EINVAL;
            }
            klee_config_add_mount(cfg, MOUNT_TMP_OVERLAY, NULL, argv[i+1]);
            i += 2;
        }
        else if (strcmp(arg, "--ro-overlay") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            if (cfg->pending_overlay_src_count < 2) {
                KLEE_ERROR("--ro-overlay requires at least two --overlay-src");
                return -EINVAL;
            }
            klee_config_add_mount(cfg, MOUNT_RO_OVERLAY, NULL, argv[i+1]);
            i += 2;
        }
        /* ==================== Modifier flags (apply to next op) ==================== */
        else if (strcmp(arg, "--perms") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            if (cfg->pending_perms_set) {
                KLEE_ERROR("--perms given twice without being consumed");
                return -EINVAL;
            }
            int perms;
            if ((rc = parse_octal(argv[i+1], &perms)) < 0) return rc;
            cfg->pending_perms = perms;
            cfg->pending_perms_set = true;
            i += 2;
        }
        else if (strcmp(arg, "--size") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            char *end;
            unsigned long long size_val = strtoull(argv[i+1], &end, 0);
            if (*end != '\0' || end == argv[i+1] || size_val == 0) {
                KLEE_ERROR("invalid size: %s", argv[i+1]);
                return -EINVAL;
            }
            cfg->pending_size = (size_t)size_val;
            cfg->pending_size_set = true;
            i += 2;
        }
        /* ==================== Namespace flags ==================== */
        else if (strcmp(arg, "--unshare-user") == 0) {
            cfg->unshare_user = true;
            i++;
        }
        else if (strcmp(arg, "--unshare-user-try") == 0) {
            cfg->unshare_user = true; /* try variant: don't fail */
            i++;
        }
        else if (strcmp(arg, "--unshare-pid") == 0) {
            cfg->unshare_pid = true;
            i++;
        }
        else if (strcmp(arg, "--unshare-ipc") == 0) {
            cfg->unshare_ipc = true;
            i++;
        }
        else if (strcmp(arg, "--unshare-uts") == 0) {
            cfg->unshare_uts = true;
            i++;
        }
        else if (strcmp(arg, "--unshare-net") == 0) {
            cfg->unshare_net = true;
            i++;
        }
        else if (strcmp(arg, "--unshare-cgroup") == 0) {
            cfg->unshare_cgroup = true;
            i++;
        }
        else if (strcmp(arg, "--unshare-cgroup-try") == 0) {
            cfg->unshare_cgroup = true;
            i++;
        }
        else if (strcmp(arg, "--unshare-all") == 0) {
            cfg->unshare_user = true;
            cfg->unshare_pid = true;
            cfg->unshare_ipc = true;
            cfg->unshare_uts = true;
            cfg->unshare_net = true;
            cfg->unshare_cgroup = true;
            i++;
        }
        else if (strcmp(arg, "--share-net") == 0) {
            cfg->share_net = true;
            i++;
        }
        /* ==================== Identity ==================== */
        else if (strcmp(arg, "--uid") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            int uid;
            if ((rc = parse_int(argv[i+1], &uid)) < 0) return rc;
            cfg->uid = (uid_t)uid;
            cfg->uid_set = true;
            i += 2;
        }
        else if (strcmp(arg, "--gid") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            int gid;
            if ((rc = parse_int(argv[i+1], &gid)) < 0) return rc;
            cfg->gid = (gid_t)gid;
            cfg->gid_set = true;
            i += 2;
        }
        else if (strcmp(arg, "--hostname") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            free(cfg->hostname);
            cfg->hostname = strdup(argv[i+1]);
            i += 2;
        }
        /* ==================== Working directory ==================== */
        else if (strcmp(arg, "--chdir") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            free(cfg->chdir_path);
            cfg->chdir_path = strdup(argv[i+1]);
            i += 2;
        }
        /* ==================== Environment ==================== */
        else if (strcmp(arg, "--setenv") == 0) {
            if ((rc = need_args(i, argc, 2, arg)) < 0) return rc;
            add_setenv(cfg, argv[i+1], argv[i+2]);
            i += 3;
        }
        else if (strcmp(arg, "--unsetenv") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            add_unsetenv(cfg, argv[i+1]);
            i += 2;
        }
        else if (strcmp(arg, "--clearenv") == 0) {
            cfg->clearenv = true;
            add_env_op(cfg, ENV_OP_CLEAR, NULL, NULL);
            i++;
        }
        /* ==================== FD-based options ==================== */
        else if (strcmp(arg, "--lock-file") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            add_lock_file(cfg, argv[i+1]);
            i += 2;
        }
        else if (strcmp(arg, "--sync-fd") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            if ((rc = parse_int(argv[i+1], &cfg->sync_fd)) < 0) return rc;
            i += 2;
        }
        else if (strcmp(arg, "--block-fd") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            if ((rc = parse_int(argv[i+1], &cfg->block_fd)) < 0) return rc;
            i += 2;
        }
        else if (strcmp(arg, "--info-fd") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            if ((rc = parse_int(argv[i+1], &cfg->info_fd)) < 0) return rc;
            i += 2;
        }
        else if (strcmp(arg, "--json-status-fd") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            if ((rc = parse_int(argv[i+1], &cfg->json_status_fd)) < 0) return rc;
            i += 2;
        }
        else if (strcmp(arg, "--seccomp") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            if ((rc = parse_int(argv[i+1], &cfg->seccomp_fd)) < 0) return rc;
            i += 2;
        }
        else if (strcmp(arg, "--add-seccomp-fd") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            int fd;
            if ((rc = parse_int(argv[i+1], &fd)) < 0) return rc;
            add_seccomp_fd(cfg, fd);
            i += 2;
        }
        else if (strcmp(arg, "--userns") == 0 || strcmp(arg, "--userns-fd") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            if ((rc = parse_int(argv[i+1], &cfg->userns_fd)) < 0) return rc;
            i += 2;
        }
        else if (strcmp(arg, "--userns2") == 0 || strcmp(arg, "--userns2-fd") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            if ((rc = parse_int(argv[i+1], &cfg->userns2_fd)) < 0) return rc;
            i += 2;
        }
        else if (strcmp(arg, "--pidns") == 0 || strcmp(arg, "--pidns-fd") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            if ((rc = parse_int(argv[i+1], &cfg->pidns_fd)) < 0) return rc;
            i += 2;
        }
        else if (strcmp(arg, "--userns-block-fd") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            if ((rc = parse_int(argv[i+1], &cfg->userns_block_fd)) < 0) return rc;
            i += 2;
        }
        /* ==================== Process flags ==================== */
        else if (strcmp(arg, "--new-session") == 0) {
            cfg->new_session = true;
            i++;
        }
        else if (strcmp(arg, "--die-with-parent") == 0) {
            cfg->die_with_parent = true;
            i++;
        }
        else if (strcmp(arg, "--as-pid-1") == 0) {
            cfg->as_pid1 = true;
            i++;
        }
        /* ==================== Capabilities ==================== */
        else if (strcmp(arg, "--cap-add") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            add_cap(&cfg->cap_add, &cfg->cap_add_count, argv[i+1]);
            i += 2;
        }
        else if (strcmp(arg, "--cap-drop") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            add_cap(&cfg->cap_drop, &cfg->cap_drop_count, argv[i+1]);
            i += 2;
        }
        /* ==================== Misc ==================== */
        else if (strcmp(arg, "--disable-userns") == 0) {
            cfg->disable_userns = true;
            i++;
        }
        else if (strcmp(arg, "--assert-userns-disabled") == 0) {
            cfg->assert_userns_disabled = true;
            i++;
        }
        /* ==================== Misc ==================== */
        else if (strcmp(arg, "--args") == 0) {
            if (from_args_fd) {
                KLEE_ERROR("--args not supported in arguments file");
                return -EINVAL;
            }
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            int fd;
            if ((rc = parse_int(argv[i+1], &fd)) < 0) return rc;
            rc = parse_args_fd(cfg, fd);
            if (rc < 0) return rc;
            i += 2;
        }
        else if (strcmp(arg, "--argv0") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            free(cfg->argv0);
            cfg->argv0 = strdup(argv[i+1]);
            i += 2;
        }
        else if (strcmp(arg, "--level-prefix") == 0) {
            cfg->level_prefix = true;
            i++;
        }
        else if (strcmp(arg, "--exec-label") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            free(cfg->exec_label);
            cfg->exec_label = strdup(argv[i+1]);
            i += 2;
        }
        else if (strcmp(arg, "--file-label") == 0) {
            if ((rc = need_args(i, argc, 1, arg)) < 0) return rc;
            free(cfg->file_label);
            cfg->file_label = strdup(argv[i+1]);
            i += 2;
        }
        else if (strcmp(arg, "--help") == 0) {
            klee_cli_usage("klee");
            return 1; /* special return: help requested */
        }
        else if (strcmp(arg, "--version") == 0) {
            fprintf(stdout, "klee 0.1.0 (bwrap-compatible translation layer)\n");
            return 1;
        }
        else {
            KLEE_ERROR("Unknown option %s", arg);
            return -EINVAL;
        }
    }

    /* Handle --share-net overriding --unshare-net */
    if (cfg->share_net)
        cfg->unshare_net = false;

    /* Everything remaining is the child command */
    if (i < argc) {
        cfg->argc = argc - i;
        cfg->argv = &argv[i];
    } else {
        cfg->argc = 0;
        cfg->argv = NULL;
    }

    return 0;
}

void klee_cli_usage(const char *progname)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS...] [--] COMMAND [ARGS...]\n"
        "\n"
        "Klee: Userspace bwrap-compatible translation layer\n"
        "\n"
        "Mount options:\n"
        "  --bind SRC DEST           Bind mount SRC to DEST\n"
        "  --bind-try SRC DEST       Bind mount SRC to DEST (ignore failure)\n"
        "  --ro-bind SRC DEST        Read-only bind mount\n"
        "  --ro-bind-try SRC DEST    Read-only bind mount (ignore failure)\n"
        "  --dev-bind SRC DEST       Device bind mount\n"
        "  --dev-bind-try SRC DEST   Device bind mount (ignore failure)\n"
        "  --bind-fd FD DEST         Bind mount open directory FD to DEST\n"
        "  --ro-bind-fd FD DEST      Read-only bind mount open directory FD\n"
        "  --tmpfs DEST              Mount tmpfs at DEST\n"
        "  --proc DEST               Mount proc at DEST\n"
        "  --dev DEST                Mount dev at DEST\n"
        "  --mqueue DEST             Mount mqueue at DEST\n"
        "  --dir DEST                Create directory at DEST\n"
        "  --symlink SRC DEST        Create symlink DEST -> SRC\n"
        "  --file FD DEST            Copy FD contents to DEST\n"
        "  --bind-data FD DEST       Bind mount FD data at DEST\n"
        "  --ro-bind-data FD DEST    Read-only bind mount FD data at DEST\n"
        "  --remount-ro DEST         Remount DEST read-only\n"
        "  --chmod OCTAL DEST        Set permissions on DEST\n"
        "  --overlay-src PATH        Add overlay source\n"
        "  --overlay RW WORK DEST    Overlay mount\n"
        "  --tmp-overlay DEST        Temporary overlay mount\n"
        "  --ro-overlay DEST         Read-only overlay mount\n"
        "  --perms OCTAL             Set permissions for next operation\n"
        "  --size BYTES              Set size for next tmpfs\n"
        "\n"
        "Namespace options:\n"
        "  --unshare-user            Create user namespace\n"
        "  --unshare-pid             Create PID namespace\n"
        "  --unshare-ipc             Create IPC namespace\n"
        "  --unshare-uts             Create UTS namespace\n"
        "  --unshare-net             Create network namespace\n"
        "  --unshare-cgroup          Create cgroup namespace\n"
        "  --unshare-all             Create all namespaces\n"
        "  --share-net               Undo --unshare-net\n"
        "  --uid UID                 Set virtual UID\n"
        "  --gid GID                 Set virtual GID\n"
        "  --hostname NAME           Set virtual hostname\n"
        "\n"
        "Process options:\n"
        "  --chdir DIR               Change to DIR in sandbox\n"
        "  --setenv VAR VALUE        Set environment variable\n"
        "  --unsetenv VAR            Unset environment variable\n"
        "  --clearenv                Clear all environment variables\n"
        "  --new-session             Create new terminal session\n"
        "  --die-with-parent         Kill sandbox on parent death\n"
        "  --as-pid-1               Run as PID 1 in sandbox\n"
        "\n"
        "FD options:\n"
        "  --lock-file PATH          Lock file path\n"
        "  --sync-fd FD              Synchronization FD\n"
        "  --block-fd FD             Block until FD is closed\n"
        "  --userns-block-fd FD      Block until user namespace is ready\n"
        "  --info-fd FD              Write sandbox info to FD\n"
        "  --json-status-fd FD       Write JSON status to FD\n"
        "  --seccomp FD              Apply seccomp filter from FD\n"
        "  --add-seccomp-fd FD       Add additional seccomp filter\n"
        "  --userns FD               Use this user namespace\n"
        "  --userns2 FD              Switch to user namespace after setup\n"
        "  --pidns FD                Use this PID namespace\n"
        "\n"
        "Capability options:\n"
        "  --cap-add CAP             Add capability\n"
        "  --cap-drop CAP            Drop capability\n"
        "\n"
        "Misc options:\n"
        "  --args FD                 Parse NUL-separated args from FD\n"
        "  --argv0 VALUE             Set argv[0] for child command\n"
        "  --level-prefix            Prepend message level to output\n"
        "  --exec-label LABEL        Set SELinux exec label\n"
        "  --file-label LABEL        Set SELinux file label\n"
        "\n",
        progname);
}
