/*
 * Klee - Userspace bwrap translation layer
 * Nested bwrap invocation handling implementation
 *
 * Instead of spawning a nested klee (which can't ptrace under the parent's
 * PTRACE_O_TRACEFORK), parse the nested bwrap argv inline from tracee memory,
 * apply mount operations to the parent's existing mount table, and rewrite
 * the execve to run the target command directly (skipping bwrap entirely).
 */
#include "compat/nested.h"
#include "process/memory.h"
#include "syscall/abi.h"
#include "process/regs.h"
#include "fs/path_resolve.h"
#include "fs/mount_table.h"
#include "cli.h"
#include "config.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <linux/limits.h>

#define DEFAULT_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

bool klee_nested_is_bwrap(const char *exe_path)
{
    if (!exe_path)
        return false;

    const char *basename = strrchr(exe_path, '/');
    basename = basename ? basename + 1 : exe_path;

    return strcmp(basename, "bwrap") == 0 ||
           strcmp(basename, "bubblewrap") == 0 ||
           strcmp(basename, "srt-bwrap") == 0 ||
           strcmp(basename, "klee") == 0;
}

/*
 * Translate a guest source path to a host path using the standard
 * klee_path_guest_to_host pattern (resolve + mount table translate).
 */
static int translate_nested_source(KleeProcess *proc, char **source)
{
    KleeResolveCtx ctx = {
        .mount_table = proc->sandbox->mount_table,
        .fd_table = proc->fd_table,
        .tracee_pid = proc->real_pid,
        .vcwd = proc->vcwd,
        .vroot = klee_mount_table_get_root(proc->sandbox->mount_table),
        .flags = 0,
    };
    char host_path[PATH_MAX];
    int rc = klee_path_guest_to_host(&ctx, *source, host_path, AT_FDCWD);
    if (rc < 0)
        return rc;
    char *translated = strdup(host_path);
    if (!translated)
        return -ENOMEM;
    free(*source);
    *source = translated;
    return 0;
}

/* Preserve the guest layer view when taking a bind from an overlay. */
static int bind_overlay_source(KleeProcess *proc, KleeMountOp *op)
{
    KleeMountTable *mt = proc->sandbox->mount_table;
    KleeResolveCtx ctx = {
        .mount_table = mt,
        .fd_table = proc->fd_table,
        .tracee_pid = proc->real_pid,
        .vcwd = proc->vcwd,
        .vroot = klee_mount_table_get_root(mt),
    };
    char guest[PATH_MAX];
    if (!op->source || klee_path_resolve(&ctx, op->source, guest, AT_FDCWD) < 0)
        return 0;
    KleeMount *mount = klee_mount_table_resolve(mt, guest);
    if (!mount || !mount->overlay)
        return 0;
    char relative[PATH_MAX], backed[PATH_MAX];
    int rc = klee_mount_table_overlay_relative(mt, guest, relative, sizeof(relative));
    if (rc < 0)
        return rc;
    rc = klee_overlay_resolve(mount->overlay, relative, backed, sizeof(backed), KLEE_OV_LOOKUP);
    if (rc < 0)
        return rc;
    struct stat entry;
    if (lstat(backed, &entry) < 0) {
        if (errno == ENOENT && (op->type == MOUNT_BIND_TRY ||
                               op->type == MOUNT_BIND_RO_TRY || op->type == MOUNT_DEV_BIND_TRY))
            return 0;
        return -errno;
    }
    op->overlay_prefix = strdup(relative);
    if (!op->overlay_prefix)
        return -ENOMEM;
    op->overlay_alias = mount->overlay;
    op->overlay_alias_readonly = mount->is_readonly;
    return 0;
}

/*
 * Apply nested mount operations to the child's mount table.
 * For FD-based ops, open the tracee's FD via /proc/<pid>/fd/<N>
 * to get a local FD that klee_mount_table_populate can use.
 *
 * Source paths in nested bwrap args are guest paths (e.g. /usr).
 * Translate them to host paths via klee_path_guest_to_host before
 * adding, so the child process can find files on the real filesystem.
 */
static int apply_nested_mounts(KleeProcess *proc, KleeMountTable *mt, KleeConfig *cfg, pid_t pid)
{
    size_t count = 0;

    /* Translate bind mount source paths from guest to host */
    for (KleeMountOp *op = cfg->mount_ops; op; op = op->next) {
        count++;
        bool needs_source_translate = false;

        switch (op->type) {
        case MOUNT_BIND_RW:
        case MOUNT_BIND_RO:
        case MOUNT_BIND_TRY:
        case MOUNT_BIND_RO_TRY:
        case MOUNT_DEV_BIND:
        case MOUNT_DEV_BIND_TRY:
        {
            int rc = bind_overlay_source(proc, op);
            if (rc < 0)
                return rc;
            needs_source_translate = true;
            break;
        }
        case MOUNT_OVERLAY:
        case MOUNT_TMP_OVERLAY:
        case MOUNT_RO_OVERLAY:
            needs_source_translate = true;
            /* Also translate overlay_srcs */
            for (int i = 0; i < op->overlay_src_count; i++) {
                int rc = translate_nested_source(proc, &op->overlay_srcs[i]);
                if (rc < 0)
                    return rc;
            }
            break;
        default:
            break;
        }

        if (needs_source_translate && op->source) {
            int rc = translate_nested_source(proc, &op->source);
            if (rc < 0)
                return rc;
        }
    }

    int *local_fds = malloc(count * sizeof(*local_fds));
    if (!local_fds)
        return -ENOMEM;
    size_t local_fd_count = 0;
    int rc;

    /* Replace tracee FD references with local FDs */
    for (KleeMountOp *op = cfg->mount_ops; op; op = op->next) {
        switch (op->type) {
        case MOUNT_FILE:
        case MOUNT_BIND_DATA:
        case MOUNT_RO_BIND_DATA:
        case MOUNT_BIND_FD:
        case MOUNT_RO_BIND_FD:
        {
            char fd_path[64];
            snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d",
                     (int)pid, op->fd);
            int local_fd = open(fd_path, O_RDONLY | O_CLOEXEC);
            if (local_fd < 0) {
                rc = -errno;
                goto out;
            }
            op->fd = local_fd;
            local_fds[local_fd_count++] = local_fd;
            break;
        }
        default:
            break;
        }
    }

    rc = klee_mount_table_populate(mt, cfg);
out:
    for (size_t i = 0; i < local_fd_count; i++)
        close(local_fds[i]);
    free(local_fds);
    return rc;
}

/*
 * Apply environment operations from a nested bwrap config to an
 * environment array.  Input envp[0..envc-1] are heap-allocated
 * "KEY=VALUE" strings.  Returns a new array in *out with *out_c entries.
 * Caller must free each string and the array itself.
 */
static int apply_env_ops(const KleeConfig *cfg,
                          char **envp, int envc,
                          char ***out, int *out_c)
{
    int cap = envc + 64;
    int count = envc;
    char **env = malloc((size_t)cap * sizeof(char *));
    if (!env)
        return -ENOMEM;

    for (int i = 0; i < envc; i++) {
        env[i] = strdup(envp[i]);
        if (!env[i]) {
            klee_abi_free_strv(env, i);
            return -ENOMEM;
        }
    }

    for (const KleeEnvOp *op = cfg->env_ops; op; op = op->next) {
        switch (op->type) {
        case ENV_OP_CLEAR:
            for (int i = 0; i < count; i++)
                free(env[i]);
            count = 0;
            break;

        case ENV_OP_SET: {
            size_t klen = strlen(op->key);
            size_t vlen = strlen(op->value);
            char *entry = malloc(klen + 1 + vlen + 1);
            if (!entry) {
                klee_abi_free_strv(env, count);
                return -ENOMEM;
            }
            memcpy(entry, op->key, klen);
            entry[klen] = '=';
            memcpy(entry + klen + 1, op->value, vlen + 1);

            bool found = false;
            for (int i = 0; i < count; i++) {
                if (strncmp(env[i], op->key, klen) == 0 &&
                    env[i][klen] == '=') {
                    free(env[i]);
                    env[i] = entry;
                    found = true;
                    break;
                }
            }
            if (!found) {
                if (count >= cap) {
                    cap = cap ? cap * 2 : 64;
                    char **tmp = realloc(env,
                                         (size_t)cap * sizeof(char *));
                    if (!tmp) {
                        free(entry);
                        klee_abi_free_strv(env, count);
                        return -ENOMEM;
                    }
                    env = tmp;
                }
                env[count++] = entry;
            }
            break;
        }

        case ENV_OP_UNSET: {
            size_t klen = strlen(op->key);
            for (int i = 0; i < count; i++) {
                if (strncmp(env[i], op->key, klen) == 0 &&
                    env[i][klen] == '=') {
                    free(env[i]);
                    env[i] = env[--count];
                    break;
                }
            }
            break;
        }
        }
    }

    *out = env;
    *out_c = count;
    return 0;
}

int klee_nested_handle_exec(KleeProcess *proc, KleeInterceptor *ic,
                             KleeEvent *ev)
{
    pid_t pid = ev->pid;
    int rc;
    char **raw_argv = NULL;
    int raw_argc = 0;
    char **new_envp = NULL;
    int new_envc = 0;
    bool env_modified = false;
    KleeConfig nested_cfg;
    bool cfg_inited = false;
    int ret = 0;

    KLEE_INFO("nested: intercepting bwrap execve from pid=%d", pid);

    /* 1. Read tracee argv from memory */
    rc = klee_abi_read_strv(proc, ic, ev->args[1], &raw_argv, &raw_argc);
    if (rc < 0 || raw_argc < 2) {
        KLEE_WARN("nested: failed to read tracee argv (rc=%d argc=%d)",
                  rc, raw_argc);
        ret = rc < 0 ? rc : -EINVAL;
        goto out;
    }

    KLEE_DEBUG("nested: bwrap invocation with %d args", raw_argc);

    klee_config_init(&nested_cfg);
    cfg_inited = true;
    rc = klee_cli_parse_in_tracee(&nested_cfg, raw_argc - 1, raw_argv + 1, pid);
    if (rc != 0) {
        KLEE_WARN("nested: failed to parse bwrap args: %d", rc);
        ret = rc < 0 ? rc : -EINVAL;
        goto out;
    }

    if (nested_cfg.argc < 1 || !nested_cfg.argv || !nested_cfg.argv[0]) {
        KLEE_WARN("nested: no target command in bwrap args");
        ret = -EINVAL;
        goto out;
    }

    KLEE_INFO("nested: target command: %s (argc=%d)",
              nested_cfg.argv[0], nested_cfg.argc);

    /* 5a. Apply environment ops (--setenv, --unsetenv, --clearenv) */
    if (nested_cfg.env_ops) {
        char **cur_envp = NULL;
        int cur_envc = 0;
        ret = klee_abi_read_strv(proc, ic, ev->args[2], &cur_envp, &cur_envc);
        if (ret < 0)
            goto out;
        ret = apply_env_ops(&nested_cfg, cur_envp, cur_envc, &new_envp, &new_envc);
        klee_abi_free_strv(cur_envp, cur_envc);
        if (ret < 0)
            goto out;
        env_modified = true;
    }

    /* 5b. Install a separate mount view for the nested command. */
    if (proc->sandbox && proc->sandbox->mount_table && nested_cfg.mount_ops) {
        KleeMountTable *table = klee_mount_table_clone(proc->sandbox->mount_table);
        KleeSandbox *child = klee_sandbox_create();
        if (!table || !child) {
            klee_mount_table_destroy(table);
            klee_sandbox_unref(child);
            ret = -ENOMEM;
            goto out;
        }
        *child = *proc->sandbox;
        child->ref_count = 1;
        child->mount_table = table;
        child->owns_mount_table = true;
        const char *hostname = proc->sandbox->hostname;
        child->hostname = hostname ? strdup(hostname) : NULL;
        rc = hostname && !child->hostname ? -ENOMEM
                                         : apply_nested_mounts(proc, table, &nested_cfg, pid);
        if (rc < 0) {
            klee_sandbox_unref(child);
            ret = rc;
            goto out;
        }
        proc->exec_previous_sandbox = proc->sandbox;
        proc->sandbox = child;

        /* Create host-side mirrors for /run/host mounts added by nested config */
        klee_mount_table_create_host_mirrors(proc->sandbox->mount_table);

        /* Expose GL extension libraries at the standard search path */
        klee_mount_table_apply_gl_extensions(proc->sandbox->mount_table);

        /* Apply pressure-vessel overrides (emulate overlayfs) */
        klee_mount_table_apply_pv_overrides(proc->sandbox->mount_table);
    }

    /* 6. Update vcwd if --chdir was specified */
    if (nested_cfg.chdir_path) {
        snprintf(proc->vcwd, PATH_MAX, "%s", nested_cfg.chdir_path);
        KLEE_DEBUG("nested: updated vcwd to %s", proc->vcwd);
    }

    /* 7. Resolve target command — PATH lookup for bare names (no '/'),
     *    then translate through the mount table. Real bwrap uses execvp()
     *    which searches PATH; we must do the same. */
    const char *target_guest = nested_cfg.argv[0];
    char target_abs[PATH_MAX];
    char target_host[PATH_MAX];

    if (!strchr(target_guest, '/')) {
        /* Bare command name — search PATH directories */
        const char *path_env = getenv("PATH");
        if (!path_env)
            path_env = DEFAULT_PATH;

        bool found = false;
        char path_buf[PATH_MAX * 4];
        snprintf(path_buf, sizeof(path_buf), "%s", path_env);

        char *saveptr = NULL;
        for (char *dir = strtok_r(path_buf, ":", &saveptr);
             dir != NULL;
             dir = strtok_r(NULL, ":", &saveptr)) {
            snprintf(target_abs, PATH_MAX, "%s/%s", dir, target_guest);
            /* Check via mount table translation if the host file exists */
            if (proc->sandbox && proc->sandbox->mount_table) {
                KleeResolveCtx ctx = {
                    .mount_table = proc->sandbox->mount_table,
                    .fd_table = proc->fd_table,
                    .tracee_pid = proc->real_pid,
                    .vcwd = proc->vcwd,
                    .vroot = klee_mount_table_get_root(
                                 proc->sandbox->mount_table),
                    .flags = 0,
                };
                rc = klee_path_guest_to_host(&ctx, target_abs,
                                              target_host, AT_FDCWD);
                if (rc == 0) {
                    struct stat st;
                    if (stat(target_host, &st) == 0 &&
                        S_ISREG(st.st_mode) &&
                        (st.st_mode & S_IXUSR)) {
                        found = true;
                        break;
                    }
                }
            } else {
                struct stat st;
                if (stat(target_abs, &st) == 0 &&
                    S_ISREG(st.st_mode) &&
                    (st.st_mode & S_IXUSR)) {
                    snprintf(target_host, PATH_MAX, "%s", target_abs);
                    found = true;
                    break;
                }
            }
        }

        if (!found) {
            KLEE_WARN("nested: command not found in PATH: %s",
                      target_guest);
            snprintf(target_abs, PATH_MAX, "%s", target_guest);
            snprintf(target_host, PATH_MAX, "%s", target_guest);
        } else {
            KLEE_DEBUG("nested: PATH lookup: %s -> %s",
                       target_guest, target_abs);
        }
    } else {
        /* Contains '/' — treat as a path, translate through mount table */
        snprintf(target_abs, PATH_MAX, "%s", target_guest);
        if (proc->sandbox && proc->sandbox->mount_table) {
            KleeResolveCtx ctx = {
                .mount_table = proc->sandbox->mount_table,
                .fd_table = proc->fd_table,
                .tracee_pid = proc->real_pid,
                .vcwd = proc->vcwd,
                .vroot = klee_mount_table_get_root(
                             proc->sandbox->mount_table),
                .flags = 0,
            };
            rc = klee_path_guest_to_host(&ctx, target_guest,
                                          target_host, AT_FDCWD);
            if (rc < 0) {
                KLEE_WARN("nested: path translation failed for %s: %d",
                          target_guest, rc);
                snprintf(target_host, PATH_MAX, "%s", target_guest);
            }
        } else {
            snprintf(target_host, PATH_MAX, "%s", target_guest);
        }
    }

    KLEE_INFO("nested: resolved %s -> %s", target_guest, target_host);

    if (ic->backend == INTERCEPT_PTRACE) {
        uint64_t filename, argv, envp;
        ret = klee_scratch_string(proc, ic, target_host, &filename);
        if (ret < 0)
            goto out;
        char *original_argv0 = nested_cfg.argv[0];
        if (nested_cfg.argv0)
            nested_cfg.argv[0] = nested_cfg.argv0;
        ret = klee_abi_stage_strv(proc, ic, nested_cfg.argv, nested_cfg.argc, &argv);
        nested_cfg.argv[0] = original_argv0;
        if (ret < 0)
            goto out;
        if (env_modified) {
            ret = klee_abi_stage_strv(proc, ic, new_envp, new_envc, &envp);
            if (ret < 0)
                goto out;
            klee_regs_set_arg(proc, 2, envp);
        }
        klee_regs_set_arg(proc, 0, filename);
        klee_regs_set_arg(proc, 1, argv);
        ret = klee_regs_push(ic, proc);
        if (ret < 0)
            goto out;
    }

    snprintf(proc->saved_path, PATH_MAX, "%s", target_abs);
    snprintf(proc->resolved_guest, PATH_MAX, "%s", target_abs);
    snprintf(proc->translated_path, PATH_MAX, "%s", target_host);

out:
    if (ret < 0)
        klee_process_finish_mount_exec(proc, false);
    if (cfg_inited)
        klee_config_destroy(&nested_cfg);
    klee_abi_free_strv(new_envp, new_envc);
    klee_abi_free_strv(raw_argv, raw_argc);
    return ret;
}
