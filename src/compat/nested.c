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

#define MAX_NESTED_ARGV 4096
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

static void free_argv(char **argv, int argc)
{
    if (!argv)
        return;
    for (int i = 0; i < argc; i++)
        free(argv[i]);
    free(argv);
}

/*
 * Read the tracee's argv pointer array and strings from memory.
 * On x86_64 each pointer is 8 bytes; read until a NULL pointer.
 * Returns heap-allocated string array in *out_argv.
 */
static int read_tracee_argv(KleeInterceptor *ic, pid_t pid,
                            uint64_t argv_addr,
                            char ***out_argv, int *out_argc)
{
    char **argv = NULL;
    int argc = 0;
    int cap = 0;

    for (int i = 0; i < MAX_NESTED_ARGV; i++) {
        uint64_t ptr = 0;
        int rc = klee_read_mem(ic, pid, &ptr,
                               (const void *)(uintptr_t)(argv_addr + (uint64_t)i * 8),
                               sizeof(ptr));
        if (rc < 0) {
            free_argv(argv, argc);
            return rc;
        }
        if (ptr == 0)
            break;

        char buf[PATH_MAX];
        rc = klee_read_string(ic, pid, buf, sizeof(buf),
                              (const void *)(uintptr_t)ptr);
        if (rc < 0) {
            free_argv(argv, argc);
            return rc;
        }

        if (argc >= cap) {
            cap = cap ? cap * 2 : 32;
            char **tmp = realloc(argv, (size_t)cap * sizeof(char *));
            if (!tmp) {
                free_argv(argv, argc);
                return -ENOMEM;
            }
            argv = tmp;
        }
        argv[argc] = strdup(buf);
        if (!argv[argc]) {
            free_argv(argv, argc);
            return -ENOMEM;
        }
        argc++;
    }

    *out_argv = argv;
    *out_argc = argc;
    return 0;
}

/*
 * Expand --args FD entries in argv by reading NUL-separated arguments
 * from the tracee's file descriptors via /proc/<pid>/fd/<FD>.
 * Returns a new heap-allocated argv with --args FD pairs replaced by
 * their expanded content.
 */
static int expand_args_fds(pid_t pid, int argc, char **argv,
                           int *out_argc, char ***out_argv)
{
    char **result = NULL;
    int count = 0;
    int cap = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--args") == 0 && i + 1 < argc) {
            int fd = atoi(argv[i + 1]);
            char fd_path[64];
            snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d",
                     (int)pid, fd);

            int local_fd = open(fd_path, O_RDONLY);
            if (local_fd < 0) {
                KLEE_WARN("nested: cannot open tracee fd %d via %s: %s",
                          fd, fd_path, strerror(errno));
                i++; /* skip FD argument */
                continue;
            }

            /* Read entire content */
            char *buf = NULL;
            size_t buf_len = 0;
            char tmp[4096];
            ssize_t n;
            while ((n = read(local_fd, tmp, sizeof(tmp))) > 0) {
                char *new_buf = realloc(buf, buf_len + (size_t)n);
                if (!new_buf) {
                    free(buf);
                    close(local_fd);
                    free_argv(result, count);
                    return -ENOMEM;
                }
                buf = new_buf;
                memcpy(buf + buf_len, tmp, (size_t)n);
                buf_len += (size_t)n;
            }
            close(local_fd);

            /* Split on NUL bytes */
            if (buf && buf_len > 0) {
                for (size_t pos = 0; pos < buf_len; ) {
                    size_t slen = strlen(buf + pos);
                    if (slen == 0 && pos + 1 >= buf_len)
                        break;
                    if (count >= cap) {
                        cap = cap ? cap * 2 : 64;
                        char **tmp_r = realloc(result,
                                               (size_t)cap * sizeof(char *));
                        if (!tmp_r) {
                            free(buf);
                            free_argv(result, count);
                            return -ENOMEM;
                        }
                        result = tmp_r;
                    }
                    result[count] = strdup(buf + pos);
                    if (!result[count]) {
                        free(buf);
                        free_argv(result, count);
                        return -ENOMEM;
                    }
                    count++;
                    pos += slen + 1;
                }
            }
            free(buf);
            i++; /* skip FD argument */
        } else {
            if (count >= cap) {
                cap = cap ? cap * 2 : 64;
                char **tmp_r = realloc(result,
                                       (size_t)cap * sizeof(char *));
                if (!tmp_r) {
                    free_argv(result, count);
                    return -ENOMEM;
                }
                result = tmp_r;
            }
            result[count] = strdup(argv[i]);
            if (!result[count]) {
                free_argv(result, count);
                return -ENOMEM;
            }
            count++;
        }
    }

    *out_argv = result;
    *out_argc = count;
    return 0;
}

/*
 * Apply nested mount operations to the parent's mount table.
 * For FD-based ops, open the tracee's FD via /proc/<pid>/fd/<N>
 * to get a local FD that klee_mount_table_populate can use.
 */
static int apply_nested_mounts(KleeMountTable *mt, KleeConfig *cfg, pid_t pid)
{
    int local_fds[256];
    int local_fd_count = 0;

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
            int local_fd = open(fd_path, O_RDONLY);
            if (local_fd >= 0) {
                op->fd = local_fd;
                if (local_fd_count < 256)
                    local_fds[local_fd_count++] = local_fd;
            } else {
                KLEE_WARN("nested: cannot open tracee fd %d for mount: %s",
                          op->fd, strerror(errno));
            }
            break;
        }
        default:
            break;
        }
    }

    int rc = klee_mount_table_populate(mt, cfg);

    /* Close local FDs we opened for the tracee */
    for (int i = 0; i < local_fd_count; i++)
        close(local_fds[i]);

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
            free_argv(env, i);
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
                free_argv(env, count);
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
                        free_argv(env, count);
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
    char **exp_argv = NULL;
    int exp_argc = 0;
    char **new_envp = NULL;
    int new_envc = 0;
    bool env_modified = false;
    KleeConfig nested_cfg;
    bool cfg_inited = false;
    int ret = 0;

    KLEE_INFO("nested: intercepting bwrap execve from pid=%d", pid);

    /* 1. Read tracee argv from memory */
    rc = read_tracee_argv(ic, pid, ev->args[1], &raw_argv, &raw_argc);
    if (rc < 0 || raw_argc < 2) {
        KLEE_WARN("nested: failed to read tracee argv (rc=%d argc=%d)",
                  rc, raw_argc);
        ret = rc < 0 ? rc : -EINVAL;
        goto out;
    }

    KLEE_DEBUG("nested: bwrap invocation with %d args", raw_argc);

    /* 2. Skip argv[0] (bwrap executable name) — CLI parser doesn't expect it */
    char **bwrap_args = raw_argv + 1;
    int bwrap_argc = raw_argc - 1;

    /* 3. Expand --args FD entries by reading from /proc/<pid>/fd/<FD> */
    rc = expand_args_fds(pid, bwrap_argc, bwrap_args, &exp_argc, &exp_argv);
    if (rc < 0) {
        KLEE_WARN("nested: failed to expand --args FDs: %d", rc);
        ret = rc;
        goto out;
    }

    KLEE_DEBUG("nested: expanded argv: %d -> %d entries",
               bwrap_argc, exp_argc);

    /* 4. Parse expanded argv into a temporary KleeConfig */
    klee_config_init(&nested_cfg);
    cfg_inited = true;

    rc = klee_cli_parse(&nested_cfg, exp_argc, exp_argv);
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
        rc = read_tracee_argv(ic, pid, ev->args[2],
                              &cur_envp, &cur_envc);
        if (rc == 0 && cur_envc >= 0) {
            rc = apply_env_ops(&nested_cfg, cur_envp, cur_envc,
                               &new_envp, &new_envc);
            if (rc == 0) {
                env_modified = true;
                KLEE_DEBUG("nested: env modified (%d -> %d vars)",
                           cur_envc, new_envc);
            }
            free_argv(cur_envp, cur_envc);
        } else {
            KLEE_WARN("nested: failed to read tracee envp: %d", rc);
        }
    }

    /* 5b. Apply nested mount operations to parent's mount table */
    if (proc->sandbox && proc->sandbox->mount_table && nested_cfg.mount_ops) {
        rc = apply_nested_mounts(proc->sandbox->mount_table,
                                 &nested_cfg, pid);
        if (rc < 0)
            KLEE_WARN("nested: some mount ops failed: %d", rc);

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

    /* 8-11. Write new exec path and argv to tracee scratch memory,
     *       update registers */
    if (ic->backend == INTERCEPT_PTRACE) {
        int target_argc = nested_cfg.argc;

        /* Allocate tracking array for string addresses */
        uint64_t *str_addrs = calloc((size_t)target_argc,
                                     sizeof(uint64_t));
        if (!str_addrs) {
            ret = -ENOMEM;
            goto out;
        }

        klee_regs_fetch(ic, proc);
        uint64_t rsp = klee_regs_get_sp(proc);

        /* Save original arg values for exit-time restore */
        proc->saved_args[0] = ev->args[0];
        proc->saved_args[1] = ev->args[1];

        /*
         * Scratch layout below tracee RSP:
         *   RSP - 128 (red zone) - PATH_MAX : exec path (arg0)
         *   below that                       : argv strings
         *   below that (8-byte aligned)      : argv pointer array
         */
        uint64_t exec_addr = rsp - 128 - PATH_MAX;

        /* Write exec host path */
        rc = klee_write_string(ic, pid,
                               (void *)(uintptr_t)exec_addr,
                               target_host);
        if (rc < 0) {
            KLEE_WARN("nested: failed to write exec path: %d", rc);
            free(str_addrs);
            goto out;
        }

        /* Write argv strings below the exec path */
        const char *argv0_str = nested_cfg.argv0
                                    ? nested_cfg.argv0
                                    : nested_cfg.argv[0];
        uint64_t cursor = exec_addr;

        for (int i = 0; i < target_argc; i++) {
            const char *s = (i == 0) ? argv0_str : nested_cfg.argv[i];
            size_t slen = strlen(s) + 1; /* include NUL */
            cursor -= slen;
            str_addrs[i] = cursor;

            rc = klee_write_string(ic, pid,
                                   (void *)(uintptr_t)cursor, s);
            if (rc < 0) {
                KLEE_WARN("nested: failed to write argv[%d]: %d",
                          i, rc);
                free(str_addrs);
                goto out;
            }
        }

        /* Align cursor down to 8 bytes for pointer array */
        cursor &= ~(uint64_t)7;

        /* Write argv pointer array + NULL terminator */
        uint64_t argv_array = cursor
                              - (uint64_t)(target_argc + 1) * 8;

        for (int i = 0; i < target_argc; i++) {
            rc = klee_write_mem(ic, pid,
                    (const void *)(uintptr_t)(argv_array
                                              + (uint64_t)i * 8),
                    &str_addrs[i], 8);
            if (rc < 0) {
                KLEE_WARN("nested: failed to write argv ptr[%d]: %d",
                          i, rc);
                free(str_addrs);
                goto out;
            }
        }
        /* NULL terminator */
        uint64_t null_val = 0;
        rc = klee_write_mem(ic, pid,
                (const void *)(uintptr_t)(argv_array
                                          + (uint64_t)target_argc * 8),
                &null_val, 8);
        if (rc < 0) {
            KLEE_WARN("nested: failed to write argv NULL: %d", rc);
            free(str_addrs);
            goto out;
        }

        free(str_addrs);

        /* Write envp strings and pointer array below argv array */
        uint64_t envp_array = 0;
        if (env_modified && new_envp && new_envc > 0) {
            uint64_t *env_addrs = calloc((size_t)new_envc,
                                         sizeof(uint64_t));
            if (!env_addrs) {
                ret = -ENOMEM;
                goto out;
            }

            uint64_t ecursor = argv_array;
            for (int i = 0; i < new_envc; i++) {
                size_t slen = strlen(new_envp[i]) + 1;
                ecursor -= slen;
                env_addrs[i] = ecursor;
                rc = klee_write_string(ic, pid,
                        (void *)(uintptr_t)ecursor, new_envp[i]);
                if (rc < 0) {
                    KLEE_WARN("nested: failed to write env[%d]: %d",
                              i, rc);
                    free(env_addrs);
                    goto out;
                }
            }

            ecursor &= ~(uint64_t)7;
            envp_array = ecursor
                         - (uint64_t)(new_envc + 1) * 8;

            for (int i = 0; i < new_envc; i++) {
                rc = klee_write_mem(ic, pid,
                        (const void *)(uintptr_t)(envp_array
                                                  + (uint64_t)i * 8),
                        &env_addrs[i], 8);
                if (rc < 0) {
                    free(env_addrs);
                    goto out;
                }
            }
            uint64_t env_null = 0;
            klee_write_mem(ic, pid,
                    (const void *)(uintptr_t)(envp_array
                                              + (uint64_t)new_envc * 8),
                    &env_null, 8);
            free(env_addrs);
        }

        /* Update registers: arg0 = exec path, arg1 = argv array */
        klee_regs_set_arg(proc, 0, exec_addr);
        klee_regs_set_arg(proc, 1, argv_array);
        if (env_modified && envp_array) {
            proc->saved_args[2] = ev->args[2];
            klee_regs_set_arg(proc, 2, envp_array);
        }
        klee_regs_push(ic, proc);

        /* Track modified args for exit-time restore (if exec fails) */
        proc->path_arg_idx[0] = 0;
        proc->path_arg_idx[1] = 1;
        proc->path_arg_count = 2;
        if (env_modified && envp_array) {
            proc->path_arg_idx[2] = 2;
            proc->path_arg_count = 3;
        }
        proc->path_modified = true;
    }

    /* 13. Set vexe to the target command's resolved guest path */
    snprintf(proc->vexe, PATH_MAX, "%s", target_abs);

out:
    if (cfg_inited)
        klee_config_destroy(&nested_cfg);
    free_argv(new_envp, new_envc);
    free_argv(exp_argv, exp_argc);
    free_argv(raw_argv, raw_argc);
    return ret;
}
