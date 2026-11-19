/*
 * Klee - Userspace bwrap translation layer
 * Zypak compatibility layer implementation
 *
 * Detects the Zypak environment (Flatpak Chrome), auto-exposes its
 * library/binary paths, and intercepts flatpak-spawn execve calls so
 * child processes stay inside KLEE's supervised process tree.
 *
 * Detection/auto-expose follows the steam_compat.c pattern.
 * The flatpak-spawn handler follows the nested.c pattern.
 */
#include "compat/zypak_compat.h"
#include "process/memory.h"
#include "syscall/abi.h"
#include "process/regs.h"
#include "fs/path_resolve.h"
#include "fs/mount_table.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <linux/limits.h>

#define MAX_ARGV 4096
#define DEFAULT_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

/* ------------------------------------------------------------------ */
/* Tracee memory helpers (duplicated from nested.c for module isolation) */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Detection                                                           */
/* ------------------------------------------------------------------ */

bool klee_zypak_detect(void)
{
    if (getenv("ZYPAK_BIN"))
        return true;
    if (getenv("ZYPAK_LIB"))
        return true;

    const char *preload = getenv("LD_PRELOAD");
    if (preload && strstr(preload, "libzypak"))
        return true;

    return false;
}

bool klee_zypak_detect_from_mounts(KleeMountTable *mt)
{
    if (!mt)
        return false;

    /* Check if zypak-helper is visible in the mount table */
    static const char *zypak_paths[] = {
        "/app/bin/zypak-helper",
        "/app/bin/zypak-wrapper.sh",
        NULL,
    };

    for (const char **p = zypak_paths; *p; p++) {
        /* A root bind (`--bind / /`) makes resolve() match every path, so
         * mount coverage alone is NOT evidence of Zypak — that misdetects
         * every ordinary sandbox that bind-mounts / as Chrome/Zypak and
         * silently forces unshare_user / uid=1000 / disables unshare_pid.
         * Require the helper to actually exist at the translated host path. */
        char host_path[PATH_MAX];
        if (klee_mount_table_translate(mt, *p, host_path, sizeof(host_path)) < 0)
            continue;
        if (access(host_path, F_OK) == 0) {
            KLEE_DEBUG("zypak: detected via mount table: %s -> %s", *p, host_path);
            return true;
        }
    }

    return false;
}

/* ------------------------------------------------------------------ */
/* Auto-expose                                                         */
/* ------------------------------------------------------------------ */

static void expose_path_if_exists(KleeMountTable *mt, const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0) {
        klee_mount_table_add(mt, MOUNT_BIND_RO, path, path, true, 0755);
        KLEE_DEBUG("zypak: auto-exposed %s", path);
    }
}

int klee_zypak_auto_expose(KleeMountTable *mt)
{
    if (!mt)
        return -1;

    const char *zypak_bin = getenv("ZYPAK_BIN");
    const char *zypak_lib = getenv("ZYPAK_LIB");

    if (zypak_bin) {
        expose_path_if_exists(mt, zypak_bin);
        KLEE_INFO("zypak: exposing ZYPAK_BIN=%s", zypak_bin);
    }

    if (zypak_lib) {
        expose_path_if_exists(mt, zypak_lib);
        KLEE_INFO("zypak: exposing ZYPAK_LIB=%s", zypak_lib);
    }

    /* Expose individual libzypak*.so paths from LD_PRELOAD */
    const char *preload = getenv("LD_PRELOAD");
    if (preload) {
        char buf[PATH_MAX * 4];
        snprintf(buf, sizeof(buf), "%s", preload);
        char *saveptr = NULL;
        for (char *tok = strtok_r(buf, ": ", &saveptr);
             tok != NULL;
             tok = strtok_r(NULL, ": ", &saveptr)) {
            if (strstr(tok, "libzypak")) {
                expose_path_if_exists(mt, tok);
                /* Also expose the directory containing the library */
                char dir[PATH_MAX];
                snprintf(dir, sizeof(dir), "%s", tok);
                char *slash = strrchr(dir, '/');
                if (slash) {
                    *slash = '\0';
                    expose_path_if_exists(mt, dir);
                }
            }
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Basename checks                                                      */
/* ------------------------------------------------------------------ */

bool klee_zypak_is_flatpak_spawn(const char *exe_path)
{
    if (!exe_path)
        return false;

    const char *base = strrchr(exe_path, '/');
    base = base ? base + 1 : exe_path;

    return strcmp(base, "flatpak-spawn") == 0;
}

bool klee_zypak_is_chrome_sandbox(const char *exe_path)
{
    if (!exe_path)
        return false;

    const char *base = strrchr(exe_path, '/');
    base = base ? base + 1 : exe_path;

    return strcmp(base, "chrome-sandbox") == 0;
}

/* ------------------------------------------------------------------ */
/* Nullify CHROME_DEVEL_SANDBOX in tracee envp                          */
/* ------------------------------------------------------------------ */

void klee_zypak_nullify_sandbox_env(KleeInterceptor *ic, pid_t pid,
                                     KleeAbi abi, uint64_t envp_addr)
{
    if (!envp_addr)
        return;
    static const char name[] = "CHROME_DEVEL_SANDBOX=";
    const size_t name_len = sizeof(name) - 1;
    for (int i = 0; i < MAX_ARGV; i++) {
        uint64_t ptr;
        if (klee_abi_read_ptr(ic, pid, abi, envp_addr + i * klee_abi_ptr_size(abi),
                              &ptr) < 0 || !ptr)
            return;
        char prefix[sizeof(name)];
        if (klee_read_mem(ic, pid, prefix, (const void *)(uintptr_t)ptr,
                          sizeof(prefix)) == 0 &&
            memcmp(prefix, name, name_len) == 0 && prefix[name_len] != '\0') {
            char nul = '\0';
            klee_write_mem(ic, pid, (void *)(uintptr_t)(ptr + name_len), &nul, 1);
            return;
        }
    }
}

/* ------------------------------------------------------------------ */
/* flatpak-spawn argv parser                                           */
/*                                                                     */
/* Format (from Zypak's mimic_launcher_delegate.cc):                   */
/*   flatpak-spawn --no-network [--watch-bus] [--sandbox]              */
/*     [--env=VAR=VALUE ...] [--forward-fd=N ...]                      */
/*     [--sandbox-expose-path-ro=PATH ...]                             */
/*     TARGET_CMD [TARGET_ARGS ...]                                    */
/*                                                                     */
/* Returns the index (into argv, 0-based) of the first non-option arg */
/* (the target command), or -1 on error.                               */
/* ------------------------------------------------------------------ */

typedef struct {
    /* Collected --env=KEY=VALUE entries */
    char **env_entries;   /* "KEY=VALUE" strings */
    int env_count;
    int env_cap;

    /* Collected --sandbox-expose-path-ro=PATH entries */
    char **expose_paths;
    int expose_count;
    int expose_cap;

    /* Index of target command in argv */
    int target_idx;
} FlatpakSpawnOpts;

static void fps_opts_init(FlatpakSpawnOpts *opts)
{
    memset(opts, 0, sizeof(*opts));
    opts->target_idx = -1;
}

static void fps_opts_destroy(FlatpakSpawnOpts *opts)
{
    free(opts->env_entries);
    free(opts->expose_paths);
}

static int fps_add_env(FlatpakSpawnOpts *opts, const char *entry)
{
    if (opts->env_count >= opts->env_cap) {
        int new_cap = opts->env_cap ? opts->env_cap * 2 : 16;
        char **tmp = realloc(opts->env_entries,
                             (size_t)new_cap * sizeof(char *));
        if (!tmp)
            return -ENOMEM;
        opts->env_entries = tmp;
        opts->env_cap = new_cap;
    }
    opts->env_entries[opts->env_count++] = (char *)entry;
    return 0;
}

static int fps_add_expose(FlatpakSpawnOpts *opts, const char *path)
{
    if (opts->expose_count >= opts->expose_cap) {
        int new_cap = opts->expose_cap ? opts->expose_cap * 2 : 16;
        char **tmp = realloc(opts->expose_paths,
                             (size_t)new_cap * sizeof(char *));
        if (!tmp)
            return -ENOMEM;
        opts->expose_paths = tmp;
        opts->expose_cap = new_cap;
    }
    opts->expose_paths[opts->expose_count++] = (char *)path;
    return 0;
}

static int parse_flatpak_spawn_argv(int argc, char **argv,
                                     FlatpakSpawnOpts *opts)
{
    fps_opts_init(opts);

    for (int i = 1; i < argc; i++) {  /* skip argv[0] (flatpak-spawn) */
        const char *arg = argv[i];

        if (strncmp(arg, "--env=", 6) == 0) {
            fps_add_env(opts, arg + 6);  /* "KEY=VALUE" */
        } else if (strncmp(arg, "--sandbox-expose-path-ro=", 25) == 0) {
            fps_add_expose(opts, arg + 25);
        } else if (strncmp(arg, "--sandbox-expose-path=", 22) == 0) {
            fps_add_expose(opts, arg + 22);
        } else if (strcmp(arg, "--no-network") == 0 ||
                   strcmp(arg, "--watch-bus") == 0 ||
                   strcmp(arg, "--sandbox") == 0 ||
                   strcmp(arg, "--clear-env") == 0 ||
                   strcmp(arg, "--latest-version") == 0 ||
                   strcmp(arg, "--no-a11y-bus") == 0 ||
                   strcmp(arg, "--no-session-bus") == 0) {
            /* Boolean flags — skip */
        } else if (strncmp(arg, "--forward-fd=", 13) == 0) {
            /* FD forwarding — skip (FDs are already inherited) */
        } else if (strncmp(arg, "--sandbox-flag=", 15) == 0 ||
                   strncmp(arg, "--directory=", 12) == 0) {
            /* Other --key=value flags — skip */
        } else if (strncmp(arg, "--", 2) == 0 && strchr(arg, '=')) {
            /* Unknown --key=value — skip with warning */
            KLEE_DEBUG("zypak: skipping unknown flatpak-spawn option: %s",
                       arg);
        } else if (strcmp(arg, "--") == 0) {
            /* End of options */
            if (i + 1 < argc)
                opts->target_idx = i + 1;
            break;
        } else if (arg[0] == '-') {
            /* Unknown flag — skip with warning */
            KLEE_DEBUG("zypak: skipping unknown flatpak-spawn flag: %s",
                       arg);
        } else {
            /* First non-option: this is the target command */
            opts->target_idx = i;
            break;
        }
    }

    return opts->target_idx >= 0 ? 0 : -EINVAL;
}

/* ------------------------------------------------------------------ */
/* Apply parsed flatpak-spawn options to the tracee environment        */
/* ------------------------------------------------------------------ */

static int apply_fps_env(const FlatpakSpawnOpts *opts,
                          char **envp, int envc,
                          char ***out, int *out_c)
{
    int cap = envc + opts->env_count + 1;
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

    for (int e = 0; e < opts->env_count; e++) {
        const char *entry = opts->env_entries[e];  /* "KEY=VALUE" */
        const char *eq = strchr(entry, '=');
        if (!eq)
            continue;
        size_t klen = (size_t)(eq - entry);

        /* Replace existing or append */
        bool found = false;
        for (int i = 0; i < count; i++) {
            if (strncmp(env[i], entry, klen) == 0 &&
                env[i][klen] == '=') {
                free(env[i]);
                env[i] = strdup(entry);
                if (!env[i]) {
                    klee_abi_free_strv(env, count);
                    return -ENOMEM;
                }
                found = true;
                break;
            }
        }
        if (!found) {
            if (count >= cap) {
                cap *= 2;
                char **tmp = realloc(env, (size_t)cap * sizeof(char *));
                if (!tmp) {
                    klee_abi_free_strv(env, count);
                    return -ENOMEM;
                }
                env = tmp;
            }
            env[count] = strdup(entry);
            if (!env[count]) {
                klee_abi_free_strv(env, count);
                return -ENOMEM;
            }
            count++;
        }
    }

    *out = env;
    *out_c = count;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Main handler: intercept flatpak-spawn execve                        */
/* ------------------------------------------------------------------ */

int klee_zypak_handle_flatpak_spawn(KleeProcess *proc, KleeInterceptor *ic,
                                     KleeEvent *ev)
{
    pid_t pid = ev->pid;
    int rc;
    char **raw_argv = NULL;
    int raw_argc = 0;
    char **new_envp = NULL;
    int new_envc = 0;
    bool env_modified = false;
    FlatpakSpawnOpts opts = {0};
    int ret = 0;

    KLEE_INFO("zypak: intercepting flatpak-spawn execve from pid=%d", pid);

    /* 1. Read tracee argv from memory */
    rc = klee_abi_read_strv(proc, ic, ev->args[1], &raw_argv, &raw_argc);
    if (rc < 0 || raw_argc < 2) {
        KLEE_WARN("zypak: failed to read tracee argv (rc=%d argc=%d)",
                  rc, raw_argc);
        ret = rc < 0 ? rc : -EINVAL;
        goto out;
    }

    KLEE_DEBUG("zypak: flatpak-spawn invocation with %d args", raw_argc);
    for (int i = 0; i < raw_argc && i < 32; i++)
        KLEE_DEBUG("zypak:   argv[%d] = %s", i, raw_argv[i]);

    /* 2. Parse flatpak-spawn options */
    rc = parse_flatpak_spawn_argv(raw_argc, raw_argv, &opts);
    if (rc < 0) {
        KLEE_WARN("zypak: failed to parse flatpak-spawn args: no target command");
        ret = -EINVAL;
        goto out;
    }

    int target_idx = opts.target_idx;
    int target_argc = raw_argc - target_idx;
    char **target_argv = raw_argv + target_idx;

    KLEE_INFO("zypak: target command: %s (argc=%d)",
              target_argv[0], target_argc);

    /* 3. Apply --env=VAR=VALUE to tracee environment */
    if (opts.env_count > 0) {
        char **cur_envp = NULL;
        int cur_envc = 0;
        rc = klee_abi_read_strv(proc, ic, ev->args[2],
                              &cur_envp, &cur_envc);
        if (rc == 0 && cur_envc >= 0) {
            rc = apply_fps_env(&opts, cur_envp, cur_envc,
                               &new_envp, &new_envc);
            if (rc == 0) {
                env_modified = true;
                KLEE_DEBUG("zypak: env modified (%d -> %d vars)",
                           cur_envc, new_envc);
            }
            klee_abi_free_strv(cur_envp, cur_envc);
        } else {
            KLEE_WARN("zypak: failed to read tracee envp: %d", rc);
        }
    }

    /* 3b. Force klee env overrides in the child.  Zypak's --env= may
     *     set CHROME_DEVEL_SANDBOX to the stub sandbox path, which
     *     makes Chrome attempt the SUID sandbox and crash. */
    if (proc->sandbox && proc->sandbox->zypak_detected) {
        if (!env_modified) {
            /* No --env= entries, but we still need to override.
             * Read the tracee's current env to get a mutable copy. */
            char **cur_envp = NULL;
            int cur_envc = 0;
            rc = klee_abi_read_strv(proc, ic, ev->args[2],
                                  &cur_envp, &cur_envc);
            if (rc == 0 && cur_envc >= 0) {
                new_envp = cur_envp;
                new_envc = cur_envc;
                env_modified = true;
            }
        }
        if (env_modified && new_envp) {
            for (int i = 0; i < new_envc; i++) {
                if (strncmp(new_envp[i], "CHROME_DEVEL_SANDBOX=", 21) == 0 &&
                    new_envp[i][21] != '\0') {
                    free(new_envp[i]);
                    new_envp[i] = strdup("CHROME_DEVEL_SANDBOX=");
                    KLEE_DEBUG("zypak: forced CHROME_DEVEL_SANDBOX=\"\" "
                               "in child env");
                }
            }
        }
    }

    /* 4. Apply --sandbox-expose-path[-ro]=PATH to mount table */
    if (opts.expose_count > 0 && proc->sandbox && proc->sandbox->mount_table) {
        for (int i = 0; i < opts.expose_count; i++) {
            const char *path = opts.expose_paths[i];
            struct stat st;
            if (stat(path, &st) == 0) {
                klee_mount_table_add(proc->sandbox->mount_table,
                                     MOUNT_BIND_RO, path, path,
                                     true, 0755);
                KLEE_DEBUG("zypak: exposed path: %s", path);
            } else {
                KLEE_DEBUG("zypak: expose path not found: %s", path);
            }
        }
    }

    /* 5. Resolve target command through mount table / PATH */
    const char *target_guest = target_argv[0];
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
            KLEE_WARN("zypak: command not found in PATH: %s", target_guest);
            snprintf(target_abs, PATH_MAX, "%s", target_guest);
            snprintf(target_host, PATH_MAX, "%s", target_guest);
        } else {
            KLEE_DEBUG("zypak: PATH lookup: %s -> %s", target_guest, target_abs);
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
                KLEE_WARN("zypak: path translation failed for %s: %d",
                          target_guest, rc);
                snprintf(target_host, PATH_MAX, "%s", target_guest);
            }
        } else {
            snprintf(target_host, PATH_MAX, "%s", target_guest);
        }
    }

    KLEE_INFO("zypak: resolved %s -> %s", target_guest, target_host);

    if (ic->backend == INTERCEPT_PTRACE) {
        uint64_t filename, argv, envp;
        ret = klee_scratch_string(proc, ic, target_host, &filename);
        if (ret < 0)
            goto out;
        ret = klee_abi_stage_strv(proc, ic, target_argv, target_argc, &argv);
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
    fps_opts_destroy(&opts);
    klee_abi_free_strv(new_envp, new_envc);
    klee_abi_free_strv(raw_argv, raw_argc);
    return ret;
}
