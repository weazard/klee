/*
 * Klee - Userspace bwrap translation layer
 *
 * Entry point: parse CLI, probe interception backend, fork child,
 * set up sandbox, enter event loop.
 */
#include "cli.h"
#include "config.h"
#include "intercept/intercept.h"
#include "process/process.h"
#include "process/event.h"
#include "process/memory.h"
#include "syscall/dispatch.h"
#include "fs/mount_table.h"
#include "fs/tmpfs.h"
#include "ns/pid_ns.h"
#include "ns/user_ns.h"
#include "ns/uts_ns.h"
#include "ns/ipc_ns.h"
#include "ns/net_ns.h"
#include "ns/proc_synth.h"
#include "fuse/fuse_proc.h"
#include "steam/steam_compat.h"
#include "compat/zypak_compat.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>

static KleeLogLevel parse_log_level(void)
{
    const char *env = getenv("KLEE_LOG");
    if (!env)
        return LOG_WARN;
    if (strcmp(env, "error") == 0) return LOG_ERROR;
    if (strcmp(env, "warn") == 0)  return LOG_WARN;
    if (strcmp(env, "info") == 0)  return LOG_INFO;
    if (strcmp(env, "debug") == 0) return LOG_DEBUG;
    if (strcmp(env, "trace") == 0) return LOG_TRACE;
    return LOG_WARN;
}

static int setup_environment(const KleeConfig *cfg)
{
    /* Apply environment operations in the exact order they appeared
     * on the command line, matching bwrap's immediate-application
     * semantics. This preserves interleaving behavior like:
     *   --setenv FOO bar --clearenv --setenv BAZ qux
     * Result: only BAZ=qux (FOO was set then cleared). */
    for (const KleeEnvOp *op = cfg->env_ops; op; op = op->next) {
        switch (op->type) {
        case ENV_OP_CLEAR:
            clearenv();
            break;
        case ENV_OP_SET:
            if (setenv(op->key, op->value, 1) < 0)
                KLEE_WARN("setenv(%s) failed: %s", op->key, strerror(errno));
            break;
        case ENV_OP_UNSET:
            unsetenv(op->key);
            break;
        }
    }

    return 0;
}

static int write_info_fd(const KleeConfig *cfg, pid_t child_pid)
{
    if (cfg->info_fd < 0)
        return 0;

    /* Write child PID info - match bwrap's multi-line format */
    char buf[256];
    int len = snprintf(buf, sizeof(buf),
                       "{\n    \"child-pid\": %d\n}\n", child_pid);
    if (write(cfg->info_fd, buf, (size_t)len) < 0)
        KLEE_WARN("write to info-fd failed: %s", strerror(errno));
    close(cfg->info_fd);
    return 0;
}

static int write_json_status(const KleeConfig *cfg, pid_t child_pid)
{
    if (cfg->json_status_fd < 0)
        return 0;

    char buf[256];
    int len = snprintf(buf, sizeof(buf),
                       "{ \"child-pid\": %d }\n", child_pid);
    if (write(cfg->json_status_fd, buf, (size_t)len) < 0)
        KLEE_WARN("write to json-status-fd failed: %s", strerror(errno));
    return 0;
}

static int write_json_exit_status(const KleeConfig *cfg, int exit_code)
{
    if (cfg->json_status_fd < 0)
        return 0;

    char buf[128];
    int len = snprintf(buf, sizeof(buf),
                       "{ \"exit-code\": %d }\n", exit_code);
    if (write(cfg->json_status_fd, buf, (size_t)len) < 0)
        KLEE_WARN("write to json-status-fd failed: %s", strerror(errno));
    close(cfg->json_status_fd);
    return 0;
}

/* sync_fd is kept open for the sandbox lifetime.
 * The external process watches for EOF when the sandbox exits. */

static void wait_block_fd(const KleeConfig *cfg)
{
    if (cfg->block_fd >= 0) {
        /* Wait until block_fd is closed */
        char buf;
        while (read(cfg->block_fd, &buf, 1) > 0)
            ;
        close(cfg->block_fd);
    }
}

static void child_process(KleeInterceptor *interceptor, const KleeConfig *cfg,
                          const char *old_cwd)
{
    /* Install interception in child */
    int rc = klee_interceptor_install_child(interceptor);
    if (rc < 0) {
        fprintf(stderr, "klee: failed to install interception: %s\n",
                strerror(-rc));
        _exit(1);
    }

    /* Setup environment */
    setup_environment(cfg);

    /* Re-apply forced Zypak overrides.  setup_environment() processes
     * bwrap --setenv ops (and possibly --clearenv) which may restore
     * values klee needs to force.  Use the cfg flag since env vars set
     * in the parent may have been wiped by --clearenv. */
    if (cfg->zypak_detected) {
        setenv("CHROME_DEVEL_SANDBOX", "", 1);
        setenv("ZYPAK_ZYGOTE_STRATEGY_SPAWN", "0", 1);
    }

    /* New session if requested */
    if (cfg->new_session) {
        if (setsid() == (pid_t)-1) {
            fprintf(stderr, "klee: setsid failed: %s\n", strerror(errno));
            _exit(1);
        }
    }

    /* Die with parent if requested */
    if (cfg->die_with_parent)
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);

    /* Change directory - bwrap fallback chain:
     * 1. --chdir path (fatal on failure)
     * 2. old working directory
     * 3. $HOME
     * 4. / */
    const char *new_cwd = "/";
    if (cfg->chdir_path) {
        if (chdir(cfg->chdir_path) < 0) {
            fprintf(stderr, "klee: Can't chdir to %s: %s\n",
                    cfg->chdir_path, strerror(errno));
            _exit(1);
        }
        new_cwd = cfg->chdir_path;
    } else if (old_cwd && chdir(old_cwd) == 0) {
        new_cwd = old_cwd;
    } else {
        const char *home = getenv("HOME");
        if (home != NULL && chdir(home) == 0) {
            new_cwd = home;
        } else {
            if (chdir("/") < 0)
                { /* last resort, ignore error */ }
        }
    }
    setenv("PWD", new_cwd, 1);

    /* Execute child command */
    if (cfg->argc <= 0) {
        fprintf(stderr, "klee: no command specified\n");
        _exit(1);
    }

    /* Apply --argv0 if set */
    char *exec_path = cfg->argv[0];
    if (cfg->argv0)
        cfg->argv[0] = cfg->argv0;

    execvp(exec_path, cfg->argv);
    fprintf(stderr, "klee: exec(%s) failed: %s\n",
            exec_path, strerror(errno));
    _exit(127);
}

int main(int argc, char **argv)
{
    /* Initialize logging */
    klee_log_init(parse_log_level());

    KLEE_INFO("klee starting (pid=%d)", getpid());

    /* Ignore SIGTTOU so klee doesn't stop when the child takes the
     * terminal foreground process group via tcsetpgrp(). */
    signal(SIGTTOU, SIG_IGN);

    /* Parse CLI */
    KleeConfig cfg;
    klee_config_init(&cfg);

    int rc = klee_cli_parse(&cfg, argc - 1, argv + 1);
    if (rc > 0) {
        /* Help or version requested */
        klee_config_destroy(&cfg);
        return 0;
    }
    if (rc < 0) {
        KLEE_ERROR("CLI parse error");
        klee_config_destroy(&cfg);
        return 1;
    }

    if (cfg.argc <= 0) {
        fprintf(stderr, "klee: no command specified. Use -- COMMAND.\n");
        klee_config_destroy(&cfg);
        return 1;
    }

    /* Open session log file (always-on, organized by app/session) */
    klee_log_open_file(cfg.argv[0], getpid());
    if (klee_log_get_path())
        KLEE_INFO("session log: %s", klee_log_get_path());

    if (klee_log_get_level() >= LOG_DEBUG)
        klee_config_dump(&cfg);

    /* Log child command line to session log */
    if (cfg.argc > 0) {
        char cmdbuf[1024];
        int off = 0;
        for (int i = 0; i < cfg.argc && off < (int)sizeof(cmdbuf) - 1; i++) {
            int n = snprintf(cmdbuf + off, sizeof(cmdbuf) - (size_t)off,
                             "%s%s", i ? " " : "", cfg.argv[i]);
            if (n > 0) off += n;
        }
        KLEE_INFO("child command: %s", cmdbuf);
    }

    /* Log namespace and ID config */
    KLEE_DEBUG("config: unshare_user=%d uid_set=%d uid=%d gid_set=%d gid=%d",
               cfg.unshare_user, cfg.uid_set, cfg.uid, cfg.gid_set, cfg.gid);

    /* Log special FDs */
    if (cfg.info_fd >= 0 || cfg.sync_fd >= 0 || cfg.block_fd >= 0) {
        KLEE_DEBUG("special fds: info_fd=%d sync_fd=%d block_fd=%d",
                   cfg.info_fd, cfg.sync_fd, cfg.block_fd);
    }

    /* Initialize syscall dispatch table */
    klee_dispatch_init();

    /* Create interception backend */
    KleeInterceptor *interceptor = klee_interceptor_create();
    if (!interceptor) {
        KLEE_ERROR("failed to create interceptor");
        klee_config_destroy(&cfg);
        return 1;
    }

    /* Create sandbox */
    KleeSandbox *sandbox = klee_sandbox_create();
    if (!sandbox) {
        KLEE_ERROR("failed to create sandbox");
        interceptor->destroy(interceptor);
        klee_config_destroy(&cfg);
        return 1;
    }

    sandbox->unshare_pid = cfg.unshare_pid;
#ifdef KLEE_NO_FAKE_ROOT
    sandbox->unshare_user = false;
#else
    sandbox->unshare_user = cfg.unshare_user;
#endif
    sandbox->unshare_ipc = cfg.unshare_ipc;
    sandbox->unshare_uts = cfg.unshare_uts;
    sandbox->unshare_net = cfg.unshare_net;
    sandbox->unshare_cgroup = cfg.unshare_cgroup;

    if (cfg.hostname)
        sandbox->hostname = strdup(cfg.hostname);

    /* Create mount table */
    KleeMountTable *mount_table = klee_mount_table_create();
    if (!mount_table) {
        KLEE_ERROR("failed to create mount table");
        goto cleanup;
    }

    rc = klee_mount_table_populate(mount_table, &cfg);
    if (rc < 0) {
        KLEE_ERROR("failed to populate mount table: %d", rc);
        goto cleanup;
    }

    /* Auto-provision private /tmp when user namespace virtualization is
     * active and the real UID differs from the virtual UID.  Without
     * this, programs that construct UID-based paths under /tmp (tmux
     * with /tmp/tmux-<uid>, D-Bus session sockets, etc.) may target
     * directories owned by the real root user, causing EACCES because
     * the kernel enforces real-UID permissions.
     *
     * Only provision if no explicit /tmp mount was already specified
     * by the caller (e.g. --tmpfs /tmp or --bind ... /tmp). */
    if (cfg.unshare_user) {
        uid_t real_uid = getuid();
        uid_t virt_uid = cfg.uid_set ? cfg.uid : 0;
        if (real_uid != virt_uid) {
            KleeMount *tmp_mount = klee_mount_table_resolve(mount_table, "/tmp");
            if (!tmp_mount) {
                char *tmp_path = klee_tmpfs_create("/tmp");
                if (tmp_path) {
                    klee_mount_table_add(mount_table, MOUNT_TMPFS, tmp_path,
                                          "/tmp", false, 01777);
                    KLEE_INFO("auto-provisioned private /tmp "
                              "(real uid=%d != virtual uid=%d)",
                              real_uid, virt_uid);
                }
            }
        }
    }

    /* Pre-apply --setenv entries to the parent process so that detection
     * functions (steam) and syscall handlers (which run in the parent)
     * can see bwrap's --setenv arguments via getenv().
     * Only apply SET operations — never CLEAR/UNSET, which would destroy
     * env vars the parent needs (PATH, HOME, etc.).
     * The child also applies these in setup_environment() (idempotent). */
    for (const KleeEnvOp *op = cfg.env_ops; op; op = op->next) {
        if (op->type == ENV_OP_SET)
            setenv(op->key, op->value, 1);
    }

    /* Auto-expose Steam paths */
    klee_steam_auto_expose(mount_table);

    /* Detect and configure Zypak (Flatpak Chrome sandbox bridge).
     * Check both env vars (from bwrap --setenv) and mount table
     * (zypak-wrapper.sh sets ZYPAK_BIN inside the sandbox). */
    if (klee_zypak_detect() || klee_zypak_detect_from_mounts(mount_table)) {
        KLEE_INFO("Zypak detected in environment");
        sandbox->zypak_detected = true;
        cfg.zypak_detected = true;
        klee_zypak_auto_expose(mount_table);
        /* Ensure ZYPAK_BIN is set in the parent so syscall handlers
         * can resolve Zypak paths.  In mount-table detection mode,
         * ZYPAK_BIN won't be set yet (zypak-wrapper.sh sets it inside
         * the sandbox). */
        if (!getenv("ZYPAK_BIN"))
            setenv("ZYPAK_BIN", "/app/bin", 0);
        /* Force mimic strategy so Zypak uses flatpak-spawn (which klee
         * intercepts) instead of the spawn strategy (which escapes via
         * D-Bus portal). */
        setenv("ZYPAK_ZYGOTE_STRATEGY_SPAWN", "0", 1);
        /* Disable Chrome's SUID sandbox helper.  Chrome execs
         * chrome-sandbox via raw syscall, but the Flatpak stub just
         * does exit(1), killing the zygote.  Setting this empty makes
         * Chrome use its namespace sandbox instead, which works
         * natively under klee (clone CLONE_NEWUSER as real root). */
        setenv("CHROME_DEVEL_SANDBOX", "", 1);
        /* Force user namespace emulation.  Flatpak doesn't pass
         * --unshare-user to bwrap, but Chrome fatally refuses to run
         * as root (geteuid()==0).  Enabling unshare_user activates
         * UID/GID interception so klee virtualizes to non-root. */
        if (!cfg.unshare_user) {
            cfg.unshare_user = true;
            sandbox->unshare_user = true;
            KLEE_INFO("zypak: forced unshare_user for Chrome compatibility");
        }
        /* Default to uid/gid 1000 if bwrap didn't specify --uid/--gid.
         * Chrome's root check is geteuid()==0, so the virtual uid must
         * be non-zero for processes that don't have --no-sandbox. */
        if (!cfg.uid_set) {
            cfg.uid = 1000;
            cfg.uid_set = true;
        }
        if (!cfg.gid_set) {
            cfg.gid = 1000;
            cfg.gid_set = true;
        }
        /* Disable PID namespace virtualization for Chrome/Zypak.
         * klee assigns virtual PIDs to every clone (including threads),
         * but clone()/CLONE_CHILD_SETTID return real TIDs while
         * gettid() returns virtual TIDs — this mismatch breaks
         * Chrome's Mojo IPC and thread management. */
        cfg.unshare_pid = false;
        sandbox->unshare_pid = false;
    }

    /* Create host-side mirrors for /run/host mounts so the kernel
     * can follow host-side symlinks that reference guest paths
     * (e.g. pressure-vessel runtime library overlays). */
    klee_mount_table_create_host_mirrors(mount_table);

    /* Expose Flatpak GL extension libraries at the standard library
     * search path.  GL extensions are bind-mounted under
     * /usr/lib/<triplet>/GL/<vendor>/ but the dynamic linker only
     * searches /usr/lib/<triplet>/.  Add symlink mounts so libraries
     * like libGLX_mesa.so.0 are discoverable. */
    klee_mount_table_apply_gl_extensions(mount_table);

    /* Apply pressure-vessel overrides.  In a real bwrap container,
     * overlayfs merges host overrides onto the runtime /usr.  Since klee
     * can't do overlayfs, add explicit mount entries instead. */
    klee_mount_table_apply_pv_overrides(mount_table);

    sandbox->mount_table = mount_table;

    if (klee_log_get_level() >= LOG_DEBUG)
        klee_mount_table_dump(mount_table);

    /* Create IPC namespace */
    if (cfg.unshare_ipc) {
        sandbox->ipc_ns = klee_ipc_ns_create_unique((unsigned long)(uintptr_t)sandbox);
        if (!sandbox->ipc_ns) {
            KLEE_ERROR("failed to create IPC namespace");
            goto cleanup;
        }
    }

    /* Create PID map */
    if (cfg.unshare_pid) {
        sandbox->pid_map = klee_pid_map_create();
        if (!sandbox->pid_map) {
            KLEE_ERROR("failed to create PID map");
            goto cleanup;
        }
    }

    /* Save current working directory before fork for chdir fallback */
    char old_cwd[PATH_MAX];
    if (!getcwd(old_cwd, sizeof(old_cwd)))
        old_cwd[0] = '\0';

    /* Wait on block fd if specified (bwrap does this after setup, before exec) */
    wait_block_fd(&cfg);

    /* Fork child */
    pid_t child_pid = fork();
    if (child_pid < 0) {
        KLEE_ERROR("fork failed: %s", strerror(errno));
        goto cleanup;
    }

    if (child_pid == 0) {
        /* Child process */
        child_process(interceptor, &cfg, old_cwd[0] ? old_cwd : NULL);
        /* NOT REACHED */
        _exit(1);
    }

    /* Parent: setup interception */
    KLEE_INFO("child started pid=%d", child_pid);

    /* Create network namespace (needs child PID for slirp4netns target) */
    if (cfg.unshare_net) {
        sandbox->net_ns = klee_net_ns_create(child_pid);
        if (!sandbox->net_ns)
            KLEE_WARN("network namespace creation failed - no connectivity");
    }

    rc = klee_interceptor_setup_parent(interceptor, child_pid);
    if (rc < 0) {
        KLEE_ERROR("failed to setup parent interception: %s", strerror(-rc));
        kill(child_pid, SIGKILL);
        waitpid(child_pid, NULL, 0);
        goto cleanup;
    }

    /* Create process table and initial process */
    KleeProcessTable *proctable = klee_proctable_create();
    if (!proctable) {
        KLEE_ERROR("failed to create process table");
        kill(child_pid, SIGKILL);
        waitpid(child_pid, NULL, 0);
        goto cleanup;
    }

    KleeProcess *init_proc = klee_process_create(proctable, child_pid, sandbox);
    if (!init_proc) {
        KLEE_ERROR("failed to create init process");
        kill(child_pid, SIGKILL);
        waitpid(child_pid, NULL, 0);
        goto cleanup;
    }

    /* Assign virtual PID 1 */
    if (sandbox->pid_map) {
        init_proc->virtual_pid = klee_pid_map_add(sandbox->pid_map, child_pid);
        init_proc->virtual_ppid = 0;
    }

    /* Set initial ID state.  When Zypak is detected and no explicit
     * --uid/--gid was given, default to UID/GID 1000 instead of 0.
     * Chrome fatally refuses to run as root. */
    if (cfg.unshare_user) {
        uid_t uid = cfg.uid_set ? cfg.uid : (sandbox->zypak_detected ? 1000 : 0);
        gid_t gid = cfg.gid_set ? cfg.gid : (sandbox->zypak_detected ? 1000 : 0);
        init_proc->id_state = klee_id_state_create(uid, gid);
    }

    /* In Zypak mode, the initial process (Chrome main, launched with
     * --no-sandbox) skips UID virtualization so getuid() returns real
     * uid=0.  This lets D-Bus AUTH EXTERNAL match SO_PEERCRED.
     * Child processes re-evaluate on exec (see enter.c). */
    if (cfg.zypak_detected)
        init_proc->skip_uid_virt = true;

    /* Set initial virtual CWD */
    if (cfg.chdir_path)
        snprintf(init_proc->vcwd, PATH_MAX, "%s", cfg.chdir_path);
    else if (!getcwd(init_proc->vcwd, PATH_MAX))
        snprintf(init_proc->vcwd, PATH_MAX, "/");

    init_proc->state = PROC_STATE_RUNNING;

    /* Create FUSE /proc overlay when PID namespace is active.
     * Klee uses userspace interception, so without FUSE the child
     * would see real host PIDs via /proc. The FUSE overlay filters
     * PID directories and rewrites /proc/<pid>/status etc.
     * Falls back to tmpfs snapshot when FUSE is unavailable. */
    if (cfg.unshare_pid) {
        const char *proc_source = NULL;
        sandbox->fuse_proc = klee_fuse_proc_create(proctable, sandbox);
        if (sandbox->fuse_proc) {
            proc_source = klee_fuse_proc_get_path(sandbox->fuse_proc);
        } else {
            /* FUSE unavailable — fall back to passthrough /proc.
             * The tmpfs snapshot approach doesn't contain actual directory
             * trees like /proc/self/fd, causing ENOENT when programs call
             * opendir("/proc/self/fd").  Passthrough sacrifices PID filtering
             * in /proc listings but keeps critical paths functional. */
            proc_source = "/proc";
        }
        if (proc_source) {
            KleeMount *proc_mount = klee_mount_table_resolve(mount_table, "/proc");
            if (proc_mount && proc_mount->type == MOUNT_PROC) {
                proc_mount->source = klee_arena_strdup(mount_table->arena,
                                                        proc_source);
            } else {
                klee_mount_table_add(mount_table, MOUNT_PROC,
                                      proc_source, "/proc", false, 0755);
            }
        }
    }

    /* Write info/status FDs */
    write_info_fd(&cfg, child_pid);
    write_json_status(&cfg, child_pid);

    /* Create and run event loop */
    KleeEventLoop *event_loop = klee_event_loop_create(interceptor, proctable,
                                                         sandbox, &cfg);
    if (!event_loop) {
        KLEE_ERROR("failed to create event loop");
        kill(child_pid, SIGKILL);
        waitpid(child_pid, NULL, 0);
        goto cleanup;
    }
    event_loop->initial_child_pid = child_pid;

    int exit_status = klee_event_loop_run(event_loop);

    /* Write final exit status */
    write_json_exit_status(&cfg, exit_status);

    /* Close sync_fd now that sandbox is exiting - EOF signals watchers */
    if (cfg.sync_fd >= 0)
        close(cfg.sync_fd);

    /* Cleanup */
    klee_event_loop_destroy(event_loop);
    klee_proctable_destroy(proctable);

    KLEE_INFO("klee exiting with status %d", exit_status);

    klee_fuse_proc_destroy(sandbox->fuse_proc);
    sandbox->fuse_proc = NULL;
    klee_net_ns_destroy(sandbox->net_ns);
    sandbox->net_ns = NULL;
    klee_ipc_ns_destroy(sandbox->ipc_ns);
    sandbox->ipc_ns = NULL;
    klee_pid_map_destroy(sandbox->pid_map);
    klee_mount_table_destroy(mount_table);
    sandbox->mount_table = NULL;
    sandbox->pid_map = NULL;
    klee_sandbox_unref(sandbox);
    interceptor->destroy(interceptor);
    klee_proc_synth_cleanup();
    klee_tmpfs_cleanup();
    klee_log_close_file();
    klee_config_destroy(&cfg);
    return exit_status;

cleanup:
    if (sandbox) {
        klee_fuse_proc_destroy(sandbox->fuse_proc);
        sandbox->fuse_proc = NULL;
        klee_net_ns_destroy(sandbox->net_ns);
        sandbox->net_ns = NULL;
        klee_ipc_ns_destroy(sandbox->ipc_ns);
        sandbox->ipc_ns = NULL;
        klee_pid_map_destroy(sandbox->pid_map);
        if (mount_table)
            klee_mount_table_destroy(mount_table);
        sandbox->mount_table = NULL;
        sandbox->pid_map = NULL;
        klee_sandbox_unref(sandbox);
    }
    if (interceptor)
        interceptor->destroy(interceptor);
    klee_proc_synth_cleanup();
    klee_tmpfs_cleanup();
    klee_log_close_file();
    klee_config_destroy(&cfg);
    return 1;
}
