/*
 * Klee - CLI parser unit tests
 */
#include "cli.h"
#include "config.h"
#include "util/log.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

#define TEST(name) static void test_##name(void)
#define RUN(name) do { printf("  %s... ", #name); test_##name(); printf("OK\n"); } while(0)

TEST(basic_bind)
{
    KleeConfig cfg;
    klee_config_init(&cfg);
    char *argv[] = { "--bind", "/src", "/dest", "--", "/bin/sh" };
    int rc = klee_cli_parse(&cfg, 5, argv);
    assert(rc == 0);
    assert(cfg.mount_ops != NULL);
    assert(cfg.mount_ops->type == MOUNT_BIND_RW);
    assert(strcmp(cfg.mount_ops->source, "/src") == 0);
    assert(strcmp(cfg.mount_ops->dest, "/dest") == 0);
    assert(cfg.argc == 1);
    assert(strcmp(cfg.argv[0], "/bin/sh") == 0);
    klee_config_destroy(&cfg);
}

TEST(ro_bind)
{
    KleeConfig cfg;
    klee_config_init(&cfg);
    char *argv[] = { "--ro-bind", "/src", "/dest", "--", "/bin/sh" };
    int rc = klee_cli_parse(&cfg, 5, argv);
    assert(rc == 0);
    assert(cfg.mount_ops->type == MOUNT_BIND_RO);
    klee_config_destroy(&cfg);
}

TEST(multiple_mounts)
{
    KleeConfig cfg;
    klee_config_init(&cfg);
    char *argv[] = {
        "--bind", "/", "/",
        "--tmpfs", "/tmp",
        "--proc", "/proc",
        "--dev", "/dev",
        "--", "/bin/sh"
    };
    int rc = klee_cli_parse(&cfg, 11, argv);
    assert(rc == 0);

    KleeMountOp *op = cfg.mount_ops;
    assert(op->type == MOUNT_BIND_RW);
    op = op->next;
    assert(op->type == MOUNT_TMPFS);
    op = op->next;
    assert(op->type == MOUNT_PROC);
    op = op->next;
    assert(op->type == MOUNT_DEV);
    assert(op->next == NULL);
    klee_config_destroy(&cfg);
}

TEST(unshare_all)
{
    KleeConfig cfg;
    klee_config_init(&cfg);
    char *argv[] = { "--unshare-all", "--", "/bin/sh" };
    int rc = klee_cli_parse(&cfg, 3, argv);
    assert(rc == 0);
    assert(cfg.unshare_user == true);
    assert(cfg.unshare_pid == true);
    assert(cfg.unshare_ipc == true);
    assert(cfg.unshare_uts == true);
    assert(cfg.unshare_net == true);
    assert(cfg.unshare_cgroup == true);
    klee_config_destroy(&cfg);
}

TEST(share_net_override)
{
    KleeConfig cfg;
    klee_config_init(&cfg);
    char *argv[] = { "--unshare-all", "--share-net", "--", "/bin/sh" };
    int rc = klee_cli_parse(&cfg, 4, argv);
    assert(rc == 0);
    assert(cfg.unshare_net == false);
    klee_config_destroy(&cfg);
}

TEST(uid_gid)
{
    KleeConfig cfg;
    klee_config_init(&cfg);
    char *argv[] = { "--uid", "1000", "--gid", "1000", "--", "/bin/sh" };
    int rc = klee_cli_parse(&cfg, 6, argv);
    assert(rc == 0);
    assert(cfg.uid_set == true);
    assert(cfg.uid == 1000);
    assert(cfg.gid_set == true);
    assert(cfg.gid == 1000);
    klee_config_destroy(&cfg);
}

TEST(hostname)
{
    KleeConfig cfg;
    klee_config_init(&cfg);
    char *argv[] = { "--hostname", "myhost", "--", "/bin/sh" };
    int rc = klee_cli_parse(&cfg, 4, argv);
    assert(rc == 0);
    assert(strcmp(cfg.hostname, "myhost") == 0);
    klee_config_destroy(&cfg);
}

TEST(setenv_unsetenv)
{
    KleeConfig cfg;
    klee_config_init(&cfg);
    char *argv[] = { "--setenv", "FOO", "bar", "--unsetenv", "BAZ", "--", "/bin/sh" };
    int rc = klee_cli_parse(&cfg, 7, argv);
    assert(rc == 0);

    /* Environment ops are stored as an ordered linked list */
    KleeEnvOp *op = cfg.env_ops;
    assert(op != NULL);
    assert(op->type == ENV_OP_SET);
    assert(strcmp(op->key, "FOO") == 0);
    assert(strcmp(op->value, "bar") == 0);
    op = op->next;
    assert(op != NULL);
    assert(op->type == ENV_OP_UNSET);
    assert(strcmp(op->key, "BAZ") == 0);
    assert(op->next == NULL);

    klee_config_destroy(&cfg);
}

TEST(process_flags)
{
    KleeConfig cfg;
    klee_config_init(&cfg);
    char *argv[] = { "--new-session", "--die-with-parent", "--as-pid-1", "--", "/bin/sh" };
    int rc = klee_cli_parse(&cfg, 5, argv);
    assert(rc == 0);
    assert(cfg.new_session == true);
    assert(cfg.die_with_parent == true);
    assert(cfg.as_pid1 == true);
    klee_config_destroy(&cfg);
}

TEST(fd_options)
{
    KleeConfig cfg;
    klee_config_init(&cfg);
    char *argv[] = { "--info-fd", "3", "--json-status-fd", "4", "--seccomp", "5",
                     "--", "/bin/sh" };
    int rc = klee_cli_parse(&cfg, 8, argv);
    assert(rc == 0);
    assert(cfg.info_fd == 3);
    assert(cfg.json_status_fd == 4);
    assert(cfg.seccomp_fd == 5);
    klee_config_destroy(&cfg);
}

TEST(perms_modifier)
{
    KleeConfig cfg;
    klee_config_init(&cfg);
    char *argv[] = { "--perms", "0700", "--tmpfs", "/tmp", "--", "/bin/sh" };
    int rc = klee_cli_parse(&cfg, 6, argv);
    assert(rc == 0);
    assert(cfg.mount_ops->perms == 0700);
    klee_config_destroy(&cfg);
}

TEST(symlink)
{
    KleeConfig cfg;
    klee_config_init(&cfg);
    char *argv[] = { "--symlink", "/usr/lib", "/lib", "--", "/bin/sh" };
    int rc = klee_cli_parse(&cfg, 5, argv);
    assert(rc == 0);
    assert(cfg.mount_ops->type == MOUNT_SYMLINK);
    assert(strcmp(cfg.mount_ops->source, "/usr/lib") == 0);
    assert(strcmp(cfg.mount_ops->dest, "/lib") == 0);
    klee_config_destroy(&cfg);
}

TEST(no_separator)
{
    KleeConfig cfg;
    klee_config_init(&cfg);
    char *argv[] = { "--bind", "/", "/", "/bin/sh", "-c", "echo hello" };
    int rc = klee_cli_parse(&cfg, 6, argv);
    assert(rc == 0);
    assert(cfg.argc == 3);
    assert(strcmp(cfg.argv[0], "/bin/sh") == 0);
    klee_config_destroy(&cfg);
}

TEST(pressure_vessel_cmdline)
{
    KleeConfig cfg;
    klee_config_init(&cfg);
    char *argv[] = {
        "--unshare-all", "--share-net",
        "--uid", "0", "--gid", "0",
        "--hostname", "steamdeck",
        "--ro-bind", "/", "/",
        "--tmpfs", "/tmp",
        "--proc", "/proc",
        "--dev", "/dev",
        "--bind", "/home", "/home",
        "--die-with-parent",
        "--new-session",
        "--info-fd", "3",
        "--", "/usr/bin/id"
    };
    int rc = klee_cli_parse(&cfg, 26, argv);
    assert(rc == 0);
    assert(cfg.unshare_user == true);
    assert(cfg.unshare_pid == true);
    assert(cfg.unshare_net == false);
    assert(cfg.uid == 0);
    assert(cfg.gid == 0);
    assert(strcmp(cfg.hostname, "steamdeck") == 0);
    assert(cfg.die_with_parent == true);
    assert(cfg.new_session == true);
    assert(cfg.info_fd == 3);
    assert(cfg.argc == 1);
    assert(strcmp(cfg.argv[0], "/usr/bin/id") == 0);
    klee_config_destroy(&cfg);
}

int main(void)
{
    klee_log_init(LOG_ERROR);
    printf("=== CLI Parser Tests ===\n");
    RUN(basic_bind);
    RUN(ro_bind);
    RUN(multiple_mounts);
    RUN(unshare_all);
    RUN(share_net_override);
    RUN(uid_gid);
    RUN(hostname);
    RUN(setenv_unsetenv);
    RUN(process_flags);
    RUN(fd_options);
    RUN(perms_modifier);
    RUN(symlink);
    RUN(no_separator);
    RUN(pressure_vessel_cmdline);
    printf("All CLI tests passed!\n");
    return 0;
}
