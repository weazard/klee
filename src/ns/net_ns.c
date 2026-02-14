/*
 * Klee - Userspace bwrap translation layer
 * Network namespace implementation
 *
 * Reference: rootlesskit/pkg/network/slirp4netns/slirp4netns.go
 */
#include "ns/net_ns.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

KleeNetNs *klee_net_ns_create(pid_t target_pid)
{
    KleeNetNs *net = calloc(1, sizeof(KleeNetNs));
    if (!net)
        return NULL;

    net->slirp_pid = 0;
    net->slirp_fd = -1;
    net->active = false;

    /* Try to launch slirp4netns */
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d", target_pid);

    /* Check if slirp4netns is available */
    if (access("/usr/bin/slirp4netns", X_OK) != 0 &&
        access("/usr/local/bin/slirp4netns", X_OK) != 0) {
        KLEE_INFO("slirp4netns not found, network namespace will have no connectivity");
        return net;
    }

    pid_t pid = fork();
    if (pid < 0) {
        KLEE_WARN("failed to fork for slirp4netns: %s", strerror(errno));
        return net;
    }

    if (pid == 0) {
        /* Child: exec slirp4netns */
        execlp("slirp4netns", "slirp4netns",
               "--configure",
               "--mtu=65520",
               "--disable-host-loopback",
               pid_str, "tap0",
               (char *)NULL);
        _exit(1);
    }

    net->slirp_pid = pid;
    net->active = true;
    KLEE_INFO("launched slirp4netns pid=%d for target=%d", pid, target_pid);

    return net;
}

void klee_net_ns_destroy(KleeNetNs *net)
{
    if (!net)
        return;

    if (net->slirp_pid > 0) {
        kill(net->slirp_pid, SIGTERM);
        waitpid(net->slirp_pid, NULL, 0);
        KLEE_DEBUG("slirp4netns pid=%d terminated", net->slirp_pid);
    }

    if (net->slirp_fd >= 0)
        close(net->slirp_fd);

    free(net);
}
