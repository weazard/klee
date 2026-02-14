/*
 * Klee - Userspace bwrap translation layer
 * Network namespace (slirp4netns integration)
 */
#ifndef KLEE_NET_NS_H
#define KLEE_NET_NS_H

#include <sys/types.h>
#include <stdbool.h>

typedef struct klee_net_ns {
    pid_t slirp_pid;     /* PID of slirp4netns process */
    int slirp_fd;        /* API socket FD */
    bool active;
} KleeNetNs;

/* Create network namespace (launch slirp4netns if available) */
KleeNetNs *klee_net_ns_create(pid_t target_pid);

/* Destroy network namespace */
void klee_net_ns_destroy(KleeNetNs *net);

#endif /* KLEE_NET_NS_H */
