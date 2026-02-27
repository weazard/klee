/*
 * Klee - Userspace bwrap translation layer
 * Main epoll event loop (supervisor)
 */
#ifndef KLEE_EVENT_H
#define KLEE_EVENT_H

#include "process/process.h"
#include "intercept/intercept.h"
#include "config.h"

typedef struct klee_event_loop {
    KleeInterceptor *interceptor;
    KleeProcessTable *proctable;
    KleeSandbox *sandbox;
    const KleeConfig *config;
    int epoll_fd;
    int signal_fd;
    int exit_status;
    bool running;
    pid_t initial_child_pid;    /* direct child of klee — exit terminates loop */
} KleeEventLoop;

/* Create and initialize the event loop */
KleeEventLoop *klee_event_loop_create(KleeInterceptor *ic,
                                        KleeProcessTable *pt,
                                        KleeSandbox *sb,
                                        const KleeConfig *cfg);

/* Destroy event loop */
void klee_event_loop_destroy(KleeEventLoop *el);

/* Run the event loop until all children exit.
 * Returns the exit status of the initial child. */
int klee_event_loop_run(KleeEventLoop *el);

/* Handle a single event */
int klee_event_loop_handle(KleeEventLoop *el, KleeEvent *event);

#endif /* KLEE_EVENT_H */
