/*
 * Klee - Userspace bwrap translation layer
 * Unified backend-agnostic interception API
 */
#ifndef KLEE_INTERCEPT_H
#define KLEE_INTERCEPT_H

#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef enum {
    INTERCEPT_SECCOMP_UNOTIFY,
    INTERCEPT_PTRACE,
} InterceptBackend;

typedef enum {
    KLEE_EVENT_SYSCALL_ENTER,
    KLEE_EVENT_SYSCALL_EXIT,
    KLEE_EVENT_FORK,
    KLEE_EVENT_EXEC,
    KLEE_EVENT_EXIT,
    KLEE_EVENT_SIGNAL,
    KLEE_EVENT_CLONE,
} KleeEventType;

typedef struct {
    KleeEventType type;
    pid_t pid;
    int syscall_nr;
    uint64_t args[6];
    long retval;
    int signal;
    uint64_t notif_id;     /* seccomp_unotify notification ID */
    pid_t new_child_pid;   /* for fork/clone events */
} KleeEvent;

typedef struct klee_interceptor KleeInterceptor;

struct klee_interceptor {
    InterceptBackend backend;

    /* Backend-specific data */
    union {
        struct {
            int notif_fd;
            int listener_fd;
            int setup_pipe[2];  /* pipe for child→parent FD number transfer */
        } seccomp;
        struct {
            unsigned long options;
            bool seccomp_filter;    /* true if SECCOMP_RET_TRACE filter active */
            int status_pipe[2];     /* child→parent filter install notification */
        } ptrace;
    };

    /* Backend operations */
    int (*wait_event)(KleeInterceptor *self, KleeEvent *out);
    int (*respond)(KleeInterceptor *self, KleeEvent *event, long retval, int err);
    int (*continue_syscall)(KleeInterceptor *self, pid_t pid, int signal);
    int (*continue_running)(KleeInterceptor *self, pid_t pid, int signal);
    int (*skip_syscall)(KleeInterceptor *self, pid_t pid, long retval);
    int (*read_mem)(KleeInterceptor *self, pid_t pid,
                    void *local, const void *remote, size_t len);
    int (*write_mem)(KleeInterceptor *self, pid_t pid,
                     const void *remote, const void *local, size_t len);
    void (*destroy)(KleeInterceptor *self);
};

/* Probe and create the best available interception backend.
 * Returns NULL on failure. */
KleeInterceptor *klee_interceptor_create(void);

/* Create a specific backend */
KleeInterceptor *klee_interceptor_create_seccomp(void);
KleeInterceptor *klee_interceptor_create_ptrace(void);

/* Get the file descriptor to install seccomp filter on child
 * (only valid for seccomp_unotify backend) */
int klee_interceptor_get_seccomp_fd(KleeInterceptor *interceptor);

/* Install BPF filter for the child process (called before exec).
 * For seccomp: installs SECCOMP_RET_USER_NOTIF filter.
 * For ptrace: sets up PTRACE_TRACEME. */
int klee_interceptor_install_child(KleeInterceptor *interceptor);

/* Setup parent side after child is started.
 * For ptrace: set PTRACE_SETOPTIONS. */
int klee_interceptor_setup_parent(KleeInterceptor *interceptor, pid_t child_pid);

/* Fork a child process.  For seccomp_unotify, uses CLONE_FILES so the
 * parent can access the listener FD created by the child.  For ptrace,
 * uses regular fork(). */
pid_t klee_interceptor_fork(KleeInterceptor *interceptor);

#endif /* KLEE_INTERCEPT_H */
