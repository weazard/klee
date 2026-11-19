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

/* Syscall ABI a stop was taken in.  A 64-bit klee traces 32-bit programs
 * too (the Steam client, 32-bit games): they use the i386 syscall table
 * and registers.  The backend maps their numbers onto the x86_64 ones the
 * dispatch table is keyed by and decodes arguments accordingly. */
typedef enum {
    KLEE_ABI_X86_64 = 0,
    KLEE_ABI_I386   = 1,
} KleeAbi;

typedef enum {
    KLEE_EVENT_SYSCALL_ENTER,
    KLEE_EVENT_SYSCALL_EXIT,
    KLEE_EVENT_FORK,
    KLEE_EVENT_EXEC,
    KLEE_EVENT_EXIT,
    KLEE_EVENT_SIGNAL,
    KLEE_EVENT_CLONE,
    KLEE_EVENT_STOP,
} KleeEventType;

typedef struct {
    KleeEventType type;
    pid_t pid;
    int syscall_nr;        /* x86_64 number (what handlers are keyed by), -1 if none */
    KleeAbi abi;
    int raw_nr;            /* number as the tracee issued it */
    unsigned abi_flags;    /* KLEE_SYS32_* for i386 syscalls */
    uint64_t args[6];
    long retval;
    bool emulated;        /* the supervisor completed the syscall */
    bool repeat_syscall;  /* continue a directory read after filtering its whole batch */
    bool unclassified_stop; /* older ptrace without GET_SYSCALL_INFO */
    int signal;
    uint64_t notif_id;     /* seccomp_unotify notification ID */
    pid_t new_child_pid;   /* for fork/clone events */
    pid_t former_tid;      /* for exec from a non-leader thread */
} KleeEvent;

typedef struct klee_interceptor KleeInterceptor;

struct klee_interceptor {
    InterceptBackend backend;

    /* Backend-specific data */
    union {
        struct {
            int notif_fd;
            int listener_fd;
        } seccomp;
        struct {
            unsigned long options;
            bool seccomp_filter;    /* true if SECCOMP_RET_TRACE filter active */
            int startup_fd[2];      /* seize gate and filter install status */
            bool no_syscall_info;
            bool batch_wait;
            struct klee_wait_status *wait_statuses;
            size_t wait_next;
            size_t wait_count;
            size_t wait_capacity;
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
 * For ptrace: waits for the supervisor to attach before installing the filter. */
int klee_interceptor_install_child(KleeInterceptor *interceptor);

/* Setup parent side after child is started.
 * For ptrace: attach and leave the child stopped after filter installation. */
int klee_interceptor_setup_parent(KleeInterceptor *interceptor, pid_t child_pid);

#endif /* KLEE_INTERCEPT_H */
