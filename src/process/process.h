/*
 * Klee - Userspace bwrap translation layer
 * Per-process state management
 */
#ifndef KLEE_PROCESS_H
#define KLEE_PROCESS_H

#include <sys/types.h>
#include <sys/user.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "util/arena.h"
#include "util/hash_table.h"
#include "fs/fd_table.h"
#include "intercept/intercept.h"

/* Forward declarations */
typedef struct klee_mount_table KleeMountTable;
typedef struct klee_pid_map KleePidMap;
typedef struct klee_id_state KleeIdState;
typedef struct klee_ipc_ns KleeIpcNs;
typedef struct klee_net_ns KleeNetNs;
typedef struct klee_fuse_proc KleeFuseProc;

typedef enum {
    PROC_STATE_NEW,
    PROC_STATE_RUNNING,
    PROC_STATE_SYSCALL_ENTER,
    PROC_STATE_SYSCALL_EXIT,
    PROC_STATE_STOPPED,
    PROC_STATE_EXITING,
    PROC_STATE_DEAD,
} ProcessState;

/* Register slots */
enum {
    REG_CURRENT  = 0,
    REG_ORIGINAL = 1,
    REG_MODIFIED = 2,
    REG_SLOTS    = 3,
};

typedef struct klee_sandbox {
    KleeMountTable *mount_table;
    KleePidMap *pid_map;
    KleeIdState *root_id_state;
    KleeIpcNs *ipc_ns;
    KleeNetNs *net_ns;
    KleeFuseProc *fuse_proc;
    char *proc_snapshot_path;   /* tmpfs /proc snapshot (fallback when no FUSE) */
    char *hostname;
    bool unshare_pid;
    bool unshare_user;
    bool unshare_ipc;
    bool unshare_uts;
    bool unshare_net;
    bool unshare_cgroup;
    bool zypak_detected;
    int ref_count;
} KleeSandbox;

/* What CLONE_FS shares between threads: the virtual working directory.
 * A chdir() by one thread must be seen by the others, as in the kernel. */
typedef struct klee_fs_state {
    char cwd[PATH_MAX];
    int refs;
} KleeFsState;

typedef struct klee_process {
    pid_t real_pid;
    pid_t virtual_pid;
    pid_t virtual_ppid;

    ProcessState state;
    struct user_regs_struct regs[REG_SLOTS];

    KleeFdTable *fd_table;      /* shared with CLONE_FILES siblings */
    KleeFsState *fs;            /* shared with CLONE_FS siblings */
    char *vcwd;                 /* == fs->cwd */
    char vexe[PATH_MAX];
    unsigned long pending_clone_flags; /* flags of the clone() in flight */

    KleeIdState *id_state;
    KleeSandbox *sandbox;

    KleeArena *event_arena;   /* reset per syscall event */
    KleeArena *life_arena;    /* lives for process lifetime */

    /* Process tree links */
    struct klee_process *parent;
    struct klee_process *first_child;
    struct klee_process *next_sibling;

    /* Hash table chaining */
    struct klee_process *hash_next;

    /* Current syscall info */
    int current_syscall;
    KleeAbi abi;                /* ABI of the syscall being handled */
    int raw_nr;                 /* number as the tracee issued it */
    unsigned sys32_flags;       /* KLEE_SYS32_* for an i386 syscall */
    int arg_shift;              /* ipc(2): canonical arg n is register n+1 */
    bool demux_mem;             /* socketcall(2): canonical args live in memory */
    bool demux_dirty;           /* a handler changed a demultiplexed arg */
    int demux_nargs;
    uint64_t demux_args[6];
    uint64_t demux_saved_ptr;   /* socketcall's original argument pointer */
    int deny_errno;             /* non-zero when syscall was denied on enter */
    bool seccomp_entered;       /* waiting for extra enter-stop after SECCOMP event */
    bool suppress_initial_stop; /* suppress first SIGSTOP after fork (ptrace artifact) */
    bool skip_uid_virt;         /* skip UID/GID virtualization for this process
                                 * (returns real uid from getuid/geteuid instead of
                                 * virtual — used for Chrome main process so D-Bus
                                 * AUTH EXTERNAL matches SO_PEERCRED) */
    uint64_t saved_args[6];
    char saved_path[PATH_MAX];      /* original guest path */
    char resolved_guest[PATH_MAX];  /* absolute guest path after resolution */
    char translated_path[PATH_MAX]; /* translated host path */
    bool path_modified;
    int path_arg_count;             /* number of path args rewritten via scratch */
    int path_arg_idx[3];            /* which arg indices were rewritten */
} KleeProcess;

/* Process table (hash table real_pid → KleeProcess) */
typedef struct klee_process_table {
    KleeHashTable *by_pid;
    size_t count;
} KleeProcessTable;

/* Create/destroy process table */
KleeProcessTable *klee_proctable_create(void);
void klee_proctable_destroy(KleeProcessTable *pt);

/* Create a new process entry */
KleeProcess *klee_process_create(KleeProcessTable *pt, pid_t real_pid,
                                  KleeSandbox *sandbox);

/* Look up process by real PID */
KleeProcess *klee_process_find(KleeProcessTable *pt, pid_t real_pid);

/* Remove and free process */
void klee_process_remove(KleeProcessTable *pt, pid_t real_pid);

/* Clone process state for fork/clone.  clone_flags decides what the new
 * task shares with its creator (CLONE_FILES, CLONE_FS) and what it gets
 * copies of.  Returns NULL when out of memory; then no child is created and
 * the parent and its FD table are left as they were.  A returned child
 * always has an FD table. */
KleeProcess *klee_process_fork(KleeProcessTable *pt, KleeProcess *parent,
                                pid_t child_real_pid,
                                unsigned long clone_flags);

/* unshare(2): give the process private copies of what the flags name */
void klee_process_unshare(KleeProcess *proc, unsigned long flags);

/* Handle exec: clear cloexec FDs, update vexe */
void klee_process_exec(KleeProcess *proc, const char *new_exe);

/* Create/destroy sandbox */
KleeSandbox *klee_sandbox_create(void);
void klee_sandbox_ref(KleeSandbox *sb);
void klee_sandbox_unref(KleeSandbox *sb);

#endif /* KLEE_PROCESS_H */
