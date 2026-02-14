/*
 * Klee - Userspace bwrap translation layer
 * FUSE /proc overlay
 */
#ifndef KLEE_FUSE_PROC_H
#define KLEE_FUSE_PROC_H

#include "process/process.h"

typedef struct klee_fuse_proc KleeFuseProc;

/* Initialize FUSE /proc overlay.
 * Returns the mount path for the FUSE filesystem, or NULL if FUSE unavailable.
 * The returned path can be used as the backing for guest /proc. */
KleeFuseProc *klee_fuse_proc_create(KleeProcessTable *pt, KleeSandbox *sb);

/* Destroy FUSE /proc overlay */
void klee_fuse_proc_destroy(KleeFuseProc *fp);

/* Get the FUSE mount path */
const char *klee_fuse_proc_get_path(const KleeFuseProc *fp);

/* Get the FUSE file descriptor for epoll integration */
int klee_fuse_proc_get_fd(const KleeFuseProc *fp);

/* Process pending FUSE events */
int klee_fuse_proc_process(KleeFuseProc *fp);

/* Create a tmpfs-based /proc snapshot with filtered PIDs.
 * Fallback for when FUSE is unavailable. Creates a tmpfs directory
 * for ls listing, plus mount table entries that bind virtual PID
 * directories to real /proc/<real_pid> and pass through non-PID entries.
 * Returns the tmpfs path, or NULL on failure. */
char *klee_proc_snapshot_create(KleePidMap *pid_map, KleeMountTable *mt);

/* Refresh a /proc snapshot (update PID entries after fork/exit).
 * Adds new virtual PID dirs and mount entries, removes stale ones. */
void klee_proc_snapshot_refresh(const char *snapshot_path,
                                 KleePidMap *pid_map, KleeMountTable *mt);

#endif /* KLEE_FUSE_PROC_H */
