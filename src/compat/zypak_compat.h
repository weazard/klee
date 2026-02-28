/*
 * Klee - Userspace bwrap translation layer
 * Zypak compatibility layer for Flatpak Chrome
 *
 * Zypak bridges Chrome's sandbox expectations with Flatpak's security
 * model.  When Zypak uses the "mimic" strategy, it delegates child
 * launches to flatpak-spawn, which spawns children via the Flatpak
 * portal — OUTSIDE KLEE's process supervision.  This module detects
 * Zypak, forces the mimic strategy, intercepts flatpak-spawn execve
 * calls, and runs the target command directly inside KLEE's tree.
 */
#ifndef KLEE_ZYPAK_COMPAT_H
#define KLEE_ZYPAK_COMPAT_H

#include "process/process.h"
#include "intercept/intercept.h"
#include "fs/mount_table.h"
#include <stdbool.h>

/* Detect Zypak in the current environment (ZYPAK_BIN, ZYPAK_LIB,
 * or LD_PRELOAD containing "libzypak"). */
bool klee_zypak_detect(void);

/* Detect Zypak by checking for zypak-helper in the mount table.
 * Fallback for when env vars aren't set yet at detection time. */
bool klee_zypak_detect_from_mounts(KleeMountTable *mt);

/* Bind-mount Zypak library and binary directories into the sandbox
 * so that LD_PRELOAD works inside the virtualized filesystem. */
int klee_zypak_auto_expose(KleeMountTable *mt);

/* Check if an execve target is flatpak-spawn (basename match). */
bool klee_zypak_is_flatpak_spawn(const char *exe_path);

/* Intercept a flatpak-spawn execve: parse its options, apply --env=
 * and --sandbox-expose-path-ro= to the sandbox, then rewrite the
 * execve to run the target command directly inside KLEE's tree. */
int klee_zypak_handle_flatpak_spawn(KleeProcess *proc, KleeInterceptor *ic,
                                     KleeEvent *ev);

/* Check if an execve target is chrome-sandbox (basename match). */
bool klee_zypak_is_chrome_sandbox(const char *exe_path);

/* Nullify the CHROME_DEVEL_SANDBOX value in the tracee's envp by
 * writing a NUL byte right after the '='.  This prevents child
 * processes from retrying the SUID sandbox. */
void klee_zypak_nullify_sandbox_env(KleeInterceptor *ic, pid_t pid,
                                     uint64_t envp_addr);

#endif /* KLEE_ZYPAK_COMPAT_H */
