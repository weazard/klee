/*
 * Klee - Userspace bwrap translation layer
 * Steam overlay IPC path auto-exposure
 */
#ifndef KLEE_STEAM_COMPAT_H
#define KLEE_STEAM_COMPAT_H

#include "config.h"
#include "fs/mount_table.h"

/* Detect Steam-related paths and auto-expose them in the mount table */
int klee_steam_auto_expose(KleeMountTable *mt);

/* Check if a path is a Steam IPC path that should be passed through */
int klee_steam_is_ipc_path(const char *path);

#endif /* KLEE_STEAM_COMPAT_H */
