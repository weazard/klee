/*
 * Klee - Userspace bwrap translation layer
 * Per-process FD-to-virtual-path tracking
 */
#ifndef KLEE_FD_TABLE_H
#define KLEE_FD_TABLE_H

#include <stdbool.h>
#include <linux/limits.h>

typedef struct klee_fd_entry {
    int fd;
    char virtual_path[PATH_MAX];
    bool cloexec;
    struct klee_fd_entry *next;  /* hash chain */
} KleeFdEntry;

#define KLEE_FD_TABLE_BUCKETS 64

typedef struct klee_fd_table {
    KleeFdEntry *buckets[KLEE_FD_TABLE_BUCKETS];
    int count;
    int refs;   /* threads created with CLONE_FILES share one table */
} KleeFdTable;

/* Create empty FD table (NULL if out of memory) */
KleeFdTable *klee_fd_table_create(void);

/* Drop a reference; the table is freed with the last one */
void klee_fd_table_destroy(KleeFdTable *ft);

/* Take another reference (CLONE_FILES) */
KleeFdTable *klee_fd_table_ref(KleeFdTable *ft);

/* Clone FD table (for fork); NULL if out of memory */
KleeFdTable *klee_fd_table_clone(const KleeFdTable *ft);

/* Add or update an FD entry */
int klee_fd_table_set(KleeFdTable *ft, int fd, const char *virtual_path,
                       bool cloexec);

/* Get virtual path for FD. Returns NULL if not tracked (or ft is NULL). */
const char *klee_fd_table_get(const KleeFdTable *ft, int fd);

/* Check if FD has cloexec (false if not tracked or ft is NULL) */
bool klee_fd_table_is_cloexec(const KleeFdTable *ft, int fd);

/* Set cloexec flag on FD (no-op if not tracked or ft is NULL) */
void klee_fd_table_set_cloexec(KleeFdTable *ft, int fd, bool cloexec);

/* Remove FD (on close) */
void klee_fd_table_remove(KleeFdTable *ft, int fd);

/* Handle dup: add new_fd with same path as old_fd */
int klee_fd_table_dup(KleeFdTable *ft, int old_fd, int new_fd, bool cloexec);

/* Handle execve: remove all cloexec FDs */
void klee_fd_table_exec(KleeFdTable *ft);

#endif /* KLEE_FD_TABLE_H */
