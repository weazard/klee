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
} KleeFdTable;

/* Create empty FD table */
KleeFdTable *klee_fd_table_create(void);

/* Destroy FD table */
void klee_fd_table_destroy(KleeFdTable *ft);

/* Clone FD table (for fork) */
KleeFdTable *klee_fd_table_clone(const KleeFdTable *ft);

/* Add or update an FD entry */
int klee_fd_table_set(KleeFdTable *ft, int fd, const char *virtual_path,
                       bool cloexec);

/* Get virtual path for FD. Returns NULL if not tracked. */
const char *klee_fd_table_get(const KleeFdTable *ft, int fd);

/* Check if FD has cloexec */
bool klee_fd_table_is_cloexec(const KleeFdTable *ft, int fd);

/* Set cloexec flag on FD */
void klee_fd_table_set_cloexec(KleeFdTable *ft, int fd, bool cloexec);

/* Remove FD (on close) */
void klee_fd_table_remove(KleeFdTable *ft, int fd);

/* Handle dup: add new_fd with same path as old_fd */
int klee_fd_table_dup(KleeFdTable *ft, int old_fd, int new_fd, bool cloexec);

/* Handle execve: remove all cloexec FDs */
void klee_fd_table_exec(KleeFdTable *ft);

#endif /* KLEE_FD_TABLE_H */
