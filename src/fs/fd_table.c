/*
 * Klee - Userspace bwrap translation layer
 * FD table implementation
 */
#include "fs/fd_table.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static inline int fd_hash(int fd)
{
    return ((unsigned int)fd) % KLEE_FD_TABLE_BUCKETS;
}

KleeFdTable *klee_fd_table_create(void)
{
    KleeFdTable *ft = calloc(1, sizeof(KleeFdTable));
    return ft;
}

void klee_fd_table_destroy(KleeFdTable *ft)
{
    if (!ft)
        return;

    for (int i = 0; i < KLEE_FD_TABLE_BUCKETS; i++) {
        KleeFdEntry *e = ft->buckets[i];
        while (e) {
            KleeFdEntry *next = e->next;
            free(e);
            e = next;
        }
    }
    free(ft);
}

KleeFdTable *klee_fd_table_clone(const KleeFdTable *ft)
{
    if (!ft)
        return klee_fd_table_create();

    KleeFdTable *clone = klee_fd_table_create();
    if (!clone)
        return NULL;

    for (int i = 0; i < KLEE_FD_TABLE_BUCKETS; i++) {
        KleeFdEntry *prev = NULL;
        for (const KleeFdEntry *e = ft->buckets[i]; e; e = e->next) {
            KleeFdEntry *ne = malloc(sizeof(KleeFdEntry));
            if (!ne) {
                klee_fd_table_destroy(clone);
                return NULL;
            }
            memcpy(ne, e, sizeof(KleeFdEntry));
            ne->next = NULL;

            if (prev)
                prev->next = ne;
            else
                clone->buckets[i] = ne;
            prev = ne;
        }
    }
    clone->count = ft->count;
    return clone;
}

static KleeFdEntry *find_entry(const KleeFdTable *ft, int fd)
{
    int bucket = fd_hash(fd);
    for (KleeFdEntry *e = ft->buckets[bucket]; e; e = e->next) {
        if (e->fd == fd)
            return e;
    }
    return NULL;
}

int klee_fd_table_set(KleeFdTable *ft, int fd, const char *virtual_path,
                       bool cloexec)
{
    if (!ft)
        return -1;

    KleeFdEntry *existing = find_entry(ft, fd);
    if (existing) {
        snprintf(existing->virtual_path, PATH_MAX, "%s", virtual_path);
        existing->cloexec = cloexec;
        return 0;
    }

    KleeFdEntry *e = malloc(sizeof(KleeFdEntry));
    if (!e)
        return -1;

    e->fd = fd;
    snprintf(e->virtual_path, PATH_MAX, "%s", virtual_path);
    e->cloexec = cloexec;

    int bucket = fd_hash(fd);
    e->next = ft->buckets[bucket];
    ft->buckets[bucket] = e;
    ft->count++;
    return 0;
}

const char *klee_fd_table_get(const KleeFdTable *ft, int fd)
{
    KleeFdEntry *e = find_entry(ft, fd);
    return e ? e->virtual_path : NULL;
}

bool klee_fd_table_is_cloexec(const KleeFdTable *ft, int fd)
{
    KleeFdEntry *e = find_entry(ft, fd);
    return e ? e->cloexec : false;
}

void klee_fd_table_set_cloexec(KleeFdTable *ft, int fd, bool cloexec)
{
    KleeFdEntry *e = find_entry(ft, fd);
    if (e)
        e->cloexec = cloexec;
}

void klee_fd_table_remove(KleeFdTable *ft, int fd)
{
    if (!ft)
        return;

    int bucket = fd_hash(fd);
    KleeFdEntry **pp = &ft->buckets[bucket];

    while (*pp) {
        if ((*pp)->fd == fd) {
            KleeFdEntry *e = *pp;
            *pp = e->next;
            free(e);
            ft->count--;
            return;
        }
        pp = &(*pp)->next;
    }
}

int klee_fd_table_dup(KleeFdTable *ft, int old_fd, int new_fd, bool cloexec)
{
    const char *path = klee_fd_table_get(ft, old_fd);
    if (!path)
        return 0; /* Not tracked, OK */

    /* Remove new_fd if it exists (dup2 semantics) */
    klee_fd_table_remove(ft, new_fd);
    return klee_fd_table_set(ft, new_fd, path, cloexec);
}

void klee_fd_table_exec(KleeFdTable *ft)
{
    if (!ft)
        return;

    for (int i = 0; i < KLEE_FD_TABLE_BUCKETS; i++) {
        KleeFdEntry **pp = &ft->buckets[i];
        while (*pp) {
            if ((*pp)->cloexec) {
                KleeFdEntry *e = *pp;
                *pp = e->next;
                free(e);
                ft->count--;
            } else {
                pp = &(*pp)->next;
            }
        }
    }
}
