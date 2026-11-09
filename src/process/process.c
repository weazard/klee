/*
 * Klee - Userspace bwrap translation layer
 * Per-process state management implementation
 */
#include "process/process.h"
#include "ns/ipc_ns.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <sched.h>

KleeProcessTable *klee_proctable_create(void)
{
    KleeProcessTable *pt = calloc(1, sizeof(KleeProcessTable));
    if (!pt)
        return NULL;

    pt->by_pid = klee_ht_create();
    if (!pt->by_pid) {
        free(pt);
        return NULL;
    }

    return pt;
}

static int free_process_iter(uint64_t key, void *value, void *ctx)
{
    (void)key;
    (void)ctx;
    KleeProcess *proc = value;
    if (proc->event_arena)
        klee_arena_destroy(proc->event_arena);
    if (proc->life_arena)
        klee_arena_destroy(proc->life_arena);
    if (proc->fd_table)
        klee_fd_table_destroy(proc->fd_table);
    free(proc);
    return 0;
}

void klee_proctable_destroy(KleeProcessTable *pt)
{
    if (!pt)
        return;
    klee_ht_foreach(pt->by_pid, free_process_iter, NULL);
    klee_ht_destroy(pt->by_pid);
    free(pt);
}

KleeProcess *klee_process_create(KleeProcessTable *pt, pid_t real_pid,
                                  KleeSandbox *sandbox)
{
    KleeProcess *proc = calloc(1, sizeof(KleeProcess));
    if (!proc)
        return NULL;

    proc->real_pid = real_pid;
    proc->virtual_pid = real_pid; /* default; PID NS will remap */
    proc->state = PROC_STATE_NEW;
    proc->sandbox = sandbox;

    proc->event_arena = klee_arena_create(4096);
    proc->life_arena = klee_arena_create(4096);
    proc->fd_table = klee_fd_table_create();
    proc->fs = calloc(1, sizeof(KleeFsState));

    if (!proc->event_arena || !proc->life_arena || !proc->fd_table || !proc->fs) {
        if (proc->event_arena) klee_arena_destroy(proc->event_arena);
        if (proc->life_arena) klee_arena_destroy(proc->life_arena);
        if (proc->fd_table) klee_fd_table_destroy(proc->fd_table);
        free(proc->fs);
        free(proc);
        return NULL;
    }

    proc->fs->refs = 1;
    proc->vcwd = proc->fs->cwd;
    strcpy(proc->vcwd, "/");

    /* klee_ht_put returns NULL both for a new key and when the table could
     * not grow, so look the entry up to know it went in. */
    klee_ht_put(pt->by_pid, (uint64_t)real_pid, proc);
    if (klee_ht_get(pt->by_pid, (uint64_t)real_pid) != proc) {
        klee_arena_destroy(proc->event_arena);
        klee_arena_destroy(proc->life_arena);
        klee_fd_table_destroy(proc->fd_table);
        free(proc->fs);
        free(proc);
        return NULL;
    }
    pt->count++;

    if (sandbox)
        klee_sandbox_ref(sandbox);

    KLEE_DEBUG("created process pid=%d", real_pid);
    return proc;
}

KleeProcess *klee_process_find(KleeProcessTable *pt, pid_t real_pid)
{
    return klee_ht_get(pt->by_pid, (uint64_t)real_pid);
}

void klee_process_remove(KleeProcessTable *pt, pid_t real_pid)
{
    KleeProcess *proc = klee_ht_remove(pt->by_pid, (uint64_t)real_pid);
    if (!proc)
        return;

    /* Unlink from parent's child list */
    if (proc->parent) {
        KleeProcess **pp = &proc->parent->first_child;
        while (*pp) {
            if (*pp == proc) {
                *pp = proc->next_sibling;
                break;
            }
            pp = &(*pp)->next_sibling;
        }
    }

    /* Reparent children to parent or orphan them */
    KleeProcess *child = proc->first_child;
    while (child) {
        KleeProcess *next = child->next_sibling;
        child->parent = proc->parent;
        if (proc->parent) {
            child->next_sibling = proc->parent->first_child;
            proc->parent->first_child = child;
        } else {
            child->next_sibling = NULL;
        }
        child = next;
    }

    if (proc->sandbox)
        klee_sandbox_unref(proc->sandbox);
    if (proc->event_arena)
        klee_arena_destroy(proc->event_arena);
    if (proc->life_arena)
        klee_arena_destroy(proc->life_arena);
    if (proc->fd_table)
        klee_fd_table_destroy(proc->fd_table);
    if (proc->fs && --proc->fs->refs <= 0)
        free(proc->fs);
    free(proc);

    pt->count--;
    KLEE_DEBUG("removed process pid=%d", real_pid);
}

KleeProcess *klee_process_fork(KleeProcessTable *pt, KleeProcess *parent,
                                pid_t child_real_pid,
                                unsigned long clone_flags)
{
    /* FD table: shared with CLONE_FILES (threads), else a copy.  Obtain it
     * before the child exists: if the copy runs out of memory the fork fails
     * and nothing has changed, instead of a child running with no FD table. */
    KleeFdTable *fd_table;
    if (clone_flags & CLONE_FILES) {
        fd_table = klee_fd_table_ref(parent->fd_table);
    } else {
        fd_table = klee_fd_table_clone(parent->fd_table);
        if (!fd_table)
            return NULL;
    }

    KleeProcess *child = klee_process_create(pt, child_real_pid, parent->sandbox);
    if (!child) {
        klee_fd_table_destroy(fd_table);   /* drops the reference or the copy */
        return NULL;
    }

    /* Copy state from parent */
    memcpy(child->vexe, parent->vexe, PATH_MAX);
    child->skip_uid_virt = parent->skip_uid_virt;

    /* Working directory: shared with CLONE_FS (threads), else a copy */
    if (clone_flags & CLONE_FS) {
        free(child->fs);
        child->fs = parent->fs;
        child->fs->refs++;
    } else {
        memcpy(child->fs->cwd, parent->fs->cwd, PATH_MAX);
    }
    child->vcwd = child->fs->cwd;

    /* Replace the empty FD table klee_process_create gave the child */
    klee_fd_table_destroy(child->fd_table);
    child->fd_table = fd_table;

    /* Link into process tree */
    child->parent = parent;
    child->virtual_ppid = parent->virtual_pid;
    child->next_sibling = parent->first_child;
    parent->first_child = child;

    KLEE_DEBUG("forked: parent=%d child=%d", parent->real_pid, child_real_pid);
    return child;
}

void klee_process_unshare(KleeProcess *proc, unsigned long flags)
{
    if ((flags & CLONE_FS) && proc->fs && proc->fs->refs > 1) {
        KleeFsState *own = calloc(1, sizeof(KleeFsState));
        if (own) {
            memcpy(own->cwd, proc->fs->cwd, PATH_MAX);
            own->refs = 1;
            proc->fs->refs--;
            proc->fs = own;
            proc->vcwd = own->cwd;
        }
    }
    if ((flags & CLONE_FILES) && proc->fd_table && proc->fd_table->refs > 1) {
        KleeFdTable *own = klee_fd_table_clone(proc->fd_table);
        if (own) {
            klee_fd_table_destroy(proc->fd_table);
            proc->fd_table = own;
        }
    }
}

void klee_process_exec(KleeProcess *proc, const char *new_exe)
{
    /* Avoid UB: caller often passes proc->vexe as new_exe (overlapping
     * src/dst in snprintf).  Only copy when it's a different buffer. */
    if (new_exe && new_exe != proc->vexe)
        snprintf(proc->vexe, PATH_MAX, "%s", new_exe);

    /* Remove cloexec FDs */
    klee_fd_table_exec(proc->fd_table);

    /* Reset event arena */
    klee_arena_reset(proc->event_arena);

    KLEE_DEBUG("exec: pid=%d exe=%s", proc->real_pid, proc->vexe);
}

KleeSandbox *klee_sandbox_create(void)
{
    KleeSandbox *sb = calloc(1, sizeof(KleeSandbox));
    if (!sb)
        return NULL;
    sb->ref_count = 1;
    return sb;
}

void klee_sandbox_ref(KleeSandbox *sb)
{
    if (sb)
        sb->ref_count++;
}

void klee_sandbox_unref(KleeSandbox *sb)
{
    if (!sb)
        return;
    if (--sb->ref_count <= 0) {
        free(sb->hostname);
        /* mount_table, pid_map, and ipc_ns freed separately */
        free(sb);
    }
}
