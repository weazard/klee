/*
 * Klee - Userspace bwrap translation layer
 * PID namespace simulation
 */
#ifndef KLEE_PID_NS_H
#define KLEE_PID_NS_H

#include <sys/types.h>
#include <stdbool.h>

/* Forward declaration */
typedef struct klee_hash_table KleeHashTable;

typedef struct klee_pid_map {
    KleeHashTable *real_to_virtual;  /* real_pid → virtual_pid */
    KleeHashTable *virtual_to_real;  /* virtual_pid → real_pid */
    pid_t next_vpid;                  /* next virtual PID to assign */
    pid_t init_real_pid;              /* real PID of virtual PID 1 */
} KleePidMap;

/* Create a new PID map */
KleePidMap *klee_pid_map_create(void);

/* Destroy PID map */
void klee_pid_map_destroy(KleePidMap *pm);

/* Register a new process. First process gets vpid 1.
 * Returns the assigned virtual PID. */
pid_t klee_pid_map_add(KleePidMap *pm, pid_t real_pid);

/* Register with a specific virtual PID */
int klee_pid_map_add_explicit(KleePidMap *pm, pid_t real_pid, pid_t virtual_pid);

/* Remove a process from the map */
void klee_pid_map_remove(KleePidMap *pm, pid_t real_pid);

/* Translate real PID to virtual PID. Returns 0 if not found. */
pid_t klee_pid_map_r2v(const KleePidMap *pm, pid_t real_pid);

/* Translate virtual PID to real PID. Returns 0 if not found. */
pid_t klee_pid_map_v2r(const KleePidMap *pm, pid_t virtual_pid);

/* Check if real PID is the init process (vpid 1) */
bool klee_pid_map_is_init(const KleePidMap *pm, pid_t real_pid);

/* Get the real PID of the init process */
pid_t klee_pid_map_get_init(const KleePidMap *pm);

/* Get count of processes in namespace */
size_t klee_pid_map_count(const KleePidMap *pm);

#endif /* KLEE_PID_NS_H */
