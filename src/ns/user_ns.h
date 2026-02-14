/*
 * Klee - Userspace bwrap translation layer
 * UID/GID simulation (fake_id0 port)
 */
#ifndef KLEE_USER_NS_H
#define KLEE_USER_NS_H

#include <sys/types.h>

typedef struct klee_id_state {
    uid_t ruid, euid, suid, fsuid;
    gid_t rgid, egid, sgid, fsgid;
} KleeIdState;

/* Create ID state with given initial uid/gid */
KleeIdState *klee_id_state_create(uid_t uid, gid_t gid);

/* Clone ID state (for fork) */
KleeIdState *klee_id_state_clone(const KleeIdState *src);

/* Destroy ID state */
void klee_id_state_destroy(KleeIdState *ids);

/* set*id handlers: update internal state, return 0 (success) or negative errno.
 * These are called from enter handlers and void the real syscall. */
int klee_user_ns_handle_setuid(KleeIdState *ids, uid_t uid);
int klee_user_ns_handle_setgid(KleeIdState *ids, gid_t gid);
int klee_user_ns_handle_setreuid(KleeIdState *ids, uid_t ruid, uid_t euid);
int klee_user_ns_handle_setregid(KleeIdState *ids, gid_t rgid, gid_t egid);
int klee_user_ns_handle_setresuid(KleeIdState *ids, uid_t ruid, uid_t euid, uid_t suid);
int klee_user_ns_handle_setresgid(KleeIdState *ids, gid_t rgid, gid_t egid, gid_t sgid);
int klee_user_ns_handle_setfsuid(KleeIdState *ids, uid_t fsuid);
int klee_user_ns_handle_setfsgid(KleeIdState *ids, gid_t fsgid);

#endif /* KLEE_USER_NS_H */
