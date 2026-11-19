/*
 * Klee - Userspace bwrap translation layer
 * Tracee ABI helpers: 32-bit (i386) tracees under a 64-bit klee
 *
 * A 32-bit process in the sandbox issues i386 syscalls: other numbers,
 * arguments in ebx/ecx/edx/esi/edi/ebp, 4-byte pointers, and struct
 * layouts of its own (stat64, msghdr, cmsghdr, sock_fprog).  The backend
 * tags every stop with the ABI it saw and maps the number onto the x86_64
 * one the dispatch table is keyed by; everything here is what handlers
 * need to read and write tracee memory in the right layout, plus the
 * splitting of socketcall(2) and ipc(2) into the real calls.
 */
#ifndef KLEE_ABI_H
#define KLEE_ABI_H

#include "intercept/intercept.h"
#include "process/process.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

static inline size_t klee_abi_ptr_size(KleeAbi abi)
{
    return abi == KLEE_ABI_I386 ? 4 : 8;
}

/* Pointer-sized loads and stores in the tracee's ABI. */
int klee_abi_read_ptr(KleeInterceptor *ic, pid_t pid, KleeAbi abi,
                      uint64_t addr, uint64_t *out);
int klee_abi_read_strv(KleeProcess *proc, KleeInterceptor *ic, uint64_t base,
                        char ***out, int *count);
int klee_abi_stage_strv(KleeProcess *proc, KleeInterceptor *ic, char *const *strs,
                         int count, uint64_t *addr);
void klee_abi_free_strv(char **strs, int count);

uint32_t klee_abi_id_result(const KleeProcess *proc, uint32_t id);
int klee_abi_write_ids(KleeProcess *proc, KleeInterceptor *ic, uint64_t addr,
                       const uint32_t *ids, size_t count);

/* socketcall(2) / ipc(2): rewrite ev so it describes the real call and
 * remember how to get at its arguments.  Returns true if it did. */
bool klee_abi_demux_enter(KleeProcess *proc, KleeInterceptor *ic,
                          KleeEvent *ev);
/* After the enter handlers: if they changed arguments that live in the
 * socketcall argument array, stage a new array below the stack and point
 * the real syscall at it. */
int klee_abi_demux_commit(KleeProcess *proc, KleeInterceptor *ic);

/* Stage a pointer array using the tracee's pointer size. Count includes NUL. */
int klee_abi_stage_ptrs(KleeProcess *proc, KleeInterceptor *ic,
                         const uint64_t *ptrs, size_t count, uint64_t *addr);

/* Field offsets of the stat buffer a stat/fstat/lstat/newfstatat call
 * fills in the tracee's ABI (struct stat64 for i386). */
void klee_abi_stat_layout(KleeAbi abi, size_t *mode_off, size_t *uid_off,
                          size_t *gid_off);

/* Where a msghdr's control buffer is. */
typedef union {
    struct msghdr native;
    struct {
        uint32_t name, namelen, iov, iovlen, control, controllen, flags;
    } compat;
} KleeAbiMsg;

size_t klee_abi_msg_size(KleeAbi abi);
int klee_abi_read_msg_control(KleeInterceptor *ic, pid_t pid, KleeAbi abi,
                              uint64_t msg_addr, uint64_t *ctrl_addr,
                              size_t *ctrl_len);
/* Walk the cmsgs of a control buffer copied into buf.  *off starts at 0.
 * Returns false when there are no more; data_off/data_len locate the
 * payload inside buf. */
bool klee_abi_cmsg_next(KleeAbi abi, const uint8_t *buf, size_t len,
                        size_t *off, int *level, int *type,
                        size_t *data_off, size_t *data_len);

#endif /* KLEE_ABI_H */
