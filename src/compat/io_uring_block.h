/*
 * Klee - Userspace bwrap translation layer
 * io_uring_setup() blocking
 */
#ifndef KLEE_IO_URING_BLOCK_H
#define KLEE_IO_URING_BLOCK_H

/* Block io_uring_setup - it bypasses seccomp and ptrace */
/* This is handled directly in the enter handler (returns -ENOSYS) */

#endif /* KLEE_IO_URING_BLOCK_H */
