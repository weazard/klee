/*
 * Klee - Userspace bwrap translation layer
 * io_uring_setup() blocking - handled in enter handler
 */
#include "compat/io_uring_block.h"
/* Implementation is in syscall/enter.c: klee_enter_io_uring_setup */
typedef int klee_io_uring_block_dummy_;
