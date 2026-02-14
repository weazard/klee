/*
 * Klee - Userspace bwrap translation layer
 * tmpfs backing directory management
 */
#ifndef KLEE_TMPFS_H
#define KLEE_TMPFS_H

/* Create a tmpfs backing directory for the given guest dest path.
 * Returns newly allocated host path, or NULL on failure.
 * Caller must free() the returned string. */
char *klee_tmpfs_create(const char *guest_dest);

/* Create a tmpfs backing file from an FD.
 * Reads data from fd and writes to a temporary file.
 * Returns newly allocated host path. */
char *klee_tmpfs_create_file(const char *guest_dest, int fd);

/* Clean up all tmpfs backing directories created by this process */
void klee_tmpfs_cleanup(void);

#endif /* KLEE_TMPFS_H */
