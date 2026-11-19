/*
 * Klee - Userspace bwrap translation layer
 * Exec shim: start sandbox binaries under the sandbox's own ELF interpreter
 * without re-executing them through ld.so.
 */
#ifndef KLEE_EXEC_SHIM_H
#define KLEE_EXEC_SHIM_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* What klee needs to know about an ELF file's program interpreter. */
typedef struct {
    int elf_class;            /* ELFCLASS32 or ELFCLASS64 */
    char interp[PATH_MAX];    /* PT_INTERP string (NUL-terminated) */
    uint64_t interp_off;      /* file offset of the PT_INTERP string */
    uint64_t interp_size;     /* p_filesz of PT_INTERP, including the NUL */
} KleeElfInfo;

/* Read the PT_INTERP of the open regular ELF file (32- or 64-bit).
 * Returns 0 and fills info when the file is an ELF with a program
 * interpreter the kernel would accept, -1 otherwise. */
int klee_elf_read_interp(int fd, KleeElfInfo *info);

typedef struct klee_exec_shim KleeExecShim;

/* The per-klee-session shim, created on first use.  Never NULL unless out
 * of memory; when its directories could not be set up the prepare/alias
 * functions simply fail and callers fall back to executing ld.so. */
KleeExecShim *klee_exec_shim_get(void);

/* Stage a private copy of binary_host whose PT_INTERP names loader_host
 * (through a short symlink), and return in out_path a path to exec that is
 * called `name` so the kernel derives comm from it.  argv is left to the
 * caller: the kernel loads the right loader by itself.
 * Returns 0 on success, -1 when the shim cannot be used for this binary
 * (disabled, no usable directory, binary too large, PT_INTERP too short...). */
int klee_exec_shim_prepare(KleeExecShim *shim, int fd, const char *binary_host,
                           const KleeElfInfo *elf, const char *loader_host,
                           const char *name, char *out_path, size_t out_size);

/* Return in out_path a symlink called `name` that points at target_host, so
 * executing the target (ld.so, a script interpreter) directly still gives
 * the process the right comm.  Returns 0 on success, -1 otherwise. */
int klee_exec_shim_alias(KleeExecShim *shim, const char *target_host,
                         const char *name, char *out_path, size_t out_size);

/* Remove the session directories.  Safe to call without a shim. */
void klee_exec_shim_cleanup(void);

#endif /* KLEE_EXEC_SHIM_H */
