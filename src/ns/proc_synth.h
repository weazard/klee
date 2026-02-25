/*
 * Klee - Userspace bwrap translation layer
 * Synthetic /proc file generation for PID namespace simulation
 *
 * When klee intercepts opens on /proc/<pid>/stat or /proc/<pid>/status,
 * the kernel-generated content contains real (host) PIDs.  This module
 * reads the real file, rewrites PID fields to virtual namespace PIDs,
 * and writes the result to a temp file that the tracee opens instead.
 */
#ifndef KLEE_PROC_SYNTH_H
#define KLEE_PROC_SYNTH_H

#include "ns/pid_ns.h"
#include <linux/limits.h>

/*
 * Generate a synthetic /proc/<pid>/stat with virtual PIDs.
 * Reads /proc/<real_pid>/stat, rewrites PID fields using pid_map,
 * writes result to a temp file.
 * Returns 0 on success and fills out_path with the temp file path.
 */
int klee_proc_synth_stat(pid_t real_pid, const KleePidMap *pid_map,
                          char *out_path, size_t out_size);

/*
 * Generate a synthetic /proc/<pid>/status with virtual PIDs.
 * Same as above but for the status file.
 */
int klee_proc_synth_status(pid_t real_pid, const KleePidMap *pid_map,
                            char *out_path, size_t out_size);

/* Clean up all synthetic /proc temp files */
void klee_proc_synth_cleanup(void);

#endif /* KLEE_PROC_SYNTH_H */
