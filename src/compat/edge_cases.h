/*
 * Klee - Userspace bwrap translation layer
 * Edge case handling: openat2, name_to_handle_at, memfd, prctl
 */
#ifndef KLEE_EDGE_CASES_H
#define KLEE_EDGE_CASES_H

#include "process/process.h"
#include "intercept/intercept.h"

/* Handle openat2: read struct open_how from tracee for RESOLVE flags */
int klee_compat_handle_openat2(KleeProcess *proc, KleeInterceptor *ic,
                                KleeEvent *ev);

/* Handle name_to_handle_at: translate path, track handle */
int klee_compat_handle_name_to_handle(KleeProcess *proc, KleeInterceptor *ic,
                                       KleeEvent *ev);

/* Handle open_by_handle_at: look up tracked handle */
int klee_compat_handle_open_by_handle(KleeProcess *proc, KleeInterceptor *ic,
                                       KleeEvent *ev);

/* Handle memfd_create + execveat: track anonymous FDs */
int klee_compat_handle_memfd_create(KleeProcess *proc, KleeInterceptor *ic,
                                     KleeEvent *ev);

#endif /* KLEE_EDGE_CASES_H */
