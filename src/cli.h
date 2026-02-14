/*
 * Klee - Userspace bwrap translation layer
 * bwrap CLI argument parser
 */
#ifndef KLEE_CLI_H
#define KLEE_CLI_H

#include "config.h"

/* Parse bwrap-compatible command line arguments.
 * Returns 0 on success, negative errno on error.
 * argc/argv should NOT include the program name (argv[0]).
 */
int klee_cli_parse(KleeConfig *cfg, int argc, char **argv);

/* Print usage information */
void klee_cli_usage(const char *progname);

#endif /* KLEE_CLI_H */
