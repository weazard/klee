/*
 * Klee - Userspace bwrap translation layer
 * Leveled logging
 */
#ifndef KLEE_LOG_H
#define KLEE_LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>

typedef enum {
    LOG_ERROR = 0,
    LOG_WARN  = 1,
    LOG_INFO  = 2,
    LOG_DEBUG = 3,
    LOG_TRACE = 4,
} KleeLogLevel;

void klee_log_init(KleeLogLevel level);
void klee_log_set_level(KleeLogLevel level);
KleeLogLevel klee_log_get_level(void);

/* File-based session logging */
void klee_log_open_file(const char *app_name, pid_t pid);
void klee_log_close_file(void);
const char *klee_log_get_path(void);

void klee_log(KleeLogLevel level, const char *file, int line,
              const char *fmt, ...) __attribute__((format(printf, 4, 5)));

#define KLEE_ERROR(...) \
    klee_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define KLEE_WARN(...)  \
    klee_log(LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define KLEE_INFO(...)  \
    klee_log(LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define KLEE_DEBUG(...) \
    klee_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define KLEE_TRACE(...) \
    klee_log(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)

#endif /* KLEE_LOG_H */
