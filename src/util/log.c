/*
 * Klee - Userspace bwrap translation layer
 * Leveled logging implementation with dual stderr + file output
 */
#include "util/log.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <errno.h>

static KleeLogLevel current_level = LOG_WARN;

/* File logging state */
static FILE *log_file = NULL;
static KleeLogLevel file_level = LOG_TRACE;
static char log_path[PATH_MAX];

static const char *level_names[] = {
    "ERROR", "WARN", "INFO", "DEBUG", "TRACE"
};

static const char *level_colors[] = {
    "\033[1;31m", /* ERROR: bold red */
    "\033[1;33m", /* WARN:  bold yellow */
    "\033[1;32m", /* INFO:  bold green */
    "\033[0;36m", /* DEBUG: cyan */
    "\033[0;90m", /* TRACE: gray */
};

static const char *color_reset = "\033[0m";

void klee_log_init(KleeLogLevel level)
{
    current_level = level;
}

void klee_log_set_level(KleeLogLevel level)
{
    current_level = level;
}

KleeLogLevel klee_log_get_level(void)
{
    return current_level;
}

static KleeLogLevel parse_file_log_level(void)
{
    const char *env = getenv("KLEE_FILE_LOG");
    if (!env)
        return LOG_TRACE;
    if (strcmp(env, "off") == 0)   return (KleeLogLevel)-1;
    if (strcmp(env, "error") == 0) return LOG_ERROR;
    if (strcmp(env, "warn") == 0)  return LOG_WARN;
    if (strcmp(env, "info") == 0)  return LOG_INFO;
    if (strcmp(env, "debug") == 0) return LOG_DEBUG;
    if (strcmp(env, "trace") == 0) return LOG_TRACE;
    return LOG_DEBUG;
}

/* Recursive mkdir -p with world-writable base (multi-user safe) */
static void mkdirp(const char *path)
{
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0777);
            *p = '/';
        }
    }
    mkdir(tmp, 0777);
}

void klee_log_open_file(const char *app_name, pid_t pid)
{
    file_level = parse_file_log_level();
    if ((int)file_level < 0)
        return;  /* KLEE_FILE_LOG=off */

    const char *log_dir = getenv("KLEE_LOG_DIR");
    if (!log_dir || !log_dir[0])
        log_dir = "/tmp/klee-logs";

    /* Sanitize app name — use only the basename, replace weird chars */
    const char *base = strrchr(app_name, '/');
    base = base ? base + 1 : app_name;
    if (!base[0])
        base = "unknown";

    char safe_name[256];
    size_t j = 0;
    for (size_t i = 0; base[i] && j < sizeof(safe_name) - 1; i++) {
        char c = base[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')
            safe_name[j++] = c;
        else
            safe_name[j++] = '_';
    }
    safe_name[j] = '\0';

    /* Create app directory — leave room for the filename suffix */
    char app_dir[PATH_MAX - 64];
    snprintf(app_dir, sizeof(app_dir), "%s/%s", log_dir, safe_name);
    mkdirp(app_dir);

    /* Generate timestamped filename */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);

    int year = tm.tm_year + 1900;
    if (year < 0) year = 0;
    if (year > 9999) year = 9999;
    snprintf(log_path, sizeof(log_path),
             "%s/%04d-%02d-%02d_%02d-%02d-%02d_%d.log",
             app_dir, year, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             (int)pid);

    /* Use "we" to set O_CLOEXEC so children don't inherit the fd */
    log_file = fopen(log_path, "we");
    if (!log_file) {
        log_path[0] = '\0';
        return;
    }

    /* Write session header */
    fprintf(log_file,
            "=== klee session PID=%d ===\n"
            "time: %04d-%02d-%02d %02d:%02d:%02d\n"
            "command: %s\n"
            "===\n\n",
            (int)pid,
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec,
            app_name);
    fflush(log_file);

    /* Update latest symlink */
    char latest[PATH_MAX];
    snprintf(latest, sizeof(latest), "%s/latest", log_dir);
    unlink(latest);
    if (symlink(log_path, latest) < 0)
        { /* best-effort, ignore */ }
}

void klee_log_close_file(void)
{
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

const char *klee_log_get_path(void)
{
    return log_path[0] ? log_path : NULL;
}

void klee_log(KleeLogLevel level, const char *file, int line,
              const char *fmt, ...)
{
    int want_stderr = (level <= current_level);
    int want_file = (log_file && level <= file_level);

    if (!want_stderr && !want_file)
        return;

    /* Strip path prefix for readability */
    const char *basename = strrchr(file, '/');
    basename = basename ? basename + 1 : file;

    va_list ap;
    va_start(ap, fmt);

    /* stderr output */
    if (want_stderr) {
        int use_color = isatty(STDERR_FILENO);

        if (use_color)
            fprintf(stderr, "%s[%s]%s %s:%d: ",
                    level_colors[level], level_names[level], color_reset,
                    basename, line);
        else
            fprintf(stderr, "[%s] %s:%d: ", level_names[level], basename, line);

        va_list ap2;
        va_copy(ap2, ap);
        vfprintf(stderr, fmt, ap2);
        va_end(ap2);

        if (fmt[0] && fmt[strlen(fmt) - 1] != '\n')
            fputc('\n', stderr);
    }

    /* File output */
    if (want_file) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        struct tm tm;
        localtime_r(&ts.tv_sec, &tm);

        fprintf(log_file,
                "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] [%s] %s:%d: ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec,
                ts.tv_nsec / 1000000,
                level_names[level], basename, line);

        va_list ap3;
        va_copy(ap3, ap);
        vfprintf(log_file, fmt, ap3);
        va_end(ap3);

        if (fmt[0] && fmt[strlen(fmt) - 1] != '\n')
            fputc('\n', log_file);
        fflush(log_file);
    }

    va_end(ap);
}
