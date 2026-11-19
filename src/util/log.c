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
#include <fcntl.h>

static KleeLogLevel current_level = LOG_WARN;

/* File logging state */
static FILE *log_file = NULL;
static KleeLogLevel file_level = LOG_WARN;
static size_t file_bytes;
static const size_t file_limit = 16 * 1024 * 1024;
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

static KleeLogLevel parse_file_log_level(const char *log_dir)
{
    const char *env = getenv("KLEE_FILE_LOG");
    if (!env)
        return log_dir && *log_dir ? LOG_WARN : (KleeLogLevel)-1;
    if (strcmp(env, "off") == 0)   return (KleeLogLevel)-1;
    if (strcmp(env, "error") == 0) return LOG_ERROR;
    if (strcmp(env, "warn") == 0)  return LOG_WARN;
    if (strcmp(env, "info") == 0)  return LOG_INFO;
    if (strcmp(env, "debug") == 0) return LOG_DEBUG;
    if (strcmp(env, "trace") == 0) return LOG_TRACE;
    return LOG_DEBUG;
}

static int mkdirp(const char *path)
{
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp))
        return -1;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0700) < 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    return mkdir(tmp, 0700) == 0 || errno == EEXIST ? 0 : -1;
}

void klee_log_open_file(const char *app_name, pid_t pid)
{
    const char *log_dir = getenv("KLEE_LOG_DIR");
    file_level = parse_file_log_level(log_dir);
    if ((int)file_level < 0)
        return;

    char default_dir[64];
    if (!log_dir || !log_dir[0]) {
        snprintf(default_dir, sizeof(default_dir), "/tmp/klee-logs-%u", (unsigned)geteuid());
        log_dir = default_dir;
    }

    const char *base = strrchr(app_name, '/');
    base = base ? base + 1 : app_name;
    if (!base[0] || strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
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

    if (mkdirp(log_dir) < 0)
        return;
    int base_fd = open(log_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (base_fd < 0)
        return;
    struct stat st;
    if (fstat(base_fd, &st) < 0 || st.st_uid != geteuid() || (st.st_mode & 0022))
        goto out_base;
    if (mkdirat(base_fd, safe_name, 0700) < 0 && errno != EEXIST)
        goto out_base;
    int app_fd = openat(base_fd, safe_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (app_fd < 0)
        goto out_base;
    if (fstat(app_fd, &st) < 0 || st.st_uid != geteuid() || (st.st_mode & 0022))
        goto out_app;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    char timestamp[64], name[128];
    if (strftime(timestamp, sizeof(timestamp), "%Y-%m-%d_%H-%M-%S", &tm) == 0)
        goto out_app;
    snprintf(name, sizeof(name), "%s_%d_%09ld.log", timestamp, (int)pid, ts.tv_nsec);
    int length = snprintf(log_path, sizeof(log_path), "%s/%s/%s", log_dir, safe_name, name);
    if (length < 0 || (size_t)length >= sizeof(log_path)) {
        log_path[0] = '\0';
        goto out_app;
    }
    int fd = openat(app_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) {
        log_path[0] = '\0';
        goto out_app;
    }
    log_file = fdopen(fd, "w");
    if (!log_file) {
        close(fd);
        unlinkat(app_fd, name, 0);
        log_path[0] = '\0';
        goto out_app;
    }

    file_bytes = 0;
    fprintf(log_file, "=== klee session PID=%d ===\n", (int)pid);
    fflush(log_file);

    /* Update the pointer atomically when it is absent or already a symlink. */
    int rc = fstatat(base_fd, "latest", &st, AT_SYMLINK_NOFOLLOW);
    if ((rc == 0 && S_ISLNK(st.st_mode)) || (rc < 0 && errno == ENOENT)) {
        char latest[160], target[sizeof(safe_name) + sizeof(name) + 1];
        snprintf(latest, sizeof(latest), ".latest-%s", name);
        snprintf(target, sizeof(target), "%s/%s", safe_name, name);
        if (symlinkat(target, base_fd, latest) == 0) {
            if (renameat(base_fd, latest, base_fd, "latest") < 0)
                unlinkat(base_fd, latest, 0);
        }
    }

out_app:
    close(app_fd);
out_base:
    close(base_fd);
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

    if (want_file) {
        flockfile(log_file);
        if (file_bytes < file_limit) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            struct tm tm;
            localtime_r(&ts.tv_sec, &tm);

            int prefix = fprintf(log_file,
                    "[%04d-%02d-%02d %02d:%02d:%02d.%03ld] [%s] %s:%d: ",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000,
                    level_names[level], basename, line);
            int body = vfprintf(log_file, fmt, ap);
            if (fmt[0] && fmt[strlen(fmt) - 1] != '\n') {
                fputc('\n', log_file);
                file_bytes++;
            }
            if (prefix < 0 || body < 0)
                file_bytes = file_limit;
            else {
                file_bytes += (size_t)prefix + (size_t)body;
                if (file_bytes >= file_limit)
                    fputs("Session log size limit reached.\n", log_file);
            }
            fflush(log_file);
        }
        funlockfile(log_file);
    }

    va_end(ap);
}
