/*
 * Klee - Userspace bwrap translation layer
 * Synthetic /proc file generation for PID namespace simulation
 *
 * Uses memfd_create() to serve rewritten /proc content entirely in memory —
 * no temp files, no disk I/O.  The tracee opens the memfd via
 * /proc/<klee_pid>/fd/<N>, which the kernel resolves to the anonymous file.
 * A small ring buffer keeps recently created memfds alive until the tracee
 * has had a chance to open them.
 */
#include "ns/proc_synth.h"
#include "util/log.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/* Ring buffer of memfds.  Each slot stays open until recycled, giving the
 * tracee time to open the /proc/<klee_pid>/fd/<N> path between the enter
 * and exit handlers.  64 slots is vastly more than needed (typically only
 * 1–2 are in flight at once). */
#define MEMFD_POOL_SIZE 64

static int memfd_pool[MEMFD_POOL_SIZE];
static int memfd_pool_next = 0;
static bool memfd_pool_inited = false;
static pid_t klee_self_pid = 0;

static void memfd_pool_init(void)
{
    for (int i = 0; i < MEMFD_POOL_SIZE; i++)
        memfd_pool[i] = -1;
    memfd_pool_inited = true;
    klee_self_pid = getpid();
}

/* Add a memfd to the pool, closing the oldest if the slot is occupied. */
static void memfd_pool_add(int fd)
{
    if (!memfd_pool_inited)
        memfd_pool_init();

    if (memfd_pool[memfd_pool_next] >= 0)
        close(memfd_pool[memfd_pool_next]);

    memfd_pool[memfd_pool_next] = fd;
    memfd_pool_next = (memfd_pool_next + 1) % MEMFD_POOL_SIZE;
}

/*
 * Create an anonymous in-memory file with the given content and return
 * a path the tracee can open.
 */
static int create_memfd(const char *content, size_t len,
                        char *out_path, size_t out_size)
{
    if (!memfd_pool_inited)
        memfd_pool_init();

    int fd = memfd_create("klee_proc", MFD_CLOEXEC);
    if (fd < 0)
        return -1;

    /* Write content in full */
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, content + written, len - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        written += (size_t)n;
    }

    /* Tracee will open this path — kernel resolves the symlink to our memfd.
     * The tracee's new fd gets its own file-position at offset 0. */
    snprintf(out_path, out_size, "/proc/%d/fd/%d", klee_self_pid, fd);
    memfd_pool_add(fd);
    return 0;
}

/* Translate a real PID through the map.  Returns 0 if not found. */
static pid_t xlat(const KleePidMap *pm, pid_t real_pid)
{
    if (real_pid <= 0)
        return real_pid;
    pid_t v = klee_pid_map_r2v(pm, real_pid);
    return v > 0 ? v : 0;
}

/*
 * Rewrite /proc/<pid>/stat content.
 *
 * Format: <pid> (<comm>) <state> <ppid> <pgrp> <session> <tty_nr> <tpgid> <rest...>
 *
 * Fields 1 (pid), 4 (ppid), 5 (pgrp), 6 (session), 8 (tpgid) are PIDs
 * that need translation.  The comm field (field 2) can contain spaces and
 * parentheses, so we find the last ')' to delimit it.
 */
int klee_proc_synth_stat(pid_t real_pid, const KleePidMap *pid_map,
                          char *out_path, size_t out_size)
{
    /* Read real stat file */
    char real_path[PATH_MAX];
    snprintf(real_path, sizeof(real_path), "/proc/%d/stat", real_pid);

    FILE *f = fopen(real_path, "r");
    if (!f)
        return -1;

    char buf[4096];
    size_t len = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (len == 0)
        return -1;
    buf[len] = '\0';

    /* Find comm boundaries: first '(' and last ')' */
    char *open_paren = strchr(buf, '(');
    char *close_paren = strrchr(buf, ')');
    if (!open_paren || !close_paren || close_paren <= open_paren)
        return -1;

    /* Parse original PID */
    pid_t orig_pid;
    if (sscanf(buf, "%d ", &orig_pid) != 1)
        return -1;

    /* Extract comm (including parens) */
    size_t comm_len = (size_t)(close_paren - open_paren + 1);
    char comm[256];
    if (comm_len >= sizeof(comm))
        return -1;
    memcpy(comm, open_paren, comm_len);
    comm[comm_len] = '\0';

    /* Parse fields after ") " */
    char *after = close_paren + 2;
    char state;
    pid_t ppid, pgrp, session;
    int tty_nr;
    pid_t tpgid;
    int n = 0;

    if (sscanf(after, "%c %d %d %d %d %d%n",
               &state, &ppid, &pgrp, &session, &tty_nr, &tpgid, &n) < 6)
        return -1;

    /* Translate PIDs */
    pid_t vpid = xlat(pid_map, orig_pid);
    if (vpid <= 0)
        vpid = orig_pid;

    pid_t vppid = xlat(pid_map, ppid);

    pid_t vpgrp = xlat(pid_map, pgrp);
    if (vpgrp <= 0)
        vpgrp = vpid;

    pid_t vsession = xlat(pid_map, session);
    if (vsession <= 0)
        vsession = vpid;

    pid_t vtpgid = tpgid;
    if (tpgid > 0) {
        pid_t v = xlat(pid_map, tpgid);
        if (v > 0)
            vtpgid = v;
    }

    /* Rest of the line after tpgid (includes trailing fields and newline) */
    char *rest = after + n;

    /* Build synthetic stat line */
    char new_buf[4096];
    int new_len = snprintf(new_buf, sizeof(new_buf), "%d %s %c %d %d %d %d %d%s",
                           vpid, comm, state, vppid, vpgrp, vsession,
                           tty_nr, vtpgid, rest);
    if (new_len < 0)
        return -1;

    int rc = create_memfd(new_buf, (size_t)new_len, out_path, out_size);
    if (rc < 0)
        return -1;

    KLEE_TRACE("proc_synth: stat rpid=%d vpid=%d", real_pid, vpid);
    return 0;
}

/*
 * Rewrite /proc/<pid>/status content.
 *
 * Line-oriented format.  Fields that contain PIDs:
 *   Pid:        <pid>
 *   PPid:       <ppid>
 *   Tgid:       <tgid>
 *   TracerPid:  <tracer>   (set to 0 — klee hides its own tracing)
 *   NSpid:      <pid> [...]
 *   NStgid:     <tgid> [...]
 *   NSsid:      <sid> [...]
 *   NSpgid:     <pgid> [...]
 */
int klee_proc_synth_status(pid_t real_pid, const KleePidMap *pid_map,
                            char *out_path, size_t out_size)
{
    char real_path[PATH_MAX];
    snprintf(real_path, sizeof(real_path), "/proc/%d/status", real_pid);

    FILE *f = fopen(real_path, "r");
    if (!f)
        return -1;

    /* Build rewritten content in memory */
    char out_buf[8192];
    size_t out_pos = 0;
    size_t out_cap = sizeof(out_buf);

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        pid_t val;
        char rewritten[256];
        const char *to_write = line;

        if (sscanf(line, "TracerPid:\t%d", &val) == 1) {
            snprintf(rewritten, sizeof(rewritten), "TracerPid:\t0\n");
            to_write = rewritten;
        } else if (sscanf(line, "Pid:\t%d", &val) == 1 && val > 0) {
            pid_t v = xlat(pid_map, val);
            if (v > 0) {
                snprintf(rewritten, sizeof(rewritten), "Pid:\t%d\n", v);
                to_write = rewritten;
            }
        } else if (sscanf(line, "PPid:\t%d", &val) == 1 && val > 0) {
            pid_t v = xlat(pid_map, val);
            if (v > 0) {
                snprintf(rewritten, sizeof(rewritten), "PPid:\t%d\n", v);
                to_write = rewritten;
            }
        } else if (sscanf(line, "Tgid:\t%d", &val) == 1 && val > 0) {
            pid_t v = xlat(pid_map, val);
            if (v > 0) {
                snprintf(rewritten, sizeof(rewritten), "Tgid:\t%d\n", v);
                to_write = rewritten;
            }
        } else if (sscanf(line, "NSpid:\t%d", &val) == 1 && val > 0) {
            pid_t v = xlat(pid_map, val);
            if (v > 0) {
                snprintf(rewritten, sizeof(rewritten), "NSpid:\t%d\n", v);
                to_write = rewritten;
            }
        } else if (sscanf(line, "NStgid:\t%d", &val) == 1 && val > 0) {
            pid_t v = xlat(pid_map, val);
            if (v > 0) {
                snprintf(rewritten, sizeof(rewritten), "NStgid:\t%d\n", v);
                to_write = rewritten;
            }
        } else if (sscanf(line, "NSsid:\t%d", &val) == 1 && val > 0) {
            pid_t v = xlat(pid_map, val);
            if (v > 0) {
                snprintf(rewritten, sizeof(rewritten), "NSsid:\t%d\n", v);
                to_write = rewritten;
            }
        } else if (sscanf(line, "NSpgid:\t%d", &val) == 1 && val > 0) {
            pid_t v = xlat(pid_map, val);
            if (v > 0) {
                snprintf(rewritten, sizeof(rewritten), "NSpgid:\t%d\n", v);
                to_write = rewritten;
            }
        }

        size_t n = strlen(to_write);
        if (out_pos + n < out_cap) {
            memcpy(out_buf + out_pos, to_write, n);
            out_pos += n;
        }
    }

    fclose(f);

    int rc = create_memfd(out_buf, out_pos, out_path, out_size);
    if (rc < 0)
        return -1;

    KLEE_TRACE("proc_synth: status rpid=%d", real_pid);
    return 0;
}

void klee_proc_synth_cleanup(void)
{
    if (!memfd_pool_inited)
        return;

    /* Only clean up from the process that created the pool */
    if (klee_self_pid != 0 && klee_self_pid != getpid())
        return;

    for (int i = 0; i < MEMFD_POOL_SIZE; i++) {
        if (memfd_pool[i] >= 0) {
            close(memfd_pool[i]);
            memfd_pool[i] = -1;
        }
    }
}
