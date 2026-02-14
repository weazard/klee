/*
 * klee syscall overhead benchmark
 *
 * Measures wallclock time for various workloads under native execution
 * vs ptrace-intercepted execution.  Compile with:
 *   cc -O2 -o syscall_overhead syscall_overhead.c -lm
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/*  Timing helpers                                                     */
/* ------------------------------------------------------------------ */

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

typedef struct {
    const char *name;
    const char *category;  /* "syscall" or "compute" */
    long        iters;
    double      ms;
    long        syscalls;  /* approximate syscalls per iteration */
} Result;

static Result results[32];
static int    nresults;

static void record(const char *name, const char *cat, long iters,
                    double ms, long sc_per_iter)
{
    Result *r = &results[nresults++];
    r->name     = name;
    r->category = cat;
    r->iters    = iters;
    r->ms       = ms;
    r->syscalls = sc_per_iter;
}

/* ------------------------------------------------------------------ */
/*  Syscall-heavy benchmarks (expect noticeable overhead)              */
/* ------------------------------------------------------------------ */

static void bench_getpid(void)
{
    enum { N = 500000 };
    double t0 = now_ms();
    for (int i = 0; i < N; i++)
        (void)getpid();
    record("getpid loop", "syscall", N, now_ms() - t0, 1);
}

static void bench_stat(void)
{
    enum { N = 200000 };
    struct stat st;
    double t0 = now_ms();
    for (int i = 0; i < N; i++)
        stat("/", &st);
    record("stat(\"/\")", "syscall", N, now_ms() - t0, 1);
}

static void bench_open_close(void)
{
    enum { N = 200000 };
    double t0 = now_ms();
    for (int i = 0; i < N; i++) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd >= 0)
            close(fd);
    }
    record("open+close /dev/null", "syscall", N, now_ms() - t0, 2);
}

static void bench_read_devzero(void)
{
    enum { N = 200000 };
    char buf[4096];
    int fd = open("/dev/zero", O_RDONLY);
    if (fd < 0) return;
    double t0 = now_ms();
    for (int i = 0; i < N; i++)
        (void)read(fd, buf, sizeof(buf));
    record("read 4K /dev/zero", "syscall", N, now_ms() - t0, 1);
    close(fd);
}

static void bench_pipe_roundtrip(void)
{
    enum { N = 100000 };
    int pfd[2];
    if (pipe(pfd) < 0) return;
    char byte = 'x';
    double t0 = now_ms();
    for (int i = 0; i < N; i++) {
        (void)write(pfd[1], &byte, 1);
        (void)read(pfd[0], &byte, 1);
    }
    record("pipe write+read 1B", "syscall", N, now_ms() - t0, 2);
    close(pfd[0]);
    close(pfd[1]);
}

static void bench_fork(void)
{
    enum { N = 2000 };
    double t0 = now_ms();
    for (int i = 0; i < N; i++) {
        pid_t p = fork();
        if (p == 0)
            _exit(0);
        if (p > 0)
            waitpid(p, NULL, 0);
    }
    record("fork+exit+wait", "syscall", N, now_ms() - t0, 3);
}

static void bench_getcwd(void)
{
    enum { N = 200000 };
    char buf[4096];
    double t0 = now_ms();
    for (int i = 0; i < N; i++)
        (void)getcwd(buf, sizeof(buf));
    record("getcwd", "syscall", N, now_ms() - t0, 1);
}

/* ------------------------------------------------------------------ */
/*  Compute-heavy benchmarks (expect low overhead)                     */
/* ------------------------------------------------------------------ */

static void bench_compute_fpu(void)
{
    enum { N = 5000000 };
    volatile double acc = 1.0;
    double t0 = now_ms();
    for (int i = 1; i <= N; i++)
        acc += sin((double)i) * cos((double)i);
    record("FPU sin*cos", "compute", N, now_ms() - t0, 0);
    (void)acc;
}

static void bench_compute_int(void)
{
    enum { N = 50000000 };
    volatile unsigned long h = 0x811c9dc5;
    double t0 = now_ms();
    for (unsigned long i = 0; i < (unsigned long)N; i++) {
        h ^= i;
        h *= 0x01000193;
    }
    record("integer hash (FNV-1a)", "compute", N, now_ms() - t0, 0);
    (void)h;
}

static void bench_memset_loop(void)
{
    enum { N = 20000 };
    size_t sz = 64 * 1024;
    void *buf = malloc(sz);
    if (!buf) return;
    double t0 = now_ms();
    for (int i = 0; i < N; i++)
        memset(buf, i & 0xff, sz);
    record("memset 64K", "compute", N, now_ms() - t0, 0);
    free(buf);
}

static void bench_matrix(void)
{
    enum { DIM = 256 };
    static double a[DIM][DIM], b[DIM][DIM], c[DIM][DIM];
    for (int i = 0; i < DIM; i++)
        for (int j = 0; j < DIM; j++) {
            a[i][j] = (double)(i + j);
            b[i][j] = (double)(i - j);
        }
    double t0 = now_ms();
    for (int i = 0; i < DIM; i++)
        for (int j = 0; j < DIM; j++) {
            double s = 0;
            for (int k = 0; k < DIM; k++)
                s += a[i][k] * b[k][j];
            c[i][j] = s;
        }
    record("256x256 matmul", "compute", (long)DIM * DIM * DIM, now_ms() - t0, 0);
    (void)c[0][0];
}

/* ------------------------------------------------------------------ */
/*  Mixed workload                                                     */
/* ------------------------------------------------------------------ */

static void bench_mixed_fileio(void)
{
    enum { N = 5000 };
    char path[] = "/tmp/klee-bench-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return;
    unlink(path);
    char buf[4096];
    memset(buf, 'A', sizeof(buf));
    double t0 = now_ms();
    for (int i = 0; i < N; i++) {
        lseek(fd, 0, SEEK_SET);
        (void)write(fd, buf, sizeof(buf));
        lseek(fd, 0, SEEK_SET);
        (void)read(fd, buf, sizeof(buf));
    }
    record("file write+read 4K", "mixed", N, now_ms() - t0, 4);
    close(fd);
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("klee syscall overhead benchmark\n");
    printf("pid=%d\n\n", getpid());

    bench_getpid();
    bench_stat();
    bench_open_close();
    bench_read_devzero();
    bench_pipe_roundtrip();
    bench_getcwd();
    bench_fork();
    bench_mixed_fileio();
    bench_compute_fpu();
    bench_compute_int();
    bench_memset_loop();
    bench_matrix();

    /* Print results */
    printf("%-24s %8s %10s %12s %10s\n",
           "benchmark", "category", "iters", "time (ms)", "us/iter");
    printf("%-24s %8s %10s %12s %10s\n",
           "------------------------", "--------", "----------",
           "------------", "----------");

    for (int i = 0; i < nresults; i++) {
        Result *r = &results[i];
        double us = (r->ms * 1000.0) / r->iters;
        printf("%-24s %8s %10ld %12.1f %10.3f\n",
               r->name, r->category, r->iters, r->ms, us);
    }

    /* Machine-readable line for the comparison script */
    printf("\n#DATA");
    for (int i = 0; i < nresults; i++)
        printf("|%s:%.4f", results[i].name, results[i].ms);
    printf("\n");

    return 0;
}
