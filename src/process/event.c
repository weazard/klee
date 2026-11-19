/*
 * Klee - Userspace bwrap translation layer
 * Main event loop implementation
 */
#include "process/event.h"
#include "process/memory.h"
#include "process/regs.h"
#include "syscall/dispatch.h"
#include "syscall/sysnum.h"
#include "syscall/abi.h"
#include "ns/pid_ns.h"
#include "ns/user_ns.h"
#include "fuse/fuse_proc.h"
#include "util/log.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <linux/ptrace.h>
#include <sys/wait.h>

static volatile sig_atomic_t shutdown_signal;
static volatile sig_atomic_t watched_child;

static void request_shutdown(int sig)
{
    int saved_errno = errno;
    shutdown_signal = sig;
    /* Wake a blocking waitpid even if the signal arrived just before it. */
    if (watched_child > 0)
        kill(watched_child, SIGKILL);
    errno = saved_errno;
}

int klee_event_install_shutdown_handlers(void)
{
    struct sigaction sa = {.sa_handler = request_shutdown};
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, NULL) < 0 ||
        sigaction(SIGINT, &sa, NULL) < 0 ||
        sigaction(SIGHUP, &sa, NULL) < 0)
        return -errno;
    return 0;
}

void klee_event_watch_child(pid_t pid)
{
    watched_child = pid;
    if (pid > 0 && shutdown_signal)
        kill(pid, SIGKILL);
}

int klee_event_shutdown_status(void)
{
    return shutdown_signal ? 128 + shutdown_signal : 0;
}

KleeEventLoop *klee_event_loop_create(KleeInterceptor *ic,
                                        KleeProcessTable *pt,
                                        KleeSandbox *sb,
                                        const KleeConfig *cfg)
{
    KleeEventLoop *el = calloc(1, sizeof(KleeEventLoop));
    if (!el)
        return NULL;

    el->interceptor = ic;
    el->proctable = pt;
    el->sandbox = sb;
    el->config = cfg;
    el->running = true;
    el->exit_status = 0;
    el->epoll_fd = -1;
    el->signal_fd = -1;

    if (ic->backend == INTERCEPT_PTRACE)
        return el;

    /* Block SIGCHLD and create signalfd */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    el->signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (el->signal_fd < 0) {
        KLEE_WARN("signalfd failed: %s", strerror(errno));
    }

    /* Create epoll */
    el->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (el->epoll_fd < 0) {
        KLEE_WARN("epoll_create1 failed: %s", strerror(errno));
    }

    /* Add seccomp notif fd to epoll (if seccomp backend) */
    if (ic->backend == INTERCEPT_SECCOMP_UNOTIFY && ic->seccomp.notif_fd >= 0) {
        struct epoll_event ev = {
            .events = EPOLLIN,
            .data.fd = ic->seccomp.notif_fd,
        };
        epoll_ctl(el->epoll_fd, EPOLL_CTL_ADD, ic->seccomp.notif_fd, &ev);
    }

    /* Add signal fd to epoll */
    if (el->signal_fd >= 0) {
        struct epoll_event ev = {
            .events = EPOLLIN,
            .data.fd = el->signal_fd,
        };
        epoll_ctl(el->epoll_fd, EPOLL_CTL_ADD, el->signal_fd, &ev);
    }

    return el;
}

void klee_event_loop_destroy(KleeEventLoop *el)
{
    if (!el)
        return;
    if (el->epoll_fd >= 0)
        close(el->epoll_fd);
    if (el->signal_fd >= 0)
        close(el->signal_fd);
    klee_ht_destroy(el->early_child_stops);
    free(el);
}

static void handle_process_exit(KleeEventLoop *el, KleeProcess *proc,
                                 KleeEvent *event)
{
    pid_t real_pid = proc->real_pid;
    int exit_status = (int)event->retval;

    KLEE_DEBUG("process exit: pid=%d vpid=%d status=%d",
               real_pid, proc->virtual_pid, exit_status);

    /* A final wait status for the leader arrives after its thread group
     * has exited. An exec from another thread reuses the leader's PID. */
    if (real_pid == el->initial_child_pid) {
        klee_event_watch_child(0);
        el->exit_status = exit_status;
        el->running = false;
    }

    /* Remove from PID map */
    if (el->sandbox && el->sandbox->pid_map)
        klee_pid_map_remove(el->sandbox->pid_map, real_pid);

    /* Refresh /proc snapshot if using tmpfs fallback */
    if (el->sandbox && el->sandbox->proc_snapshot_path)
        klee_proc_snapshot_refresh(el->sandbox->proc_snapshot_path,
                                    el->sandbox->pid_map,
                                    el->sandbox->mount_table);

    /* Remove from process table */
    klee_process_remove(el->proctable, real_pid);
}

static int handle_fork(KleeEventLoop *el, KleeProcess *parent, pid_t child_pid)
{
    if (child_pid <= 0)
        return -EINVAL;

    KleeProcess *child = klee_process_fork(el->proctable, parent, child_pid,
                                           parent->pending_clone_flags);
    if (!child)
        return -ENOMEM;

    /* Assign virtual PID */
    if (el->sandbox && el->sandbox->pid_map) {
        child->virtual_pid = klee_pid_map_add(el->sandbox->pid_map, child_pid);
        child->virtual_ppid = parent->virtual_pid;
    }

    /* Refresh /proc snapshot if using tmpfs fallback */
    if (el->sandbox && el->sandbox->proc_snapshot_path)
        klee_proc_snapshot_refresh(el->sandbox->proc_snapshot_path,
                                    el->sandbox->pid_map,
                                    el->sandbox->mount_table);

    /* Clone ID state */
    if (parent->id_state) {
        child->id_state = klee_id_state_clone(parent->id_state);
        if (!child->id_state)
            return -ENOMEM;
    }

    KLEE_DEBUG("fork: parent=%d child=%d vpid=%d",
               parent->real_pid, child_pid, child->virtual_pid);
    return 0;
}

/* The kernel fills si_pid with the sender's host PID.  Present it the way
 * the namespace does: init is 1, a sender outside the sandbox is 0.  Every
 * other process keeps its host number, so this rarely has to write.
 * Only signals that carry a sender are touched: user-sent ones (si_code
 * <= 0) and SIGCHLD (CLD_*); for faults si_pid aliases si_addr. */
static void rewrite_siginfo_pid(KleeEventLoop *el, KleeProcess *proc, int sig)
{
    if (!el->sandbox || !el->sandbox->unshare_pid || !el->sandbox->pid_map)
        return;

    siginfo_t si;
    if (ptrace(PTRACE_GETSIGINFO, proc->real_pid, 0, &si) < 0)
        return;
    bool from_child = sig == SIGCHLD && si.si_code >= CLD_EXITED &&
                      si.si_code <= CLD_CONTINUED;
    if (!(si.si_code <= 0 || from_child) || si.si_pid <= 0)
        return;

    KleePidMap *pm = el->sandbox->pid_map;
    pid_t shown = klee_pid_map_r2v(pm, si.si_pid);
    if (shown <= 0) {
        if (from_child) {
            /* Only a child of a sandbox process raises SIGCHLD here; klee
             * may already have forgotten it (it exited).  Keep the id. */
            shown = si.si_pid;
        } else {
            /* A zombie klee forgot still belongs to the sandbox. */
            pid_t ppid = 0;
            if (klee_proc_status_ids(si.si_pid, NULL, &ppid) == 0 &&
                (klee_pid_map_r2v(pm, ppid) > 0 || ppid == getpid()))
                shown = si.si_pid;
            else
                shown = 0;   /* a sender outside the namespace */
        }
    }
    if (shown == si.si_pid)
        return;
    si.si_pid = shown;
    ptrace(PTRACE_SETSIGINFO, proc->real_pid, 0, &si);
}

static int resume_tracee(KleeEventLoop *el, KleeProcess *proc, int sig)
{
    KleeInterceptor *ic = el->interceptor;
    if (proc->state == PROC_STATE_SYSCALL_ENTER)
        return ic->continue_syscall(ic, proc->real_pid, sig);
    return ic->continue_running(ic, proc->real_pid, sig);
}

static bool needs_syscall_exit(const KleeProcess *proc, int nr)
{
    const KleeSyscallHandler *handler = klee_dispatch_get(nr);
    if (!handler || !handler->exit)
        return false;
    const KleeSandbox *sb = proc->sandbox;
    bool ids = sb && sb->unshare_user && proc->id_state;
    switch (nr) {
    case KLEE_SYS_stat: case KLEE_SYS_lstat: case KLEE_SYS_fstat:
    case KLEE_SYS_newfstatat: case KLEE_SYS_statx:
        return ids;
    case KLEE_SYS_getuid: case KLEE_SYS_geteuid: case KLEE_SYS_getgid:
    case KLEE_SYS_getegid: case KLEE_SYS_getresuid: case KLEE_SYS_getresgid:
    case KLEE_SYS_recvmsg: case KLEE_SYS_getsockopt:
        return ids && !proc->skip_uid_virt;
    case KLEE_SYS_getpid: case KLEE_SYS_getppid: case KLEE_SYS_gettid:
    case KLEE_SYS_getsid: case KLEE_SYS_setsid: case KLEE_SYS_getpgrp:
    case KLEE_SYS_getpgid: case KLEE_SYS_getdents: case KLEE_SYS_getdents64:
    case KLEE_SYS_ioctl:
        return sb && sb->unshare_pid;
    case KLEE_SYS_shmget: case KLEE_SYS_msgget: case KLEE_SYS_semget:
        return sb && sb->unshare_ipc;
    case KLEE_SYS_uname:
        return sb && sb->unshare_uts;
    default:
        return true;
    }
}

int klee_event_loop_handle(KleeEventLoop *el, KleeEvent *event)
{
    KleeInterceptor *ic = el->interceptor;
    KleeProcess *proc;
    if (event->type == KLEE_EVENT_EXEC && event->former_tid > 0 &&
        event->former_tid != event->pid) {
        proc = klee_process_exec_rekey(el->proctable, event->former_tid, event->pid);
        if (!proc)
            return -ECHILD;
        if (el->sandbox && el->sandbox->pid_map)
            klee_pid_map_remove(el->sandbox->pid_map, event->former_tid);
    } else {
        proc = klee_process_find(el->proctable, event->pid);
    }

    if (!proc) {
        if (event->type == KLEE_EVENT_EXIT) {
            klee_ht_remove(el->early_child_stops, (uint64_t)event->pid);
            return 0;
        }
        if (event->type != KLEE_EVENT_STOP) {
            if (ic->backend == INTERCEPT_PTRACE)
                return -ECHILD;
            proc = klee_process_create(el->proctable, event->pid, el->sandbox);
            if (!proc)
                return -ENOMEM;
        } else {
            /* An auto-attached child's initial stop can precede the fork
             * event. Its exact creator and sharing flags come from that
             * event, so keep the child stopped until we receive it. */
            if (!el->early_child_stops)
                el->early_child_stops = klee_ht_create();
            klee_ht_put(el->early_child_stops, (uint64_t)event->pid, el);
            return klee_ht_get(el->early_child_stops, (uint64_t)event->pid) ?
                   0 : -ENOMEM;
        }
    }

    if (event->type == KLEE_EVENT_SYSCALL_ENTER && event->unclassified_stop &&
        proc->state == PROC_STATE_SYSCALL_ENTER)
        event->type = KLEE_EVENT_SYSCALL_EXIT;

    switch (event->type) {
    case KLEE_EVENT_SYSCALL_ENTER:
        proc->state = PROC_STATE_SYSCALL_ENTER;
        proc->abi = event->abi;
        proc->raw_nr = event->raw_nr;
        proc->sys32_flags = event->abi_flags;
        proc->arg_shift = 0;
        proc->demux_mem = false;
        proc->demux_dirty = false;
        proc->changed_args = 0;
        proc->scratch_top = 0;
        proc->next_exe[0] = '\0';
        proc->next_skip_uid_virt = proc->skip_uid_virt;
        proc->pending_clone_flags = 0;
        /* A 32-bit socketcall/ipc becomes the real call it carries. */
        if (event->abi == KLEE_ABI_I386 && event->syscall_nr < 0)
            klee_abi_demux_enter(proc, el->interceptor, event);
        proc->current_syscall = event->syscall_nr;
        proc->emulated_syscall = false;
        event->emulated = false;
        proc->resolved_guest[0] = '\0';
        proc->saved_path[0] = '\0';
        klee_arena_reset(proc->event_arena);

        int rc = klee_dispatch_enter(proc, el->interceptor, event);
        if (rc == 0 && !event->emulated && ic->backend == INTERCEPT_PTRACE)
            rc = klee_abi_demux_commit(proc, ic);
        memcpy(proc->syscall_args, event->args, sizeof(proc->syscall_args));
        if (rc < 0 || event->emulated) {
            /* Skip the tracee syscall and deliver its result. */
            proc->emulated_result = rc < 0 ? rc : event->retval;
            proc->emulated_syscall = true;
            return ic->respond(ic, event, event->retval, rc < 0 ? -rc : 0);
        }
        if (ic->backend != INTERCEPT_PTRACE)
            return ic->respond(ic, event, 0, 0);

        if (ic->ptrace.seccomp_filter && !proc->changed_args &&
            !needs_syscall_exit(proc, event->syscall_nr))
            proc->state = PROC_STATE_RUNNING;
        return resume_tracee(el, proc, 0);

    case KLEE_EVENT_SYSCALL_EXIT: {
        /* A just-attached child or an exec can report an exit for a call
         * whose entry we did not handle. */
        if (proc->state != PROC_STATE_SYSCALL_ENTER)
            return resume_tracee(el, proc, 0);
        event->syscall_nr = proc->current_syscall;
        memcpy(event->args, proc->syscall_args, sizeof(event->args));
        if (proc->exec_previous_sandbox && event->retval < 0 &&
            (event->syscall_nr == KLEE_SYS_execve || event->syscall_nr == KLEE_SYS_execveat))
            klee_process_finish_mount_exec(proc, false);

        bool result_changed;
        if (proc->emulated_syscall) {
            event->retval = proc->emulated_result;
            result_changed = true;
        } else {
            result_changed = klee_dispatch_exit(proc, ic, event) > 0;
        }

        if (result_changed || proc->changed_args || event->repeat_syscall) {
            int rc = klee_regs_fetch(ic, proc);
            if (rc < 0)
                return rc;
            if (result_changed)
                klee_regs_set_result(proc, event->retval);
            klee_regs_restore_args(proc);
            if (event->repeat_syscall)
                klee_regs_repeat_syscall(proc);
            rc = klee_regs_push(ic, proc);
            if (rc < 0)
                return rc;
        }
        proc->state = PROC_STATE_RUNNING;
        return resume_tracee(el, proc, 0);
    }

    case KLEE_EVENT_FORK:
    case KLEE_EVENT_CLONE: {
        int rc = handle_fork(el, proc, event->new_child_pid);
        if (rc < 0)
            return rc;
        if (klee_ht_remove(el->early_child_stops, (uint64_t)event->new_child_pid)) {
            KleeProcess *child = klee_process_find(el->proctable, event->new_child_pid);
            child->state = PROC_STATE_RUNNING;
            rc = resume_tracee(el, child, 0);
            if (rc < 0 && rc != -ESRCH)
                return rc;
        }
        return resume_tracee(el, proc, 0);
    }

    case KLEE_EVENT_EXEC:
        klee_process_exec(proc, proc->next_exe);
        proc->state = PROC_STATE_RUNNING;
        proc->changed_args = 0;
        proc->stack_end = 0;
        return resume_tracee(el, proc, 0);

    case KLEE_EVENT_EXIT:
        handle_process_exit(el, proc, event);
        return 0;

    case KLEE_EVENT_STOP:
        if (proc->state == PROC_STATE_NEW) {
            proc->state = PROC_STATE_RUNNING;
            return resume_tracee(el, proc, 0);
        }
        if (event->signal == SIGTRAP)
            return resume_tracee(el, proc, 0);
        if (ptrace(PTRACE_LISTEN, event->pid, NULL, NULL) < 0)
            return -errno;
        return 0;

    case KLEE_EVENT_SIGNAL:
        if (ic->backend == INTERCEPT_PTRACE) {
            rewrite_siginfo_pid(el, proc, event->signal);
            return resume_tracee(el, proc, event->signal);
        }
        return 0;
    }

    return -EINVAL;
}

int klee_event_loop_run(KleeEventLoop *el)
{
    KLEE_INFO("entering event loop");

    if (el->interceptor->backend == INTERCEPT_PTRACE) {
        KleeInterceptor *ic = el->interceptor;
        int rc = ic->continue_running(ic, el->initial_child_pid, 0);
        if (rc < 0 && rc != -ESRCH)
            return 1;
        while (el->running && !shutdown_signal) {
            ic->ptrace.batch_wait = el->proctable->count > 1;
            KleeEvent event;
            rc = ic->wait_event(ic, &event);
            if (rc == -ESRCH || rc == -EINTR)
                continue;
            if (rc == 0) {
                rc = klee_event_loop_handle(el, &event);
                if (rc == -ESRCH)
                    continue;
            }
            if (rc < 0) {
                KLEE_ERROR("ptrace event loop failed: %s", strerror(-rc));
                el->exit_status = 1;
                break;
            }
        }
    } else {
        /* seccomp_unotify + epoll loop */
        struct epoll_event events[16];

        while (el->running) {
            int nfds = epoll_wait(el->epoll_fd, events, 16, 1000);
            if (nfds < 0) {
                if (errno == EINTR)
                    continue;
                KLEE_ERROR("epoll_wait failed: %s", strerror(errno));
                break;
            }

            for (int i = 0; i < nfds; i++) {
                if (events[i].data.fd == el->signal_fd) {
                    /* Handle SIGCHLD */
                    struct signalfd_siginfo si;
                    while (read(el->signal_fd, &si, sizeof(si)) > 0) {
                        /* Reap zombies */
                        int status;
                        pid_t pid;
                        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
                            KleeEvent event = {
                                .type = KLEE_EVENT_EXIT,
                                .pid = pid,
                                .retval = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status),
                            };
                            klee_event_loop_handle(el, &event);
                        }
                    }
                } else if (events[i].data.fd == el->interceptor->seccomp.notif_fd) {
                    /* Handle seccomp notification */
                    KleeEvent event;
                    int rc = el->interceptor->wait_event(el->interceptor, &event);
                    if (rc == 0)
                        klee_event_loop_handle(el, &event);
                }
            }

            /* Check if any children are still alive */
            if (el->proctable->count == 0) {
                KLEE_DEBUG("no more processes");
                break;
            }
        }
    }

    /* Tracees that outlived the sandbox's main process (daemons like
     * gpg-agent, orphans) are deliberately left attached: every tracee
     * inherits PTRACE_O_EXITKILL, so the kernel SIGKILLs all of them when
     * klee exits, the way a PID namespace dies with its init.
     *
     * They used to be PTRACE_DETACHed with SIGKILL as the restart signal,
     * but that signal is dropped at event-stops (seccomp, fork, exec) and
     * DETACH fails on running tracees.  The survivors lost EXITKILL, kept
     * klee's SECCOMP_RET_TRACE filter and got ENOSYS from every trapped
     * syscall (open, connect, wait4, ...) once klee was gone. */
    if (el->proctable->count > 0)
        KLEE_DEBUG("%zu traced processes remain; they die with klee",
                   el->proctable->count);
    klee_event_watch_child(0);
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;

    if (shutdown_signal)
        el->exit_status = klee_event_shutdown_status();
    KLEE_INFO("event loop exited with status %d", el->exit_status);
    return el->exit_status;
}
