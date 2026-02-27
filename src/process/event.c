/*
 * Klee - Userspace bwrap translation layer
 * Main event loop implementation
 */
#include "process/event.h"
#include "process/memory.h"
#include "process/regs.h"
#include "syscall/dispatch.h"
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
#include <sys/signalfd.h>
#include <sys/wait.h>

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
    free(el);
}

static void handle_process_exit(KleeEventLoop *el, KleeProcess *proc,
                                 KleeEvent *event)
{
    pid_t real_pid = proc->real_pid;
    int exit_status = (int)event->retval;

    KLEE_DEBUG("process exit: pid=%d vpid=%d status=%d",
               real_pid, proc->virtual_pid, exit_status);

    /* If this is vpid 1 (init), kill all namespace processes */
    if (el->sandbox && el->sandbox->unshare_pid &&
        el->sandbox->pid_map &&
        klee_pid_map_is_init(el->sandbox->pid_map, real_pid)) {
        KLEE_INFO("PID 1 exited, terminating namespace");
        el->exit_status = exit_status;
        el->running = false;
    }

    /* If this is the only/last process, stop */
    if (el->proctable->count <= 1) {
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

static void handle_fork(KleeEventLoop *el, KleeProcess *parent,
                         KleeEvent *event)
{
    pid_t child_pid = event->new_child_pid;
    if (child_pid <= 0) {
        KLEE_WARN("fork event with invalid child pid");
        return;
    }

    KleeProcess *child = klee_process_fork(el->proctable, parent, child_pid);
    if (!child) {
        KLEE_ERROR("failed to create child process %d", child_pid);
        return;
    }

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
    if (parent->id_state)
        child->id_state = klee_id_state_clone(parent->id_state);

    child->state = PROC_STATE_RUNNING;
    child->suppress_initial_stop = true;

    KLEE_DEBUG("fork: parent=%d child=%d vpid=%d",
               parent->real_pid, child_pid, child->virtual_pid);
}

int klee_event_loop_handle(KleeEventLoop *el, KleeEvent *event)
{
    KleeProcess *proc = klee_process_find(el->proctable, event->pid);

    /* New process we haven't seen yet */
    if (!proc && event->type != KLEE_EVENT_EXIT) {
        proc = klee_process_create(el->proctable, event->pid, el->sandbox);
        if (!proc) {
            KLEE_ERROR("failed to create process for pid %d", event->pid);
            return -ENOMEM;
        }
        if (el->sandbox && el->sandbox->pid_map)
            proc->virtual_pid = klee_pid_map_add(el->sandbox->pid_map, event->pid);
        proc->state = PROC_STATE_RUNNING;
        /* New process from PTRACE_O_TRACEFORK — its initial SIGSTOP
         * must be suppressed to avoid a spurious group-stop that
         * makes the parent's waitpid report it as "Stopped". */
        proc->suppress_initial_stop = true;
    }

    if (!proc)
        return 0;

    switch (event->type) {
    case KLEE_EVENT_SYSCALL_ENTER:
        /* The ptrace backend uses an rax == -ENOSYS heuristic to tell
         * syscall-enter from syscall-exit stops.  When we deny a syscall
         * (orig_rax = -1), the kernel returns -ENOSYS, so the subsequent
         * exit stop is misclassified as another enter.  Detect this using
         * the per-process state: if we already processed an enter, the
         * next syscall stop MUST be the corresponding exit.
         *
         * With the seccomp pre-filter, PTRACE_EVENT_SECCOMP is the real
         * enter, and PTRACE_SYSCALL generates an extra SIGTRAP|0x80
         * enter-stop before the exit-stop.  Skip that extra stop. */
        if (proc->state == PROC_STATE_SYSCALL_ENTER &&
            el->interceptor->backend == INTERCEPT_PTRACE) {
            if (proc->seccomp_entered) {
                /* Extra enter-stop after PTRACE_EVENT_SECCOMP — skip it */
                proc->seccomp_entered = false;
                el->interceptor->continue_syscall(el->interceptor, event->pid, 0);
                break;
            }
            /* Denied-exit misdetection (rax == -ENOSYS looks like enter) */
            event->type = KLEE_EVENT_SYSCALL_EXIT;
            event->syscall_nr = proc->current_syscall;
            goto handle_syscall_exit;
        }
        proc->state = PROC_STATE_SYSCALL_ENTER;
        proc->current_syscall = event->syscall_nr;
        proc->seccomp_entered = el->interceptor->backend == INTERCEPT_PTRACE &&
                                 el->interceptor->ptrace.seccomp_filter;
        proc->path_arg_count = 0;
        proc->deny_errno = 0;
        proc->resolved_guest[0] = '\0';
        klee_arena_reset(proc->event_arena);

        int rc = klee_dispatch_enter(proc, el->interceptor, event);
        if (rc < 0) {
            /* Deny the syscall: for ptrace, replace with invalid syscall
             * (-1 → kernel returns ENOSYS) and store the real errno to
             * override at the exit stop. */
            proc->deny_errno = -rc;
            el->interceptor->respond(el->interceptor, event, -1, -rc);
            return 0;
        }
        /* Continue the syscall */
        if (el->interceptor->backend == INTERCEPT_SECCOMP_UNOTIFY) {
            el->interceptor->respond(el->interceptor, event, 0, 0);
        } else {
            el->interceptor->continue_syscall(el->interceptor, event->pid, 0);
        }
        break;

    handle_syscall_exit:
    case KLEE_EVENT_SYSCALL_EXIT: {
        proc->state = PROC_STATE_SYSCALL_EXIT;
        event->syscall_nr = proc->current_syscall;

        /* Consolidate all register modifications into a single push */
        bool need_reg_push = false;

        /* If the syscall was denied on enter, override the return value
         * (kernel returned ENOSYS for the invalid -1 syscall) with the
         * actual errno we want the tracee to see. */
        if (proc->deny_errno && el->interceptor->backend == INTERCEPT_PTRACE) {
            klee_regs_fetch(el->interceptor, proc);
            klee_regs_set_result(proc, (long)-proc->deny_errno);
            need_reg_push = true;
            proc->deny_errno = 0;
            /* Skip normal exit dispatch — syscall was denied */
            if (need_reg_push)
                klee_regs_push(el->interceptor, proc);
            proc->state = PROC_STATE_RUNNING;
            el->interceptor->continue_running(el->interceptor, event->pid, 0);
            break;
        }

        int exit_rc = klee_dispatch_exit(proc, el->interceptor, event);

        if (exit_rc > 0 && el->interceptor->backend == INTERCEPT_PTRACE) {
            klee_regs_fetch(el->interceptor, proc);
            klee_regs_set_result(proc, event->retval);
            need_reg_push = true;
        }

        /* Restore original syscall arg registers if path was rewritten.
         * On enter, we pointed the arg at a scratch area below the stack;
         * now restore the original pointer so the tracee's view is unchanged. */
        if (proc->path_modified && el->interceptor->backend == INTERCEPT_PTRACE) {
            if (!need_reg_push)
                klee_regs_fetch(el->interceptor, proc);
            for (int i = 0; i < proc->path_arg_count; i++) {
                int idx = proc->path_arg_idx[i];
                klee_regs_set_arg(proc, idx, proc->saved_args[idx]);
            }
            proc->path_arg_count = 0;
            proc->path_modified = false;
            need_reg_push = true;
        }

        if (need_reg_push)
            klee_regs_push(el->interceptor, proc);

        proc->state = PROC_STATE_RUNNING;
        if (el->interceptor->backend == INTERCEPT_PTRACE)
            el->interceptor->continue_running(el->interceptor, event->pid, 0);
        break;
    }

    case KLEE_EVENT_FORK:
    case KLEE_EVENT_CLONE:
        handle_fork(el, proc, event);
        if (el->interceptor->backend == INTERCEPT_PTRACE) {
            el->interceptor->continue_syscall(el->interceptor, event->pid, 0);
            /* Also continue the child */
            if (event->new_child_pid > 0)
                el->interceptor->continue_running(el->interceptor,
                                                   event->new_child_pid, 0);
        }
        break;

    case KLEE_EVENT_EXEC:
        klee_process_exec(proc, proc->vexe);
        /* After successful exec the old process image is gone — there will
         * be no syscall-exit-stop for the execve.  Reset state so the next
         * intercepted syscall from the new program isn't misclassified as
         * a syscall exit for the old execve. */
        proc->state = PROC_STATE_RUNNING;
        proc->path_modified = false;
        proc->path_arg_count = 0;
        proc->seccomp_entered = false;
        if (el->interceptor->backend == INTERCEPT_PTRACE)
            el->interceptor->continue_running(el->interceptor, event->pid, 0);
        break;

    case KLEE_EVENT_EXIT:
        handle_process_exit(el, proc, event);
        /* If this was a PTRACE_EVENT_EXIT stop the process hasn't truly
         * exited yet — continue it so the kernel finishes the exit and
         * delivers SIGCHLD to the real parent (e.g. bash waiting in
         * wait4).  Harmless if the process already exited (WIFEXITED). */
        if (el->interceptor->backend == INTERCEPT_PTRACE)
            el->interceptor->continue_running(el->interceptor, event->pid, 0);
        break;

    case KLEE_EVENT_SIGNAL:
        if (el->interceptor->backend == INTERCEPT_PTRACE) {
            int sig = event->signal;
            /* Suppress terminal job-control signals. The tracee is
             * effectively always in a "background" process group from
             * the kernel's perspective (klee holds the foreground).
             * Forwarding SIGTTOU/SIGTTIN would stop the tracee when
             * it tries terminal I/O or tcsetpgrp(); suppressing them
             * lets the operation proceed (same as SIG_IGN behavior). */
            if (sig == SIGTTOU || sig == SIGTTIN)
                sig = 0;
            /* Suppress the initial SIGSTOP that newly-forked children
             * receive from PTRACE_O_TRACEFORK.  Without this, a race
             * between the parent's fork event and the child's SIGSTOP
             * can cause the SIGSTOP to be delivered, putting the child
             * into group-stop.  The parent shell then sees it as
             * "Stopped" even though the user never pressed Ctrl+Z. */
            if (sig == SIGSTOP && proc->suppress_initial_stop) {
                KLEE_DEBUG("suppressing initial SIGSTOP for pid=%d", event->pid);
                sig = 0;
                proc->suppress_initial_stop = false;
            }
            el->interceptor->continue_running(el->interceptor,
                                               event->pid, sig);
        }
        break;
    }

    return 0;
}

int klee_event_loop_run(KleeEventLoop *el)
{
    KLEE_INFO("entering event loop");

    if (el->interceptor->backend == INTERCEPT_PTRACE) {
        /* ptrace loop: use waitpid */
        while (el->running) {
            KleeEvent event;
            int rc = el->interceptor->wait_event(el->interceptor, &event);

            if (rc == -ECHILD) {
                KLEE_DEBUG("no more children");
                break;
            }
            if (rc == -EINTR)
                continue;
            if (rc < 0) {
                KLEE_ERROR("wait_event failed: %d", rc);
                break;
            }

            klee_event_loop_handle(el, &event);
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

    KLEE_INFO("event loop exited with status %d", el->exit_status);
    return el->exit_status;
}
