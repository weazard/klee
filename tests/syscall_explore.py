#!/usr/bin/env python3
"""
Syscall behavior explorer for klee development.

Tests how tgkill, kill, clone, unshare, and related syscalls behave
under various conditions. Run outside klee to see baseline behavior,
then inside klee to compare.

Usage:
    python3 tests/syscall_explore.py [test_name]
    python3 tests/syscall_explore.py            # run all tests
    python3 tests/syscall_explore.py tgkill     # run only tgkill tests
"""

import ctypes
import ctypes.util
import errno
import os
import signal
import struct
import sys
import threading
import time

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# Syscall numbers (x86_64)
SYS_clone       = 56
SYS_clone3      = 435
SYS_fork        = 57
SYS_vfork       = 58
SYS_kill        = 62
SYS_tgkill      = 234
SYS_tkill       = 200
SYS_getpid      = 39
SYS_gettid      = 186
SYS_getppid     = 110
SYS_unshare     = 272
SYS_wait4       = 61
SYS_waitid      = 247
SYS_setsid      = 112

# Clone flags
CLONE_VM        = 0x00000100
CLONE_FS        = 0x00000200
CLONE_FILES     = 0x00000400
CLONE_SIGHAND   = 0x00000800
CLONE_PIDFD     = 0x00001000
CLONE_PTRACE    = 0x00002000
CLONE_VFORK     = 0x00004000
CLONE_PARENT    = 0x00008000
CLONE_THREAD    = 0x00010000
CLONE_NEWNS     = 0x00020000
CLONE_SYSVSEM   = 0x00040000
CLONE_SETTLS    = 0x00080000
CLONE_PARENT_SETTID   = 0x00100000
CLONE_CHILD_CLEARTID  = 0x00200000
CLONE_DETACHED        = 0x00400000
CLONE_UNTRACED        = 0x00800000
CLONE_CHILD_SETTID    = 0x01000000
CLONE_NEWCGROUP       = 0x02000000
CLONE_NEWUTS          = 0x04000000
CLONE_NEWIPC          = 0x08000000
CLONE_NEWUSER         = 0x10000000
CLONE_NEWPID          = 0x20000000
CLONE_NEWNET          = 0x40000000
CLONE_IO              = 0x80000000

# Unshare flags (same as CLONE_NEW*)
UNSHARE_NEWNS      = CLONE_NEWNS
UNSHARE_NEWUTS     = CLONE_NEWUTS
UNSHARE_NEWIPC     = CLONE_NEWIPC
UNSHARE_NEWUSER    = CLONE_NEWUSER
UNSHARE_NEWPID     = CLONE_NEWPID
UNSHARE_NEWNET     = CLONE_NEWNET
UNSHARE_NEWCGROUP  = CLONE_NEWCGROUP

syscall = libc.syscall
syscall.restype = ctypes.c_long


def errmsg():
    """Get the error message for the current errno."""
    e = ctypes.get_errno()
    return f"errno={e} ({os.strerror(e)})" if e else "success"


def raw_syscall(nr, *args):
    """Invoke a raw syscall and return (retval, errno)."""
    ctypes.set_errno(0)
    ret = syscall(ctypes.c_long(nr), *[ctypes.c_long(a) for a in args])
    return ret, ctypes.get_errno()


def header(name):
    print(f"\n{'=' * 60}")
    print(f"  {name}")
    print(f"{'=' * 60}")


# ---------------------------------------------------------------------------
# PID / TID identity tests
# ---------------------------------------------------------------------------
def test_pid_identity():
    """Show how getpid/gettid/getppid behave, including in threads."""
    header("PID / TID Identity")

    pid, _ = raw_syscall(SYS_getpid)
    tid, _ = raw_syscall(SYS_gettid)
    ppid, _ = raw_syscall(SYS_getppid)

    print(f"Main thread:")
    print(f"  getpid()  = {pid}")
    print(f"  gettid()  = {tid}")
    print(f"  getppid() = {ppid}")
    print(f"  os.getpid()  = {os.getpid()}")
    print(f"  os.getppid() = {os.getppid()}")
    print(f"  pid == tid: {pid == tid}  (main thread: should be True)")

    results = {}

    def thread_func(name):
        t_pid, _ = raw_syscall(SYS_getpid)
        t_tid, _ = raw_syscall(SYS_gettid)
        t_ppid, _ = raw_syscall(SYS_getppid)
        results[name] = (t_pid, t_tid, t_ppid)

    t1 = threading.Thread(target=thread_func, args=("thread-1",))
    t2 = threading.Thread(target=thread_func, args=("thread-2",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    for name, (t_pid, t_tid, t_ppid) in sorted(results.items()):
        print(f"\n{name}:")
        print(f"  getpid()  = {t_pid}  (should match main pid={pid})")
        print(f"  gettid()  = {t_tid}  (should differ from main tid={tid})")
        print(f"  getppid() = {t_ppid} (should match main ppid={ppid})")
        print(f"  tgid==pid: {t_pid == pid}")
        print(f"  tid!=pid:  {t_tid != pid}")


# ---------------------------------------------------------------------------
# kill() tests
# ---------------------------------------------------------------------------
def test_kill():
    """Test kill() with various signal and PID combinations."""
    header("kill() Behavior")

    pid = os.getpid()
    ppid = os.getppid()

    # Signal 0 = existence check
    tests = [
        (pid, 0, "kill(self, 0) - existence check"),
        (ppid, 0, "kill(parent, 0) - existence check"),
        (1, 0, "kill(init/pid1, 0) - existence check"),
        (99999, 0, "kill(nonexistent, 0) - should fail ESRCH"),
        (-1, 0, "kill(-1, 0) - all processes"),
        (0, 0, "kill(0, 0) - process group"),
        (-pid, 0, "kill(-self, 0) - own process group"),
    ]

    for target, sig, desc in tests:
        ret, e = raw_syscall(SYS_kill, target, sig)
        status = "OK" if ret == 0 else f"FAIL {os.strerror(e)}"
        print(f"  {desc}: ret={ret} {status}")

    # Fork a child and test kill across processes
    print("\n  --- Cross-process kill ---")
    r, w = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(w)
        # Child: wait for parent to signal us
        os.read(r, 1)
        os._exit(0)

    os.close(r)
    time.sleep(0.05)

    # Parent: signal the child
    ret, e = raw_syscall(SYS_kill, child, 0)
    print(f"  kill(child={child}, 0): ret={ret} {'OK' if ret == 0 else os.strerror(e)}")

    ret, e = raw_syscall(SYS_kill, child, signal.SIGTERM)
    print(f"  kill(child={child}, SIGTERM): ret={ret} {'OK' if ret == 0 else os.strerror(e)}")

    os.close(w)
    os.waitpid(child, 0)


# ---------------------------------------------------------------------------
# tgkill() tests
# ---------------------------------------------------------------------------
def test_tgkill():
    """Test tgkill() - thread-directed signal delivery."""
    header("tgkill() Behavior")

    pid = os.getpid()
    main_tid, _ = raw_syscall(SYS_gettid)

    print(f"Process PID={pid}, main TID={main_tid}")

    # tgkill(tgid, tid, sig)
    # Signal 0 = existence check without sending
    tests = [
        (pid, main_tid, 0, "tgkill(self, main_tid, 0) - check main thread"),
        (pid, main_tid, signal.SIGURG, "tgkill(self, main_tid, SIGURG) - harmless signal"),
        (pid, 99999, 0, "tgkill(self, bad_tid, 0) - nonexistent thread"),
        (99999, main_tid, 0, "tgkill(bad_tgid, main_tid, 0) - wrong process"),
        (0, main_tid, 0, "tgkill(0, main_tid, 0) - tgid=0"),
        (-1, main_tid, 0, "tgkill(-1, main_tid, 0) - tgid=-1"),
    ]

    for tgid, tid, sig, desc in tests:
        ret, e = raw_syscall(SYS_tgkill, tgid, tid, sig)
        status = "OK" if ret == 0 else f"errno={e} ({os.strerror(e)})"
        print(f"  {desc}: ret={ret} {status}")

    # Test tgkill to a child thread
    print("\n  --- tgkill to child threads ---")
    child_tids = []
    barrier = threading.Barrier(3)
    received = {"count": 0}
    orig_handler = signal.getsignal(signal.SIGUSR1)

    def sigusr1_handler(signum, frame):
        received["count"] += 1

    signal.signal(signal.SIGUSR1, sigusr1_handler)

    def thread_target():
        tid, _ = raw_syscall(SYS_gettid)
        child_tids.append(tid)
        barrier.wait()
        time.sleep(0.5)  # Wait to receive signals

    t1 = threading.Thread(target=thread_target)
    t2 = threading.Thread(target=thread_target)
    t1.start()
    t2.start()
    barrier.wait()  # Wait for threads to register their TIDs

    for tid in child_tids:
        ret, e = raw_syscall(SYS_tgkill, pid, tid, 0)
        status = "OK" if ret == 0 else f"errno={e} ({os.strerror(e)})"
        print(f"  tgkill(self, child_tid={tid}, 0): ret={ret} {status}")

        ret, e = raw_syscall(SYS_tgkill, pid, tid, signal.SIGUSR1)
        status = "OK" if ret == 0 else f"errno={e} ({os.strerror(e)})"
        print(f"  tgkill(self, child_tid={tid}, SIGUSR1): ret={ret} {status}")

    t1.join()
    t2.join()
    print(f"  Signals received: {received['count']}")

    signal.signal(signal.SIGUSR1, orig_handler)

    # tgkill after thread exit
    print("\n  --- tgkill to exited threads ---")
    for tid in child_tids:
        ret, e = raw_syscall(SYS_tgkill, pid, tid, 0)
        status = "OK" if ret == 0 else f"errno={e} ({os.strerror(e)})"
        print(f"  tgkill(self, exited_tid={tid}, 0): ret={ret} {status}")


# ---------------------------------------------------------------------------
# tkill() tests
# ---------------------------------------------------------------------------
def test_tkill():
    """Test tkill() - like tgkill but without tgid."""
    header("tkill() Behavior")

    tid, _ = raw_syscall(SYS_gettid)

    tests = [
        (tid, 0, "tkill(self_tid, 0) - check self"),
        (99999, 0, "tkill(bad_tid, 0) - nonexistent"),
    ]

    for target_tid, sig, desc in tests:
        ret, e = raw_syscall(SYS_tkill, target_tid, sig)
        status = "OK" if ret == 0 else f"errno={e} ({os.strerror(e)})"
        print(f"  {desc}: ret={ret} {status}")


# ---------------------------------------------------------------------------
# unshare() tests
# ---------------------------------------------------------------------------
def test_unshare():
    """Test unshare() with various namespace flags."""
    header("unshare() Behavior")

    print(f"Running as uid={os.getuid()}, euid={os.geteuid()}")
    print(f"Capabilities determine what namespaces can be created.\n")

    flag_names = [
        (UNSHARE_NEWUSER,   "CLONE_NEWUSER"),
        (UNSHARE_NEWNS,     "CLONE_NEWNS"),
        (UNSHARE_NEWPID,    "CLONE_NEWPID"),
        (UNSHARE_NEWUTS,    "CLONE_NEWUTS"),
        (UNSHARE_NEWIPC,    "CLONE_NEWIPC"),
        (UNSHARE_NEWNET,    "CLONE_NEWNET"),
        (UNSHARE_NEWCGROUP, "CLONE_NEWCGROUP"),
    ]

    # Test each flag individually in a child process (so failures don't
    # affect the parent's namespace)
    for flag, name in flag_names:
        child = os.fork()
        if child == 0:
            ret, e = raw_syscall(SYS_unshare, flag)
            if ret == 0:
                # Show what changed
                pid_after, _ = raw_syscall(SYS_getpid)
                msg = f"OK (pid after={pid_after})"
            else:
                msg = f"FAILED errno={e} ({os.strerror(e)})"
            # Write result and exit
            sys.stdout.write(f"  unshare({name}): {msg}\n")
            sys.stdout.flush()
            os._exit(0)
        os.waitpid(child, 0)

    # Test combinations
    print("\n  --- Flag combinations ---")
    combos = [
        (CLONE_NEWUSER | CLONE_NEWPID, "NEWUSER|NEWPID"),
        (CLONE_NEWUSER | CLONE_NEWNS, "NEWUSER|NEWNS"),
        (CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS,
         "NEWUSER|NEWNS|NEWPID|NEWIPC|NEWUTS"),
        (0, "0 (no flags)"),
    ]

    for flags, name in combos:
        child = os.fork()
        if child == 0:
            ret, e = raw_syscall(SYS_unshare, flags)
            msg = "OK" if ret == 0 else f"FAILED errno={e} ({os.strerror(e)})"
            sys.stdout.write(f"  unshare({name}): {msg}\n")
            sys.stdout.flush()
            os._exit(0)
        os.waitpid(child, 0)


# ---------------------------------------------------------------------------
# clone() flag behavior tests
# ---------------------------------------------------------------------------
def test_clone_flags():
    """Test which clone flags affect namespace creation."""
    header("clone() Namespace Flags (via fork+unshare proxy)")

    print("Note: Python can't directly invoke clone() with namespace flags")
    print("safely. Instead we test fork() + unshare() which is equivalent.\n")

    # For each namespace flag, fork a child that calls unshare
    ns_flags = [
        (CLONE_NEWNS,     "CLONE_NEWNS",     "/proc/self/ns/mnt"),
        (CLONE_NEWPID,    "CLONE_NEWPID",    "/proc/self/ns/pid"),
        (CLONE_NEWUTS,    "CLONE_NEWUTS",     "/proc/self/ns/uts"),
        (CLONE_NEWIPC,    "CLONE_NEWIPC",     "/proc/self/ns/ipc"),
        (CLONE_NEWNET,    "CLONE_NEWNET",     "/proc/self/ns/net"),
        (CLONE_NEWUSER,   "CLONE_NEWUSER",    "/proc/self/ns/user"),
        (CLONE_NEWCGROUP, "CLONE_NEWCGROUP",  "/proc/self/ns/cgroup"),
    ]

    # Read parent's namespace inodes
    parent_ns = {}
    for flag, name, ns_path in ns_flags:
        try:
            parent_ns[name] = os.stat(ns_path).st_ino
        except OSError:
            parent_ns[name] = None

    for flag, name, ns_path in ns_flags:
        r_fd, w_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(r_fd)
            ret, e = raw_syscall(SYS_unshare, flag)
            if ret == 0:
                try:
                    child_ino = os.stat(ns_path).st_ino
                    parent_ino = parent_ns.get(name)
                    changed = "CHANGED" if child_ino != parent_ino else "SAME"
                    msg = f"OK ns_ino={child_ino} ({changed})"
                except OSError as ex:
                    msg = f"OK but stat failed: {ex}"
            else:
                msg = f"FAILED errno={e} ({os.strerror(e)})"
            os.write(w_fd, msg.encode())
            os.close(w_fd)
            os._exit(0)

        os.close(w_fd)
        result = os.read(r_fd, 256).decode()
        os.close(r_fd)
        os.waitpid(child, 0)
        print(f"  {name}: {result}")


# ---------------------------------------------------------------------------
# wait4/waitid PID translation tests
# ---------------------------------------------------------------------------
def test_wait():
    """Test wait4/waitid behavior with various PID arguments."""
    header("wait4() / waitid() Behavior")

    # Fork a child that exits immediately
    child = os.fork()
    if child == 0:
        os._exit(42)

    # wait4(pid, &status, options, &rusage)
    # We use os.wait4 which wraps the syscall
    pid, status, rusage = os.wait4(child, 0)
    exit_code = os.waitstatus_to_exitcode(status)
    print(f"  wait4(child={child}): returned pid={pid}, exit_code={exit_code}")
    print(f"    Expected: pid={child}, exit_code=42")

    # Test wait4(-1, ...) - wait for any child
    child2 = os.fork()
    if child2 == 0:
        os._exit(77)

    pid2, status2, rusage2 = os.wait4(-1, 0)
    exit_code2 = os.waitstatus_to_exitcode(status2)
    print(f"  wait4(-1): returned pid={pid2}, exit_code={exit_code2}")
    print(f"    Expected: pid={child2}, exit_code=77")

    # Test wait4(0, ...) - wait for any child in same process group
    child3 = os.fork()
    if child3 == 0:
        os._exit(33)

    pid3, status3, rusage3 = os.wait4(0, 0)
    exit_code3 = os.waitstatus_to_exitcode(status3)
    print(f"  wait4(0): returned pid={pid3}, exit_code={exit_code3}")
    print(f"    Expected: pid={child3}, exit_code=33")


# ---------------------------------------------------------------------------
# Signal delivery through ptrace
# ---------------------------------------------------------------------------
def test_signals():
    """Test various signal delivery scenarios relevant to ptrace."""
    header("Signal Delivery Scenarios")

    received_signals = []
    orig_handlers = {}

    def make_handler(signame):
        def handler(signum, frame):
            tid, _ = raw_syscall(SYS_gettid)
            received_signals.append((signame, signum, tid))
        return handler

    # Install handlers for non-fatal signals
    test_sigs = [
        (signal.SIGUSR1, "SIGUSR1"),
        (signal.SIGUSR2, "SIGUSR2"),
        (signal.SIGURG, "SIGURG"),
        (signal.SIGWINCH, "SIGWINCH"),
    ]

    for sig, name in test_sigs:
        orig_handlers[sig] = signal.getsignal(sig)
        signal.signal(sig, make_handler(name))

    pid = os.getpid()
    main_tid, _ = raw_syscall(SYS_gettid)

    # 1. Self-signal via kill
    os.kill(pid, signal.SIGUSR1)
    print(f"  kill(self, SIGUSR1): delivered={len(received_signals) > 0}")

    # 2. Self-signal via tgkill
    before = len(received_signals)
    raw_syscall(SYS_tgkill, pid, main_tid, signal.SIGUSR2)
    print(f"  tgkill(self, main_tid, SIGUSR2): delivered={len(received_signals) > before}")

    # 3. Cross-thread signal
    thread_ready = threading.Event()
    thread_tid = [0]

    def thread_waiter():
        thread_tid[0], _ = raw_syscall(SYS_gettid)
        thread_ready.set()
        time.sleep(1)

    t = threading.Thread(target=thread_waiter)
    t.start()
    thread_ready.wait()

    before = len(received_signals)
    raw_syscall(SYS_tgkill, pid, thread_tid[0], signal.SIGURG)
    time.sleep(0.1)
    print(f"  tgkill(self, thread_tid={thread_tid[0]}, SIGURG): delivered={len(received_signals) > before}")

    # 4. Signal from child process
    r, w = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(r)
        # Child sends signal to parent
        os.kill(os.getppid(), signal.SIGWINCH)
        os.write(w, b"x")
        os.close(w)
        os._exit(0)

    os.close(w)
    os.read(r, 1)
    os.close(r)
    time.sleep(0.1)
    os.waitpid(child, 0)
    has_winch = any(s[0] == "SIGWINCH" for s in received_signals)
    print(f"  kill(parent, SIGWINCH) from child: delivered={has_winch}")

    t.join()

    # Restore handlers
    for sig, handler in orig_handlers.items():
        signal.signal(sig, handler)

    print(f"\n  All signals received: {received_signals}")


# ---------------------------------------------------------------------------
# Process exit and orphan behavior
# ---------------------------------------------------------------------------
def test_exit_behavior():
    """Test how process exit interacts with parent wait."""
    header("Process Exit Behavior")

    # 1. Normal exit
    child = os.fork()
    if child == 0:
        os._exit(0)
    pid, status = os.waitpid(child, 0)
    print(f"  Normal exit(0): wait returned pid={pid}, WIFEXITED={os.WIFEXITED(status)}, "
          f"code={os.WEXITSTATUS(status)}")

    # 2. Signal exit
    child = os.fork()
    if child == 0:
        os.kill(os.getpid(), signal.SIGKILL)
        os._exit(1)  # shouldn't reach
    pid, status = os.waitpid(child, 0)
    print(f"  SIGKILL exit: wait returned pid={pid}, WIFSIGNALED={os.WIFSIGNALED(status)}, "
          f"sig={os.WTERMSIG(status) if os.WIFSIGNALED(status) else 'N/A'}")

    # 3. Multi-child: parent waits for all
    children = []
    for i in range(5):
        c = os.fork()
        if c == 0:
            time.sleep(0.01 * i)
            os._exit(i + 10)
        children.append(c)

    results = []
    for _ in children:
        pid, status = os.waitpid(-1, 0)
        results.append((pid, os.WEXITSTATUS(status)))

    print(f"  Multi-child wait results: {results}")
    print(f"    Expected PIDs (any order): {children}")

    # 4. Orphan reparenting
    r, w = os.pipe()
    grandchild_r, grandchild_w = os.pipe()

    child = os.fork()
    if child == 0:
        os.close(r)
        # Create grandchild
        gc = os.fork()
        if gc == 0:
            os.close(grandchild_r)
            # Grandchild: report new parent after child exits
            time.sleep(0.2)
            new_ppid = os.getppid()
            os.write(grandchild_w, str(new_ppid).encode())
            os.close(grandchild_w)
            os._exit(0)
        # Child exits, orphaning grandchild
        os.close(grandchild_w)
        os.write(w, str(gc).encode())
        os.close(w)
        os._exit(0)

    os.close(w)
    os.close(grandchild_w)

    # Read grandchild PID from child
    gc_pid = int(os.read(r, 32).decode())
    os.close(r)
    os.waitpid(child, 0)

    # Read grandchild's new parent
    new_ppid = os.read(grandchild_r, 32).decode()
    os.close(grandchild_r)
    print(f"  Orphan reparenting: grandchild={gc_pid}, new ppid={new_ppid}")
    print(f"    (Expected: reparented to init/subreaper, not our pid={os.getpid()})")

    # Clean up grandchild
    try:
        os.waitpid(gc_pid, 0)
    except ChildProcessError:
        pass  # Already reaped by init


# ---------------------------------------------------------------------------
# SIGTTOU / SIGTTIN tests (suppressed by klee)
# ---------------------------------------------------------------------------
def test_tty_signals():
    """Test SIGTTOU/SIGTTIN behavior (klee suppresses these)."""
    header("SIGTTOU / SIGTTIN Behavior")

    received = {"sigttou": False, "sigttin": False}

    def ttou_handler(signum, frame):
        received["sigttou"] = True

    def ttin_handler(signum, frame):
        received["sigttin"] = True

    old_ttou = signal.getsignal(signal.SIGTTOU)
    old_ttin = signal.getsignal(signal.SIGTTIN)

    signal.signal(signal.SIGTTOU, ttou_handler)
    signal.signal(signal.SIGTTIN, ttin_handler)

    pid = os.getpid()

    os.kill(pid, signal.SIGTTOU)
    print(f"  kill(self, SIGTTOU): received={received['sigttou']}")

    os.kill(pid, signal.SIGTTIN)
    print(f"  kill(self, SIGTTIN): received={received['sigttin']}")

    print(f"  Note: klee suppresses SIGTTOU/SIGTTIN (sets sig=0 on delivery)")
    print(f"  Under klee, these should NOT be received.")

    signal.signal(signal.SIGTTOU, old_ttou)
    signal.signal(signal.SIGTTIN, old_ttin)


# ---------------------------------------------------------------------------
# seccomp filter test
# ---------------------------------------------------------------------------
def test_seccomp():
    """Test seccomp() syscall behavior (klee intercepts and may block)."""
    header("seccomp() Behavior")

    SECCOMP_SET_MODE_STRICT = 0
    SECCOMP_SET_MODE_FILTER = 1

    # Try seccomp in a child (since it may restrict us permanently)
    child = os.fork()
    if child == 0:
        # Try SECCOMP_SET_MODE_FILTER with NULL filter (should fail EFAULT or EINVAL)
        ret, e = raw_syscall(272, SECCOMP_SET_MODE_FILTER, 0, 0)  # 272 = unshare, wrong!
        # Actually seccomp syscall is 317
        ret, e = raw_syscall(317, SECCOMP_SET_MODE_FILTER, 0, 0)
        msg = f"ret={ret} errno={e} ({os.strerror(e) if e else 'success'})"
        sys.stdout.write(f"  seccomp(FILTER, 0, NULL): {msg}\n")
        sys.stdout.flush()
        os._exit(0)

    os.waitpid(child, 0)

    print(f"  Note: klee intercepts seccomp() and typically denies it")
    print(f"  to prevent tracees from installing their own seccomp filters")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
ALL_TESTS = {
    "pid_identity": test_pid_identity,
    "kill": test_kill,
    "tgkill": test_tgkill,
    "tkill": test_tkill,
    "unshare": test_unshare,
    "clone_flags": test_clone_flags,
    "wait": test_wait,
    "signals": test_signals,
    "exit": test_exit_behavior,
    "tty_signals": test_tty_signals,
    "seccomp": test_seccomp,
}


def main():
    print(f"Klee Syscall Explorer")
    print(f"PID={os.getpid()} UID={os.getuid()} EUID={os.geteuid()}")
    print(f"Running on: {'inside klee' if os.environ.get('KLEE_SESSION') else 'bare metal'}")

    if len(sys.argv) > 1:
        name = sys.argv[1]
        if name in ALL_TESTS:
            ALL_TESTS[name]()
        else:
            print(f"Unknown test: {name}")
            print(f"Available: {', '.join(ALL_TESTS.keys())}")
            sys.exit(1)
    else:
        for name, func in ALL_TESTS.items():
            try:
                func()
            except Exception as e:
                print(f"\n  !!! TEST FAILED: {e}")

    print(f"\n{'=' * 60}")
    print(f"  Done")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
