#!/bin/bash
# Klee - Regression tests for specific bug fixes
#
# These tests are self-contained (no Conty dependency) and use --bind / /
# to map the host root as the container root.
#
# Covers:
#   1. Exec state reset after successful execve (event.c fix)
#   2. prctl(PR_SET_DUMPABLE, 0) interception (enter.c fix)
#   3. AF_UNIX socket bind()/connect() path translation (enter.c)
#   4. Child exit-code propagation (ptrace_backend.c)
#   5. Read-only EROFS errno + PID-ns getpid + no false Zypak detection
#   6. FUSE /proc overlay shutdown does not deadlock klee
#   7. Flatpak layout (/app mount) must not trigger Zypak; peer creds consistent
#   8. Genuine Zypak mode virtualizes to the real uid (D-Bus auth compat)
#   9. bwrap 0.11.1/0.12 parity: SIGCHLD reset; --not-a-security-boundary
#  10. Exec translation holds under fork load (fork-event race, event.c)
#  11. --unshare-ipc: private SysV keys, objects removed on exit (ipc_ns.c)
#  12. --unshare-pid: kill/sigqueue/pidfd_open confined to the sandbox
#  13. --unshare-pid: orphans adopted by init, init's parent reads 0
#  14. Processes outliving the main command die with klee
#  15. Processes keep their own name under identity mounts (no ld.so hop)
#  16. --ro-bind follows the kernel's rules: device nodes stay writable
#  17. Process identity (comm, cmdline, argv[0]) with a sandbox-private ld.so
#  18. 32-bit (i386) tracees are interposed like 64-bit ones
#  19. utimensat/xattr/statfs & co. are translated and honour read-only mounts
#  20. --unshare-pid: one consistent PID numbering, host PIDs out of reach
#  21. Threads share the virtual cwd and fd table (CLONE_FS/CLONE_FILES)
#  22. execveat/fexecve and /proc/self/fd/N execs get the sandbox's loader
#  23. statx shows the virtual owner
#  24. dup2(fd, fd) and dup2 of an untracked fd keep descriptor paths right
#  25. Writable overlays never modify their lower layers
set -e

KLEE="${KLEE:-./klee}"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

echo "=== Regression Tests ==="

# ---------------------------------------------------------------------------
# Fix 1: Exec state reset after successful execve
#
# After exec, proc->state must be reset to PROC_STATE_RUNNING so the first
# intercepted syscall from the new program image isn't misclassified as a
# stale syscall exit for the old execve.
# ---------------------------------------------------------------------------

echo "--- Dynamic binary loading ---"
output=$($KLEE --bind / / -- /bin/ls / 2>/dev/null || true)
if echo "$output" | grep -q "bin"; then
    pass "dynamic binary exec"
else
    fail "dynamic binary exec (got: $output)"
fi

echo "--- Shebang script execution ---"
TMPSCRIPT=$(mktemp /tmp/klee-test-shebang.XXXXXX)
cat > "$TMPSCRIPT" <<'SCRIPT'
#!/bin/sh
echo "shebang-ok"
SCRIPT
chmod +x "$TMPSCRIPT"
output=$($KLEE --bind / / -- "$TMPSCRIPT" 2>/dev/null || true)
rm -f "$TMPSCRIPT"
if echo "$output" | grep -q "shebang-ok"; then
    pass "shebang exec"
else
    fail "shebang exec (got: $output)"
fi

echo "--- Subprocess exec chain ---"
output=$($KLEE --bind / / -- /bin/sh -c '/bin/echo subprocess-ok' 2>/dev/null || true)
if echo "$output" | grep -q "subprocess-ok"; then
    pass "subprocess exec chain"
else
    fail "subprocess exec chain (got: $output)"
fi

# ---------------------------------------------------------------------------
# Fix 2: prctl(PR_SET_DUMPABLE, 0) must not break path translation
#
# Programs like gpg-agent set dumpable=0 to protect secrets.  This makes
# process_vm_readv / PTRACE_PEEKDATA return EIO, breaking all path
# translation.  Klee now rewrites the arg from 0 to 1.
# ---------------------------------------------------------------------------

echo "--- prctl(PR_SET_DUMPABLE, 0) path translation ---"
if command -v python3 >/dev/null 2>&1; then
    output=$($KLEE --bind / / --tmpfs /tmp -- python3 -c '
import ctypes, ctypes.util, os, sys
PR_SET_DUMPABLE = 4
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
# Set non-dumpable — klee should rewrite this to keep dumpable=1
libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
# If path translation still works, stat("/tmp") will succeed
# (it goes through klee mount table -> tmpfs backing)
try:
    os.stat("/tmp")
    print("dumpable-ok")
except OSError as e:
    print(f"dumpable-fail: {e}")
' 2>/dev/null || true)
    if echo "$output" | grep -q "dumpable-ok"; then
        pass "prctl dumpable path translation"
    else
        fail "prctl dumpable path translation (got: $output)"
    fi

    echo "--- prctl(PR_SET_DUMPABLE, 0) file I/O after prctl ---"
    output=$($KLEE --bind / / --tmpfs /tmp -- python3 -c '
import ctypes, ctypes.util, os
PR_SET_DUMPABLE = 4
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
# Write and read a file — requires path translation for /tmp
try:
    with open("/tmp/klee-dumpable-test", "w") as f:
        f.write("hello")
    with open("/tmp/klee-dumpable-test", "r") as f:
        data = f.read()
    if data == "hello":
        print("fileio-ok")
    else:
        print(f"fileio-fail: read back {data!r}")
except OSError as e:
    print(f"fileio-fail: {e}")
' 2>/dev/null || true)
    if echo "$output" | grep -q "fileio-ok"; then
        pass "file I/O after prctl dumpable"
    else
        fail "file I/O after prctl dumpable (got: $output)"
    fi
else
    echo "  SKIP: python3 not available (prctl tests)"
fi

# ---------------------------------------------------------------------------
# Fix 3: AF_UNIX socket bind()/connect() path translation
#
# bind() and connect() on AF_UNIX sockets must translate the sun_path
# through the mount table so sockets land in the container filesystem,
# not on the host.
# ---------------------------------------------------------------------------

echo "--- Unix socket bind() path translation ---"
if command -v python3 >/dev/null 2>&1; then
    output=$($KLEE --bind / / --tmpfs /run/klee-sock-test -- python3 -c '
import socket, os, sys

sock_path = "/run/klee-sock-test/test.sock"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.bind(sock_path)
    # Check the socket exists inside the container
    if os.path.exists(sock_path):
        print("bind-ok")
    else:
        print("bind-fail: socket file not found")
except OSError as e:
    print(f"bind-fail: {e}")
finally:
    s.close()
' 2>/dev/null || true)
    if echo "$output" | grep -q "bind-ok"; then
        pass "unix socket bind path translation"
    else
        fail "unix socket bind path translation (got: $output)"
    fi

    echo "--- Unix socket bind() does not leak to host ---"
    # The socket must NOT appear on the real host filesystem
    if [ ! -e /run/klee-sock-test/test.sock ]; then
        pass "bind does not leak to host"
    else
        fail "bind leaked socket to host at /run/klee-sock-test/test.sock"
        rm -f /run/klee-sock-test/test.sock
    fi

    echo "--- Unix socket connect() after bind() ---"
    output=$($KLEE --bind / / --tmpfs /run/klee-sock-test -- python3 -c '
import socket, os, sys, threading

sock_path = "/run/klee-sock-test/conn.sock"

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(sock_path)
server.listen(1)

def accept_one():
    conn, _ = server.accept()
    data = conn.recv(64)
    conn.sendall(data)
    conn.close()

t = threading.Thread(target=accept_one)
t.daemon = True
t.start()

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    client.connect(sock_path)
    client.sendall(b"ping")
    reply = client.recv(64)
    if reply == b"ping":
        print("connect-ok")
    else:
        print(f"connect-fail: got {reply!r}")
except OSError as e:
    print(f"connect-fail: {e}")
finally:
    client.close()
    server.close()
' 2>/dev/null || true)
    if echo "$output" | grep -q "connect-ok"; then
        pass "unix socket connect path translation"
    else
        fail "unix socket connect path translation (got: $output)"
    fi
else
    echo "  SKIP: python3 not available (socket tests)"
fi


# ---------------------------------------------------------------------------
# Fix 4: Child exit-code propagation (ptrace_backend.c)
# PTRACE_EVENT_EXIT's GETEVENTMSG is the raw wait status word; it must be
# decoded with WEXITSTATUS, else exit(N) truncates to 0.
# ---------------------------------------------------------------------------
echo "--- Child exit-code propagation ---"
rc0=0;  $KLEE --bind / / -- /bin/sh -c 'exit 0'  2>/dev/null || rc0=$?
rc42=0; $KLEE --bind / / -- /bin/sh -c 'exit 42' 2>/dev/null || rc42=$?
rc1=0;  $KLEE --bind / / -- /bin/sh -c 'exit 1'  2>/dev/null || rc1=$?
if [ "$rc0" = "0" ] && [ "$rc42" = "42" ] && [ "$rc1" = "1" ]; then
    pass "child exit status propagated"
else
    fail "child exit status propagated (got $rc0/$rc42/$rc1, want 0/42/1)"
fi

# ---------------------------------------------------------------------------
# Fix 1: Read-only mounts return EROFS, not ENOSYS (event.c deny-override)
# ---------------------------------------------------------------------------
echo "--- Read-only returns EROFS (not ENOSYS) ---"
if command -v python3 >/dev/null 2>&1; then
    out=$($KLEE --ro-bind / / -- python3 -c '
import os, errno
try:
    os.open("/klee-roerrno", os.O_WRONLY | os.O_CREAT, 0o644)
    print("NOERR")
except OSError as e:
    print("EROFS" if e.errno == errno.EROFS else os.strerror(e.errno))
' 2>/dev/null || true)
    if echo "$out" | grep -q "EROFS"; then
        pass "ro-bind returns EROFS"
    else
        fail "ro-bind returns EROFS (got: $out)"
    fi
else
    echo "  SKIP: python3 not available (EROFS errno test)"
fi

# ---------------------------------------------------------------------------
# Fix 2/3: --unshare-pid virtualizes getpid() to 1, and a plain root bind is
# NOT misdetected as Zypak (which used to force-disable the PID namespace).
# ---------------------------------------------------------------------------
echo "--- PID namespace getpid virtualization ---"
out=$($KLEE --bind / / --unshare-pid -- /bin/sh -c 'echo $$' 2>/dev/null || true)
if [ "$out" = "1" ]; then
    pass "unshare-pid getpid()==1"
else
    fail "unshare-pid getpid()==1 (got: $out)"
fi

echo "--- No false Zypak detection on plain root bind ---"
zlog=$(KLEE_LOG=info $KLEE --bind / / -- /bin/true 2>&1 | grep -i "zypak" || true)
if [ -z "$zlog" ]; then
    pass "no false zypak detection on --bind / /"
else
    fail "no false zypak detection (got: $zlog)"
fi


# ---------------------------------------------------------------------------
# Fix 5: FUSE /proc overlay must not deadlock klee at shutdown.
# The FUSE loop thread blocks reading /dev/fuse; fuse_unmount() must run
# before pthread_join(), otherwise klee hangs on every --proc invocation
# (i.e. all real Flatpak/Steam use).  No-op on builds without FUSE3.
# ---------------------------------------------------------------------------
echo "--- FUSE /proc overlay shutdown (no deadlock) ---"
if timeout 20 $KLEE --bind / / --proc /proc -- /bin/true 2>/dev/null; then
    pass "klee terminates with --proc (no FUSE deadlock)"
else
    rc=$?
    if [ "$rc" = "124" ]; then
        fail "klee hung at shutdown with --proc (FUSE deadlock)"
    else
        pass "klee terminates with --proc (rc=$rc)"
    fi
fi


# ---------------------------------------------------------------------------
# Fix 6 (class check): Flatpak-shaped mount layout must NOT trigger Zypak.
# Every Flatpak app mounts /app; detection that treats mount *coverage* of
# /app/bin/zypak-helper as evidence flips ALL flatpaks into Chrome/Zypak
# mode, forcing unshare_user/UID virtualization — which breaks credential-
# authenticated channels (D-Bus) and cut app-store-type apps (Bazaar) off
# the network while plain apps kept working.
# ---------------------------------------------------------------------------
echo "--- Flatpak-layout: no Zypak misdetection from /app mount ---"
FAKEAPP=$(mktemp -d /tmp/klee-fakeapp.XXXXXX)
mkdir -p "$FAKEAPP/bin"
zlog=$(KLEE_LOG=info $KLEE --ro-bind /usr /usr --ro-bind /bin /bin --ro-bind /lib /lib --ro-bind /lib64 /lib64 --bind "$FAKEAPP" /app -- /bin/true 2>&1 | grep -i "zypak" || true)
rm -rf "$FAKEAPP"
if [ -z "$zlog" ]; then
    pass "no zypak misdetection with /app mount (flatpak layout)"
else
    fail "zypak misdetected on flatpak layout (got: $zlog)"
fi

# ---------------------------------------------------------------------------
# Class check: UID virtualization must keep peer credentials consistent.
# D-Bus EXTERNAL auth compares the client-claimed uid (getuid) with
# SO_PEERCRED; if klee virtualizes one but not the other, bus auth times
# out and every portal/system-helper consumer looks "offline".
# ---------------------------------------------------------------------------
echo "--- SO_PEERCRED consistent with getuid() under --unshare-user ---"
if command -v python3 >/dev/null 2>&1; then
    out=$($KLEE --bind / / --unshare-user --uid 0 --gid 0 -- python3 -c '
import socket, struct, os
a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
creds = b.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
pid, uid, gid = struct.unpack("3i", creds)
me = os.getuid()
print("consistent" if uid == me else f"MISMATCH peercred_uid={uid} getuid={me}")
' 2>/dev/null || true)
    if echo "$out" | grep -q "consistent"; then
        pass "SO_PEERCRED uid matches getuid under uid virtualization"
    else
        fail "SO_PEERCRED uid matches getuid (got: $out)"
    fi
else
    echo "  SKIP: python3 not available (peercred test)"
fi


# ---------------------------------------------------------------------------
# Class check: genuine Zypak mode must virtualize to the REAL uid.
# A real Electron flatpak ships /app/bin/zypak-helper, so Zypak mode
# legitimately engages — but defaulting the virtual uid to a hardcoded
# 1000 breaks D-Bus EXTERNAL auth for every user whose real uid != 1000
# (root containers included).  Expect: virtual uid == real uid, except
# real root maps to 1000 (Chrome refuses euid 0).
# ---------------------------------------------------------------------------
echo "--- Zypak true-positive: virtual uid tracks real uid ---"
FAKEAPP=$(mktemp -d /tmp/klee-zypakapp.XXXXXX)
mkdir -p "$FAKEAPP/bin"
printf "#!/bin/sh\nexit 0\n" > "$FAKEAPP/bin/zypak-helper"
chmod +x "$FAKEAPP/bin/zypak-helper"
real_uid=$(id -u)
want=$real_uid
[ "$real_uid" = "0" ] && want=1000
got=$($KLEE --bind / / --bind "$FAKEAPP" /app -- /usr/bin/id -u 2>/dev/null || true)
rm -rf "$FAKEAPP"
if [ "$got" = "$want" ]; then
    pass "zypak virtual uid == $want (real=$real_uid)"
else
    fail "zypak virtual uid (got: '$got', want: $want, real: $real_uid)"
fi


# ---------------------------------------------------------------------------
# bwrap 0.12 parity: --not-a-security-boundary is accepted and fail-open.
# ---------------------------------------------------------------------------
echo "--- --not-a-security-boundary accepted (bwrap 0.12) ---"
rcf=0; $KLEE --not-a-security-boundary --bind / / -- /bin/sh -c 'exit 3' 2>/dev/null || rcf=$?
if [ "$rcf" = "3" ]; then
    pass "--not-a-security-boundary accepted, exit propagated"
else
    fail "--not-a-security-boundary (rc=$rcf, want 3)"
fi

# ---------------------------------------------------------------------------
# bwrap 0.11.1 parity: inherited SIGCHLD=SIG_IGN must not break the sandbox.
# Ptraced children are exempt from auto-reaping, but the seccomp-unotify
# signalfd path discards ignored signals; klee resets the disposition.
# ---------------------------------------------------------------------------
echo "--- SIGCHLD=SIG_IGN parent: exit code still propagates ---"
if command -v python3 >/dev/null 2>&1; then
    rcs=0
    python3 -c "import signal,os; signal.signal(signal.SIGCHLD, signal.SIG_IGN); os.execv(\"$KLEE\",[\"$KLEE\",\"--bind\",\"/\",\"/\",\"--\",\"/bin/sh\",\"-c\",\"exit 7\"])" 2>/dev/null || rcs=$?
    if [ "$rcs" = "7" ]; then
        pass "exit code propagates with SIGCHLD ignored"
    else
        fail "exit code with SIGCHLD ignored (rc=$rcs, want 7)"
    fi
else
    echo "  SKIP: python3 not available (SIGCHLD test)"
fi

# ---------------------------------------------------------------------------
# Fix 10: fork-event race.  A new tracee's initial stop can be reported
# before its creator's fork event; resuming the child from the fork event
# released syscall stops klee had not processed yet, so execve/connect/open
# ran untranslated (~20% of execs in a busy fork loop).  Exec a binary that
# only exists at a sandbox path: any untranslated exec fails with ENOENT.
# ---------------------------------------------------------------------------
echo "--- Exec translation holds under fork load (fork-event race) ---"
if [ -e /opt/klee-forkrace ]; then
    echo "  SKIP: /opt/klee-forkrace exists on the host"
else
    KT=$(mktemp -d /tmp/klee-forkrace.XXXXXX)
    cp /bin/true "$KT/marker"
    cat > "$KT/run.sh" <<'SCRIPT'
#!/bin/sh
for w in 1 2 3 4; do
    ( i=0; bad=0
      while [ $i -lt 25 ]; do
          /opt/klee-forkrace/marker 2>/dev/null || bad=$((bad + 1))
          i=$((i + 1))
      done
      echo $bad > "$1/w$w" ) &
done
wait
cat "$1"/w* | awk '{ s += $1 } END { print "untranslated=" s + 0 }'
SCRIPT
    chmod +x "$KT/run.sh"
    out=$($KLEE --bind / / --bind "$KT" /opt/klee-forkrace -- "$KT/run.sh" "$KT" 2>/dev/null || true)
    rm -rf "$KT"
    if [ "$out" = "untranslated=0" ]; then
        pass "all 100 execs translated under fork load"
    else
        fail "execs escaped translation under fork load (got: $out)"
    fi
fi

# ---------------------------------------------------------------------------
# Fix 11: --unshare-ipc.  The translated SysV key was only written to klee's
# copy of the syscall arguments, never to the tracee's registers, so every
# sandbox used raw host keys, and nothing was removed when it exited.
# ---------------------------------------------------------------------------
echo "--- --unshare-ipc: private SysV keys, objects removed on exit ---"
if command -v python3 >/dev/null 2>&1; then
    IPCPY=$(mktemp /tmp/klee-ipc.XXXXXX)
    cat > "$IPCPY" <<'PY'
import ctypes, sys
libc = ctypes.CDLL(None, use_errno=True)
IPC_CREAT, IPC_EXCL, IPC_RMID, IPC_STAT = 0o1000, 0o2000, 0, 2
op, arg = sys.argv[1], sys.argv[2]
if op == "create":
    print(libc.shmget(int(arg, 16), 4096, IPC_CREAT | IPC_EXCL | 0o600))
elif op == "lookup":
    print(libc.shmget(int(arg, 16), 0, 0))
elif op == "alive":
    buf = ctypes.create_string_buffer(256)
    print(1 if libc.shmctl(int(arg), IPC_STAT, buf) == 0 else 0)
elif op == "rm":
    shmid = libc.shmget(int(arg, 16), 0, 0)
    if shmid >= 0:
        libc.shmctl(shmid, IPC_RMID, None)
PY
    K=0x4b1e5eed
    python3 "$IPCPY" rm $K
    id_a=$($KLEE --bind / / --unshare-ipc -- python3 "$IPCPY" create $K 2>/dev/null || echo -1)
    host_sees=$(python3 "$IPCPY" lookup $K)
    a_alive=0
    [ "$id_a" -ge 0 ] 2>/dev/null && a_alive=$(python3 "$IPCPY" alive "$id_a")
    id_b=$($KLEE --bind / / --unshare-ipc -- python3 "$IPCPY" create $K 2>/dev/null || echo -1)
    python3 "$IPCPY" rm $K
    python3 "$IPCPY" create $K >/dev/null
    in_sees=$($KLEE --bind / / --unshare-ipc -- python3 "$IPCPY" lookup $K 2>/dev/null || echo err)
    python3 "$IPCPY" rm $K
    rm -f "$IPCPY"
    if [ "$id_a" -ge 0 ] 2>/dev/null && [ "$host_sees" = "-1" ] &&
       [ "$a_alive" = "0" ] && [ "$id_b" -ge 0 ] 2>/dev/null &&
       [ "$in_sees" = "-1" ]; then
        pass "SysV keys private per sandbox; objects removed on exit"
    else
        fail "--unshare-ipc (create=$id_a host_lookup=$host_sees alive_after_exit=$a_alive second_sandbox=$id_b host_key_inside=$in_sees)"
    fi
else
    echo "  SKIP: python3 not available (IPC namespace test)"
fi

# ---------------------------------------------------------------------------
# Fix 12: --unshare-pid containment.  PIDs outside the sandbox were passed
# straight to the kernel (kill) or never translated (sigqueue, pidfd_open),
# so a sandboxed process could signal host processes by number.  The same
# calls must still reach the sandbox's own processes by virtual PID.
# ---------------------------------------------------------------------------
echo "--- --unshare-pid: signals and pidfds stay inside the sandbox ---"
if command -v python3 >/dev/null 2>&1; then
    out=$($KLEE --bind / / --unshare-pid -- python3 -c '
import ctypes, os, signal, struct, sys, time
host = int(sys.argv[1])          # the test harness: a host process
libc = ctypes.CDLL(None, use_errno=True)
class sigval(ctypes.Union):
    _fields_ = [("i", ctypes.c_int), ("p", ctypes.c_void_p)]
libc.sigqueue.argtypes = [ctypes.c_int, ctypes.c_int, sigval]
def sq(pid):
    if libc.sigqueue(pid, 0, sigval(0)) != 0:
        raise OSError(ctypes.get_errno(), "sigqueue")
res = []
def outside(name, fn):
    try:
        fn()
        res.append(name + "=reached-host")
    except OSError as e:
        res.append(name + ("=ok" if e.errno == 3 else "=" + str(e.errno)))
outside("kill", lambda: os.kill(host, 0))
outside("sigqueue", lambda: sq(host))
outside("pidfd_open", lambda: os.close(os.pidfd_open(host)))
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.write(w, struct.pack("i", os.getpid()))
    time.sleep(5)
    os._exit(0)
vpid = struct.unpack("i", os.read(r, 4))[0]
fd = os.pidfd_open(vpid)
real = int(open("/proc/self/fdinfo/%d" % fd).read().split("Pid:")[1].split()[0])
sq(vpid)
res.append("child=ok" if real == pid else "child=wrong")
os.kill(vpid, signal.SIGKILL)
os.waitpid(pid, 0)
print(" ".join(res))
' $$ 2>/dev/null || true)
    if [ "$out" = "kill=ok sigqueue=ok pidfd_open=ok child=ok" ]; then
        pass "kill/sigqueue/pidfd_open confined to the PID namespace"
    else
        fail "PID namespace signal containment (got: $out)"
    fi
else
    echo "  SKIP: python3 not available (signal containment test)"
fi

# ---------------------------------------------------------------------------
# Fix 13: --unshare-pid orphans.  klee is the subreaper, so orphans stay in
# the sandbox (and get reaped instead of piling up under the host's init).
# As in a real PID namespace they report init (vpid 1) as their parent, and
# init reports 0 rather than klee's host PID.
# ---------------------------------------------------------------------------
echo "--- --unshare-pid: orphans are adopted by init ---"
if command -v python3 >/dev/null 2>&1; then
    out=$($KLEE --bind / / --unshare-pid -- python3 -c '
import os, time
r, w = os.pipe()
if os.fork() == 0:
    if os.fork() == 0:
        time.sleep(0.3)          # outlive the intermediate parent
        os.write(w, b"%d" % os.getppid())
        os._exit(0)
    os._exit(0)
os.wait()
orphan = os.read(r, 16).decode()
init = [l.split()[1] for l in open("/proc/self/status") if l.startswith("PPid:")][0]
print("orphan=%s init=%s getppid=%d" % (orphan, init, os.getppid()))
' 2>/dev/null || true)
    if [ "$out" = "orphan=1 init=0 getppid=0" ]; then
        pass "orphan reparented to vpid 1; init reports parent 0"
    else
        fail "orphan/init parent pids (got: $out)"
    fi
else
    echo "  SKIP: python3 not available (orphan test)"
fi

# ---------------------------------------------------------------------------
# Fix 14: processes that outlive the main command used to be detached; at
# event-stops that drops the SIGKILL, so survivors kept running with klee's
# seccomp filter and got ENOSYS from every trapped syscall (a forking loop
# then spins on "fork: Function not implemented").  They now stay attached
# and PTRACE_O_EXITKILL kills them when klee exits.
# ---------------------------------------------------------------------------
echo "--- Processes outliving the main command die with klee ---"
marker=$(( 600000 + $$ % 100000 ))
tag="klee-survivor-$$"
# The stat() loops keep tracees parked at seccomp stops, where the old
# detach dropped its SIGKILL.
$KLEE --bind / / -- /bin/sh -c "for i in 1 2 3 4; do sh -c 'while :; do [ -e / ]; done' $tag & done; sh -c 'sleep $marker & exit 0'; sleep 0.5" >/dev/null 2>&1 || true
sleep 1
# [k] keeps the grep from matching its own command line.
left=$(ps -eo args | grep -cE "^(/usr/bin/)?sleep $marker\$|[k]lee-survivor-$$\$" || true)
if [ "$left" = "0" ]; then
    pass "no processes survive klee"
else
    fail "$left process(es) survived klee"
    pkill -f "^(/usr/bin/)?sleep $marker\$" 2>/dev/null || true
    pkill -f "[k]lee-survivor-$$\$" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Fix 15: process names.  klee re-executed dynamic binaries through ld.so
# even when the kernel would load the very same loader, so comm, cmdline and
# /proc/<pid>/exe all said ld-linux, breaking ps/pgrep/pidof/killall and
# peers that identify processes by name.
# ---------------------------------------------------------------------------
echo "--- Processes keep their own name under identity mounts ---"
comm=$($KLEE --bind / / -- /bin/cat /proc/self/comm 2>/dev/null || true)
if [ "$comm" = "cat" ]; then
    pass "comm is the program, not ld-linux"
else
    fail "comm under --bind / / (got: $comm)"
fi

# ---------------------------------------------------------------------------
# Fix 16: read-only mounts follow the kernel's rules for what needs write
# access.  klee refused every write-mode open under --ro-bind, but a real
# MS_RDONLY mount still lets you write to device nodes, fifos and sockets,
# reopen an existing file with O_CREAT, and gives ENOENT/EISDIR where no
# write would ever happen.  echo > /dev/null under --ro-bind / / failed.
# ---------------------------------------------------------------------------
echo "--- Read-only mounts: device nodes and existing-file opens ---"
out=$($KLEE --ro-bind / / -- /bin/sh -c 'echo hi > /dev/null && echo devnull-ok' 2>/dev/null || true)
if [ "$out" = "devnull-ok" ]; then
    pass "write to /dev/null under --ro-bind / /"
else
    fail "write to /dev/null under --ro-bind / / (got: $out)"
fi
if command -v python3 >/dev/null 2>&1; then
    out=$($KLEE --ro-bind / / -- python3 -c '
import os, errno
def t(fn):
    try:
        fn(); return "ok"
    except OSError as e:
        return errno.errorcode[e.errno]
print(t(lambda: os.close(os.open("/etc/passwd", os.O_RDONLY | os.O_CREAT, 0o644))),
      t(lambda: os.open("/etc/passwd", os.O_WRONLY)),
      t(lambda: os.open("/etc/klee-ro-missing", os.O_WRONLY)),
      t(lambda: os.open("/etc/klee-ro-missing", os.O_WRONLY | os.O_CREAT, 0o644)),
      t(lambda: os.open("/etc", os.O_WRONLY)),
      t(lambda: os.open("/etc", os.O_TMPFILE | os.O_WRONLY, 0o644)))
' 2>/dev/null || true)
    if [ "$out" = "ok EROFS ENOENT EROFS EISDIR EROFS" ]; then
        pass "ro-bind open() results match a real read-only mount"
    else
        fail "ro-bind open() results (got: $out)"
    fi
else
    echo "  SKIP: python3 not available (ro-bind open semantics)"
fi

# ---------------------------------------------------------------------------
# Fix 17: process identity when the sandbox has its own ld.so.  The kernel
# resolves PT_INTERP on the host, so klee ran every dynamic binary from a
# Conty/Steam-runtime style rootfs as "ld.so <program>": comm became
# ld-linux-x86-64, cmdline grew the loader, argv[0] turned into the resolved
# path, and ps/pgrep/pidof/killall could not find anything by name.  Such
# binaries now run as private copies whose PT_INTERP names the sandbox's
# loader (src/syscall/exec_shim.c).
#
# The rootfs here is the host's /usr and /etc plus a *copy* of the host's
# loader at /lib64: same code, different file, so the rewrite must happen.
# ---------------------------------------------------------------------------
echo "--- Process identity with a sandbox-private ld.so ---"
LOADER=/lib64/ld-linux-x86-64.so.2
if [ -e "$LOADER" ] && command -v python3 >/dev/null 2>&1; then
    R=$(mktemp -d /tmp/klee-test-rootfs.XXXXXX)
    mkdir -p "$R/lib64"
    cp -L "$LOADER" "$R/lib64/"
    ln -s usr/bin "$R/bin"
    ln -s usr/lib "$R/lib"
    printf '#!/bin/sh\ncat /proc/$$/comm\n' > "$R/script.sh"
    chmod +x "$R/script.sh"
    KARGS="--bind $R / --ro-bind /usr /usr --ro-bind /etc /etc --proc /proc --dev /dev"
    before=$(ls -d /tmp/klee-exec.* /tmp/kl-?????? 2>/dev/null | wc -l)

    out=$($KLEE $KARGS -- /usr/bin/python3 -c 'import os; os.execv("/bin/cat", ["custom-argv0", "/proc/self/comm", "/proc/self/cmdline"])' 2>/dev/null | tr "\0" " " || true)
    if [ "$out" = "cat
custom-argv0 /proc/self/comm /proc/self/cmdline " ]; then
        pass "comm, cmdline and argv[0] are the program's own"
    else
        fail "process identity with private ld.so (got: $(printf '%s' "$out" | tr '\n' '|'))"
    fi

    out=$($KLEE $KARGS -- /script.sh 2>/dev/null || true)
    if [ "$out" = "script.sh" ]; then
        pass "a script's comm is the script's name"
    else
        fail "script comm with private ld.so (got: $out)"
    fi

    # Seen from the host while it runs: ps/pgrep find the program, not ld.so
    marker="2.$(( 700000 + $$ % 100000 ))"
    $KLEE $KARGS -- /bin/sleep "$marker" >/dev/null 2>&1 &
    kpid=$!
    sleep 1
    spid=$(pgrep -f "^/bin/sleep $marker\$" | head -1)
    scomm=$( [ -n "$spid" ] && cat "/proc/$spid/comm" 2>/dev/null )
    if [ "$scomm" = "sleep" ]; then
        pass "host ps/pgrep see the program by name"
    else
        fail "host view of a sandbox process (pid=$spid comm=$scomm)"
    fi
    wait $kpid 2>/dev/null || true

    after=$(ls -d /tmp/klee-exec.* /tmp/kl-?????? 2>/dev/null | wc -l)
    if [ "$after" -le "$before" ]; then
        pass "session directories removed on exit"
    else
        fail "session directories left behind ($before -> $after)"
    fi

    # Without copies klee runs ld.so itself; comm must still be the program's
    out=$(KLEE_EXEC_SHIM=0 $KLEE $KARGS -- /bin/cat /proc/self/comm 2>/dev/null || true)
    if [ "$out" = "cat" ]; then
        pass "ld.so fallback keeps comm"
    else
        fail "ld.so fallback comm (got: $out)"
    fi

    rm -rf "$R"
else
    echo "  SKIP: $LOADER or python3 not available (process identity)"
fi

# ---------------------------------------------------------------------------
# Fix 18: 32-bit tracees.  klee's seccomp filter only trapped the x86_64
# ABI and the backend only decoded x86_64 registers, so a 32-bit program
# (the Steam client, 32-bit games) ran with no path, pid or uid translation
# at all.  tests/klee32.s is a freestanding i386 program issuing raw
# int $0x80 syscalls, so no 32-bit libc or loader is needed on the host.
# ---------------------------------------------------------------------------
echo "--- 32-bit (i386) tracees: paths, pids, uids, EROFS, socketcall, exec ---"
LOADER=/lib64/ld-linux-x86-64.so.2
if [ -e "$LOADER" ] && command -v as >/dev/null 2>&1 && command -v ld >/dev/null 2>&1; then
    R=$(mktemp -d /tmp/klee-test-i386.XXXXXX)
    if as --32 -o "$R/klee32.o" tests/klee32.s 2>/dev/null &&
       ld -m elf_i386 -static -o "$R/klee32" "$R/klee32.o" 2>/dev/null; then
        mkdir -p "$R/lib64" "$R/tmp"
        cp -L "$LOADER" "$R/lib64/"
        ln -s usr/bin "$R/bin"
        ln -s usr/lib "$R/lib"
        echo hi > "$R/guest-file"
        KARGS="--bind $R / --ro-bind /usr /usr --ro-bind /etc /etc --proc /proc --dev /dev"
        expected=$(printf 'T1=hi\nT2=00000001\nT3=00001092\nT4=ffffffe2\nT5=00000000\nT6=/klee32\nT7=00001092\nexec-ok\nsh')
        out=$($KLEE $KARGS --unshare-pid --unshare-user --uid 4242 --gid 4242 -- /klee32 2>/dev/null || true)
        if [ "$out" = "$expected" ]; then
            pass "i386 syscalls translated (open/stat64/getpid/getuid32/socketcall/execve)"
        else
            fail "i386 syscalls (got: $(printf '%s' "$out" | tr '\n' '|'))"
        fi
        if [ -S "$R/tmp/klee32.sock" ]; then
            pass "socketcall(SYS_BIND) path translated into the rootfs"
        else
            fail "socketcall(SYS_BIND) path translation"
        fi
        rm -f "$R/tmp/klee32.sock"
        out=$(KLEE_EXEC_SHIM=0 $KLEE $KARGS -- /klee32 2>/dev/null | tail -2 | tr '\n' ' ' || true)
        if [ "$out" = "exec-ok sh " ]; then
            pass "ld.so fallback rebuilds argv with 4-byte pointers"
        else
            fail "ld.so fallback from a 32-bit caller (got: $out)"
        fi
        rm -f /usr/klee-32-erofs   # only exists if the EROFS check failed
    else
        echo "  SKIP: cannot assemble a 32-bit test binary"
    fi
    rm -rf "$R"
else
    echo "  SKIP: no x86_64 loader or binutils (32-bit tracee test)"
fi

# ---------------------------------------------------------------------------
# Fix 19: path syscalls that were never intercepted (utimensat, utimes,
# utime, futimesat, *xattr, statfs, fchmodat2, fanotify_mark,
# name_to_handle_at, open_tree) went to the host filesystem untranslated:
# utime() on a guest path changed the host file of the same name, statfs and
# getxattr got ENOENT, and none of them honoured --ro-bind.  chown/lchown/
# fchownat also skipped the read-only check.
# ---------------------------------------------------------------------------
echo "--- Timestamps, xattrs and statfs follow the mount table ---"
if command -v python3 >/dev/null 2>&1 && [ -e /lib64/ld-linux-x86-64.so.2 ]; then
    R=$(mktemp -d /tmp/klee-test-paths.XXXXXX)
    mkdir -p "$R/lib64" "$R/tmp"
    cp -L /lib64/ld-linux-x86-64.so.2 "$R/lib64/"
    ln -s usr/bin "$R/bin"
    ln -s usr/lib "$R/lib"
    echo hi > "$R/guest-file"
    HV=$(mktemp /tmp/klee-test-victim.XXXXXX)
    touch -d '2001-01-01' "$HV" "$R$HV"
    out=$($KLEE --bind "$R" / --ro-bind /usr /usr --ro-bind /etc /etc --proc /proc --dev /dev \
          -- /usr/bin/python3 -c "
import os, errno
def t(fn):
    try: fn(); return 'ok'
    except OSError as e: return errno.errorcode[e.errno]
print(t(lambda: os.utime('$HV', (1000000000, 1000000000))),
      t(lambda: os.statvfs('/guest-file')),
      t(lambda: os.getxattr('/guest-file', 'user.nope')),
      t(lambda: os.utime('/usr/bin/true', None)),
      t(lambda: os.setxattr('/usr/bin/true', 'user.k', b'v')),
      t(lambda: os.chown('/usr/bin/true', 0, 0)))" 2>/dev/null || true)
    hmt=$(stat -c %Y "$HV"); gmt=$(stat -c %Y "$R$HV")
    rm -rf "$R" "$HV"
    if [ "$out" = "ok ok ENODATA EROFS EROFS EROFS" ] && [ "$hmt" != "1000000000" ] && [ "$gmt" = "1000000000" ]; then
        pass "utime/statfs/xattr translated; read-only mounts enforced"
    else
        fail "path syscalls (got: $out host-mtime=$hmt guest-mtime=$gmt)"
    fi
else
    echo "  SKIP: python3 or x86_64 loader not available (path syscalls)"
fi

# ---------------------------------------------------------------------------
# Fix 20: --unshare-pid numbering.  fork() returned the host PID while the
# child's getpid() returned a small virtual one, so pidfiles, wait() results
# and SIGCHLD disagreed with the child's own view.  Now init is 1 and every
# other process keeps its host number everywhere, including si_pid.  PIDs of
# host processes stay out of reach: sched_*, setpriority, prlimit and
# /proc/<pid> see them as nonexistent, as in a real PID namespace.
# ---------------------------------------------------------------------------
echo "--- --unshare-pid: consistent PIDs, host PIDs unreachable ---"
if command -v python3 >/dev/null 2>&1; then
    out=$($KLEE --bind / / --unshare-pid --setenv HOSTPID $$ -- python3 -c '
import os, signal, time, errno, resource
signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGCHLD, signal.SIGUSR1])
r, w = os.pipe()
p = os.fork()
if p == 0:
    os.write(w, str(os.getpid()).encode()); os.kill(os.getppid(), signal.SIGUSR1); os._exit(0)
cv = int(os.read(r, 32))
u = signal.sigwaitinfo([signal.SIGUSR1]); c = signal.sigwaitinfo([signal.SIGCHLD])
wp, _ = os.waitpid(-1, 0)
same = p == cv == wp == c.si_pid == u.si_pid
host = int(os.environ["HOSTPID"])
def t(fn):
    try: fn(); return "reached"
    except OSError as e: return errno.errorcode[e.errno]
print("same=%s init=%d ppid=%d" % (same, os.getpid(), os.getppid()),
      t(lambda: os.sched_getaffinity(host)), t(lambda: os.setpriority(os.PRIO_PROCESS, host, 0)),
      t(lambda: resource.prlimit(host, resource.RLIMIT_NOFILE)), t(lambda: open("/proc/%d/status" % host)),
      "self=%s" % t(lambda: resource.prlimit(0, resource.RLIMIT_NOFILE)))' 2>/dev/null || true)
    if [ "$out" = "same=True init=1 ppid=0 ESRCH ESRCH ESRCH ENOENT self=reached" ]; then
        pass "fork/getpid/wait/si_pid agree; host PIDs are ESRCH/ENOENT"
    else
        fail "PID numbering/containment (got: $out)"
    fi
else
    echo "  SKIP: python3 not available (PID numbering test)"
fi

# ---------------------------------------------------------------------------
# Fix 21: threads.  Every clone got private copies of klee's virtual cwd
# and fd table, so after one thread chdir()ed, a relative open in another
# thread resolved against the stale directory (ENOENT), and a dirfd opened
# by one thread was unknown to the others.  Clones now share both when
# CLONE_FS/CLONE_FILES say so, and unshare() splits them again.
# ---------------------------------------------------------------------------
echo "--- Threads share cwd and fd table ---"
if command -v python3 >/dev/null 2>&1 && [ -e /lib64/ld-linux-x86-64.so.2 ]; then
    R=$(mktemp -d /tmp/klee-test-threads.XXXXXX)
    mkdir -p "$R/lib64" "$R/d1" "$R/d2"
    cp -L /lib64/ld-linux-x86-64.so.2 "$R/lib64/"
    ln -s usr/bin "$R/bin"
    ln -s usr/lib "$R/lib"
    echo d1 > "$R/d1/f"
    echo d2 > "$R/d2/f"
    out=$($KLEE --bind "$R" / --ro-bind /usr /usr --ro-bind /etc /etc --proc /proc --dev /dev \
          -- /usr/bin/python3 -c '
import os, threading, errno, ctypes
res = {}
def a():
    os.chdir("/d2"); res["dirfd"] = os.open("/d2", os.O_RDONLY)
t = threading.Thread(target=a); t.start(); t.join()
def b():
    try: res["rel"] = open("f").read().strip()
    except OSError as e: res["rel"] = errno.errorcode[e.errno]
    try: res["at"] = os.read(os.open("f", os.O_RDONLY, dir_fd=res["dirfd"]), 10).decode().strip()
    except OSError as e: res["at"] = errno.errorcode[e.errno]
t = threading.Thread(target=b); t.start(); t.join()
libc = ctypes.CDLL(None, use_errno=True)
def c():
    libc.unshare(0x200); os.chdir("/d1")      # CLONE_FS: private cwd from now on
t = threading.Thread(target=c); t.start(); t.join()
print(res["rel"], res["at"], os.getcwd())' 2>/dev/null || true)
    rm -rf "$R"
    if [ "$out" = "d2 d2 /d2" ]; then
        pass "chdir and dirfds are shared between threads; unshare(CLONE_FS) splits"
    else
        fail "thread-shared cwd/fd table (got: $out)"
    fi
else
    echo "  SKIP: python3 or x86_64 loader not available (threads test)"
fi

# ---------------------------------------------------------------------------
# Fix 22: exec by descriptor.  execveat() and execs of /proc/self/fd/N
# skipped the interpreter handling, so in a rootfs sandbox they ran the
# program with the host's loader.  They now go through the same path as
# execve, with the program reached through /proc/<pid>/fd/<fd>.
# ---------------------------------------------------------------------------
echo "--- execveat/fexecve use the sandbox's loader ---"
if command -v python3 >/dev/null 2>&1 && [ -e /lib64/ld-linux-x86-64.so.2 ]; then
    R=$(mktemp -d /tmp/klee-test-fexec.XXXXXX)
    mkdir -p "$R/lib64"
    cp -L /lib64/ld-linux-x86-64.so.2 "$R/lib64/"
    ln -s usr/bin "$R/bin"
    ln -s usr/lib "$R/lib"
    out=$($KLEE --bind "$R" / --ro-bind /usr /usr --ro-bind /etc /etc --proc /proc --dev /dev \
          -- /usr/bin/python3 -c '
import os, ctypes
cmd = "grep -m1 -o \"[^ ]*ld-linux[^ ]*\" /proc/self/maps"
fd = os.open("/bin/sh", os.O_RDONLY)
if os.fork() == 0:
    os.execve("/proc/self/fd/%d" % fd, ["sh", "-c", cmd], {})
os.wait()
if os.fork() == 0:
    d = os.open("/bin", os.O_RDONLY)
    libc = ctypes.CDLL(None, use_errno=True)
    argv = (ctypes.c_char_p * 4)(b"sh", b"-c", cmd.encode(), None)
    libc.syscall(322, d, b"sh", argv, (ctypes.c_char_p * 1)(None), 0)   # execveat(dirfd, "sh")
    os._exit(1)
os.wait()
os.execve(fd, ["sh", "-c", cmd], {})                                     # fexecve' 2>/dev/null | sort -u || true)
    if [ "$out" = "/lib64/ld-linux-x86-64.so.2" ] || [ "$out" = "$R/lib64/ld-linux-x86-64.so.2" ]; then
        # the maps show the host path of the loader actually mapped
        if [ "$out" = "$R/lib64/ld-linux-x86-64.so.2" ]; then
            pass "execve(/proc/self/fd), execveat(dirfd) and fexecve map the sandbox loader"
        else
            fail "exec by fd used the host loader"
        fi
    else
        fail "exec by fd (got: $(printf '%s' "$out" | tr '\n' '|'))"
    fi
    rm -rf "$R"
else
    echo "  SKIP: python3 or x86_64 loader not available (exec by fd test)"
fi

# ---------------------------------------------------------------------------
# Fix 23: statx showed the real owner.  uid/gid were read and written at the
# offsets struct stat uses, which in struct statx hold the mode and inode.
# ---------------------------------------------------------------------------
echo "--- statx shows the virtual owner ---"
SX=$(mktemp /tmp/klee-statx.XXXXXX)
out=$($KLEE --bind / / --unshare-user --uid 4321 --gid 4321 -- stat -c '%u:%g %a %i' "$SX" 2>/dev/null || true)
want="4321:4321 $(stat -c '%a %i' "$SX")"
if [ "$out" = "$want" ]; then
    pass "statx: virtual uid/gid, mode and inode intact"
else
    fail "statx (got: $out, want: $want)"
fi
rm -f "$SX"

# ---------------------------------------------------------------------------
# Fix 24: dup2(fd, fd) freed the descriptor's path and then copied it from
# the freed entry; dup2 of an untracked fd over a tracked one kept the old
# path, so *at() calls on it resolved against a directory it no longer is.
# ---------------------------------------------------------------------------
echo "--- dup2 keeps descriptor paths right ---"
if command -v python3 >/dev/null 2>&1; then
    out=$($KLEE --bind / / -- python3 -c '
import os
d = os.open("/etc", os.O_RDONLY | os.O_DIRECTORY)
os.dup2(d, d)
os.fchdir(d)
print(os.getcwd())
r, w = os.pipe()
os.dup2(r, d)
try:
    os.open("hostname", os.O_RDONLY, dir_fd=d)
    print("opened")
except NotADirectoryError:
    print("ENOTDIR")' 2>/dev/null | tr '\n' ' ' || true)
    if [ "$out" = "/etc ENOTDIR " ]; then
        pass "dup2(fd, fd) and dup2 of an untracked fd"
    else
        fail "dup2 (got: $out)"
    fi
else
    echo "  SKIP: python3 not available (dup2 test)"
fi

# ---------------------------------------------------------------------------
# Fix 25: writable overlays wrote through to their lower layers: writes and
# deletions hit the lower files, new names were lost.  Only the upper layer
# may change.
# ---------------------------------------------------------------------------
echo "--- Writable overlays leave the lower layers alone ---"
OV=$(mktemp -d /tmp/klee-ov.XXXXXX)
mkdir -p "$OV/lower/dir" "$OV/upper" "$OV/work"
echo original > "$OV/lower/file"
echo keep > "$OV/lower/victim"
echo inner > "$OV/lower/dir/inner"
out=$($KLEE --bind / / --overlay-src "$OV/lower" --tmp-overlay /mnt/klee-ov -- /bin/sh -c '
cd /mnt/klee-ov && echo changed > file && rm victim && echo new > new &&
mkdir dir/sub && mv dir dir2 &&
echo "$(cat file) $(ls | tr "\n" " ")$(ls dir2 | tr "\n" " ")"' 2>/dev/null || true)
lower="$(cat "$OV/lower/file" "$OV/lower/victim" "$OV/lower/dir/inner" | tr '\n' ' ')$(ls "$OV/lower" | tr '\n' ' ')"
if [ "$out" = "changed dir2 file new inner sub " ] &&
   [ "$lower" = "original keep inner dir file victim " ]; then
    pass "--tmp-overlay: copy-up, whiteouts and new names stay in the upper layer"
else
    fail "--tmp-overlay (got: $out | lower: $lower)"
fi
$KLEE --bind / / --overlay-src "$OV/lower" --overlay "$OV/upper" "$OV/work" /mnt/klee-ov -- \
    /bin/sh -c 'echo changed > /mnt/klee-ov/file && echo new > /mnt/klee-ov/new' >/dev/null 2>&1 || true
out=$(cat "$OV/upper/file" "$OV/upper/new" "$OV/lower/file" 2>/dev/null | tr '\n' ' ')
if [ "$out" = "changed new original " ]; then
    pass "--overlay: changes land in the upper directory"
else
    fail "--overlay (got: $out)"
fi
rm -rf "$OV"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $FAIL
