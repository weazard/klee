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

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $FAIL
