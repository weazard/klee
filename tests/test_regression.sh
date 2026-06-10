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

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $FAIL
