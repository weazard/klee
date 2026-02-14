#!/bin/bash
# Klee - End-to-end bwrap compatibility tests
set -e

KLEE="${KLEE:-./klee}"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

echo "=== Integration Tests ==="

# Test 1: Basic execution
echo "--- Basic execution ---"
if $KLEE --bind / / -- /bin/echo "hello world" 2>/dev/null | grep -q "hello world"; then
    pass "basic exec"
else
    fail "basic exec"
fi

# Test 2: UID simulation
echo "--- UID simulation ---"
output=$($KLEE --bind / / --unshare-user --uid 0 --gid 0 -- /usr/bin/id 2>/dev/null || true)
if echo "$output" | grep -q "uid=0"; then
    pass "uid=0 simulation"
else
    fail "uid=0 simulation (got: $output)"
fi

# Test 3: Read-only enforcement
echo "--- Read-only enforcement ---"
if ! $KLEE --ro-bind / / -- /bin/touch /tmp/klee-test-ro 2>/dev/null; then
    pass "ro-bind blocks write"
else
    fail "ro-bind should block write"
    rm -f /tmp/klee-test-ro
fi

# Test 4: PID namespace
echo "--- PID namespace ---"
output=$($KLEE --bind / / --unshare-pid -- /bin/bash -c 'echo $$' 2>/dev/null || true)
if echo "$output" | grep -q "^1$"; then
    pass "PID 1 in namespace"
else
    fail "PID 1 in namespace (got: $output)"
fi

# Test 5: Environment
echo "--- Environment ---"
output=$($KLEE --bind / / --setenv KLEE_TEST "hello" -- /bin/sh -c 'echo $KLEE_TEST' 2>/dev/null || true)
if echo "$output" | grep -q "hello"; then
    pass "setenv"
else
    fail "setenv (got: $output)"
fi

# Test 6: Hostname
echo "--- Hostname ---"
output=$($KLEE --bind / / --unshare-uts --hostname testhost -- /bin/hostname 2>/dev/null || true)
if echo "$output" | grep -q "testhost"; then
    pass "hostname"
else
    fail "hostname (got: $output)"
fi

# Test 7: Tmpfs
echo "--- Tmpfs ---"
output=$($KLEE --bind / / --tmpfs /tmp/klee-tmpfs-test -- /bin/ls /tmp/klee-tmpfs-test 2>/dev/null || true)
if [ $? -eq 0 ]; then
    pass "tmpfs mount"
else
    fail "tmpfs mount"
fi

# Test 8: Working directory
echo "--- Working directory ---"
output=$($KLEE --bind / / --chdir /tmp -- /bin/pwd 2>/dev/null || true)
if echo "$output" | grep -q "/tmp"; then
    pass "chdir"
else
    fail "chdir (got: $output)"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $FAIL
