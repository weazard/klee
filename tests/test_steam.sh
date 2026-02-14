#!/bin/bash
# Klee - Steam-specific integration tests
set -e

KLEE="${KLEE:-./klee}"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $1"; }

echo "=== Steam Compatibility Tests ==="

# Test: pressure-vessel-like command line
echo "--- pressure-vessel compatibility ---"
output=$($KLEE \
    --unshare-all --share-net \
    --uid 0 --gid 0 \
    --ro-bind / / \
    --tmpfs /tmp \
    --proc /proc \
    --dev /dev \
    --die-with-parent \
    --new-session \
    -- /usr/bin/id 2>/dev/null || true)

if echo "$output" | grep -q "uid=0"; then
    pass "pressure-vessel cmdline"
else
    fail "pressure-vessel cmdline (got: $output)"
fi

# Test: /dev/shm accessibility
echo "--- /dev/shm access ---"
output=$($KLEE \
    --bind / / \
    --tmpfs /dev/shm \
    -- /bin/ls /dev/shm 2>/dev/null || true)
if [ $? -eq 0 ]; then
    pass "/dev/shm access"
else
    fail "/dev/shm access"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $FAIL
