#!/bin/bash
#
# Run syscall overhead benchmark natively and under klee, then compare.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BENCH="$SCRIPT_DIR/syscall_overhead"
BWRAP="$(command -v bwrap)"

# Build if needed
if [ ! -x "$BENCH" ] || [ "$BENCH.c" -nt "$BENCH" ]; then
    echo "==> Compiling benchmark..."
    cc -O2 -o "$BENCH" "$BENCH.c" -lm
fi

echo "==> bwrap: $BWRAP"
echo ""

# ---- Native run ----
echo "========================================"
echo "  NATIVE (no interception)"
echo "========================================"
NATIVE=$("$BENCH" 2>&1)
echo "$NATIVE"
echo ""

# ---- klee run ----
echo "========================================"
echo "  UNDER KLEE (ptrace interception)"
echo "========================================"
KLEE=$("$BWRAP" --bind / / --dev /dev --proc /proc -- "$BENCH" 2>&1)
echo "$KLEE"
echo ""

# ---- Comparison ----
NATIVE_DATA=$(echo "$NATIVE" | grep '^#DATA' | sed 's/^#DATA//')
KLEE_DATA=$(echo "$KLEE"     | grep '^#DATA' | sed 's/^#DATA//')

echo "========================================"
echo "  COMPARISON  (overhead = klee / native)"
echo "========================================"
printf "%-24s %10s %10s %10s\n" "benchmark" "native ms" "klee ms" "overhead"
printf "%-24s %10s %10s %10s\n" \
       "------------------------" "----------" "----------" "----------"

# Parse and compare each benchmark
IFS='|' read -ra N_FIELDS <<< "$NATIVE_DATA"
IFS='|' read -ra K_FIELDS <<< "$KLEE_DATA"

for nf in "${N_FIELDS[@]}"; do
    [ -z "$nf" ] && continue
    name="${nf%%:*}"
    ntime="${nf##*:}"

    # Find matching klee result
    ktime=""
    for kf in "${K_FIELDS[@]}"; do
        [ -z "$kf" ] && continue
        kname="${kf%%:*}"
        if [ "$kname" = "$name" ]; then
            ktime="${kf##*:}"
            break
        fi
    done
    [ -z "$ktime" ] && continue

    # Compute overhead ratio (using awk for float math)
    ratio=$(awk "BEGIN { if ($ntime > 0) printf \"%.2fx\", $ktime / $ntime; else print \"n/a\" }")

    printf "%-24s %10s %10s %10s\n" "$name" "$ntime" "$ktime" "$ratio"
done

echo ""
echo "overhead > 1.0x = klee is slower; ~1.0x = no measurable difference"
