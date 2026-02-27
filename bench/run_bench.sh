#!/bin/bash
#
# Run syscall overhead benchmark natively and under klee with both
# interception backends (ptrace and seccomp_unotify), then compare.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BENCH="$SCRIPT_DIR/syscall_overhead"
BWRAP="$(command -v bwrap)"
BWRAP_ARGS=(--bind / / --dev /dev --proc /proc --)
TIMEOUT=120

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

# ---- ptrace run ----
echo "========================================"
echo "  UNDER KLEE (ptrace backend)"
echo "========================================"
PTRACE=$(timeout "$TIMEOUT" "$BWRAP" "${BWRAP_ARGS[@]}" "$BENCH" 2>&1) || true
echo "$PTRACE"
echo ""

# ---- seccomp_unotify run ----
echo "========================================"
echo "  UNDER KLEE (seccomp_unotify backend)"
echo "========================================"
UNOTIFY=$(KLEE_USE_UNOTIFY=1 timeout "$TIMEOUT" "$BWRAP" "${BWRAP_ARGS[@]}" "$BENCH" 2>&1) || true
echo "$UNOTIFY"
echo ""

# ---- Extract machine-readable data ----
NATIVE_DATA=$(echo "$NATIVE"  | grep '^#DATA' | sed 's/^#DATA//')
PTRACE_DATA=$(echo "$PTRACE"  | grep '^#DATA' | sed 's/^#DATA//') || true
UNOTIFY_DATA=$(echo "$UNOTIFY" | grep '^#DATA' | sed 's/^#DATA//') || true

if [ -z "$PTRACE_DATA" ]; then
    echo "WARNING: ptrace backend produced no results (timed out or crashed)"
fi
if [ -z "$UNOTIFY_DATA" ]; then
    echo "WARNING: seccomp_unotify backend produced no results (timed out or crashed)"
fi

# ---- Comparison ----
echo "========================================"
echo "  COMPARISON  (overhead = backend / native)"
echo "========================================"
printf "%-24s %10s %10s %10s %10s %10s\n" \
       "benchmark" "native ms" "ptrace ms" "unotify ms" "pt overh" "un overh"
printf "%-24s %10s %10s %10s %10s %10s\n" \
       "------------------------" "----------" "----------" "----------" "----------" "----------"

# Parse data into associative arrays
declare -A NATIVE_MAP PTRACE_MAP UNOTIFY_MAP

IFS='|' read -ra N_FIELDS <<< "$NATIVE_DATA"
for f in "${N_FIELDS[@]}"; do
    [ -z "$f" ] && continue
    NATIVE_MAP["${f%%:*}"]="${f##*:}"
done

if [ -n "$PTRACE_DATA" ]; then
    IFS='|' read -ra P_FIELDS <<< "$PTRACE_DATA"
    for f in "${P_FIELDS[@]}"; do
        [ -z "$f" ] && continue
        PTRACE_MAP["${f%%:*}"]="${f##*:}"
    done
fi

if [ -n "$UNOTIFY_DATA" ]; then
    IFS='|' read -ra U_FIELDS <<< "$UNOTIFY_DATA"
    for f in "${U_FIELDS[@]}"; do
        [ -z "$f" ] && continue
        UNOTIFY_MAP["${f%%:*}"]="${f##*:}"
    done
fi

# Iterate in native order for stable output
for nf in "${N_FIELDS[@]}"; do
    [ -z "$nf" ] && continue
    name="${nf%%:*}"
    ntime="${NATIVE_MAP[$name]:-}"
    ptime="${PTRACE_MAP[$name]:-}"
    utime="${UNOTIFY_MAP[$name]:-}"
    [ -z "$ntime" ] && continue

    pratio="n/a"
    uratio="n/a"
    [ -n "$ptime" ] && pratio=$(awk "BEGIN { if ($ntime > 0) printf \"%.2fx\", $ptime / $ntime; else print \"n/a\" }")
    [ -n "$utime" ] && uratio=$(awk "BEGIN { if ($ntime > 0) printf \"%.2fx\", $utime / $ntime; else print \"n/a\" }")

    printf "%-24s %10s %10s %10s %10s %10s\n" \
           "$name" "$ntime" "${ptime:-—}" "${utime:-—}" "$pratio" "$uratio"
done

echo ""

# ---- Head-to-head ----
if [ -n "$PTRACE_DATA" ] && [ -n "$UNOTIFY_DATA" ]; then
    echo "========================================"
    echo "  HEAD-TO-HEAD  (ptrace vs seccomp_unotify)"
    echo "========================================"
    printf "%-24s %10s %10s %10s\n" \
           "benchmark" "ptrace ms" "unotify ms" "pt/un"
    printf "%-24s %10s %10s %10s\n" \
           "------------------------" "----------" "----------" "----------"

    for nf in "${N_FIELDS[@]}"; do
        [ -z "$nf" ] && continue
        name="${nf%%:*}"
        ptime="${PTRACE_MAP[$name]:-}"
        utime="${UNOTIFY_MAP[$name]:-}"
        [ -z "$ptime" ] || [ -z "$utime" ] && continue

        ratio=$(awk "BEGIN { if ($utime > 0) printf \"%.2fx\", $ptime / $utime; else print \"n/a\" }")

        printf "%-24s %10s %10s %10s\n" "$name" "$ptime" "$utime" "$ratio"
    done

    echo ""
fi

echo "overhead > 1.0x = slower than baseline; ~1.0x = no measurable difference"
echo "pt/un > 1.0x = ptrace is slower than seccomp_unotify"
