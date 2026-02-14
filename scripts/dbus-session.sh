#!/bin/sh
# Source via: eval "$(./scripts/dbus-session.sh)"
# Creates a temporary session D-Bus and exports the variables.

if [ -n "$KLEE_DBUS_PID" ]; then
    echo "echo 'D-Bus session already running (pid $KLEE_DBUS_PID)'"
    exit 0
fi

DBUS_DIR=$(mktemp -d "${TMPDIR:-/tmp}/klee-dbus.XXXXXX")
DBUS_SOCK="$DBUS_DIR/bus"

dbus-daemon --session --fork --address="unix:path=$DBUS_SOCK" --print-pid > "$DBUS_DIR/pid" 2>/dev/null
DBUS_PID=$(cat "$DBUS_DIR/pid")

if [ -z "$DBUS_PID" ]; then
    rm -rf "$DBUS_DIR"
    echo "echo 'Failed to start dbus-daemon'" >&2
    exit 1
fi

cat <<EOF
export DBUS_SESSION_BUS_ADDRESS="unix:path=$DBUS_SOCK"
export DBUS_SESSION_BUS_PID="$DBUS_PID"
export KLEE_DBUS_PID="$DBUS_PID"
export KLEE_DBUS_DIR="$DBUS_DIR"
klee_dbus_cleanup() {
    kill "$KLEE_DBUS_PID" 2>/dev/null
    rm -rf "$KLEE_DBUS_DIR"
    unset DBUS_SESSION_BUS_ADDRESS DBUS_SESSION_BUS_PID KLEE_DBUS_PID KLEE_DBUS_DIR
    unset -f klee_dbus_cleanup
}
trap klee_dbus_cleanup EXIT
EOF
