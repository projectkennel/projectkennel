#!/usr/bin/env bash
# Stop the host-side loopback listeners the net-host-deny-wins setup started.
# $1 = scratch dir.
set -u
SCRATCH="${1:-}"
[ -n "$SCRATCH" ] || exit 0
if [ -f "$SCRATCH/host_listeners.pids" ]; then
    while read -r pid; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done <"$SCRATCH/host_listeners.pids"
fi
exit 0
