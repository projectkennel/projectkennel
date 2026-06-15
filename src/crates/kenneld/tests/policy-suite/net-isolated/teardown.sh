#!/usr/bin/env bash
# Stop the host-side loopback listener the net-isolated setup started. $1 = scratch dir.
set -u
SCRATCH="${1:-}"
[ -n "$SCRATCH" ] || exit 0
if [ -f "$SCRATCH/host_listener.pid" ]; then
    kill "$(cat "$SCRATCH/host_listener.pid")" 2>/dev/null || true
fi
exit 0
