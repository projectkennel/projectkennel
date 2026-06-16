#!/usr/bin/env bash
# Stop the backgrounded host connector the net-bind-mirror setup started. $1 = scratch dir.
set -u
SCRATCH="${1:-}"
[ -n "$SCRATCH" ] || exit 0
if [ -f "$SCRATCH/connector.pid" ]; then
    kill "$(cat "$SCRATCH/connector.pid")" 2>/dev/null || true
fi
exit 0
