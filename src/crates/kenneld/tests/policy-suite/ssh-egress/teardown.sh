#!/usr/bin/env bash
# Stop the destination sshd the ssh-egress setup started. $1 = the scratch dir.
set -u
SCRATCH="${1:-}"
[[ -n "$SCRATCH" ]] || exit 0
if [[ -f "$SCRATCH/dest_sshd.pid" ]]; then
    kill "$(cat "$SCRATCH/dest_sshd.pid")" 2>/dev/null || true
fi
exit 0
