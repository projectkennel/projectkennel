#!/usr/bin/env bash
#
# interactive-pty — an interactive `kennel run`, end to end (§7.9.2).
#
# The suite driver redirects every case's stdin, so `kennel run` never sees a terminal and the
# daemon's interactive path (the pty master hand-back, the pty broker, the proxied terminal
# socket) is never taken. This hook runs the CLI under script(1), which gives it a real
# pseudo-terminal, and checks two things: the workload's exit status came back as 0, and the
# marker the workload printed on its terminal arrived on ours.
#
#   $1 = case dir   $2 = KENNEL (installed CLI)   $3 = SUITE_KEY   $4 = scratch
set -euo pipefail

# shellcheck source=../suite-lib.sh
. "$1/../suite-lib.sh"
suite_case "$@"

if ! command -v script >/dev/null 2>&1; then
    echo "SKIP: script(1) is not installed (util-linux); it provides the pseudo-terminal"
    exit 77
fi

name="$(suite_compile "$CASE_DIR/policy.toml")"
suite_defer "suite_unstage $name"

# -q quiet, -e return the child's exit status, -c the command; the typescript goes to $out.
out="$SCRATCH/typescript"
rc=0
script -qec "'$KENNEL' run $name $name" "$out" >/dev/null 2>&1 || rc=$?

if [[ "$rc" -ne 0 ]]; then
    echo "interactive-pty: the interactive run exited $rc" >&2
    cat "$out" >&2 || true
    exit 1
fi
if ! grep -q 'KENNEL-PTY-OK' "$out"; then
    echo "interactive-pty: the workload's terminal output did not reach the CLI's terminal" >&2
    cat "$out" >&2 || true
    exit 1
fi
