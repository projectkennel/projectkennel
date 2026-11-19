#!/usr/bin/env bash
#
# Suite case: ns-not-enterable (self-driving). Starts a kennel, then — from the host, as the
# operator — asserts that none of its namespaces can be joined and that its view cannot be read
# through /proc. Exit 0 iff every attempt is REFUSED.
#
#   $1 = the case dir   $2 = the kennel CLI   $3 = the suite key id   $4 = a scratch dir
set -euo pipefail

. "$1/../suite-lib.sh"
suite_case "$@"

command -v nsenter >/dev/null || { echo "ns-not-enterable: no nsenter (util-linux)" >&2; exit 2; }
[[ "$(id -u)" != 0 ]] || { echo "ns-not-enterable: must run as the unprivileged operator" >&2; exit 2; }

name="$(suite_compile "$CASE_DIR/kennel.toml")"
suite_defer "suite_unstage $name"

"$KENNEL" run "$name" "$name" </dev/null >"$SCRATCH/run.log" 2>&1 &
suite_defer "\"$KENNEL\" stop $name >/dev/null 2>&1"

# kennel-bin-init's host pid, from the CLI's own listing (a kennel still starting lists pid 0).
pid=""
for _ in $(seq 100); do
    pid="$("$KENNEL" list 2>/dev/null | awk -v n="$name" '$1 == n && $4 == "running" { print $3 }')"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] && break
    pid=""; sleep 0.1
done
[[ -n "$pid" ]] || { echo "ns-not-enterable: the kennel did not start" >&2; cat "$SCRATCH/run.log" >&2; exit 1; }

fail=0
refused() { # refused <what> <cmd...>: the command must FAIL.
    local what="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "ns-not-enterable: FAIL — $what succeeded from outside the kennel" >&2
        fail=1
    fi
}

# The control that the pid is right and alive: /proc/<pid> exists and is the kennel's uid-0 init.
[[ "$(stat -c %u "/proc/$pid")" == 0 ]] \
    || { echo "ns-not-enterable: pid $pid is not the kennel's uid-0 init" >&2; exit 1; }

refused "joining the user namespace"            nsenter -t "$pid" -U true
refused "joining the user + mount namespaces"   nsenter -t "$pid" -U -m true
refused "joining the mount namespace"           nsenter -t "$pid" -m true
refused "joining the pid namespace"             nsenter -t "$pid" -p true
refused "joining the ipc namespace"             nsenter -t "$pid" -i true
refused "reading the view via /proc/<init>/root" ls "/proc/$pid/root/"
refused "reading the cwd via /proc/<init>/cwd"   ls "/proc/$pid/cwd/"

[[ "$fail" = 0 ]] || exit 1
echo "ns-not-enterable: every attempt to enter kennel pid $pid from the host was refused"
