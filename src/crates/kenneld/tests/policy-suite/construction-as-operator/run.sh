#!/usr/bin/env bash
#
# Suite case: construction-as-operator (self-driving). Runs a kennel with a writable grant on a
# fresh host directory, then asserts host-side that view construction left nothing there owned
# by root. Exit 0 iff the grant was live AND every inode in it belongs to the operator.
#
#   $1 = the case dir   $2 = the kennel CLI   $3 = the suite key id   $4 = a scratch dir
set -euo pipefail

. "$1/../suite-lib.sh"
suite_case "$@"

[[ "$(id -u)" != 0 ]] || { echo "construction-as-operator: must run as the unprivileged operator" >&2; exit 2; }

dir="$HOME/kennel-e2e/construction-as-operator"
rm -rf "$dir"
mkdir -p "$dir"
suite_defer "rm -rf \"$dir\""

name="$(suite_compile "$CASE_DIR/kennel.toml")"
suite_defer "suite_unstage $name"
"$KENNEL" run "$name" "$name" </dev/null \
    || { echo "construction-as-operator: the kennel did not run cleanly" >&2; exit 1; }

# Control: the grant was a live writable bind of this host directory.
[[ -e "$dir/from-workload" ]] \
    || { echo "construction-as-operator: the workload's file did not reach the host directory" >&2; exit 1; }
# Control: construction did create something here (the trust-manifest mask placeholder), so
# the ownership check below is not vacuous.
[[ -e "$dir/.trust-manifest.json" ]] \
    || { echo "construction-as-operator: no mask placeholder in the grant — this case needs updating" >&2; exit 2; }

rooted="$(find "$dir" -uid 0 -print)"
if [[ -n "$rooted" ]]; then
    echo "construction-as-operator: FAIL — view construction left root-owned inodes on the host:" >&2
    echo "$rooted" >&2
    exit 1
fi
echo "construction-as-operator: every inode construction created in the grant is the operator's"
