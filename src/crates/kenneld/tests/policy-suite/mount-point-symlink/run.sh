#!/usr/bin/env bash
#
# Suite case: mount-point-symlink (self-driving). Plants a symlink where a trust-manifest mask
# must be mounted, then asserts the kennel REFUSES to start. Exit 0 iff construction failed
# closed, the workload never ran, and nothing was created through the link.
#
#   $1 = the case dir   $2 = the kennel CLI   $3 = the suite key id   $4 = a scratch dir
set -euo pipefail

. "$1/../suite-lib.sh"
suite_case "$@"

dir="$HOME/kennel-e2e/mount-point-symlink"
rm -rf "$dir"
mkdir -p "$dir/decoy"
suite_defer "rm -rf \"$dir\""
# What an earlier workload with this write grant could have left: the manifest store path is
# a link to a directory it controls.
ln -s decoy "$dir/.trust-manifest.d"

name="$(suite_compile "$CASE_DIR/kennel.toml")"
suite_defer "suite_unstage $name"

set +e
"$KENNEL" run "$name" "$name" </dev/null >"$SCRATCH/run.log" 2>&1
rc=$?
set -e

if [[ -e "$dir/WORKLOAD-RAN" ]]; then
    echo "mount-point-symlink: FAIL — the workload ran with the mask path a symlink" >&2
    exit 1
fi
if [[ "$rc" = 0 ]]; then
    echo "mount-point-symlink: FAIL — the kennel started (rc 0) with a symlink at a mask path" >&2
    cat "$SCRATCH/run.log" >&2
    exit 1
fi
if [[ ! -L "$dir/.trust-manifest.d" ]] || [[ -n "$(ls -A "$dir/decoy")" ]]; then
    echo "mount-point-symlink: FAIL — the link was replaced or something was created through it" >&2
    exit 1
fi
grep -q "symlink is never accepted" "$SCRATCH/run.log" \
    || { echo "mount-point-symlink: refused, but not for the symlink (rc $rc):" >&2; cat "$SCRATCH/run.log" >&2; exit 1; }
echo "mount-point-symlink: construction refused the symlinked mask path (rc $rc); the workload never ran"
