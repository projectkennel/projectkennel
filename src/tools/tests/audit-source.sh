#!/usr/bin/env bash
# Tests for tools/audit-source.sh error paths (offline; §15.4 spirit).
#
# The PASS path downloads from GitHub and is validated by hand against a real
# crate (libc). These cases cover the offline-checkable argument and
# precondition handling.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="$HERE/../audit-source.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
check() { # <desc> <expected-rc> <actual-rc>
	if [[ "$2" -eq "$3" ]]; then pass=$((pass + 1)); else
		fail=$((fail + 1))
		echo "FAIL: $1 (wanted rc $2, got $3)" >&2
	fi
}

mkdir -p "$TMP/src/vendor"

# usage on too-few args.
rc=0
KENNEL_ROOT="$TMP" "$TOOL" onlyone >/dev/null 2>&1 || rc=$?
check "usage on missing version" 2 "$rc"

# missing vendored .crate.
rc=0
KENNEL_ROOT="$TMP" "$TOOL" nope 1.0.0 >/dev/null 2>&1 || rc=$?
check "refuses an un-vendored crate" 1 "$rc"

# a .crate that lacks .cargo_vcs_info.json cannot be tied to a commit.
mkdir -p "$TMP/build/foo-1.0.0"
printf 'fn main() {}\n' >"$TMP/build/foo-1.0.0/lib.rs"
tar -czf "$TMP/src/vendor/foo-1.0.0.crate" -C "$TMP/build" foo-1.0.0
rc=0
KENNEL_ROOT="$TMP" "$TOOL" foo 1.0.0 >/dev/null 2>&1 || rc=$?
check "refuses a .crate with no .cargo_vcs_info.json" 1 "$rc"

echo "audit-source tests: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
