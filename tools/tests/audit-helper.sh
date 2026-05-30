#!/usr/bin/env bash
# Tests for tools/audit-helper.sh draft mechanics (offline; §5.5 / §15.4 spirit).
#
# The network subcommands (fetch, confirm) are not exercised here — they hit
# static.crates.io and are validated by hand. draft is deterministic and is the
# security-relevant output (the candidate hash and entry the reviewer fills in).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HELPER="$HERE/../audit-helper.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
check() { # <desc> <0|1 expected-rc> <actual-rc>
	if [ "$2" -eq "$3" ]; then pass=$((pass + 1)); else
		fail=$((fail + 1))
		echo "FAIL: $1 (wanted rc $2, got $3)" >&2
	fi
}

mkdir -p "$TMP/crates-archive"
printf 'fake bytes\n' >"$TMP/crates-archive/foo-1.2.3.crate"
want_sha="$(sha256sum "$TMP/crates-archive/foo-1.2.3.crate" | cut -d' ' -f1)"

# draft for a vendored crate succeeds and emits the correct hash + pin.
out="$(KENNEL_ROOT="$TMP" "$HELPER" draft foo 1.2.3)"
rc=0
check "draft exits 0 for vendored crate" 0 "$rc"
printf '%s\n' "$out" | grep -qF "crate-sha256 = \"$want_sha\"" &&
	dp=0 || dp=1
check "draft emits the computed sha256" 0 "$dp"
printf '%s\n' "$out" | grep -qF 'version = "=1.2.3"' && vp=0 || vp=1
check "draft emits the exact-pin version" 0 "$vp"

# draft refuses when the crate is not vendored.
rc=0
KENNEL_ROOT="$TMP" "$HELPER" draft missing 9.9.9 >/dev/null 2>&1 || rc=$?
[ "$rc" -ne 0 ] && rc=1
check "draft refuses an un-vendored crate" 1 "$rc"

# bad arg count -> usage (exit 2).
rc=0
KENNEL_ROOT="$TMP" "$HELPER" draft foo >/dev/null 2>&1 || rc=$?
check "usage on bad arg count" 2 "$rc"

echo "audit-helper tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
