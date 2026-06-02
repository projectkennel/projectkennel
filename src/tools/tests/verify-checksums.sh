#!/usr/bin/env bash
# Tests for tools/verify-checksums.sh (CODING-STANDARDS.md §5.5 / §15.4 spirit).
#
# Builds fixture trees (a CHECKSUMS.toml + src/vendor/ + Cargo.lock) and
# asserts the verifier's accept/reject verdict. Self-contained; uses a fake
# .crate file whose hash we compute, so no network or real registry is needed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
VERIFY="$HERE/../verify-checksums.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

# run_case <want 0|1> <name> <root-dir>
run_case() {
	local want="$1" name="$2" root="$3" got=0
	KENNEL_VERIFY_ROOT="$root" "$VERIFY" >/dev/null 2>&1 || got=$?
	[ "$got" -ne 0 ] && got=1
	if [ "$got" -eq "$want" ]; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1))
		echo "FAIL: $name (wanted exit $want, got $got)" >&2
	fi
}

# Build a fixture with one registry crate "foo 1.0.0". Knobs corrupt it.
#   $1 dir  $2 mode: ok|badhash|nofile|extra|lockunpinned|empty
make_fixture() {
	local dir="$1" mode="$2"
	mkdir -p "$dir/src/vendor" "$dir/supply-chain"
	if [ "$mode" = "empty" ]; then
		: >"$dir/supply-chain/CHECKSUMS.toml"
		cat >"$dir/Cargo.lock" <<-EOF
			version = 4
			[[package]]
			name = "kennel-text"
			version = "0.0.0"
		EOF
		return
	fi

	printf 'fake crate bytes for foo 1.0.0\n' >"$dir/src/vendor/foo-1.0.0.crate"
	local sha
	sha="$(sha256sum "$dir/src/vendor/foo-1.0.0.crate" | cut -d' ' -f1)"
	local msha="$sha"
	[ "$mode" = "badhash" ] && msha="0000000000000000000000000000000000000000000000000000000000000000"
	[ "$mode" = "nofile" ] && rm -f "$dir/src/vendor/foo-1.0.0.crate"
	[ "$mode" = "extra" ] && printf 'orphan\n' >"$dir/src/vendor/bar-2.0.0.crate"

	cat >"$dir/supply-chain/CHECKSUMS.toml" <<-EOF
		[crate."foo"]
		version = "=1.0.0"
		crate-sha256 = "$msha"
		audited-by = "tester"
		audited-on = "2026-05-30"
	EOF

	local lockver="1.0.0"
	[ "$mode" = "lockunpinned" ] && lockver="9.9.9"
	cat >"$dir/Cargo.lock" <<-EOF
		version = 4
		[[package]]
		name = "foo"
		version = "$lockver"
		source = "registry+https://github.com/rust-lang/crates.io-index"
		checksum = "$sha"

		[[package]]
		name = "kennel-text"
		version = "0.0.0"
	EOF
}

for spec in "0 empty empty" "0 ok ok" "1 badhash badhash" "1 nofile nofile" \
	"1 extra-unrecorded extra" "1 lock-unpinned lockunpinned"; do
	set -- $spec
	want="$1" name="$2" mode="$3"
	d="$TMP/$name"
	make_fixture "$d" "$mode"
	run_case "$want" "$name" "$d"
done

# And the real repository (currently empty manifest) must pass.
run_case 0 "real-repo-empty" "$(git -C "$HERE" rev-parse --show-toplevel)"

echo "verify-checksums tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
