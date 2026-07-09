#!/usr/bin/env bash
#
# Guard: the release payload stage-tree.sh assembles is exactly what install.sh consumes.
#
# install.sh is a pure tarball installer — it places a payload (binaries + dist/keys/templates/…) that
# sits beside it, and refuses to run without one. stage-tree.sh assembles that payload and is the
# single source of truth for the binary list. If the two drift — a binary stage-tree forgets to
# stage, or install.sh reaches for one stage-tree never places — the tarball install breaks on that
# file (as 0.3.0's did, when install.sh read a `target/<triple>/release` tree the tarball lacked).
#
# W10's three-dir layout: the payload encodes each binary's destination in its staging subdir —
#   bin/      → <libexec>            host-side only (blacklisted from views)
#   facades/  → <facades_dir>        the in-cage binaries a view runs
#   pathbin/  → /usr/bin             the `kennel` shim, the one name on PATH
#
# This reproduces the staging from fake (empty) binaries — it does not build — and asserts each group
# stages to its subdir, install.sh --dry-run resolves every binary it installs to a payload file, and
# the SHA256SUMS manifest covers everything (especially the trust-store public key).

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$repo_root"
stage_tree="src/tools/stage-tree.sh"

# The binary lists, read from stage-tree.sh (the source of truth) so this guard never drifts from it.
host_rel_bins="$(sed -n 's/^HOST_REL_BINS="\(.*\)"$/\1/p' "$stage_tree")"
host_stat_bins="$(sed -n 's/^HOST_STAT_BINS="\(.*\)"$/\1/p' "$stage_tree")"
facade_stat_bins="$(sed -n 's/^FACADE_STAT_BINS="\(.*\)"$/\1/p' "$stage_tree")"
test_bins="$(sed -n 's/^TEST_BINS="\(.*\)"$/\1/p' "$stage_tree")"
if [[ -z "$host_rel_bins" ]] || [[ -z "$host_stat_bins" ]] || [[ -z "$facade_stat_bins" ]] || [[ -z "$test_bins" ]]; then
	echo "FAIL: could not read HOST_REL_BINS/HOST_STAT_BINS/FACADE_STAT_BINS/TEST_BINS from $stage_tree" >&2
	exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Fake the two build-output dirs with empty, present binaries (this guard does not compile anything).
# REL holds the host-dynamic set plus the host execution unit (kennel-host); STAT holds the static
# in-kennel set: host init, the facades, the spawn unit (kennel-spawn), the shim (kennel), test drivers.
fake_rel="$tmp/rel"; fake_stat="$tmp/stat"
install -d "$fake_rel" "$fake_stat"
for b in $host_rel_bins kennel-host kennel-compose;                                       do : > "$fake_rel/$b";  chmod 0755 "$fake_rel/$b";  done
for b in $host_stat_bins $facade_stat_bins $test_bins kennel kennel-spawn; do : > "$fake_stat/$b"; chmod 0755 "$fake_stat/$b"; done

# Assemble the payload exactly as build-release.sh and the e2e install do.
payload="$tmp/payload"
bash "$stage_tree" --dest "$payload" --rel "$fake_rel" --stat "$fake_stat"

# The payload's three binary subdirs, installer at the root, and NO mirror of the source tree.
[[ -x "$payload/install.sh" ]] || { echo "FAIL: stage-tree did not place install.sh at the payload root" >&2; exit 1; }
for d in bin facades pathbin; do
	[[ -d "$payload/$d" ]] || { echo "FAIL: stage-tree did not create $d/" >&2; exit 1; }
done
if [[ -e "$payload/src" ]] || [[ -e "$payload/target" ]]; then
	echo "FAIL: payload mirrors the source tree (src/ or target/) — it must be flat" >&2
	exit 1
fi

# Every binary install.sh installs must resolve to a file the payload actually contains.
status=0
while read -r src; do
	[[ -e "$src" ]] || { echo "FAIL: install references a missing payload binary: ${src#"$payload"/}" >&2; status=1; }
done < <(
	bash "$payload/install.sh" --dry-run 2>/dev/null \
		| grep -oE "$payload/(bin|facades|pathbin)/[^ ]+" | sort -u
)

# Each subdir holds exactly the source-of-truth set — no dead weight, no missing piece.
check_dir() {
	local dir="$1" expected_list="$2"
	local staged expected
	staged="$(cd "$payload/$dir" && ls | sort)"
	expected="$(printf '%s' "$expected_list" | tr ' ' '\n' | sed '/^$/d' | sort)"
	if [[ "$staged" != "$expected" ]]; then
		echo "FAIL: staged $dir/ does not match its source-of-truth set" >&2
		diff <(printf '%s\n' "$expected") <(printf '%s\n' "$staged") >&2 || true
		status=1
	fi
}
check_dir bin     "$host_rel_bins $host_stat_bins host"
check_dir facades "$facade_stat_bins spawn run-claude.sh"
check_dir pathbin "kennel kennel-compose"

# The integrity manifest must cover EVERYTHING shipped — and the verify must actually pass from the
# payload root. Especially the trust-store public key(s): the anchor the signature chain hangs from.
[[ -f "$payload/SHA256SUMS" ]] || { echo "FAIL: stage-tree did not write a SHA256SUMS manifest" >&2; exit 1; }
if ! ( cd "$payload" && sha256sum -c SHA256SUMS >/dev/null 2>&1 ); then
	echo "FAIL: SHA256SUMS does not verify against the staged payload" >&2
	status=1
fi
while read -r f; do
	rel="${f#"$payload"/}"
	grep -qF "  ./$rel" "$payload/SHA256SUMS" || { echo "FAIL: shipped file not in SHA256SUMS: $rel" >&2; status=1; }
done < <(find "$payload" -type f ! -name SHA256SUMS)
if ! grep -qE '  \./keys/.+\.pub$' "$payload/SHA256SUMS"; then
	echo "FAIL: no trust-store public key (keys/*.pub) in SHA256SUMS — the manifest must cover it" >&2
	status=1
fi

# A release payload must NOT ship the in-cage TEST drivers — they are the test suite, staged only
# under --with-test-bins (for the spawn e2e/bench), never carried by a real release.
for b in $test_bins; do
	[[ -e "$payload/facades/$b" ]] && { echo "FAIL: release payload ships a test-only binary: $b" >&2; status=1; }
done
# …and --with-test-bins must add exactly those drivers, into facades/ (they run in-cage).
payload_t="$tmp/payload-test"
bash "$stage_tree" --dest "$payload_t" --rel "$fake_rel" --stat "$fake_stat" --with-test-bins
for b in $test_bins; do
	[[ -e "$payload_t/facades/$b" ]] || { echo "FAIL: --with-test-bins did not stage the test driver $b into facades/" >&2; status=1; }
done

[[ "$status" -eq 0 ]] && echo "ok: stage-tree.sh payload and install.sh agree (three-dir layout, installer at root, full SHA256SUMS incl. the trust key; test drivers excluded from a release)"
exit "$status"
