#!/usr/bin/env bash
#
# Guard: a spawn-target template must not point at a workload/exec binary that does not exist.
#
# The rot this catches, from the tree it shipped in: three spawn templates (pure-compute,
# scratch-fs, net-fetch) referenced `/usr/libexec/kennel/mcp-{compute,scratch,fetch}` workload
# binaries that were never built — no source, no staged payload, no install. They COMPILE
# clean (the loader-resolution pass silently skips a missing binary), so nothing caught it;
# a spawn of any of them 127s at execve. This gate makes a dead-binary workload fail CI.
#
# For each shipped template that is a SPAWN TARGET (carries a `[[mutable]]` manifest — the
# thing an agent instantiates), every ABSOLUTE path in `[exec].allow` and the `[workload].argv`
# entrypoint must resolve to a real binary:
#   * a host system binary (`/bin/*`, `/usr/bin/*`, …): exists on the build host; and
#   * a kennel-shipped binary (`/usr/libexec/kennel*/*`): present in the staged payload tree.
# A `~`/relative/`$VAR` path is a runtime-resolved value, not a build-time binary — skipped.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$repo_root"

templates_dir="toml/templates"
# The staged payload's kennel binary dirs (a kennel-shipped exec path must live here). The
# stage tree is built on demand so the check does not depend on a prior `make`.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
if ! bash "$repo_root/src/tools/stage-tree.sh" --dest "$stage" --with-test-bins >/dev/null 2>&1; then
	echo "spawn-target-binaries: could not stage the payload tree" >&2
	exit 2
fi

# Is an absolute path a real binary? Host paths must exist on the host; kennel-libexec paths
# must exist in the staged payload (bin/ or facades/, flattened by stage-tree).
binary_exists() {
	local path="$1" base
	case "$path" in
		/usr/libexec/kennel*/*)
			base="$(basename "$path")"
			[[ -e "$stage/bin/$base" || -e "$stage/facades/$base" || -e "$stage/pathbin/$base" ]]
			;;
		/*)
			[[ -e "$path" ]]
			;;
		*)
			# Not an absolute path (a `~`/relative/`$VAR` runtime value) — not our concern.
			return 0
			;;
	esac
}

fail=0
checked=0
for dir in "$templates_dir"/*/; do
	f="$dir/policy.toml"
	[[ -f "$f" ]] || continue
	name="$(basename "$dir")"
	# A spawn target carries a `[[mutable]]` manifest. Non-spawn templates (bases,
	# service kennels) are out of scope for this gate.
	grep -q '^\[\[mutable\]\]' "$f" || continue
	checked=$((checked + 1))

	# Collect the absolute paths named by `[exec].allow` (bare-list or `.add` deltas) and
	# the `[workload].argv[0]` entrypoint. A crude but faithful extractor: every quoted
	# absolute path on an `allow`/`path`/`argv` line.
	paths="$(grep -E '^\s*(allow|argv|path)\s*=|^\s*"/' "$f" \
		| grep -oE '"/[^"]+"' | tr -d '"' | sort -u)"

	for p in $paths; do
		if ! binary_exists "$p"; then
			echo "spawn-target-binaries: FAIL: $name references a non-existent binary: $p" >&2
			fail=1
		fi
	done
done

if [[ "$fail" -ne 0 ]]; then
	echo "spawn-target-binaries: a spawn target points at a binary that does not exist (dead workload)." >&2
	exit 1
fi
echo "spawn-target-binaries: OK — $checked spawn target(s), every exec/workload binary resolves"
