#!/usr/bin/env bash
# Tests for tools/install-ci-tools.sh (offline; §5.5 / §15.4 spirit).
#
# Network downloading is not exercised here — the real upstream fetches are
# validated by hand at pin time. What matters for security is the verify/extract
# decision: a matching hash installs, any mismatch or unratified-placeholder
# hash refuses, and offline-with-no-cache refuses. Those are driven from a
# fixture manifest + a fixture archive seeded in the cache (CI_TOOLS_OFFLINE=1,
# so the script never reaches the network).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../install-ci-tools.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
check() { # <desc> <expected-rc> <actual-rc>
	if [ "$2" -eq "$3" ]; then pass=$((pass + 1)); else
		fail=$((fail + 1))
		echo "FAIL: $1 (wanted rc $2, got $3)" >&2
	fi
}

# Build a fixture archive: pkg/faketool, gzip-compressed tarball.
mkdir -p "$TMP/build/pkg"
printf '#!/bin/sh\necho faketool\n' >"$TMP/build/pkg/faketool"
chmod +x "$TMP/build/pkg/faketool"
tar -C "$TMP/build" -czf "$TMP/faketool-1.0.tar.gz" pkg/faketool
good_sha="$(sha256sum "$TMP/faketool-1.0.tar.gz" | cut -d' ' -f1)"

# A fixture repo root with a tools/ci-tools.toml and a seeded cache.
root="$TMP/root"
mkdir -p "$root/tools" "$root/cache"
cp "$TMP/faketool-1.0.tar.gz" "$root/cache/faketool-1.0.tar.gz"

write_manifest() { # <sha> <audited-by>
	cat >"$root/tools/ci-tools.toml" <<-EOF
		[tool."faketool"]
		version = "1.0"
		url = "https://example.invalid/faketool-1.0.tar.gz"
		archive-sha256 = "$1"
		bin-path = "pkg/faketool"
		audited-by = "$2"
	EOF
}

run() { # sets global rc; installs into a fresh bindir
	rm -rf "$root/bin"
	rc=0
	KENNEL_ROOT="$root" CI_TOOLS_CACHE="$root/cache" CI_TOOLS_OFFLINE=1 \
		"$SCRIPT" "$root/bin" >/dev/null 2>&1 || rc=$?
}

# 1. Matching hash + ratified entry: installs, binary present, exit 0.
write_manifest "$good_sha" "remco"
run
check "matching hash installs" 0 "$rc"
[ -x "$root/bin/faketool" ] && bp=0 || bp=1
check "installed binary is present and executable" 0 "$bp"

# 2. Hash mismatch: refuses (exit 1), no binary placed.
write_manifest "0000000000000000000000000000000000000000000000000000000000000000" "remco"
run
check "hash mismatch refuses" 1 "$rc"
[ -x "$root/bin/faketool" ] && bp=1 || bp=0
check "no binary placed on mismatch" 0 "$bp"
# the cache copy is restored for later cases (mismatch deletes it)
cp "$TMP/faketool-1.0.tar.gz" "$root/cache/faketool-1.0.tar.gz"

# 3. Placeholder PENDING hash: refuses (exit 1) — never installs an unpinned tool.
write_manifest "PENDING" "remco"
run
check "PENDING archive-sha256 refuses" 1 "$rc"

# 4. Empty hash: refuses (exit 1).
write_manifest "" "remco"
run
check "empty archive-sha256 refuses" 1 "$rc"

# 5. Ratified-but-uncached + offline: refuses with the download exit code (3).
write_manifest "$good_sha" "remco"
rm -f "$root/cache/faketool-1.0.tar.gz"
run
check "offline with no cache refuses (download error)" 3 "$rc"
cp "$TMP/faketool-1.0.tar.gz" "$root/cache/faketool-1.0.tar.gz"

# 6. Matching hash but PENDING approval still installs (hash is the integrity
#    gate; the second-approval governance gate is branch-protection, not this).
write_manifest "$good_sha" "PENDING"
run
check "PENDING approval still installs (warns only)" 0 "$rc"

echo "install-ci-tools tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
