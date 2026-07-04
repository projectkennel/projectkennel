#!/usr/bin/env bash
# Tests for tools/install-ci-tools.sh (offline; §5.5 / §15.4 spirit).
#
# Network downloading is not exercised here — the real upstream fetches are
# validated by hand at pin time. What matters for security is the verify/extract
# decision: a matching hash installs, any mismatch or unratified-placeholder
# hash refuses, offline-with-no-cache refuses, and the per-arch selection picks
# the host's artifact (falling back to a pinned-source build, refusing when
# neither exists). Those are driven from a fixture manifest + fixture archives
# seeded in the cache (CI_TOOLS_OFFLINE=1, so the script never reaches the
# network; CI_TOOLS_ARCH=testarch, so the host's real arch is irrelevant).
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
mkdir -p "$root/src/tools" "$root/cache"
cp "$TMP/faketool-1.0.tar.gz" "$root/cache/faketool-1.0.tar.gz"

write_manifest() { # <sha> <audited-by> [<arch>]
	cat >"$root/src/tools/ci-tools.toml" <<-EOF
		[tool."faketool"]
		version = "1.0"

		[tool."faketool".artifact."${3:-testarch}"]
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
		CI_TOOLS_ARCH=testarch "$SCRIPT" "$root/bin" >/dev/null 2>&1 || rc=$?
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

# 7. Artifact pinned only for a DIFFERENT arch, no source fallback: refuses
#    (exit 2) — the manifest cannot serve this host.
write_manifest "$good_sha" "remco" "otherarch"
run
check "no artifact for host arch refuses" 2 "$rc"
[ -x "$root/bin/faketool" ] && bp=1 || bp=0
check "no binary placed when arch is unserved" 0 "$bp"

# 8. Two artifacts: the non-matching arch's entry (even with a refusal-grade
#    PENDING hash) is ignored; the host arch's good entry installs.
cat >"$root/src/tools/ci-tools.toml" <<-EOF
	[tool."faketool"]
	version = "1.0"

	[tool."faketool".artifact."otherarch"]
	url = "https://example.invalid/faketool-1.0-otherarch.tar.gz"
	archive-sha256 = "PENDING"
	bin-path = "pkg/faketool"
	audited-by = "PENDING"

	[tool."faketool".artifact."testarch"]
	url = "https://example.invalid/faketool-1.0.tar.gz"
	archive-sha256 = "$good_sha"
	bin-path = "pkg/faketool"
	audited-by = "remco"
	EOF
run
check "selection picks the host arch among multiple artifacts" 0 "$rc"

# 9. Source fallback: no artifact for the host arch, but an artifact."source"
#    pins a buildable crate tarball — hash-verified, then cargo-built (offline:
#    the fixture crate has no dependencies). Needs cargo; skipped without it.
if command -v cargo >/dev/null 2>&1; then
	# The fixture crate lives outside the repo, where rustup may have no default
	# toolchain — pin this shell to the repo's (the test runs from the repo).
	if command -v rustup >/dev/null 2>&1; then
		tc="$(rustup show active-toolchain 2>/dev/null | awk 'NR==1{print $1}')"
		[ -n "$tc" ] && export RUSTUP_TOOLCHAIN="$tc"
	fi
	srcdir="$TMP/srcbuild/faketool-1.0"
	mkdir -p "$srcdir/src"
	cat >"$srcdir/Cargo.toml" <<-EOF
		[package]
		name = "faketool"
		version = "1.0.0"
		edition = "2021"
	EOF
	printf 'fn main() { println!("faketool 1.0.0"); }\n' >"$srcdir/src/main.rs"
	(cd "$srcdir" && cargo generate-lockfile --offline --quiet)
	tar -C "$TMP/srcbuild" -czf "$TMP/faketool-src.tar.gz" faketool-1.0
	src_sha="$(sha256sum "$TMP/faketool-src.tar.gz" | cut -d' ' -f1)"
	# the installer caches a source tarball under <name>-<version>-<basename>
	cp "$TMP/faketool-src.tar.gz" "$root/cache/faketool-1.0-source.tar.gz"
	cat >"$root/src/tools/ci-tools.toml" <<-EOF
		[tool."faketool"]
		version = "1.0"

		[tool."faketool".artifact."source"]
		url = "https://example.invalid/source.tar.gz"
		archive-sha256 = "$src_sha"
		src-path = "faketool-1.0"
		audited-by = "remco"
	EOF
	run
	check "source fallback builds and installs" 0 "$rc"
	[ -x "$root/bin/faketool" ] && bp=0 || bp=1
	check "source-built binary is present and executable" 0 "$bp"
else
	echo "skip: cargo not on PATH — source-fallback build not exercised" >&2
fi

echo "install-ci-tools tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
