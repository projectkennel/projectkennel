#!/usr/bin/env bash
# Project Kennel — CI tool installer (CODING-STANDARDS.md §5.5, §14).
#
# Installs the supply-chain gate's tools (cargo-deny, cargo-audit, cargo-vet) by
# downloading the exact prebuilt binaries pinned in tools/ci-tools.toml and
# verifying each archive's SHA-256 against that manifest BEFORE extracting it.
# This is the install path the offline `.cargo/config.toml` forces on us:
# `cargo install` cannot resolve these tools (crates.io is replaced by the local
# registry), so we treat the upstream release binary exactly as we treat a
# vendored .crate — pin it, hash it, refuse anything that does not match.
#
# A post-publish swap of a GitHub release asset is therefore caught here: the
# manifest hash is authoritative, not whatever the server currently serves.
#
# Usage:
#   tools/install-ci-tools.sh [<bindir>]
#     <bindir>  where to place the verified binaries (default: $ROOT/.ci-tools/bin)
#
# Env:
#   KENNEL_ROOT       repo root override (default: git toplevel)
#   CI_TOOLS_CACHE    archive download cache (default: $ROOT/.ci-tools/cache)
#   CI_TOOLS_OFFLINE  if set, never fetch; require the archive already in cache
#                     (used by the offline test harness)
#
# On success the binaries are in <bindir>; add it to PATH. Exit codes:
#   0 ok · 1 verification/extract failure · 2 usage/manifest error · 3 download failure
#
# bash for arrays/pipefail (§15.4); coreutils sha256sum is the only crypto, as in
# verify-checksums.sh (no hand-rolled hashing).
set -euo pipefail

ROOT="${KENNEL_ROOT:-$(git rev-parse --show-toplevel)}"
MANIFEST="$ROOT/tools/ci-tools.toml"
BINDIR="${1:-$ROOT/.ci-tools/bin}"
CACHE="${CI_TOOLS_CACHE:-$ROOT/.ci-tools/cache}"

[ -f "$MANIFEST" ] || { echo "install-ci-tools: no manifest at $MANIFEST" >&2; exit 2; }

# --- parse ci-tools.toml -> "<name>\t<url>\t<sha>\t<bin-path>\t<audited-by>" ---
# Assumes the documented field order within each [tool."<name>"] block.
parse_tools() {
	awk '
		/^\[tool\."/          { flush(); name=$0; sub(/^\[tool\."/,"",name); sub(/"\].*$/,"",name); next }
		/^url[ \t]*=/         { url=val() }
		/^archive-sha256[ \t]*=/ { sha=val() }
		/^bin-path[ \t]*=/    { bin=val() }
		/^audited-by[ \t]*=/  { by=val() }
		END { flush() }
		function val(   v) { v=$0; sub(/^[^=]*=[ \t]*"/,"",v); sub(/".*/,"",v); return v }
		function flush() {
			if (name!="") print name "\t" url "\t" sha "\t" bin "\t" by
			name=""; url=""; sha=""; bin=""; by=""
		}
	' "$MANIFEST"
}

download() { # <url> <dest>
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1" -o "$2"
	elif command -v wget >/dev/null 2>&1; then
		wget -q "$1" -O "$2"
	else
		echo "install-ci-tools: need curl or wget" >&2; exit 3
	fi
}

mkdir -p "$BINDIR" "$CACHE"
n=0
while IFS=$'\t' read -r name url sha bin by; do
	[ -n "$name" ] || continue
	n=$((n + 1))

	case "$sha" in
		"" | PENDING | TODO | TODO-* )
			echo "install-ci-tools: $name has no usable archive-sha256 (\"$sha\") — refusing (§5.5)" >&2
			exit 1 ;;
	esac

	archive="$CACHE/$(basename "$url")"
	if [ ! -f "$archive" ]; then
		if [ -n "${CI_TOOLS_OFFLINE:-}" ]; then
			echo "install-ci-tools: offline and $archive not cached" >&2; exit 3
		fi
		echo "install-ci-tools: downloading $name ($url)" >&2
		download "$url" "$archive.part"
		mv "$archive.part" "$archive"
	fi

	got="$(sha256sum "$archive" | cut -d' ' -f1)"
	if [ "$got" != "$sha" ]; then
		echo "install-ci-tools: SHA-256 mismatch for $name" >&2
		echo "  manifest: $sha" >&2
		echo "  computed: $got" >&2
		rm -f "$archive" # do not keep a non-matching artefact around
		exit 1
	fi

	# Extract just the pinned binary. GNU tar autodetects gz/xz/etc. on read.
	tmp="$(mktemp -d)"
	if ! tar -C "$tmp" -xf "$archive" "$bin" 2>/dev/null; then
		echo "install-ci-tools: $name archive has no member '$bin'" >&2
		rm -rf "$tmp"; exit 1
	fi
	install -m 0755 "$tmp/$bin" "$BINDIR/$name"
	rm -rf "$tmp"

	if [ "$by" = "PENDING" ] || [ -z "$by" ]; then
		echo "install-ci-tools: WARNING: $name is verified-by-hash but the §5.5 second" >&2
		echo "  approval is still PENDING (tools/ci-tools.toml) — gate must stay non-required" >&2
	fi
	echo "install-ci-tools: $name OK -> $BINDIR/$name" >&2
done < <(parse_tools)

[ "$n" -gt 0 ] || { echo "install-ci-tools: manifest has no [tool.*] entries" >&2; exit 2; }
echo "install-ci-tools: $n tool(s) installed in $BINDIR" >&2
echo "$BINDIR" # stdout: the bindir, so callers can `PATH="$(tools/install-ci-tools.sh):$PATH"`
