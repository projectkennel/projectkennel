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
# The manifest pins one artifact per arch (`[tool."<name>".artifact."<arch>"]`,
# keyed by `uname -m`); this script installs the artifact matching the host, so
# the gate runs on the x86_64 CI runners and an aarch64 dev host alike. A tool
# whose upstream ships no binary for the host arch pins an `artifact."source"`
# fallback instead: the hash-verified release source tarball, built here with
# `cargo install --locked` (the tarball's committed Cargo.lock pins every
# dependency, and cargo enforces it). A source build takes minutes, so a binary
# already in <bindir> at the pinned version is reused.
#
# Usage:
#   tools/install-ci-tools.sh [<bindir>]
#     <bindir>  where to place the verified binaries (default: $ROOT/.ci-tools/bin)
#
# Env:
#   KENNEL_ROOT       repo root override (default: git toplevel)
#   CI_TOOLS_CACHE    archive download cache (default: $ROOT/.ci-tools/cache)
#   CI_TOOLS_OFFLINE  if set, never fetch; require the archive already in cache,
#                     and pass --offline to any source build
#                     (used by the offline test harness)
#   CI_TOOLS_ARCH     host arch override (default: uname -m; the test harness
#                     pins it so fixtures are host-independent)
#
# On success the binaries are in <bindir>; add it to PATH. Exit codes:
#   0 ok · 1 verification/extract/build failure · 2 usage/manifest error
#   3 download failure or missing downloader/toolchain
#
# bash for arrays/pipefail (§15.4); coreutils sha256sum is the only crypto, as in
# verify-checksums.sh (no hand-rolled hashing).
set -euo pipefail

ROOT="${KENNEL_ROOT:-$(git rev-parse --show-toplevel)}"
MANIFEST="$ROOT/src/tools/ci-tools.toml"
BINDIR="${1:-$ROOT/.ci-tools/bin}"
CACHE="${CI_TOOLS_CACHE:-$ROOT/.ci-tools/cache}"
HOSTARCH="${CI_TOOLS_ARCH:-$(uname -m)}"

[ -f "$MANIFEST" ] || { echo "install-ci-tools: no manifest at $MANIFEST" >&2; exit 2; }

# --- parse ci-tools.toml ---------------------------------------------------
# One row per [tool."<name>".artifact."<arch>"] block:
#   "<name>|<version>|<arch>|<url>|<sha>|<bin-path>|<src-path>|<audited-by>"
# ('|' because empty fields survive it — a binary artifact has no src-path, a
# source artifact no bin-path, and tab is IFS whitespace so empties would
# collapse). `version` comes from the enclosing [tool."<name>"] block. Assumes
# the documented field order within each block.
parse_tools() {
	awk '
		/^\[tool\."/ {
			flush()
			line=$0
			if (line ~ /\.artifact\."/) {
				n=line; sub(/^\[tool\."/,"",n); sub(/"\..*$/,"",n)
				a=line; sub(/^.*artifact\."/,"",a); sub(/"\].*$/,"",a)
				name=n; arch=a
			} else {
				n=line; sub(/^\[tool\."/,"",n); sub(/"\].*$/,"",n)
				name=n; ver=""
			}
			next
		}
		/^version[ \t]*=/        { ver=val() }
		/^url[ \t]*=/            { url=val() }
		/^archive-sha256[ \t]*=/ { sha=val() }
		/^bin-path[ \t]*=/       { bin=val() }
		/^src-path[ \t]*=/       { src=val() }
		/^audited-by[ \t]*=/     { by=val() }
		END { flush() }
		function val(   v) { v=$0; sub(/^[^=]*=[ \t]*"/,"",v); sub(/".*/,"",v); return v }
		function flush() {
			if (arch!="") print name "|" ver "|" arch "|" url "|" sha "|" bin "|" src "|" by
			arch=""; url=""; sha=""; bin=""; src=""; by=""
		}
	' "$MANIFEST"
}

download() { # <url> <dest>
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https' --tlsv1.2 "$1" -o "$2"
	elif command -v wget >/dev/null 2>&1; then
		wget -q --https-only "$1" -O "$2"
	else
		echo "install-ci-tools: need curl or wget" >&2; exit 3
	fi
}

# --- select one artifact per tool: exact host arch, else the source fallback ---
declare -A ROW_EXACT ROW_SOURCE SEEN
NAMES=()
while IFS='|' read -r name ver arch url sha bin src by; do
	[ -n "$name" ] || continue
	if [ -z "${SEEN[$name]:-}" ]; then SEEN[$name]=1; NAMES+=("$name"); fi
	row="$ver|$arch|$url|$sha|$bin|$src|$by"
	case "$arch" in
		"$HOSTARCH") ROW_EXACT[$name]="$row" ;;
		source)      ROW_SOURCE[$name]="$row" ;;
	esac
done < <(parse_tools)

[ "${#NAMES[@]}" -gt 0 ] || { echo "install-ci-tools: manifest has no [tool.*] entries" >&2; exit 2; }

mkdir -p "$BINDIR" "$CACHE"
for name in "${NAMES[@]}"; do
	row="${ROW_EXACT[$name]:-${ROW_SOURCE[$name]:-}}"
	if [ -z "$row" ]; then
		echo "install-ci-tools: $name pins no artifact for host arch '$HOSTARCH' and no \"source\" fallback" >&2
		exit 2
	fi
	IFS='|' read -r ver arch url sha bin src by <<<"$row"

	case "$sha" in
		"" | PENDING | TODO | TODO-* )
			echo "install-ci-tools: $name has no usable archive-sha256 (\"$sha\") — refusing (§5.5)" >&2
			exit 1 ;;
	esac
	if [ "$by" = "PENDING" ] || [ -z "$by" ]; then
		echo "install-ci-tools: WARNING: $name ($arch) is verified-by-hash but the §5.5 second" >&2
		echo "  approval is still PENDING (tools/ci-tools.toml)" >&2
	fi

	# A source build takes minutes; reuse a previous build at the pinned version.
	if [ "$arch" = "source" ] && [ -x "$BINDIR/$name" ] \
		&& "$BINDIR/$name" --version 2>/dev/null | grep -qF "$ver"; then
		echo "install-ci-tools: $name $ver already built -> $BINDIR/$name" >&2
		continue
	fi

	# Cache key: the asset basename — except source tarballs, which upstream
	# names generically (source.tar.gz), so those get a <name>-<version> prefix.
	case "$arch" in
		source) archive="$CACHE/$name-$ver-$(basename "$url")" ;;
		*)      archive="$CACHE/$(basename "$url")" ;;
	esac
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

	tmp="$(mktemp -d)"
	if [ "$arch" = "source" ]; then
		command -v cargo >/dev/null 2>&1 || {
			echo "install-ci-tools: $name needs a source build on $HOSTARCH but cargo is not on PATH" >&2
			rm -rf "$tmp"; exit 3; }
		if ! tar -C "$tmp" -xf "$archive" || [ ! -d "$tmp/$src" ]; then
			echo "install-ci-tools: $name source archive has no directory '$src'" >&2
			rm -rf "$tmp"; exit 1
		fi
		echo "install-ci-tools: building $name $ver from pinned source (cargo install --locked)" >&2
		# Build with CWD OUTSIDE the repo: cargo reads config from the working
		# directory upward, and the repo's offline `.cargo/config.toml` replaces
		# crates.io with the local registry, which cannot serve the tool's dep
		# tree. The toolchain still comes from the repo's pin — resolved here
		# explicitly, since outside the repo rustup may have no default.
		if command -v rustup >/dev/null 2>&1; then
			tc="$(cd "$ROOT" && rustup show active-toolchain 2>/dev/null | awk 'NR==1{print $1}')"
			[ -n "$tc" ] && export RUSTUP_TOOLCHAIN="$tc"
		fi
		if ! (cd "$tmp/$src" && cargo install --locked ${CI_TOOLS_OFFLINE:+--offline} --quiet \
			--path . --root "$tmp/inst") >&2; then
			echo "install-ci-tools: $name source build failed" >&2
			rm -rf "$tmp"; exit 1
		fi
		install -m 0755 "$tmp/inst/bin/$name" "$BINDIR/$name"
	else
		# Extract just the pinned binary. GNU tar autodetects gz/xz/etc. on read.
		if ! tar -C "$tmp" -xf "$archive" "$bin" 2>/dev/null; then
			echo "install-ci-tools: $name archive has no member '$bin'" >&2
			rm -rf "$tmp"; exit 1
		fi
		install -m 0755 "$tmp/$bin" "$BINDIR/$name"
	fi
	rm -rf "$tmp"

	echo "install-ci-tools: $name OK -> $BINDIR/$name" >&2
done

echo "install-ci-tools: ${#NAMES[@]} tool(s) installed in $BINDIR" >&2
echo "$BINDIR" # stdout: the bindir, so callers can `PATH="$(tools/install-ci-tools.sh):$PATH"`
