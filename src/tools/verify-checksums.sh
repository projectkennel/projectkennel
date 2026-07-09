#!/usr/bin/env bash
# Project Kennel checksum verifier — independent shell witness (§5.5.1).
#
# The second of the two verifier paths required by CODING-STANDARDS.md §5.5:
# this one uses only the system `sha256sum` (coreutils), so a compromise of the
# `sha2` crate that the Rust verifier (tools/verify-checksums) depends on cannot
# also subvert this check. CI and the maintainer release checklist run both and
# require them to agree.
#
# It enforces CHECKSUMS.toml as the integrity ground truth against the vendored
# .crate artefacts and Cargo.lock:
#
#   1. every src/vendor/*.crate is recorded in CHECKSUMS.toml,
#   2. every CHECKSUMS.toml entry has its .crate in src/vendor/,
#   3. every computed SHA-256 matches the manifest,
#   4. every registry crate in Cargo.lock is pinned in the manifest,
#   5. every Cargo.lock registry checksum equals our manifest hash.
#
# With no dependencies yet, the manifest and archive are empty and every check
# passes vacuously; the script is correct and ready for the first vendored dep.
#
# bash: associative arrays, to cross-reference three sources (§15.4).
set -euo pipefail

# Allow the test harness to point at a fixture tree; default to the repo root.
ROOT="${KENNEL_VERIFY_ROOT:-$(git rev-parse --show-toplevel)}"
MANIFEST="$ROOT/supply-chain/CHECKSUMS.toml"
ARCHIVE="$ROOT/src/vendor"
LOCK="$ROOT/Cargo.lock"

errors=0
err() {
	echo "verify-checksums: FAIL: $1" >&2
	errors=$((errors + 1))
}

# --- parse CHECKSUMS.toml -> "<name>\t<version>\t<sha>" ---------------------
# Assumes the documented field order (version before crate-sha256) within each
# [crate."<name>"] block.
parse_manifest() {
	[[ -f "$MANIFEST" ]] || return 0
	awk '
		/^\[crate\."/      { name=$0; sub(/^\[crate\."/,"",name); sub(/"\].*$/,"",name); ver=""; sha=""; next }
		/^version[ \t]*=/      { v=$0; sub(/^version[ \t]*=[ \t]*"/,"",v); sub(/".*/,"",v); sub(/^=/,"",v); ver=v }
		/^crate-sha256[ \t]*=/ { s=$0; sub(/^crate-sha256[ \t]*=[ \t]*"/,"",s); sub(/".*/,"",s); sha=s;
		                         if (name!="" && ver!="" && sha!="") print name "\t" ver "\t" sha }
	' "$MANIFEST"
}

# --- parse Cargo.lock registry packages -> "<name>\t<version>\t<checksum>" --
parse_lock() {
	[[ -f "$LOCK" ]] || return 0
	awk '
		/^\[\[package\]\]/ { name=""; ver=""; src=""; sum=""; inpkg=1; next }
		inpkg && /^name = "/     { name=$0; sub(/^name = "/,"",name); sub(/".*/,"",name) }
		inpkg && /^version = "/  { ver=$0;  sub(/^version = "/,"",ver); sub(/".*/,"",ver) }
		inpkg && /^source = "/   { src=$0;  sub(/^source = "/,"",src); sub(/".*/,"",src) }
		inpkg && /^checksum = "/ { sum=$0;  sub(/^checksum = "/,"",sum); sub(/".*/,"",sum) }
		/^[[:space:]]*$/ { if (inpkg && src ~ /registry/) print name "\t" ver "\t" sum; inpkg=0 }
		END { if (inpkg && src ~ /registry/) print name "\t" ver "\t" sum }
	' "$LOCK"
}

declare -A manifest_sha=() # "<name> <version>" -> sha
declare -A claimed=()      # src/vendor filename -> 1 (matched a manifest entry)

# Load the manifest and verify each entry's artefact (checks 2 and 3).
n_entries=0
while IFS=$'\t' read -r name ver sha; do
	[[ -n "$name" ]] || continue
	n_entries=$((n_entries + 1))
	manifest_sha["$name $ver"]="$sha"
	file="$ARCHIVE/$name-$ver.crate"
	if [[ ! -f "$file" ]]; then
		err "manifest entry $name $ver has no $name-$ver.crate in src/vendor/"
		continue
	fi
	got="$(sha256sum "$file" | cut -d' ' -f1)"
	if [[ "$got" != "$sha" ]]; then
		err "hash mismatch for $name-$ver.crate: manifest $sha, computed $got"
	fi
	claimed["$name-$ver.crate"]=1
done < <(parse_manifest)

# Every artefact on disk must be claimed by a manifest entry (check 1).
if [[ -d "$ARCHIVE" ]]; then
	while IFS= read -r path; do
		[[ -n "$path" ]] || continue
		base="$(basename "$path")"
		if [ -z "${claimed[$base]:-}" ]; then
			err "src/vendor/$base is not recorded in CHECKSUMS.toml"
		fi
	done < <(find "$ARCHIVE" -maxdepth 1 -name '*.crate' -type f 2>/dev/null)
fi

# Cargo.lock cross-checks (checks 4 and 5).
n_lock=0
while IFS=$'\t' read -r name ver sum; do
	[[ -n "$name" ]] || continue
	n_lock=$((n_lock + 1))
	want="${manifest_sha["$name $ver"]:-}"
	if [[ -z "$want" ]]; then
		err "Cargo.lock references $name $ver, which is not pinned in CHECKSUMS.toml"
	elif [[ -n "$sum" ]] && [[ "$sum" != "$want" ]]; then
		err "Cargo.lock checksum for $name $ver disagrees with CHECKSUMS.toml"
	fi
done < <(parse_lock)

if [[ "$errors" -ne 0 ]]; then
	echo "verify-checksums: $errors problem(s) found" >&2
	exit 1
fi
echo "verify-checksums: OK ($n_entries manifest entries, $n_lock registry crates in Cargo.lock)"
