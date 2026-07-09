#!/usr/bin/env bash
# Project Kennel dependency audit helper — shell mechanics (§5.5).
#
# The mechanical half of adding a CHECKSUMS.toml entry: fetch the .crate
# independently of Cargo, confirm byte-equality with the vendored artefact, and
# draft the manifest/ledger entries for the reviewer to fill in. It does the
# tarball juggling so the reviewer's job is *reading the source*.
#
# This is the dependency-free shell stand-in for the planned Rust
# `tools/audit-helper`; that one lands once `sha2` is itself vendored (the §5.5.1
# bootstrap). Until then this covers the fetch/hash/draft mechanics.
#
# IMPORTANT — what this does NOT do (by design, §5.5):
#   * It does not perform the human cross-source verification. `verified-against`
#     is left for you to fill after you independently check upstream git tags,
#     signatures (KEYS.md), and docs.rs.
#   * It does not commit anything.
#   * Byte-equality with static.crates.io is ONE source; it is not sufficient on
#     its own (a registry compromise serves the same bytes to both fetches).
#
# bash for arrays/pipefail (§15.4).
set -euo pipefail

# KENNEL_ROOT lets the test harness redirect the archive; default to the repo.
ROOT="${KENNEL_ROOT:-$(git rev-parse --show-toplevel)}"
ARCHIVE="$ROOT/src/vendor"
BASE_URL="https://static.crates.io/crates"

usage() {
	cat >&2 <<-EOF
		usage: audit-helper.sh <command> <name> <version>
		  fetch    download <name>-<version>.crate into src/vendor/ (refuses overwrite)
		  confirm  re-download independently and byte-compare with the vendored .crate
		  draft    print CHECKSUMS.toml + DEPENDENCIES.md drafts for the reviewer to fill
	EOF
	exit 2
}

# Pick a downloader once.
download() { # <url> <dest>
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https' --tlsv1.2 "$1" -o "$2"
	elif command -v wget >/dev/null 2>&1; then
		wget -q --https-only "$1" -O "$2"
	else
		echo "audit-helper: need curl or wget" >&2
		exit 1
	fi
}

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }

crate_url() { echo "$BASE_URL/$1/$1-$2.crate"; }

cmd_fetch() {
	local name="$1" ver="$2"
	mkdir -p "$ARCHIVE"
	local dest="$ARCHIVE/$name-$ver.crate"
	if [ -e "$dest" ]; then
		echo "audit-helper: $dest exists; updates are an explicit rm + re-fetch" >&2
		exit 1
	fi
	download "$(crate_url "$name" "$ver")" "$dest"
	echo "fetched $dest"
	echo "sha256: $(sha256_of "$dest")"
}

cmd_confirm() {
	local name="$1" ver="$2"
	local dest="$ARCHIVE/$name-$ver.crate"
	[ -f "$dest" ] || {
		echo "audit-helper: $dest not vendored yet (run 'fetch' first)" >&2
		exit 1
	}
	local tmp
	tmp="$(mktemp)"
	# shellcheck disable=SC2064
	trap "rm -f '$tmp'" EXIT
	download "$(crate_url "$name" "$ver")" "$tmp"
	if cmp -s "$dest" "$tmp"; then
		echo "confirm: vendored $name-$ver.crate is byte-identical to static.crates.io"
		echo "sha256: $(sha256_of "$dest")"
		echo "NOTE: one source only. Cross-check upstream git tag + signature before recording."
	else
		echo "confirm: MISMATCH — vendored bytes differ from static.crates.io. Do NOT record." >&2
		exit 1
	fi
}

cmd_draft() {
	local name="$1" ver="$2"
	local dest="$ARCHIVE/$name-$ver.crate"
	[ -f "$dest" ] || {
		echo "audit-helper: $dest not vendored yet (run 'fetch' first)" >&2
		exit 1
	}
	local sha
	sha="$(sha256_of "$dest")"
	cat <<-EOF
		# Run tools/audit-source.sh $name $ver first: it confirms this .crate
		# matches the public GitHub source at the release tag (provenance
		# independent of crates.io) and prints a verified-against line to paste.
		#
		# ---- draft CHECKSUMS.toml entry (fill audited-by / verified-against, then commit) ----
		[crate."$name"]
		version = "=$ver"
		crate-sha256 = "$sha"
		audited-by = "<your-maintainer-handle>"
		audited-on = "<ISO-date>"
		verified-against = [
		    "crates.io published .crate (independent download)",
		    "github.com/<org>/<repo> tag v$ver (signature per KEYS.md)",
		    "docs.rs source archive",
		]

		# ---- draft DEPENDENCIES.md entry ----
		## $name

		- **Version:** =$ver (exact pin)
		- **Justification:** <what it does; why we use it not write it (§5.1)>
		- **Licence:** <MIT / BSD / Apache-2.0 / ISC>
		- **Reviewer:** <maintainer who read the source>
		- **Transitive deps added:** <list>
		- **Proc-macros / build.rs:** <none, or note + §5.3 justification>

		Reminder (§5.5): two maintainer approvals; commit CHECKSUMS.toml, the
		.crate, and Cargo.lock together; the reviewer reads the source — the hash
		only proves "what we audited is what we use".
	EOF
}

[ $# -eq 3 ] || usage
case "$1" in
fetch) cmd_fetch "$2" "$3" ;;
confirm) cmd_confirm "$2" "$3" ;;
draft) cmd_draft "$2" "$3" ;;
*) usage ;;
esac
