#!/usr/bin/env bash
# Project Kennel source-provenance verifier (CODING-STANDARDS.md §5.5).
#
# The crates.io .crate sha256 only proves "this is what crates.io served" — it
# is not independent of crates.io. This tool gives the independent check §5.5
# actually wants: it confirms the vendored .crate's source code matches the
# public upstream GitHub repository at the exact commit the crate was published
# from.
#
# How: a published .crate embeds `.cargo_vcs_info.json` recording the upstream
# git commit (sha1) and the crate's path within the repo. We download GitHub's
# tarball for THAT commit and check every source file in the .crate is present,
# byte-identical, in the upstream tree. Files cargo synthesises at publish
# (the normalised Cargo.toml, Cargo.toml.orig, .cargo_vcs_info.json, Cargo.lock)
# are handled explicitly; Cargo.toml.orig is compared to the upstream Cargo.toml.
#
# A PASS means: the code you are about to compile is exactly the public source
# at github.com/<repo>@<sha>. That is provenance crates.io cannot fake without
# also compromising GitHub at that commit.
#
# Usage: audit-source.sh <name> <version> [<org/repo>]
#   The repo is auto-detected from the crate's `repository` field; override it
#   as the third argument if that field is missing or wrong (verify it yourself).
#
# bash for arrays/pipefail (§15.4). Needs: tar, curl, cmp, python3 (json).
set -euo pipefail

ROOT="${KENNEL_ROOT:-$(git rev-parse --show-toplevel)}"
ARCHIVE="$ROOT/crates-archive"

[ $# -ge 2 ] || {
	echo "usage: audit-source.sh <name> <version> [<org/repo>]" >&2
	exit 2
}
NAME="$1"
VER="$2"
REPO_OVERRIDE="${3:-}"

CRATE="$ARCHIVE/$NAME-$VER.crate"
[ -f "$CRATE" ] || {
	echo "audit-source: $CRATE not vendored (run audit-helper.sh fetch first)" >&2
	exit 1
}

TMP="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

# --- unpack the vendored .crate -------------------------------------------
tar -xzf "$CRATE" -C "$TMP"
CRATE_DIR="$TMP/$NAME-$VER"
[ -d "$CRATE_DIR" ] || {
	echo "audit-source: unexpected .crate layout (no $NAME-$VER/ dir)" >&2
	exit 1
}

# --- read the embedded upstream commit + path -----------------------------
VCS="$CRATE_DIR/.cargo_vcs_info.json"
[ -f "$VCS" ] || {
	echo "audit-source: $NAME-$VER has no .cargo_vcs_info.json — cannot tie it to" \
		"an upstream commit. Fall back to a manual tag comparison." >&2
	exit 1
}
SHA="$(python3 -c "import json,sys; print(json.load(open('$VCS'))['git']['sha1'])")"
PATH_IN_VCS="$(python3 -c "import json; print(json.load(open('$VCS')).get('path_in_vcs',''))")"

# --- determine the GitHub repo --------------------------------------------
if [ -n "$REPO_OVERRIDE" ]; then
	SLUG="$REPO_OVERRIDE"
else
	# Read the repository from the NORMALISED Cargo.toml: cargo resolves
	# workspace inheritance (`repository.workspace = true`) there at publish
	# time, whereas Cargo.toml.orig keeps the unresolved form.
	URL="$(grep -m1 -E '^repository[[:space:]]*=[[:space:]]*"' "$CRATE_DIR/Cargo.toml" | sed -E 's/.*"(.*)".*/\1/' || true)"
	case "$URL" in
	*github.com/*) SLUG="$(echo "$URL" | sed -E 's#.*github.com/##; s#\.git$##; s#/+$##' | cut -d/ -f1,2)" ;;
	*)
		echo "audit-source: crate's repository is not a github.com URL ('$URL')." >&2
		echo "  Pass the repo explicitly: audit-source.sh $NAME $VER <org/repo>" >&2
		exit 1
		;;
	esac
fi
echo "crate repository : github.com/$SLUG"
echo "published commit : $SHA${PATH_IN_VCS:+  (path: $PATH_IN_VCS)}"

# --- fetch the upstream tree at that exact commit -------------------------
echo "fetching github.com/$SLUG @ $SHA ..."
curl -fsSL "https://codeload.github.com/$SLUG/tar.gz/$SHA" -o "$TMP/upstream.tgz"
mkdir "$TMP/upstream"
tar -xzf "$TMP/upstream.tgz" -C "$TMP/upstream"
TOP="$(find "$TMP/upstream" -maxdepth 1 -mindepth 1 -type d)"
REPO_BASE="$TOP"
[ -n "$PATH_IN_VCS" ] && REPO_BASE="$TOP/$PATH_IN_VCS"
[ -d "$REPO_BASE" ] || {
	echo "audit-source: path '$PATH_IN_VCS' not found in the upstream tree" >&2
	exit 1
}

# --- compare every crate source file against the upstream tree ------------
# cargo-synthesised files are handled explicitly, not byte-compared as source.
skip_re='^(Cargo\.toml|Cargo\.toml\.orig|\.cargo_vcs_info\.json|Cargo\.lock)$'
matched=0
mismatched=()
missing=()

while IFS= read -r -d '' f; do
	rel="${f#"$CRATE_DIR"/}"
	if [[ "$rel" =~ $skip_re ]]; then
		continue
	fi
	up="$REPO_BASE/$rel"
	root="$TOP/$rel"
	if [ -f "$up" ] && cmp -s "$f" "$up"; then
		matched=$((matched + 1))
	elif [ "$REPO_BASE" != "$TOP" ] && [ -f "$root" ] && cmp -s "$f" "$root"; then
		# A repo-root file (README, LICENSE-*) that cargo pulls into a
		# sub-crate's package from the workspace root.
		matched=$((matched + 1))
	elif [ -f "$up" ]; then
		mismatched+=("$rel")
	else
		missing+=("$rel")
	fi
done < <(find "$CRATE_DIR" -type f -print0)

# Cargo.toml.orig is the upstream manifest cargo copied in verbatim: it must
# match the repo's Cargo.toml. The normalised Cargo.toml is cargo's own output.
manifest_note="(no Cargo.toml.orig)"
if [ -f "$CRATE_DIR/Cargo.toml.orig" ]; then
	if cmp -s "$CRATE_DIR/Cargo.toml.orig" "$REPO_BASE/Cargo.toml"; then
		manifest_note="Cargo.toml.orig == upstream Cargo.toml"
	else
		manifest_note="Cargo.toml.orig DIFFERS from upstream Cargo.toml — inspect"
	fi
fi

# --- confirm the published commit is the release tag ----------------------
# Resolve the version's git tag (via the GitHub API, which dereferences
# annotated tags to their commit) and confirm it equals the published commit.
# This closes the loop: .crate <- published from commit X <- which is tag <ver>.
tag_status="UNVERIFIED (no tag matched '$VER' or 'v$VER' — confirm manually)"
tag_problem=0
for tag in "$VER" "v$VER"; do
	tag_sha="$(curl -fsSL "https://api.github.com/repos/$SLUG/commits/$tag" 2>/dev/null |
		python3 -c "import json,sys; print(json.load(sys.stdin).get('sha',''))" 2>/dev/null || true)"
	[ -n "$tag_sha" ] || continue
	if [ "$tag_sha" = "$SHA" ]; then
		tag_status="tag '$tag' -> the published commit"
		TAG_USED="$tag"
	else
		tag_status="MISMATCH — tag '$tag' is $tag_sha, not the published $SHA"
		tag_problem=1
	fi
	break
done

echo
echo "source files byte-identical : $matched"
echo "manifest                    : $manifest_note"
echo "release tag                 : $tag_status"

problem=0
if [ "${#mismatched[@]}" -gt 0 ]; then
	problem=1
	echo "DIFFERING files (${#mismatched[@]}):" >&2
	printf '  %s\n' "${mismatched[@]}" >&2
fi
if [ "${#missing[@]}" -gt 0 ]; then
	problem=1
	echo "files in .crate but NOT in upstream (${#missing[@]}):" >&2
	printf '  %s\n' "${missing[@]}" >&2
fi

echo
if [ "$problem" -ne 0 ] || [ "$tag_problem" -ne 0 ] || [[ "$manifest_note" == *DIFFERS* ]]; then
	echo "audit-source: PROBLEM — the .crate does not cleanly match the upstream source." >&2
	echo "Do NOT record this dependency until the differences are explained." >&2
	exit 1
fi

echo "audit-source: PASS — every source file in $NAME-$VER.crate is byte-identical"
echo "to github.com/$SLUG @ $SHA${TAG_USED:+ (tag $TAG_USED)}."
echo
echo "verified-against line for CHECKSUMS.toml:"
echo "    \"github.com/$SLUG @ $SHA${TAG_USED:+ (tag $TAG_USED)} — $matched source files byte-identical via tools/audit-source.sh\","
if [ -z "${TAG_USED:-}" ]; then
	echo "NOTE: the release tag was not auto-confirmed; verify the commit corresponds" >&2
	echo "to the published version before recording." >&2
fi
