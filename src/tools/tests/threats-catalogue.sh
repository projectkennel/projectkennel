#!/usr/bin/env bash
# Sync check: dist/threats/catalogue.toml must cover exactly the same threat ids,
# at the same version, as the canonical docs/reference/THREATS.md.
#
# THREATS.md is the canonical catalogue (prose); catalogue.toml is the machine form
# `kennel policy risks` reads. This guard fails CI if THREATS.md gains, renames, or
# drops a threat (or bumps its version) without catalogue.toml following — so the two
# cannot silently drift. Edit THREATS.md first, then mirror the change.
#
# Reviewed like any other code (CODING-STANDARDS.md §15.4): set -euo pipefail, no
# network, no side effects.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
THREATS="${KENNEL_THREATS_MD:-$ROOT/docs/reference/THREATS.md}"
CAT="${KENNEL_CATALOGUE:-$ROOT/dist/threats/catalogue.toml}"

fail=0
note() { echo "threats-catalogue: $*" >&2; }

[[ -f "$THREATS" ]] || { note "missing $THREATS"; exit 1; }
[[ -f "$CAT" ]] || { note "missing $CAT"; exit 1; }

# --- versions -------------------------------------------------------------
# THREATS.md carries a "Version X.Y · <date>" line; catalogue.toml a
# catalogue_version = "X.Y".
md_version="$(grep -oE 'Version [0-9]+\.[0-9]+' "$THREATS" | head -1 | awk '{print $2}')"
cat_version="$(grep -oE 'catalogue_version *= *"[0-9]+\.[0-9]+"' "$CAT" | head -1 \
	| grep -oE '[0-9]+\.[0-9]+')"
if [[ "$md_version" != "$cat_version" ]]; then
	note "version mismatch: THREATS.md=$md_version catalogue.toml=$cat_version"
	fail=1
fi

# --- id sets --------------------------------------------------------------
# THREATS.md: in-scope ids are the "## T<f>.<i> — title" headings; out-of-scope
# ids are the "| X<n> |" table rows. catalogue.toml: every `id = "..."`.
md_ids="$(
	{
		grep -oE '^## (T[0-9]+\.[0-9]+)' "$THREATS" | awk '{print $2}'
		grep -oE '^\| (X[0-9]+) ' "$THREATS" | tr -d '|' | awk '{print $1}'
	} | sort -u
)"
cat_ids="$(grep -oE 'id *= *"[^"]+"' "$CAT" | sed -E 's/id *= *"([^"]+)"/\1/' | sort -u)"

only_md="$(comm -23 <(printf '%s\n' "$md_ids") <(printf '%s\n' "$cat_ids"))"
only_cat="$(comm -13 <(printf '%s\n' "$md_ids") <(printf '%s\n' "$cat_ids"))"

if [[ -n "$only_md" ]]; then
	note "in THREATS.md but NOT in catalogue.toml:"; printf '  %s\n' $only_md >&2
	fail=1
fi
if [[ -n "$only_cat" ]]; then
	note "in catalogue.toml but NOT in THREATS.md:"; printf '  %s\n' $only_cat >&2
	fail=1
fi

if [[ "$fail" -eq 0 ]]; then
	n="$(printf '%s\n' "$cat_ids" | grep -c .)"
	echo "threats-catalogue: OK — $n ids, version $cat_version, in sync with THREATS.md"
fi
exit "$fail"
