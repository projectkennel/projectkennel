#!/usr/bin/env bash
#
# Guard: a change to the policy schema's SHAPE forces a `SETTLED_SCHEMA_VERSION` bump.
#
# The W17 handshake makes a schema *version* skew legible ("restart the daemon"); this is the other
# half — the discipline that makes it fire at all. The 0.3.1 field finding slipped a new settled
# field (`[trust].on_change`) in WITHOUT bumping `SETTLED_SCHEMA_VERSION`, so no version check, old
# or new, caught it; it surfaced as a cryptic `unknown field` deep in policy loading.
#
# We pin the *structure* of the generated policy JSON schema (`schema/policy.toml.schema`, the one
# the editor extension consumes — the authorable field set, where that drift lives) to the current
# `SETTLED_SCHEMA_VERSION`, in an append-only lock. The fingerprint strips `description`/`title`, so a
# doc-only edit does NOT force a bump — only a field/type/required/enum change does. Then:
#   * changing the schema shape WITHOUT bumping the version → the v<N> fingerprint mismatches → FAIL.
#   * bumping to v<N+1> → no pin for v<N+1> yet → FAIL until you add one (the old v<N> line is
#     immutable history). So a schema change cannot land without a deliberate version bump + re-pin.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$repo_root"

schema="schema/policy.toml.schema"
lock="schema/schema-version.lock"
version_src="src/crates/kennel-lib-policy/src/lib.rs"

[[ -f "$schema" ]] || { echo "FAIL: $schema is missing (run gen-schema)" >&2; exit 1; }

# The current settled-schema version, read from the source of truth.
version="$(sed -n 's/^pub const SETTLED_SCHEMA_VERSION: u32 = \([0-9]\+\);$/\1/p' "$version_src")"
[[ -n "$version" ]] || { echo "FAIL: could not read SETTLED_SCHEMA_VERSION from $version_src" >&2; exit 1; }

# The schema's structural fingerprint: field names/types/required/enums, with descriptions and titles
# stripped (a doc edit must not force a version bump) and keys canonically sorted.
fingerprint() {
	local schema_file="$1"
	python3 - "$schema_file" <<'PY'
import json, sys, hashlib
def strip(o):
    if isinstance(o, dict):
        return {k: strip(v) for k, v in o.items() if k not in ("description", "title")}
    if isinstance(o, list):
        return [strip(x) for x in o]
    return o
d = json.load(open(sys.argv[1]))
canon = json.dumps(strip(d), sort_keys=True, separators=(",", ":"))
print(hashlib.sha256(canon.encode("utf-8")).hexdigest())
PY
}

live="$(fingerprint "$schema")"

[[ -f "$lock" ]] || { echo "FAIL: $lock is missing — add the line \"$version $live\"" >&2; exit 1; }

# The pinned fingerprint for the current version (append-only: one "<version> <sha256>" line each).
pinned="$(awk -v v="$version" '$1 == v { print $2 }' "$lock")"

if [[ -z "$pinned" ]]; then
	echo "FAIL: SETTLED_SCHEMA_VERSION is v$version but $lock has no pin for it." >&2
	echo "      If you bumped the version for a real schema change, append this line to $lock:" >&2
	echo "          $version $live" >&2
	exit 1
fi

if [[ "$pinned" != "$live" ]]; then
	echo "FAIL: the policy schema's shape changed but SETTLED_SCHEMA_VERSION is still v$version." >&2
	echo "      A new/removed/retyped field is exactly the 0.3.1 drift class. Either:" >&2
	echo "        (a) it is intentional — BUMP SETTLED_SCHEMA_VERSION in $version_src and append a" >&2
	echo "            new pin line to $lock (the v$version line stays, as history); or" >&2
	echo "        (b) revert the schema change." >&2
	echo "      Pinned v$version: $pinned" >&2
	echo "      Live shape:       $live" >&2
	exit 1
fi

echo "ok: policy schema shape is pinned to SETTLED_SCHEMA_VERSION v$version"
