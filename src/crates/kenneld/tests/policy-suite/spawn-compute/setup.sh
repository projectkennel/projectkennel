#!/usr/bin/env bash
#
# Stage the repointed `pure-compute` spawn target: compile the installed reference-template
# source to a signed settled artefact at the standard user template path, so the spawner
# below may instantiate it. Prints the spawner policy path on its last stdout line.
set -euo pipefail
CASE_DIR="$1"
KENNEL="/usr/bin/kennel"
CFG="${XDG_CONFIG_HOME:-$HOME/.config}/kennel"
SUITE_KEY="$CFG/keys/kennel-suite"
SRC="/usr/lib/kennel/templates/pure-compute/policy.toml"
OUT="$CFG/templates/pure-compute/pure-compute.settled.toml"
[[ -x "$KENNEL" ]]    || { echo "no installed kennel at $KENNEL (run policy-e2e.sh without --no-install)" >&2; exit 2; }
[[ -f "$SUITE_KEY" ]] || { echo "no suite key at $SUITE_KEY" >&2; exit 2; }
[[ -f "$SRC" ]]       || { echo "pure-compute not installed at $SRC (install.sh ships the reference templates)" >&2; exit 2; }
mkdir -p "$(dirname "$OUT")"
"$KENNEL" policy compile "$SRC" --key "$SUITE_KEY" --trust-dir "$CFG/keys" --no-lock --output "$OUT" >&2
echo "$CASE_DIR/policy.toml"
