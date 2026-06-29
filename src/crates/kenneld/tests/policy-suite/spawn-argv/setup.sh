#!/usr/bin/env bash
#
# Per-case fixture for spawn-argv: compile + SIGN the `argv-tool` spawn target to its settled form
# with the suite key the daemon trusts, and install it into the standard user template cascade
# (`~/.config/kennel/templates`). argv-tool opens `[workload].argv` as a freeform mutable field, so
# the requester's `facade-spawn run … -- <cmd>` supplies the command the sibling runs; the grant pins
# argv-tool's signature at compile and kenneld re-verifies that exact commitment at SPAWN. Prints the
# requester policy on the last stdout line.
#
#   $1 = the case dir (this script's dir)   $2 = scratch (unused)
set -euo pipefail

CASE_DIR="$1"
KENNEL="/usr/bin/kennel"
CFG="${XDG_CONFIG_HOME:-$HOME/.config}/kennel"
SUITE_KEY="$CFG/keys/kennel-suite"
SRC="/usr/lib/kennel/templates/argv-tool/policy.toml"   # the installed reference-template source
OUT="$CFG/templates/argv-tool/argv-tool.settled.toml"   # the standard user template path

[ -x "$KENNEL" ]    || { echo "no installed kennel at $KENNEL (run policy-e2e.sh without --no-install)" >&2; exit 2; }
[ -f "$SUITE_KEY" ] || { echo "no suite key at $SUITE_KEY" >&2; exit 2; }
[ -f "$SRC" ]       || { echo "argv-tool not installed at $SRC (install.sh ships the reference templates)" >&2; exit 2; }

mkdir -p "$(dirname "$OUT")"
# Compile the installed source; base-confined resolves from the standard template cascade. The
# freeform `workload.argv` variant warns loudly at compile (the footgun rule) — expected, to stderr.
"$KENNEL" policy compile "$SRC" --key "$SUITE_KEY" --trust-dir "$CFG/keys" --no-lock --output "$OUT" >&2

echo "$CASE_DIR/policy.toml"
