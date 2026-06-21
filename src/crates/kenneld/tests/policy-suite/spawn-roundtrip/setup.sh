#!/usr/bin/env bash
#
# Per-case fixture for spawn-roundtrip: compile + SIGN the `echo-tool` spawn target to its settled
# form with the suite key the daemon trusts, and install it into the **standard** user template
# cascade (`~/.config/kennel/templates`). A spawn target is the complete signed *settled* policy the
# daemon load-verifies and instantiates as-is (§7.12); the requester's grant pins its signature at
# compile and kenneld re-verifies that exact commitment at SPAWN — both resolving the one artefact
# from the standard path, never the source tree. Prints the requester policy on the last stdout line.
#
#   $1 = the case dir (this script's dir)   $2 = scratch (unused)
set -euo pipefail

CASE_DIR="$1"
KENNEL="/usr/libexec/kennel/kennel"
CFG="${XDG_CONFIG_HOME:-$HOME/.config}/kennel"
SUITE_KEY="$CFG/keys/kennel-suite.key"
SRC="/usr/lib/kennel/templates/echo-tool/policy.toml"   # the installed reference-template source
OUT="$CFG/templates/echo-tool/echo-tool.settled.toml"   # the standard user template path

[ -x "$KENNEL" ]    || { echo "no installed kennel at $KENNEL (run policy-e2e.sh without --no-install)" >&2; exit 2; }
[ -f "$SUITE_KEY" ] || { echo "no suite key at $SUITE_KEY" >&2; exit 2; }
[ -f "$SRC" ]       || { echo "echo-tool not installed at $SRC (install.sh ships the reference templates)" >&2; exit 2; }

mkdir -p "$(dirname "$OUT")"
# Compile the installed source; base-confined resolves from the standard template cascade.
"$KENNEL" policy compile "$SRC" --key "$SUITE_KEY" --trust-dir "$CFG/keys" --no-lock --output "$OUT" >&2

echo "$CASE_DIR/policy.toml"
