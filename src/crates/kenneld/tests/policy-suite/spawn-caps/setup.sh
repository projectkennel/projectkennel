#!/usr/bin/env bash
#
# Per-case fixture for spawn-caps: compile + SIGN echo-tool to its settled form with the suite key
# and install it into the standard user template cascade, so the grant's `echo-tool@v1` resolves when
# `facade-spawn caps` interrogates it. Prints the requester policy on the last stdout line.
set -euo pipefail
CASE_DIR="$1"
KENNEL="/usr/bin/kennel"
CFG="${XDG_CONFIG_HOME:-$HOME/.config}/kennel"
SUITE_KEY="$CFG/keys/kennel-suite.key"
SRC="/usr/lib/kennel/templates/echo-tool/policy.toml"
OUT="$CFG/templates/echo-tool/echo-tool.settled.toml"
[ -x "$KENNEL" ]    || { echo "no installed kennel at $KENNEL (run policy-e2e.sh without --no-install)" >&2; exit 2; }
[ -f "$SUITE_KEY" ] || { echo "no suite key at $SUITE_KEY" >&2; exit 2; }
[ -f "$SRC" ]       || { echo "echo-tool not installed at $SRC (install.sh ships the reference templates)" >&2; exit 2; }
mkdir -p "$(dirname "$OUT")"
"$KENNEL" policy compile "$SRC" --key "$SUITE_KEY" --trust-dir "$CFG/keys" --no-lock --output "$OUT" >&2
echo "$CASE_DIR/policy.toml"
