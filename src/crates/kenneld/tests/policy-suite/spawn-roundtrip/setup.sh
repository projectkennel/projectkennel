#!/usr/bin/env bash
#
# Per-case fixture for spawn-roundtrip: compile + SIGN the `echo-tool` spawn target to its settled
# form with the suite key the daemon trusts, beside its source (`templates/echo-tool/`). A spawn
# target is the complete signed *settled* policy the daemon load-verifies and instantiates as-is
# (§7.12) — the requester's grant pins its signature at compile, and kenneld re-verifies that exact
# commitment at SPAWN. Prints the requester policy path on the last stdout line (the runner runs it).
#
#   $1 = the case dir (this script's dir)   $2 = a scratch dir (unused here)
set -euo pipefail

CASE_DIR="$1"
REPO_ROOT="$(cd "$(dirname "$0")/../../../../../.." && pwd)"
KENNEL="/usr/libexec/kennel/kennel"
KEY_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/kennel/keys"
SUITE_KEY="$KEY_DIR/kennel-suite.key"

[ -x "$KENNEL" ] || { echo "no installed kennel at $KENNEL (run policy-e2e.sh without --no-install)" >&2; exit 2; }
[ -f "$SUITE_KEY" ] || { echo "no suite key at $SUITE_KEY" >&2; exit 2; }

# The settled, suite-signed echo-tool the daemon resolves at SPAWN (beside its committed source).
"$KENNEL" policy compile "$REPO_ROOT/templates/echo-tool/policy.toml" \
    --template-dir "$REPO_ROOT/templates" --trust-dir "$KEY_DIR" --key "$SUITE_KEY" --no-lock \
    --output "$REPO_ROOT/templates/echo-tool/echo-tool.settled.toml" >&2

# The runner runs the requester (which spawns echo-tool@v1 and round-trips the channel).
echo "$CASE_DIR/policy.toml"
