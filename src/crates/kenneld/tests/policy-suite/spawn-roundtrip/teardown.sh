#!/usr/bin/env bash
#
# Remove the suite-signed settled echo-tool the case produced (the committed source stays).
#   $1 = scratch dir (unused). REPO_ROOT is derived from this script's location.
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../../../../../.." && pwd)"
rm -f "$REPO_ROOT/templates/echo-tool/echo-tool.settled.toml"
