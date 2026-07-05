#!/usr/bin/env bash
#
# Per-case fixture for fs-redirect: the host tree the asymmetric grant reads from.
#
#   ~/kennel-e2e/redirect/granted/aka.json    LOCAL       (the symmetric inode the redirect shadows)
#   ~/kennel-e2e/redirect/granted/plain.json  LOCAL       (stays symmetric — the control)
#   ~/kennel-e2e/redirect/store/real.json     REDIRECTED  (the redirect source; never granted itself)
#
#   $1 = the case dir   $2 = a scratch dir (unused; the fixture must live under ~ for the ~ grant)
set -euo pipefail

CASE_DIR="$1"

BASE="$HOME/kennel-e2e/redirect"
rm -rf "$BASE"
mkdir -p "$BASE/granted" "$BASE/store"
printf 'LOCAL' > "$BASE/granted/aka.json"
printf 'LOCAL' > "$BASE/granted/plain.json"
printf 'REDIRECTED' > "$BASE/store/real.json"

# No substitution needed — run the case's own policy.
echo "$CASE_DIR/policy.toml"
