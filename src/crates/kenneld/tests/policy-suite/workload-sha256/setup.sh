#!/usr/bin/env bash
#
# Per-case fixture for workload-sha256: the policy carries the digest of a binary on THIS host,
# so it is generated here. Prints the generated policy's path on its last stdout line.
#
#   $1 = the case dir   $2 = a scratch dir (the generated policy lands here)
set -euo pipefail

CASE_DIR="$1"
SCRATCH="$2"

# A small dynamically linked binary every host has; resolved, because the pin is on the file.
BINARY="$(readlink -f /usr/bin/true)"
DIGEST="$(sha256sum -b "$BINARY" | cut -d' ' -f1)"

sed -e "s|__BINARY__|$BINARY|g" -e "s|__DIGEST__|$DIGEST|g" \
    "$CASE_DIR/policy.toml" > "$SCRATCH/policy.toml"
echo "$SCRATCH/policy.toml"
