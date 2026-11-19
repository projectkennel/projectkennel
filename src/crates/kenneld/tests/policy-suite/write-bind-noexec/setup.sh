#!/usr/bin/env bash
#
# Per-case fixtures for write-bind-noexec: two host directories the policy grants writable (one
# default, one with `mmap_exec = true`). Prints this case's policy path on the last stdout line.
#
#   $1 = the case dir   $2 = a scratch dir (unused)
set -euo pipefail
CASE_DIR="$1"
rm -rf "$HOME/kennel-e2e-229"
mkdir -p "$HOME/kennel-e2e-229/plain" "$HOME/kennel-e2e-229/mapped"
echo "$CASE_DIR/policy.toml"
