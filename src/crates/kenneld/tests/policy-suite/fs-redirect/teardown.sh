#!/usr/bin/env bash
# Remove the fs-redirect host fixture (always clean up after tests).
set -euo pipefail
rm -rf "$HOME/kennel-e2e/redirect"
