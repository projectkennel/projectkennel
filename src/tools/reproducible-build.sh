#!/usr/bin/env bash
# Project Kennel reproducible release build (BUILD-ENV.md §Reproducibility,
# CODING-STANDARDS.md §8).
#
# Produces release binaries whose bytes do not depend on *where* or *when* they
# were built, so two builders on two machines hash-for-hash agree (the §8
# double-build-and-compare check). Two host-specific things would otherwise leak
# into a binary and break that:
#
#   1. Absolute source paths (the workspace, the cargo home, the rustup sysroot)
#      baked into panic messages and debug info. We remap each to a fixed virtual
#      root with `--remap-path-prefix`. (`trim-paths`, the built-in successor,
#      is not yet stable on the pinned toolchain — rust-toolchain.toml is stable
#      only — so we use the remap flags, which are stable.)
#   2. A build timestamp. rustc embeds none and honours `SOURCE_DATE_EPOCH`; we
#      pin it to the HEAD commit time so any timestamp rustc *does* derive is a
#      function of the source, not the wall clock.
#
# The release profile's `codegen-units = 1` removes the remaining parallel-codegen
# non-determinism (see Cargo.toml).
#
# Usage:
#   src/tools/reproducible-build.sh [extra cargo args...]
# Environment:
#   KENNEL_PROFILE   cargo profile to build (default: release-with-debuginfo)
#   SOURCE_DATE_EPOCH  override the derived epoch (default: HEAD commit time)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROFILE="${KENNEL_PROFILE:-release-with-debuginfo}"

# A source-derived, not wall-clock, timestamp.
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
	SOURCE_DATE_EPOCH="$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)"
fi
export SOURCE_DATE_EPOCH

# Remap the three host-specific path roots to fixed virtual prefixes. The vendored
# deps already live under the workspace (src/vendor), so the workspace remap covers
# them; the cargo-home and rustup remaps cover the registry cache and std/sysroot.
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTUP_HOME_DIR="${RUSTUP_HOME:-$HOME/.rustup}"
REMAP="--remap-path-prefix=$ROOT=/kennel"
REMAP="$REMAP --remap-path-prefix=$CARGO_HOME_DIR=/cargo"
REMAP="$REMAP --remap-path-prefix=$RUSTUP_HOME_DIR=/rustup"
export RUSTFLAGS="${RUSTFLAGS:-} $REMAP"

echo "reproducible-build: profile=$PROFILE SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" >&2
echo "reproducible-build: RUSTFLAGS=$RUSTFLAGS" >&2

# `--locked --offline`: build only from the vendored, checksum-pinned registry, so
# the build is a pure function of the committed tree (CODING-STANDARDS §5.5).
exec cargo build --profile "$PROFILE" --locked --offline "$@"
