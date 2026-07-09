#!/usr/bin/env bash
#
# mesh-roundtrip — the cross-kennel provide/consume loop, end to end (§7.13.4).
#
# Proves the whole mesh on real kennels: an ondemand PROVIDER offers `test.mesh.echo` (af-unix) and
# serves ping→pong at its endpoint; a CONSUMER declares `[[consumes]]` it at an `at` socket. The
# consumer's workload connects to `at` — and kenneld's af-unix facade + broker resolve the capability,
# socket-activate the cold provider (W6), reach its endpoint through /proc/<pid>/root, and splice.
# Exit 0 iff the consumer reads `pong` back across the kennel boundary; that exit IS the verdict.
#
# A self-driving case (like oci-substrate): `kennel run` constructs ONE kennel, but the mesh needs a
# provider AND a consumer plus enablement, so this hook owns the whole flow.
#
#   $1 = case dir   $2 = KENNEL (installed CLI)   $3 = SUITE_KEY   $4 = scratch (unused)
set -euo pipefail

# shellcheck source=../suite-lib.sh
. "$1/../suite-lib.sh"
suite_case "$@"

# Enable the provider ONDEMAND (the lazy path: the consumer's first connect socket-activates
# it, exercising W6's consume-with-wait), then run the consumer — its exit is the verdict.
suite_enable_ondemand "$CASE_DIR/provider.toml" mesh-provider
suite_run_consumer "$CASE_DIR/consumer.toml"
