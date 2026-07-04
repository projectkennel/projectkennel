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

CASE_DIR="$1"
KENNEL="$2"
SUITE_KEY="$3"
CFG="${XDG_CONFIG_HOME:-$HOME/.config}/kennel"
KEYS="$CFG/keys"
ONDEMAND="$CFG/ondemand"
PROVIDER_LINK="$ONDEMAND/mesh-provider"

cleanup() {
    # Stop the activated provider before unlinking (leave the daemon cold for later cases).
    "$KENNEL" stop mesh-provider >/dev/null 2>&1 || true
    rm -f "$PROVIDER_LINK"
    "$KENNEL" daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Compile + sign the provider to its settled form and enable it ONDEMAND — the enablement entry IS
#    the signed settled policy the daemon load-verifies (§7.13.6); ondemand so the consumer's first
#    connect socket-activates it (exercising W6's lazy path + the consume-with-wait).
mkdir -p "$ONDEMAND"
"$KENNEL" policy compile "$CASE_DIR/provider.toml" --key "$SUITE_KEY" --trust-dir "$KEYS" \
    --no-lock --output "$PROVIDER_LINK"

# 2. Refresh the catalogue so the daemon knows `test.mesh.echo` (a Pending ondemand provider).
"$KENNEL" daemon-reload

# 3. Run the consumer: its workload connects to the `at` socket; kenneld activates the provider and
#    brokers the connector. The consumer's exit code is the verdict (the round-trip held iff 0).
# No `exec`: the cleanup trap must fire when the consumer exits (exec would replace
# the shell and leak the enabled provider link into the user tier for later cases).
"$KENNEL" run "$CASE_DIR/consumer.toml" mesh-consumer --key "$SUITE_KEY" --trust-dir "$KEYS" </dev/null
exit "$?"
