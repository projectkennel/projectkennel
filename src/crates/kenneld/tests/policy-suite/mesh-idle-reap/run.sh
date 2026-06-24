#!/usr/bin/env bash
#
# mesh-idle-reap — the W6 ondemand idle-reaping loop, end to end (§7.13.6).
#
# Proves the full activate → idle → reap → pending → re-activate cycle on real kennels. An ondemand
# PROVIDER offers `test.mesh.idle` (af-unix) with a short `[lifecycle].ttl` — for an ondemand provider
# that TTL is its idle grace. A CONSUMER `[[consumes]]` it; its first connect socket-activates the cold
# provider. Once the consumer exits no consumer kennel runs, so at the next TTL fire kenneld reaps the
# provider through the existing §9.7 TTL custodian — NOT a restart: the supervisor returns it to
# declared-but-pending and stops, so a fresh consume re-activates it from cold.
#
# The verdict is this hook's exit code (set -e + explicit fails):
#   1. consumer #1 round-trips pong  → the cold provider activated and served      (exit 0)
#   2. after idling past the TTL: readiness == pending AND the provider is NOT running → reaped, not
#      restarted (a crash-restart would bounce back to ready+running — the bug this case guards)
#   3. consumer #2 round-trips pong  → the reaped provider re-activated from cold   (exit 0)
#
# A self-driving case (like mesh-roundtrip): the mesh needs a provider AND a consumer plus enablement,
# so this hook owns the whole flow.
#
#   $1 = case dir   $2 = KENNEL (installed CLI)   $3 = SUITE_KEY   $4 = scratch (unused)
set -euo pipefail

CASE_DIR="$1"
KENNEL="$2"
SUITE_KEY="$3"
CFG="${XDG_CONFIG_HOME:-$HOME/.config}/kennel"
KEYS="$CFG/keys"
ONDEMAND="$CFG/ondemand"
PROVIDER_LINK="$ONDEMAND/mesh-idle-provider"

cleanup() {
    rm -f "$PROVIDER_LINK"
    "$KENNEL" daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The readiness of `test.mesh.idle` in the mesh section of `kennel list` (column 3 of its row); empty
# if the provider is not catalogued. The capability name appears only in the mesh row, never the
# running-kennel topology, so this never confuses the two sections.
readiness_of() {
    "$KENNEL" list 2>/dev/null | awk '/test\.mesh\.idle/ { print $3 }'
}

# Whether a provider kennel is live in the running-kennel topology (its row starts with the name).
provider_running() {
    "$KENNEL" list 2>/dev/null | grep -Eq '^mesh-idle-provider[[:space:]]'
}

# 1. Compile + sign the provider to its settled form and enable it ONDEMAND — the enablement entry IS
#    the signed settled policy the daemon load-verifies (§7.13.6); ondemand so the consumer's first
#    connect socket-activates it.
mkdir -p "$ONDEMAND"
"$KENNEL" policy compile "$CASE_DIR/provider.toml" --key "$SUITE_KEY" --trust-dir "$KEYS" \
    --no-lock --output "$PROVIDER_LINK"

# 2. Refresh the catalogue so the daemon knows `test.mesh.idle` (a Pending ondemand provider).
"$KENNEL" daemon-reload

# 3. Activate: the consumer's workload connects to its `at` socket; kenneld activates the cold provider
#    and brokers the connector. Exit 0 iff the round-trip held.
"$KENNEL" run "$CASE_DIR/consumer.toml" mesh-idle-consumer --key "$SUITE_KEY" --trust-dir "$KEYS" </dev/null \
    || { echo "mesh-idle-reap: activation round-trip failed (consumer #1 did not read pong)" >&2; exit 1; }

# The provider served, so it is ready and running right after activation (well inside its 4s TTL).
r="$(readiness_of)"
[ "$r" = "ready" ] || { echo "mesh-idle-reap: after activation readiness is '$r', expected 'ready'" >&2; exit 1; }

# 4. Idle past the TTL — no consumer kennel runs now, so the next TTL fire reaps the provider. Wait
#    well beyond the TTL: long enough that a (buggy) crash-restart would have reconstructed back to
#    ready+running, so a still-pending + not-running provider can only be a clean reap.
sleep 12

# 5. The provider is reaped: declared-but-pending AND no live kennel. A restart would show ready (or a
#    running kennel) instead — this is the assertion that distinguishes a reap from a mis-read crash.
r="$(readiness_of)"
[ "$r" = "pending" ] || { echo "mesh-idle-reap: after idle the readiness is '$r', expected 'pending' (reaped)" >&2; exit 1; }
if provider_running; then
    echo "mesh-idle-reap: the provider is still running after the idle reap (restarted, not reaped)" >&2
    exit 1
fi

# 6. Re-activate from cold: a fresh consume must socket-activate the reaped provider again and
#    round-trip — proving the reap returned it to a re-activatable state, not a dead one.
"$KENNEL" run "$CASE_DIR/consumer.toml" mesh-idle-consumer --key "$SUITE_KEY" --trust-dir "$KEYS" </dev/null \
    || { echo "mesh-idle-reap: re-activation round-trip failed (reaped provider did not come back)" >&2; exit 1; }

echo "mesh-idle-reap: activate → idle → reap → pending → re-activate held"
