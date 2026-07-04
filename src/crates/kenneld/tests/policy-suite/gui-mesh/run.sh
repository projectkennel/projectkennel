#!/usr/bin/env bash
#
# gui-mesh — the confined-GUI display path, end to end (§7.14 / 02-11-confined-gui.md).
#
# Proves the compositor-broker over the real mesh: an ondemand GUI-service PROVIDER runs
# `compositor-broker`, which listens on its endpoint and spawns one nested compositor per
# accepted connection (here a headless `facade-mesh-probe serve-display` stand-in that binds
# the broker-assigned $XDG_RUNTIME_DIR/wayland-0 and echoes). A CONSUMER declares `[[consumes]]`
# the capability at an `at` socket. The consumer's connect socket-activates the provider; kenneld
# brokers the connect to the broker's listen socket, which spawns the compositor and relays. Exit 0
# iff the consumer reads `pong` back across the kennel boundary, through the broker→compositor relay —
# the same path a real app's Wayland traffic rides. That exit IS the verdict.
#
# Headless by design: the broker + mesh are what this case tests, not the renderer — a real GUI kennel
# swaps `cage` for the stand-in and adds the host-Wayland leg + /dev/dri (see provider.toml).
#
#   $1 = case dir   $2 = KENNEL (installed CLI)   $3 = SUITE_KEY   $4 = scratch (unused)
set -euo pipefail

CASE_DIR="$1"
KENNEL="$2"
SUITE_KEY="$3"
CFG="${XDG_CONFIG_HOME:-$HOME/.config}/kennel"
KEYS="$CFG/keys"
ONDEMAND="$CFG/ondemand"
PROVIDER_LINK="$ONDEMAND/gui-provider"

cleanup() {
    # Stop the activated provider before unlinking (leave the daemon cold for later cases).
    "$KENNEL" stop gui-provider >/dev/null 2>&1 || true
    rm -f "$PROVIDER_LINK"
    "$KENNEL" daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Compile + sign the GUI-service provider to its settled form and enable it ONDEMAND — the consumer's
#    first connect socket-activates it (W6 lazy path + consume-with-wait).
mkdir -p "$ONDEMAND"
"$KENNEL" policy compile "$CASE_DIR/provider.toml" --key "$SUITE_KEY" --trust-dir "$KEYS" \
    --no-lock --output "$PROVIDER_LINK"

# 2. Refresh the catalogue so the daemon knows `test.gui.wayland` (a Pending ondemand provider).
"$KENNEL" daemon-reload

# 3. Run the consumer: its workload connects to the `at` socket; kenneld activates the GUI-service
#    provider, the compositor-broker spawns this connection's compositor, and the round-trip is brokered.
#    The consumer's exit code is the verdict (the broker relay reached a spawned compositor iff 0).
# No `exec`: the cleanup trap must fire when the consumer exits (exec would replace
# the shell and leak the enabled provider link into the user tier for later cases).
"$KENNEL" run "$CASE_DIR/consumer.toml" gui-consumer --key "$SUITE_KEY" --trust-dir "$KEYS" </dev/null
exit "$?"
