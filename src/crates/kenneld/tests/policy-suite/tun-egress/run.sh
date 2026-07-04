#!/usr/bin/env bash
#
# tun-egress — the UDP-egress mediation path over the standing tun-broker, end to end (§8 / W2).
#
# Proves the tun path on real kennels: a STANDING tun-broker service kennel registers its egress sink,
# and a `[net.udp]` consumer with `[[consumes]] org.projectkennel.tun-udp` comes up with its tun and
# `facade-tun`. On bring-up the consumer's `facade-tun` `CONNECT_AFUNIX`es the tun capability on the
# per-kennel bus; kenneld resolves the consumer's grants + tun `/64`, delivers them to the broker's
# sink, and the broker mints this session's socketpair + a fresh `tun-flow` mediator. The consumer's
# workload then confirms its tun is present in its own netns; that exit IS the verdict (a failed
# consume leaves no facade and no tun path).
#
# Self-driving (like dbus-brokered): `kennel run` builds ONE kennel, but this needs the PROVIDER
# (the standing broker) up before the CONSUMER, so the hook owns the flow. Unlike the ondemand
# dbus/gui brokers, the tun-broker is STANDING — its connect is special-cased and never activates a
# cold provider — so the hook runs it in the background rather than relying on socket-activation.
#
#   $1 = case dir   $2 = KENNEL (installed CLI)   $3 = SUITE_KEY   $4 = scratch dir
set -euo pipefail

CASE_DIR="$1"
KENNEL="$2"
SUITE_KEY="$3"
SCRATCH="${4:-$(mktemp -d)}"
CFG="${XDG_CONFIG_HOME:-$HOME/.config}/kennel"
KEYS="$CFG/keys"
ONDEMAND="$CFG/ondemand"
BROKER_LINK="$ONDEMAND/tun-broker"
# The broker provides the reserved `org.projectkennel.*` namespace, which only a VENDOR-provenance
# key may claim (§7.13.5). The real deployment ships the broker template signed by the maintainer
# key; this test authorizes its own suite key as vendor — the fixture equivalent of "the project
# signs the broker". The mediation under test is identical.
VENDOR_KEYS="/usr/lib/kennel/keys"
VENDOR_SUITE_PUB="$VENDOR_KEYS/kennel-suite.pub"

BROKER_PID=""
cleanup() {
    [ -n "$BROKER_PID" ] && kill "$BROKER_PID" 2>/dev/null || true
    "$KENNEL" stop tun-broker >/dev/null 2>&1 || true
    rm -f "$BROKER_LINK"
    sudo rm -f "$VENDOR_SUITE_PUB" 2>/dev/null || true
    "$KENNEL" daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Authorize the suite key for the reserved namespace by placing its pubkey in the vendor dir.
sudo install -m 0644 "${SUITE_KEY}.pub" "$VENDOR_SUITE_PUB"

# 1. Compile + sign the provider to its settled form and enable it, so the daemon catalogues
#    `org.projectkennel.tun-udp` (the consumer's `required` consume resolves against it).
mkdir -p "$ONDEMAND"
"$KENNEL" policy compile "$CASE_DIR/provider.toml" --key "$SUITE_KEY" --trust-dir "$KEYS" \
    --no-lock --output "$BROKER_LINK"
"$KENNEL" daemon-reload

# 2. Start the standing broker in the background: it registers its egress sink and loops. `facade-tun`
#    retries its connect (~5s), so the consumer below tolerates this start racing its bring-up.
"$KENNEL" run "$CASE_DIR/provider.toml" tun-broker --key "$SUITE_KEY" --trust-dir "$KEYS" \
    </dev/null >"$SCRATCH/broker.log" 2>&1 &
BROKER_PID=$!

# 3. Run the consumer: its tun is constructed, `facade-tun` connects the broker (grants delivered,
#    session minted), and the workload confirms its tun. The consumer's exit code is the verdict.
exec "$KENNEL" run "$CASE_DIR/consumer.toml" tun-consumer --key "$SUITE_KEY" --trust-dir "$KEYS" </dev/null
