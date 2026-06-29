#!/usr/bin/env bash
#
# dbus-brokered — the full D-Bus mediation path over the connector mesh, end to end (§7.7).
#
# Proves the brokered path on real kennels: an ondemand `dbus-broker` service kennel mediates the
# session bus over the mesh; a consumer with `[dbus.session]` + `[[consumes]] org.projectkennel.dbus`
# runs `dbus-send GetId`. The consumer's facade SVC_CONNECTs the per-kennel bus (resolve + activate
# the broker + wait Ready), gets the mesh path, connects there; kenneld resolves the consumer by its
# cgroup → ctx → filter and ACCEPT_SESSIONs it to the broker, which mediates to the REAL bus. Exit 0
# iff GetId round-trips the whole brokered path; that exit IS the verdict.
#
# Self-driving (like mesh-roundtrip): `kennel run` constructs ONE kennel, but this needs a PROVIDER
# (the broker) plus enablement before the CONSUMER, so the hook owns the flow.
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
BROKER_LINK="$ONDEMAND/dbus-broker"
# The broker provides the reserved `org.projectkennel.*` namespace, which only a VENDOR-provenance
# key may claim (§7.13.5). The real deployment ships the broker template signed by the maintainer
# key (which lives in the vendor dir); this test instead authorizes its own suite key as vendor —
# the fixture equivalent of "the project signs the broker". The mediation under test is identical.
VENDOR_KEYS="/usr/lib/kennel/keys"
VENDOR_SUITE_PUB="$VENDOR_KEYS/kennel-suite.pub"

cleanup() {
    rm -f "$BROKER_LINK"
    sudo rm -f "$VENDOR_SUITE_PUB" 2>/dev/null || true
    "$KENNEL" daemon-reload >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Authorize the suite key for the reserved namespace by placing its pubkey in the vendor dir.
sudo install -m 0644 "${SUITE_KEY}.pub" "$VENDOR_SUITE_PUB"

# The operator's real session bus — the same socket the legacy host-dbus path reaches. kenneld
# (operator context) connects to it on the broker's behalf via the [[unix.allow]] leg.
REAL_ADDR="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$(id -u)/bus}"
REAL_BUS="${REAL_ADDR#unix:path=}"
REAL_BUS="${REAL_BUS%%,*}"
if [ ! -S "$REAL_BUS" ]; then
    echo "dbus-brokered: no session bus socket at $REAL_BUS (need a running user D-Bus)" >&2
    exit 2
fi

# 1. Materialise the provider policy with the real bus path, compile + sign it to its settled form,
#    and enable it ONDEMAND — so the consumer's first connect socket-activates the broker (W6).
mkdir -p "$ONDEMAND"
PROVIDER_SRC="$SCRATCH/provider.toml"
sed "s#__REAL_BUS__#$REAL_BUS#" "$CASE_DIR/provider.toml" >"$PROVIDER_SRC"
"$KENNEL" policy compile "$PROVIDER_SRC" --key "$SUITE_KEY" --trust-dir "$KEYS" \
    --no-lock --output "$BROKER_LINK"

# 2. Refresh the catalogue so the daemon knows org.projectkennel.dbus{,-broker} (a Pending provider).
"$KENNEL" daemon-reload

# 3. Run the consumer: its workload's dbus-send drives the brokered round trip. Exit code is verdict.
exec "$KENNEL" run "$CASE_DIR/consumer.toml" dbus-consumer --key "$SUITE_KEY" --trust-dir "$KEYS" </dev/null
