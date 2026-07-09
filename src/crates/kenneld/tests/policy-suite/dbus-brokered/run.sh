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

# shellcheck source=../suite-lib.sh
. "$1/../suite-lib.sh"
suite_case "$@"

# The broker claims the reserved `org.projectkennel.*` namespace — vendor-provenance only
# (§7.13.5) — so the suite key is authorized as vendor for this case (the fixture
# equivalent of "the project signs the broker"; the mediation under test is identical).
suite_vendor_trust_suite_key

# The operator's real session bus — the same socket the legacy host-dbus path reaches. kenneld
# (operator context) connects to it on the broker's behalf via the [[unix.allow]] leg.
REAL_ADDR="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$(id -u)/bus}"
REAL_BUS="${REAL_ADDR#unix:path=}"
REAL_BUS="${REAL_BUS%%,*}"
if [[ ! -S "$REAL_BUS" ]]; then
    echo "dbus-brokered: no session bus socket at $REAL_BUS (need a running user D-Bus)" >&2
    exit 2
fi

# Materialise the provider policy with the real bus path, enable it ONDEMAND (the consumer's
# first connect socket-activates the broker), then run the consumer — dbus-send's exit
# through the whole brokered round trip is the verdict.
sed "s#__REAL_BUS__#$REAL_BUS#" "$CASE_DIR/provider.toml" >"$SCRATCH/provider.toml"
suite_enable_ondemand "$SCRATCH/provider.toml" dbus-broker
suite_run_consumer "$CASE_DIR/consumer.toml"
