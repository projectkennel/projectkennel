#!/usr/bin/env bash
#
# Suite case: registration-denied (self-driving). Enables the standing D-Bus broker (so its mesh
# bus exists and is mounted into the consumer), then runs a consumer whose workload tries the
# three provider-only verbs. The consumer's exit is the verdict.
#
#   $1 = the case dir   $2 = the kennel CLI   $3 = the suite key id   $4 = a scratch dir
set -euo pipefail

. "$1/../suite-lib.sh"
suite_case "$@"

suite_vendor_trust_suite_key

REAL_ADDR="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$(id -u)/bus}"
REAL_BUS="${REAL_ADDR#unix:path=}"
REAL_BUS="${REAL_BUS%%,*}"
if [[ ! -S "$REAL_BUS" ]]; then
    echo "registration-denied: no session bus socket at $REAL_BUS (need a running user D-Bus)" >&2
    exit 2
fi

sed "s#__REAL_BUS__#$REAL_BUS#" "$CASE_DIR/../dbus-brokered/provider.toml" >"$SCRATCH/provider.toml"
suite_enable_ondemand "$SCRATCH/provider.toml" dbus-broker
suite_run_consumer "$CASE_DIR/consumer.toml"
