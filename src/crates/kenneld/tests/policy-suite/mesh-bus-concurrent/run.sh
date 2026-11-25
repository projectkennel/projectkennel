#!/usr/bin/env bash
#
# mesh-bus-concurrent — several kennels reach the same mesh bus at once (§7.13.4a).
#
# Every other mesh case starts one consumer and waits for it. This one starts four at the same
# moment, three times over, against one ondemand provider. In each round the four race to
# create the bus (one must create it, the others must wait and then share it), and between
# rounds the last consumer to leave tears the bus down while the next round is already asking
# for it. A bus created twice, a consumer handed a bus that is being torn down, or a start left
# waiting on a lock all show up as a consumer that fails or a round that hangs into the
# driver's timeout.
#
# It reuses the provider and consumer of `dbus-brokered`: the D-Bus broker's bus is a mesh bus.
#
#   $1 = case dir   $2 = KENNEL (installed CLI)   $3 = SUITE_KEY   $4 = scratch
set -euo pipefail

# shellcheck source=../suite-lib.sh
. "$1/../suite-lib.sh"
suite_case "$@"

BROKERED="$CASE_DIR/../dbus-brokered"

suite_vendor_trust_suite_key

REAL_ADDR="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$(id -u)/bus}"
REAL_BUS="${REAL_ADDR#unix:path=}"
REAL_BUS="${REAL_BUS%%,*}"
if [[ ! -S "$REAL_BUS" ]]; then
    echo "SKIP: no session bus socket at $REAL_BUS (need a running user D-Bus)"
    exit 77
fi

sed "s#__REAL_BUS__#$REAL_BUS#" "$BROKERED/provider.toml" >"$SCRATCH/provider.toml"
suite_enable_ondemand "$SCRATCH/provider.toml" dbus-broker

name="$(suite_compile "$BROKERED/consumer.toml")"
suite_defer "suite_unstage $name"

CONSUMERS=4
ROUNDS=3
failed=0
for round in $(seq 1 "$ROUNDS"); do
    pids=()
    for i in $(seq 1 "$CONSUMERS"); do
        "$KENNEL" run "$name" "$name-r$round-c$i" </dev/null >"$SCRATCH/r$round-c$i.log" 2>&1 &
        pids+=("$!")
    done
    for i in "${!pids[@]}"; do
        rc=0
        wait "${pids[$i]}" || rc=$?
        if [[ "$rc" -ne 0 ]]; then
            failed=$((failed + 1))
            echo "mesh-bus-concurrent: round $round consumer $((i + 1)) exited $rc" >&2
            cat "$SCRATCH/r$round-c$((i + 1)).log" >&2 || true
        fi
    done
done

if [[ "$failed" -ne 0 ]]; then
    echo "mesh-bus-concurrent: $failed of $((CONSUMERS * ROUNDS)) consumers failed" >&2
    exit 1
fi
