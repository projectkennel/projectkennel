#!/usr/bin/env bash
#
# binder-peer-stalled — a mesh peer that stops answering costs the daemon nothing but a wait.
#
# When a consumer connects to a brokered bus, kenneld sends the broker a synchronous binder
# transaction (NEW_SESSION) and waits for the reply on one of its looper threads. The broker is a
# process inside a kennel. If it never answers, that wait used to be a busy loop on a non-blocking
# descriptor with no deadline: one daemon thread at full CPU for as long as the broker stayed
# silent, and one more for every further consumer.
#
# The case reproduces that with the real broker, stopped with SIGSTOP:
#   1. a consumer runs through the broker         → works (the control: the path is live)
#   2. the broker is stopped, a consumer runs     → kenneld must sleep, not spin, while it waits
#   3. the wait ends at the deadline and the broker is resumed
#   4. a consumer runs again                      → works (the thread that waited serves again)
#
#   $1 = case dir   $2 = KENNEL (installed CLI)   $3 = SUITE_KEY   $4 = scratch dir
set -euo pipefail

# shellcheck source=../suite-lib.sh
. "$1/../suite-lib.sh"
suite_case "$@"
suite_vendor_trust_suite_key

REAL_ADDR="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$(id -u)/bus}"
REAL_BUS="${REAL_ADDR#unix:path=}"
REAL_BUS="${REAL_BUS%%,*}"
if [[ ! -S "$REAL_BUS" ]]; then
    echo "binder-peer-stalled: no session bus socket at $REAL_BUS (need a running user D-Bus)" >&2
    exit 2
fi

sed "s#__REAL_BUS__#$REAL_BUS#" "$CASE_DIR/provider.toml" >"$SCRATCH/provider.toml"
suite_enable_ondemand "$SCRATCH/provider.toml" dbus-broker
name="$(suite_compile "$CASE_DIR/consumer.toml")"
suite_defer "suite_unstage $name"

consume() { "$KENNEL" run "$name" "$name" </dev/null >"$SCRATCH/consume.log" 2>&1; }

# 1. The control: the brokered path works, and the broker is now running.
consume || { echo "binder-peer-stalled: the brokered path is not working to begin with" >&2
             cat "$SCRATCH/consume.log" >&2; exit 1; }

broker="$(pgrep -u "$(id -u)" -f '^/usr/libexec/kennel-facades/dbus-broker' | head -n1 || true)"
daemon="$(pgrep -u "$(id -u)" -x kenneld | head -n1 || true)"
[[ -n "$broker" && -n "$daemon" ]] \
    || { echo "binder-peer-stalled: broker ($broker) or kenneld ($daemon) not found" >&2; exit 1; }

# CPU time kenneld has used so far, in clock ticks (utime + stime).
cpu_ticks() { awk '{ print $14 + $15 }' "/proc/$daemon/stat"; }

# 2. Stop the broker and start a consumer; its connect now waits on a peer that will not answer.
kill -STOP "$broker"
suite_defer "kill -CONT $broker"
timeout 90 "$KENNEL" run "$name" "$name" </dev/null >"$SCRATCH/stalled.log" 2>&1 &
stalled=$!
suite_defer "kill $stalled; \"$KENNEL\" stop $name >/dev/null 2>&1"

sleep 5 # let the consumer reach the brokered connect
before="$(cpu_ticks)"
sleep 10
after="$(cpu_ticks)"
used=$((after - before))
hz="$(getconf CLK_TCK)"
# A spinning thread uses the whole ten seconds (10 * hz ticks). Allow one second of real work.
if ((used > hz)); then
    echo "binder-peer-stalled: FAIL — kenneld used $used ticks of CPU in 10 s waiting on a stopped peer (a busy wait)" >&2
    exit 1
fi

# 3. Past the deadline (30 s from the connect) the daemon gives the wait up. Resume the broker.
sleep 25
kill -CONT "$broker"
"$KENNEL" stop "$name" >/dev/null 2>&1 || true
wait "$stalled" 2>/dev/null || true

# 4. The daemon still serves the brokered path: the thread that waited is back in the pool.
ok=0
for _ in 1 2 3; do
    if consume; then ok=1; break; fi
    sleep 2
done
if [[ "$ok" != 1 ]]; then
    echo "binder-peer-stalled: FAIL — the brokered path did not recover after the peer resumed" >&2
    cat "$SCRATCH/consume.log" >&2
    exit 1
fi
echo "binder-peer-stalled: kenneld used $used ticks in 10 s while its peer was stopped, and the path recovered"
