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

# shellcheck source=../suite-lib.sh
. "$1/../suite-lib.sh"
suite_case "$@"

# The broker claims the reserved `org.projectkennel.*` namespace — vendor-provenance only
# (§7.13.5) — so the suite key is authorized as vendor for this case (the fixture
# equivalent of "the project signs the broker"; the mediation under test is identical).
suite_vendor_trust_suite_key

# 1. Enable the provider so the daemon catalogues `org.projectkennel.tun-udp` (the
#    consumer's `required` consume resolves against it).
suite_enable_ondemand "$CASE_DIR/provider.toml" tun-broker

# 2. Start the standing broker in the background: it registers its egress sink and loops.
#    `facade-tun` retries its connect (~5s), so the consumer below tolerates this start
#    racing its bring-up. Dogfood flow: stage + compile in the authoring house, run the
#    settled by name.
suite_compile "$CASE_DIR/provider.toml" >/dev/null
suite_defer "suite_unstage tun-broker"
"$KENNEL" run tun-broker tun-broker </dev/null >"$SCRATCH/broker.log" 2>&1 &
BROKER_PID=$!
suite_defer "kill $BROKER_PID 2>/dev/null"

# 3. Run the consumer: its tun is constructed, `facade-tun` connects the broker (grants
#    delivered, session minted), and the workload confirms its tun. Exit is the verdict.
suite_run_consumer "$CASE_DIR/consumer.toml"
