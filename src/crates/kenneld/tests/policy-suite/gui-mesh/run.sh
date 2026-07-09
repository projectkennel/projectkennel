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

# shellcheck source=../suite-lib.sh
. "$1/../suite-lib.sh"
suite_case "$@"

# Enable the GUI-service provider ONDEMAND (the consumer's first connect socket-activates it;
# the compositor-broker spawns one compositor per accepted connection), then run the consumer —
# the round-trip through the broker→compositor relay is the verdict.
suite_enable_ondemand "$CASE_DIR/provider.toml" gui-provider
suite_run_consumer "$CASE_DIR/consumer.toml"
