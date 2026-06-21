#!/usr/bin/env bash
#
# Spawn-latency profiling harness (ROADMAP-0.3.0 W10): measure kennel CONSTRUCTION
# latency end-to-end across the privilege-domain boundaries (kennel → kenneld →
# privhelper → kennel-bin-init → workload), per boundary, against the REAL installed
# Project Kennel — the same `kennel run` path the policy suite drives.
#
# HOW it measures, without a profiler: the spawn-path tracer (kennel_lib_config::Tracer)
# stamps every `step` milestone with a wall-clock `[t=<nanos>]` at Debug level, and the
# milestones from kenneld + the privhelper share the host clock, so the delta between two
# consecutive milestones IS that boundary's latency. This is the STABLE, always-on path
# (no nightly, no XRay): the LLVM-XRay function-level deep-dive the roadmap also mentions is
# a separate, optional local nightly build — it cannot ship "always-on" on a stable release,
# so the tracer is the boundary instrumentation that does (CODING-STANDARDS §2.1: stable only).
#
# It drives a minimal construction N times under load, reports the per-boundary breakdown
# (median + p90) and the construction-span total + rate, and treats teardown as its own span.
# A skip is not a proof: a missing prerequisite aborts with the precise cause.
#
#   Usage: src/tools/spawn-latency.sh [--no-install] [N] [case]
#     --no-install   use the already-installed kennel (skip build+install)
#     N              constructions to time (default 30)
#     case           a policy-suite case name to construct (default net-none)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

UID_NUM="$(id -u)"
[ "$UID_NUM" = "0" ] && { echo "run as the ordinary operator, not root" >&2; exit 2; }

DO_INSTALL=1
N=30
CASE="net-none"
for a in "$@"; do
    case "$a" in
        --no-install) DO_INSTALL=0 ;;
        [0-9]*) N="$a" ;;
        *) CASE="$a" ;;
    esac
done

KENNEL="/usr/libexec/kennel/kennel"
[ -x "$KENNEL" ] || KENNEL="$(command -v kennel || true)"
SUITE_DIR="$REPO_ROOT/src/crates/kenneld/tests/policy-suite"
POLICY="$SUITE_DIR/$CASE/policy.toml"
SYSTEM_TOML="/etc/kennel/system.toml"
KEY_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/kennel/keys"
SUITE_KEY="$KEY_DIR/kennel-suite.key"
SUBKENNEL_LINE="${UID_NUM}:42:0000000002:kennel-dev"

[ -f "$POLICY" ] || { echo "no such case: $POLICY" >&2; exit 2; }

SYSTEM_TOML_SAVED=""; SYSTEM_TOML_EXISTED=0
cleanup() {
    if [ "$SYSTEM_TOML_EXISTED" = 1 ]; then
        printf '%s' "$SYSTEM_TOML_SAVED" | sudo tee "$SYSTEM_TOML" >/dev/null 2>&1 || true
    else
        sudo rm -f "$SYSTEM_TOML" 2>/dev/null || true
    fi
    systemctl --user restart kenneld.service 2>/dev/null || true
}
trap cleanup EXIT

# 1. Build + install the real thing (so the tracer carries the [t=] stamp), unless --no-install.
if [ "$DO_INSTALL" = 1 ]; then
    echo "== building + installing release (sudo install.sh) =="
    HOST_TRIPLE="$(uname -m)-unknown-linux-gnu"
    cargo build --release --offline --frozen --locked \
        -p kenneld -p kennel-cli -p kennel-host-delegate -p kennel-host-dbus >/dev/null
    RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --offline --frozen --locked \
        --target "$HOST_TRIPLE" -p kennel-bin-oci-entry -p kennel-bin-init -p kennel-facade >/dev/null
    cargo build --release --offline --frozen --locked -p kennel-privhelper --features bpf-egress >/dev/null
    sudo bash "$REPO_ROOT/src/tools/install.sh" --no-build >/dev/null || { echo "install failed" >&2; exit 1; }
fi
[ -x "$KENNEL" ] || { echo "kennel not installed — run without --no-install" >&2; exit 2; }

# 2. Admin inputs install.sh does not fabricate: the subkennel allocation + a trusted signing key.
sudo touch /etc/kennel/subkennel
sudo grep -qE "^${UID_NUM}:" /etc/kennel/subkennel || echo "$SUBKENNEL_LINE" | sudo tee -a /etc/kennel/subkennel >/dev/null
[ -f "$SUITE_KEY" ] || "$KENNEL" keygen kennel-suite >/dev/null

# 3. Turn on the timestamped spawn-path trace (restored on exit) and restart the service.
echo "== enabling log_level=debug (restored on exit) =="
if sudo test -e "$SYSTEM_TOML"; then SYSTEM_TOML_EXISTED=1; SYSTEM_TOML_SAVED="$(sudo cat "$SYSTEM_TOML")"; fi
{ [ "$SYSTEM_TOML_EXISTED" = 1 ] && printf '%s\n' "$SYSTEM_TOML_SAVED" | grep -v '^log_level'; \
  echo 'log_level = "debug"'; } | sudo tee "$SYSTEM_TOML" >/dev/null
systemctl --user restart kenneld.service 2>/dev/null || systemctl --user start kenneld.service
SOCK="${XDG_RUNTIME_DIR:-/run/user/$UID_NUM}/kennel/control.sock"
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "kenneld.service did not bind $SOCK" >&2; exit 1; }

# 4. Drive N constructions, capturing each run's trace burst from the journal by cursor. One warm-up
#    run (cold caches/JIT of the path) is discarded.
echo "== timing $N construction(s) of '$CASE' =="
RUNS_DIR="$(mktemp -d)"; trap 'rm -rf "$RUNS_DIR"; cleanup' EXIT
run_once() {
    local out="$1"
    local cur; cur="$(journalctl --user -u kenneld.service -n0 -o export --show-cursor 2>/dev/null \
        | sed -n 's/^-- cursor: //p' | tail -1)"
    "$KENNEL" run "$POLICY" --key "$SUITE_KEY" >/dev/null 2>&1 || true
    # Give the journal a moment to flush the privhelper/kenneld lines, then collect this run's burst.
    sleep 0.05
    journalctl --user -u kenneld.service --after-cursor "$cur" -o cat 2>/dev/null > "$out"
}
run_once /dev/null  # warm-up, discarded
START_NS="$(date +%s%N)"
for i in $(seq 1 "$N"); do run_once "$RUNS_DIR/run-$i.log"; done
END_NS="$(date +%s%N)"

# 5. Parse the [t=<nanos>] milestones per run and aggregate. Each run's milestones, sorted by t,
#    give per-transition deltas (the boundary latencies) and a construction span (first→last).
awk -v n="$N" -v wall_ns="$((END_NS - START_NS))" '
function ms(ns){ return sprintf("%.2f ms", ns/1000000) }
FNR==1 { delete T; delete M; k=0 }
match($0, /\[t=([0-9]+)\] (.*)$/, g) {
    # Collapse volatile run-specific suffixes (pids, ctx, byte counts) so the same milestone
    # across runs aggregates under one label.
    lbl=g[2]; gsub(/[0-9]+/, "#", lbl); T[k]=g[1]+0; M[k]=lbl; k++
}
ENDFILE {
    if (k >= 2) {
        span = T[k-1] - T[0]; spans[++ns_i] = span
        for (j=0; j<k-1; j++) {
            d = T[j+1] - T[j]; key = M[j] " -> " M[j+1]
            sum[key] += d; cnt[key]++; if (d > mx[key]) mx[key] = d
            all[key] = 1
        }
    }
}
END {
    asort(spans); med = spans[int(ns_i*0.5)+0 < 1 ? 1 : int(ns_i*0.5)]; p90 = spans[int(ns_i*0.9)+0 < 1 ? 1 : int(ns_i*0.9)]
    printf "\n  construction span (first→last milestone), %d runs:\n", ns_i
    printf "    median %s   p90 %s\n", ms(med), ms(p90)
    printf "    rate   %.1f constructions/sec (wall, incl. workload+teardown)\n", n/(wall_ns/1000000000)
    printf "\n  per-boundary (mean latency, slowest first):\n"
    nb=0; for (key in all) { mean[nb]=sum[key]/cnt[key]; lab[nb]=key; nb++ }
    for (a=0;a<nb;a++) for (b=a+1;b<nb;b++) if (mean[b]>mean[a]) { t=mean[a];mean[a]=mean[b];mean[b]=t; s=lab[a];lab[a]=lab[b];lab[b]=s }
    for (a=0;a<nb && a<14;a++) printf "    %8s  %s\n", ms(mean[a]), lab[a]
}
' "$RUNS_DIR"/run-*.log

echo
echo "  (note: off-CPU hop profiling — perf sched / bpftrace offcputime — and the XRay function-level"
echo "   deep-dive are follow-on increments; this is the always-on boundary breakdown.)"
