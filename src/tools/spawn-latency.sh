#!/usr/bin/env bash
#
# Spawn-latency profiling harness (ROADMAP-0.3.0 W10): measure kennel CONSTRUCTION and
# TEARDOWN latency end-to-end across the privilege-domain boundaries (kennel → kenneld →
# privhelper → kennel-bin-init → workload → teardown), per boundary, against the REAL installed
# Project Kennel — the same `kennel run` path the policy suite drives.
#
# HOW it measures, without a profiler: the spawn-path tracer (kennel_lib_config::Tracer) stamps
# every `step` milestone with a wall-clock `[t=<nanos>]` at Debug level, and the milestones from
# kenneld + the privhelper + kennel-bin-init share the host clock (CLOCK_REALTIME), so the delta
# between two consecutive milestones IS that boundary's latency. Construction and teardown are
# split into two first-class spans (a slow teardown makes spawn rates teardown-limited, §W10).
#
# WHY also off-CPU (--offcpu): a wall-clock boundary delta cannot tell *work* from *waiting*. The
# cross-process hops (factory → boot-sync, child build → fexecve) are dominated by one process
# BLOCKED on another's progress — off-CPU, not on-CPU. `--offcpu` attributes off-CPU time to the
# spawn-path processes via the sched_switch tracepoint, so the methodology is honest about which
# milliseconds are reclaimable (on-CPU work) versus structural (a blocked wait on a child exec).
#
# WHY a baseline/compare (--baseline/--compare): the **TCB latency delta is a runtime-behavioural
# signal** — a structural addition to the hot path (e.g. the SPAWN verb landing in Thrust 3) shifts
# the path's internal proportions even when it doesn't move absolute numbers. Snapshot a profile
# now (--baseline), re-run after the change (--compare), and read the per-boundary drift.
#
# The high-res function-level deep-dive (LLVM XRay, `-Z instrument-xray`) is a LOCAL DEV build on a
# nightly toolchain only — it cannot ship on the stable release path (CODING-STANDARDS §2.1), so it
# is documented as a recipe (--xray-recipe), not wired into this always-on harness.
#
# A skip is not a proof: a missing prerequisite aborts with the precise cause.
#
#   Usage: src/tools/spawn-latency.sh [opts] [N] [case]
#     --no-install      use the already-installed kennel (skip build+install)
#     --offcpu          additionally attribute off-CPU time to the spawn-path processes (needs sudo bpftrace)
#     --baseline FILE   write the parsed profile to FILE (per-boundary means + spans) for later --compare
#     --compare FILE    diff this run's profile against a FILE written by an earlier --baseline
#     --xray-recipe     print the nightly LLVM-XRay function-level recipe and exit
#     N                 constructions to time (default 30)
#     case              a policy-suite case name to construct (default net-none)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

print_xray_recipe() {
    cat <<'RECIPE'
LLVM-XRay function-level deep-dive (LOCAL DEV ONLY — nightly toolchain; never the release path):

  # 1. Build kenneld + the privhelper with XRay sleds (boundary-only sleds keep the overhead low;
  #    drop the always-instrument-function-count threshold for an all-function dev profile).
  RUSTFLAGS="-Z instrument-xray=always" \
    cargo +nightly build --release -p kenneld -p kennel-privhelper

  # 2. Run one construction with patching enabled; XRay drops an xray-log.* per process.
  XRAY_OPTIONS="patch_premain=true xray_mode=xray-basic verbosity=1" \
    ./target/release/<binary> ...

  # 3. Convert to a fl. graph / per-function latency account.
  llvm-xray account xray-log.<binary>.* --sort=sum --top=25 --format=text
  llvm-xray stack   xray-log.<binary>.* --aggregate-threads --stack-format=flame | flamegraph.pl

This harness deliberately does NOT shell out to the above: the stable release path carries the
always-on tracer boundary instrumentation instead (CODING-STANDARDS §2.1, stable toolchain only).
RECIPE
}

UID_NUM="$(id -u)"
[ "$UID_NUM" = "0" ] && { echo "run as the ordinary operator, not root" >&2; exit 2; }

DO_INSTALL=1
OFFCPU=0
BASELINE_OUT=""
COMPARE_IN=""
N=30
CASE="net-none"
while [ $# -gt 0 ]; do
    case "$1" in
        --no-install) DO_INSTALL=0 ;;
        --offcpu) OFFCPU=1 ;;
        --baseline) shift; BASELINE_OUT="${1:?--baseline needs a FILE}" ;;
        --compare) shift; COMPARE_IN="${1:?--compare needs a FILE}" ;;
        --xray-recipe) print_xray_recipe; exit 0 ;;
        [0-9]*) N="$1" ;;
        *) CASE="$1" ;;
    esac
    shift
done

KENNEL="/usr/bin/kennel"
[ -x "$KENNEL" ] || KENNEL="$(command -v kennel || true)"
SUITE_DIR="$REPO_ROOT/src/crates/kenneld/tests/policy-suite"
CASE_DIR="$SUITE_DIR/$CASE"
POLICY="$CASE_DIR/policy.toml"
CASE_RUN="$CASE_DIR/run.sh"
SYSTEM_TOML="/etc/kennel/system.toml"
KEY_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/kennel/keys"
SUITE_KEY="$KEY_DIR/kennel-suite"

[ -n "$COMPARE_IN" ] && { [ -f "$COMPARE_IN" ] || { echo "no baseline to compare: $COMPARE_IN" >&2; exit 2; }; }

# A self-driving case (run.sh) is OCI-rooted (`kennel oci run`, needs a fetched image); a plain
# policy.toml case is tmpfs-rooted. Tag spans by root kind so a tmpfs↔OCI comparison is legible.
if [ -f "$CASE_RUN" ]; then
    ROOT_KIND="OCI"
elif [ -f "$POLICY" ]; then
    ROOT_KIND="tmpfs"
    grep -qiE '^\s*\[rootfs\]|^\s*oci\s*=|image\s*=' "$POLICY" 2>/dev/null && ROOT_KIND="OCI"
else
    echo "no such case: $CASE_DIR (need policy.toml or run.sh)" >&2; exit 2
fi

SYSTEM_TOML_SAVED=""; SYSTEM_TOML_EXISTED=0
RUNS_DIR=""
cleanup() {
    [ -n "$RUNS_DIR" ] && rm -rf "$RUNS_DIR"
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
    # install.sh is a pure tarball installer — stage the just-built bins into a flat payload
    # (stage-tree.sh) and install that, like a user installs an unpacked release.
    STAGE="$(mktemp -d)"
    bash "$REPO_ROOT/src/tools/stage-tree.sh" --dest "$STAGE" >/dev/null || { echo "staging failed" >&2; exit 1; }
    sudo bash "$STAGE/install.sh" >/dev/null || { echo "install failed" >&2; exit 1; }
    rm -rf "$STAGE"
fi
[ -x "$KENNEL" ] || { echo "kennel not installed — run without --no-install" >&2; exit 2; }

# 2. Admin input install.sh does not fabricate: a trusted signing key (the kennel's
#    reserved subnet is uid-derived, so there is no allocation file to provision).
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

# One construction of the case: a plain `kennel run` for a tmpfs case, the case's own run.sh for a
# self-driving (OCI) case. Both go through the real construction + teardown path.
construct_once() {
    if [ -f "$CASE_RUN" ]; then
        ( cd "$CASE_DIR" && KENNEL="$KENNEL" SUITE_KEY="$SUITE_KEY" bash "$CASE_RUN" ) >/dev/null 2>&1 || true
    else
        "$KENNEL" run "$POLICY" --key "$SUITE_KEY" >/dev/null 2>&1 || true
    fi
}

# 4. Drive N constructions, capturing each run's trace burst from the journal by cursor. One warm-up
#    run (cold caches/JIT of the path) is discarded.
echo "== timing $N construction(s) of '$CASE' (root: $ROOT_KIND) =="
RUNS_DIR="$(mktemp -d)"
run_once() {
    local out="$1"
    local cur; cur="$(journalctl --user -u kenneld.service -n0 -o export --show-cursor 2>/dev/null \
        | sed -n 's/^-- cursor: //p' | tail -1)"
    construct_once
    # Give the journal a moment to flush the privhelper/kenneld lines, then collect this run's burst.
    sleep 0.05
    journalctl --user -u kenneld.service --after-cursor "$cur" -o cat 2>/dev/null > "$out"
}
run_once /dev/null  # warm-up, discarded

# Optional off-CPU attribution: account off-CPU time per spawn-path process over a short burst of
# constructions, so the wall-clock boundaries can be read as work-vs-wait. Best-effort: a kernel
# without the sched tracepoint, or no sudo bpftrace, downgrades to a clear note (a skip is not a proof).
OFFCPU_OUT=""
if [ "$OFFCPU" = 1 ]; then
    if sudo -n bpftrace --version >/dev/null 2>&1; then
        OFFCPU_OUT="$RUNS_DIR/offcpu.txt"
        OFFCPU_RUNS=10
        sudo -n bpftrace -e '
            tracepoint:sched:sched_switch {
                @off[args->prev_pid] = nsecs;
                if (@off[args->next_pid]) {
                    if (strncmp(args->next_comm, "kennel", 6) == 0) {
                        @offcpu_us[args->next_comm] = sum((nsecs - @off[args->next_pid]) / 1000);
                    }
                    delete(@off[args->next_pid]);
                }
            }
            END { clear(@off); }' >"$OFFCPU_OUT" 2>/dev/null &
        BPF_PID=$!
        sleep 0.4  # let the probe attach
        for _ in $(seq 1 "$OFFCPU_RUNS"); do construct_once; done
        sudo -n kill -INT "$BPF_PID" 2>/dev/null || true
        wait "$BPF_PID" 2>/dev/null || true
    else
        echo "  (--offcpu skipped: sudo bpftrace unavailable on this host)"
    fi
fi

START_NS="$(date +%s%N)"
for i in $(seq 1 "$N"); do run_once "$RUNS_DIR/run-$i.log"; done
END_NS="$(date +%s%N)"

PROFILE_OUT="$RUNS_DIR/profile.txt"

# 5. Parse the [t=<nanos>] milestones per run and aggregate. Each run's milestones split into a
#    CONSTRUCTION phase (everything before the first `teardown:` milestone) and a TEARDOWN phase;
#    each phase yields a span (first→last) and per-boundary deltas. A machine profile is written to
#    PROFILE_OUT for --baseline / --compare.
gawk -v n="$N" -v wall_ns="$((END_NS - START_NS))" -v profile_out="$PROFILE_OUT" -v root_kind="$ROOT_KIND" '
function ms(ns){ return sprintf("%.2f ms", ns/1000000) }
function pick(arr, count, frac,   idx){ idx = int(count*frac); if (idx < 1) idx = 1; if (idx > count) idx = count; return arr[idx] }
FNR==1 { delete T; delete M; delete PH; k=0 }
match($0, /\[t=([0-9]+)\] (.*)$/, g) {
    lbl=g[2]; gsub(/[0-9]+/, "#", lbl)        # collapse volatile pids/ctx/byte counts to one label
    phase = (lbl ~ /^teardown:/) ? "teardown" : "construct"
    T[k]=g[1]+0; M[k]=lbl; PH[k]=phase; k++
}
ENDFILE {
    # Per phase, in input (chronological, shared-clock) order: span = last - first, boundaries = deltas.
    delete fc; delete ft; cf=0; ct=0
    for (j=0; j<k; j++) { if (PH[j]=="construct") { ci[cf]=j; cf++ } else { ti[ct]=j; ct++ } }
    if (cf >= 2) {
        cspan[++cs_i] = T[ci[cf-1]] - T[ci[0]]
        for (j=0; j<cf-1; j++) { d=T[ci[j+1]]-T[ci[j]]; key="C|" M[ci[j]] " -> " M[ci[j+1]]; sum[key]+=d; cnt[key]++; all[key]=1 }
    }
    if (ct >= 2) {
        tspan[++ts_i] = T[ti[ct-1]] - T[ti[0]]
        for (j=0; j<ct-1; j++) { d=T[ti[j+1]]-T[ti[j]]; key="T|" M[ti[j]] " -> " M[ti[j+1]]; sum[key]+=d; cnt[key]++; all[key]=1 }
    }
}
END {
    asort(cspan); asort(tspan)
    printf "\n  root kind: %s\n", root_kind
    printf "\n  CONSTRUCTION span (first→last milestone), %d runs:\n", cs_i
    if (cs_i) printf "    median %s   p90 %s\n", ms(pick(cspan,cs_i,0.5)), ms(pick(cspan,cs_i,0.9))
    if (ts_i) {
        printf "\n  TEARDOWN span (first-class; a slow reclaim makes spawn teardown-limited), %d runs:\n", ts_i
        printf "    median %s   p90 %s\n", ms(pick(tspan,ts_i,0.5)), ms(pick(tspan,ts_i,0.9))
    } else
        printf "\n  TEARDOWN span: no teardown milestones captured (case exits before reclaim trace flush)\n"
    printf "    rate   %.1f constructions/sec (wall, incl. workload+teardown)\n", n/(wall_ns/1000000000)

    printf "\n  per-boundary (mean latency, slowest first; C=construct T=teardown):\n"
    nb=0; for (key in all) { mean[nb]=sum[key]/cnt[key]; lab[nb]=key; nb++ }
    for (a=0;a<nb;a++) for (b=a+1;b<nb;b++) if (mean[b]>mean[a]) { t=mean[a];mean[a]=mean[b];mean[b]=t; s=lab[a];lab[a]=lab[b];lab[b]=s }
    for (a=0;a<nb && a<16;a++) { tag=substr(lab[a],1,1); printf "    %8s  [%s] %s\n", ms(mean[a]), tag, substr(lab[a],3) }

    # Machine profile for --baseline / --compare: one boundary per line + the span medians.
    if (cs_i) printf "__cspan_med__\t%d\n", pick(cspan,cs_i,0.5) > profile_out
    if (cs_i) printf "__cspan_p90__\t%d\n", pick(cspan,cs_i,0.9) > profile_out
    if (ts_i) printf "__tspan_med__\t%d\n", pick(tspan,ts_i,0.5) > profile_out
    for (a=0;a<nb;a++) printf "%s\t%d\n", lab[a], mean[a] > profile_out
}
' "$RUNS_DIR"/run-*.log

# 6. Off-CPU attribution (if gathered): off-CPU residency per spawn-path process over the burst.
#    The honest read: a *per-construction* process (the `kennel` CLI, kennel-bin-init, the
#    privhelper) lives for one construction, so its off-CPU IS that construction's blocked-wait on
#    the hops — confirming the slow boundaries are waits, not CPU. A *daemon* (kenneld and its
#    kennel-lib-binder loopers) outlives every run, so its figure folds in idle parking between
#    runs and is NOT a per-construction cost — labelled as such so it is not misread.
if [ -n "$OFFCPU_OUT" ] && [ -s "$OFFCPU_OUT" ]; then
    echo
    echo "  off-CPU residency per spawn-path process (mean ms / construction, over $OFFCPU_RUNS runs):"
    gawk -v runs="$OFFCPU_RUNS" '
        function kind(c){ return (c == "kenneld" || c ~ /^kennel-lib/) ? "daemon (incl. idle parking — not per-construction)" : "per-construction blocked-wait on the hops" }
        match($0, /@offcpu_us\[([^\]]+)\]: ([0-9]+)/, g) { rows[g[1]] = g[2]+0 }
        END {
            n=0; for (c in rows) { v[n]=rows[c]; lab[n]=c; n++ }
            for (a=0;a<n;a++) for (b=a+1;b<n;b++) if (v[b]>v[a]) { t=v[a];v[a]=v[b];v[b]=t; s=lab[a];lab[a]=lab[b];lab[b]=s }
            for (a=0;a<n;a++) printf "    %8.2f ms  %-16s [%s]\n", (v[a]/runs)/1000, lab[a], kind(lab[a])
        }' "$OFFCPU_OUT"
fi

# 7. TCB latency delta: diff this run's profile against an earlier baseline (the runtime-behavioural
#    signal — a structural hot-path change shifts internal proportions even at flat absolute numbers).
if [ -n "$COMPARE_IN" ]; then
    echo
    echo "  TCB latency delta vs baseline ($COMPARE_IN), boundaries that moved most:"
    awk -F'\t' '
        function ms(ns){ return sprintf("%+.2f ms", ns/1000000) }
        NR==FNR { base[$1]=$2+0; next }
        { cur[$1]=$2+0; seen[$1]=1 }
        END {
            n=0
            for (k in seen)  { d = cur[k] - (k in base ? base[k] : 0); delta[n]=d; lab[n]=k; isnew[n]=(k in base)?0:1; n++ }
            for (k in base)  if (!(k in seen)) { delta[n]=-base[k]; lab[n]=k; isnew[n]=2; n++ }  # gone
            for (a=0;a<n;a++) for (b=a+1;b<n;b++) if ((delta[b]<0?-delta[b]:delta[b])>(delta[a]<0?-delta[a]:delta[a])) {
                t=delta[a];delta[a]=delta[b];delta[b]=t; s=lab[a];lab[a]=lab[b];lab[b]=s; q=isnew[a];isnew[a]=isnew[b];isnew[b]=q }
            for (a=0;a<n && a<12;a++) {
                tag = isnew[a]==1 ? " (NEW)" : (isnew[a]==2 ? " (GONE)" : "")
                printf "    %12s  %s%s\n", ms(delta[a]), lab[a], tag
            }
        }' "$COMPARE_IN" "$PROFILE_OUT"
fi

# 8. Snapshot this profile as a baseline for a later --compare (e.g. before/after the SPAWN verb lands).
if [ -n "$BASELINE_OUT" ]; then
    cp "$PROFILE_OUT" "$BASELINE_OUT"
    echo
    echo "  baseline profile written: $BASELINE_OUT  (re-run with --compare $BASELINE_OUT after a hot-path change)"
fi
