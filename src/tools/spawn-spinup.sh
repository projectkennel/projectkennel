#!/usr/bin/env bash
#
# Spawn-spinup comparison harness (ROADMAP-0.3.0, W10 "one layer down").
#
# Spin up a SINGLE long-lived **control kennel** (one `kennel run`), and inside its one lifetime run
# the same payload N times in a row, two ways, and compare them — so the numbers are the spinup itself,
# with NO per-run CLI launch and NO per-run policy compile in the way:
#
#   DIRECT     — the control kennel `fork`/`exec`s the payload (`/bin/true`, `python3 -c …`) and reaps
#                it. The process-spinup floor: the work, with no new kennel around it.
#   EPHEMERAL  — the control kennel transacts verb::SPAWN for the payload's signed template, so kenneld
#                mints a scoped sibling kennel to run it; the bench reads the sibling's channel to EOF
#                (it has run and exited). The full isolated-kennel spinup, one layer down.
#
# The control kennel's workload (`facade-spawn-bench`) times each whole run (monotonic, reaped) and
# prints `direct <ns>` / `spawn <ns>` per iteration on stdout, which a plain `kennel run` returns here.
# The DIRECT↔EPHEMERAL delta is what wrapping each run in its own fresh kennel costs. kenneld's
# `[t=<nanos>]` trace stream additionally breaks the EPHEMERAL side into its in-daemon phases (the
# SPAWN handler validate→mint, and the construction) — printed alongside, from the journal.
#
# This is NOT 20× a oneshot `kennel run → kenneld → child`: there is one control kennel per workload,
# and the loop lives inside it. The only `kennel run` wall paid is the control kennel's own, once.
#
# CAVEAT 1: the kenneld trace rides the journald sink (a blocking write) — it perturbs the in-daemon
# sub-spans; the DIRECT/EPHEMERAL wall lines are the bench's own monotonic clock and do not.
#
# CAVEAT 2 (CPU frequency): construction is workload-independent by design (`workload running` is
# stamped when kenneld has the pid back, before the payload's own fexecve). On an unpinned box
# (`scaling_governor = powersave/schedutil`) this can read otherwise CROSS-workload: the direct loop
# runs first, so a heavy payload (python, ~300 ms of CPU) ramps the cores to turbo before ITS spawn
# loop while a trivial one (/bin/true, ~15 ms) leaves them idle — so the heavy payload's construct
# clocks faster. Pin `performance` for a fair cross-workload comparison; the medians then converge.
#
#   Usage: src/tools/spawn-spinup.sh [--no-install] [N]
#     --no-install   use the already-installed kennel (skip build+install)
#     N              iterations per loop (default 20)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

UID_NUM="$(id -u)"
[ "$UID_NUM" = "0" ] && { echo "run as the ordinary operator, not root" >&2; exit 2; }

DO_INSTALL=1
N=20
while [ $# -gt 0 ]; do
    case "$1" in
        --no-install) DO_INSTALL=0 ;;
        [0-9]*) N="$1" ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
    shift
done

KENNEL="/usr/libexec/kennel/kennel"
[ -x "$KENNEL" ] || KENNEL="$(command -v kennel || true)"
SYSTEM_TOML="/etc/kennel/system.toml"
CFG="${XDG_CONFIG_HOME:-$HOME/.config}/kennel"
KEY_DIR="$CFG/keys"
SUITE_KEY="$KEY_DIR/kennel-suite.key"
TPL_DIR="$CFG/templates"
SUBKENNEL_LINE="${UID_NUM}:42:0000000002:kennel-dev"

WORKLOAD_LABELS=("/bin/true" "python3 -c print('hello')")
WORKLOAD_TEMPLATES=("true-tool" "pyhello-tool")

SYSTEM_TOML_SAVED=""; SYSTEM_TOML_EXISTED=0
WORK=""
cleanup() {
    [ -n "$WORK" ] && rm -rf "$WORK"
    rm -rf "$TPL_DIR/true-tool" "$TPL_DIR/pyhello-tool" 2>/dev/null || true
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
    # (stage-tree.sh) and install that, like a user installs an unpacked release. --with-test-bins:
    # the bench driver facade-spawn-bench is a test binary a release never ships.
    STAGE="$(mktemp -d)"
    bash "$REPO_ROOT/src/tools/stage-tree.sh" --dest "$STAGE" --with-test-bins >/dev/null || { echo "staging failed" >&2; exit 1; }
    sudo bash "$STAGE/install.sh" >/dev/null || { echo "install failed" >&2; exit 1; }
    rm -rf "$STAGE"
fi
[ -x "$KENNEL" ] || { echo "kennel not installed — run without --no-install" >&2; exit 2; }

# 2. Admin inputs install.sh does not fabricate: the subkennel allocation + a trusted signing key.
sudo touch /etc/kennel/subkennel
sudo grep -qE "^${UID_NUM}:" /etc/kennel/subkennel || echo "$SUBKENNEL_LINE" | sudo tee -a /etc/kennel/subkennel >/dev/null
[ -f "$SUITE_KEY" ] || "$KENNEL" keygen kennel-suite >/dev/null

# 3. Compile + SIGN the two spawn templates to their settled form (suite key the daemon trusts) and
#    install into the standard user cascade — exactly the spawn-roundtrip case's fixture path.
echo "== compiling + signing spawn templates (true-tool, pyhello-tool) =="
for t in true-tool pyhello-tool; do
    SRC="/usr/lib/kennel/templates/$t/policy.toml"
    [ -f "$SRC" ] || { echo "template $t not installed at $SRC (install.sh ships the reference templates)" >&2; exit 2; }
    mkdir -p "$TPL_DIR/$t"
    "$KENNEL" policy compile "$SRC" --key "$SUITE_KEY" --trust-dir "$KEY_DIR" --no-lock \
        --output "$TPL_DIR/$t/$t.settled.toml" >/dev/null
done

# 4. Generate one CONTROL-kennel policy per workload: a confined kennel that may exec the payload
#    directly AND holds a [spawn] grant for the payload's template, whose workload is the bench driver.
WORK="$(mktemp -d)"
gen_control() {  # $1=name $2=template@v1 $3=exec-extra-csv $4=argv-tail-csv
    cat > "$WORK/$1.toml" <<EOF
name = "$1"
template_base = "base-confined@v1"
[net]
mode = "none"
[fs]
read = ["/usr/**", "/bin/**", "/lib/**", "/lib64/**"]
[exec]
allow = ["/usr/libexec/kennel/facade-spawn-bench", "/bin/sh", $3]
[workload]
argv = ["/usr/libexec/kennel/facade-spawn-bench", "$N", "$2", $4]
pinned = true
[lifecycle]
ttl = "10m"
ttl_action = "exit"
[ulimits]
as = "4G"
nproc = "256"
cpu = "60"
[spawn]
max_instances = 8
reason = "spinup bench: $N direct + $N spawn of $2"
[[spawn.allow]]
template = "$2"
EOF
}
gen_control spinup-true    true-tool@v1    '"/bin/true", "/usr/bin/true"' '"/bin/true"'
gen_control spinup-pyhello pyhello-tool@v1 '"/usr/bin/python3", "/usr/bin/python3.12"' \
    '"/usr/bin/python3", "-c", "print('"'"'hello'"'"')"'

# 5. Turn on the timestamped spawn-path trace (restored on exit) and (re)start the service.
echo "== enabling log_level=debug (restored on exit) =="
if sudo test -e "$SYSTEM_TOML"; then SYSTEM_TOML_EXISTED=1; SYSTEM_TOML_SAVED="$(sudo cat "$SYSTEM_TOML")"; fi
{ [ "$SYSTEM_TOML_EXISTED" = 1 ] && printf '%s\n' "$SYSTEM_TOML_SAVED" | grep -v '^log_level'; \
  echo 'log_level = "debug"'; } | sudo tee "$SYSTEM_TOML" >/dev/null
systemctl --user restart kenneld.service 2>/dev/null || systemctl --user start kenneld.service
SOCK="${XDG_RUNTIME_DIR:-/run/user/$UID_NUM}/kennel/control.sock"
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "kenneld.service did not bind $SOCK" >&2; exit 1; }

# median + p90 of a file of integer nanoseconds, formatted ms (gawk asort).
stats() {
    gawk 'NF{a[++n]=$1+0} END{
        if(!n){printf "      n/a            n/a "; exit}
        asort(a); m=int(n*0.5); if(m<1)m=1; p=int(n*0.9); if(p<1)p=1;
        printf "%8.2f ms      %8.2f ms", a[m]/1e6, a[p]/1e6
    }' "$1"
}

echo "== $N direct vs $N ephemeral spin-ups, inside ONE control kennel per workload =="
echo

for idx in 0 1; do
    label="${WORKLOAD_LABELS[$idx]}"
    tname="${WORKLOAD_TEMPLATES[$idx]}"
    case "$tname" in
        true-tool)    control="$WORK/spinup-true.toml" ;;
        pyhello-tool) control="$WORK/spinup-pyhello.toml" ;;
    esac

    # One control-kennel run. Capture the bench's stdout (the direct/spawn wall lines) and the
    # kenneld trace burst (the in-daemon EPHEMERAL phase breakdown) for this run by journal cursor.
    cur="$(journalctl --user -u kenneld.service -n0 -o export --show-cursor 2>/dev/null \
        | sed -n 's/^-- cursor: //p' | tail -1)"
    "$KENNEL" run "$control" --key "$SUITE_KEY" --trust-dir "$KEY_DIR" \
        >"$WORK/out.$idx" 2>"$WORK/err.$idx" || true
    sleep 0.3  # let late sibling-teardown milestones flush to the journal
    journalctl --user -u kenneld.service --after-cursor "$cur" -o cat 2>/dev/null > "$WORK/burst.$idx"

    # The bench's own monotonic wall, per loop.
    gawk '$1=="direct"{print $2}' "$WORK/out.$idx" > "$WORK/direct.$idx"
    gawk '$1=="spawn"{print $2}'  "$WORK/out.$idx" > "$WORK/spawn.$idx"
    # The in-daemon EPHEMERAL breakdown from the trace: handler (recv→mint), construct (start→run),
    # and teardown (`teardown: workload exited` → `run_kennel: teardown complete`). The `.spawn-`
    # filter on the complete line keeps the control kennel's own teardown out of the sibling samples;
    # the bench serializes on answer-EOF, so each sibling's reclaim completes before the next's begins.
    gawk 'match($0,/\[t=([0-9]+)\] (.*)/,g){t=g[1]+0;m=g[2];
        if(m ~ /spawn: SPAWN received/){recv=t; cstart=0; open=1}
        else if(m ~ /spawn: validated \+ minted/ && open){print "HANDLER", t-recv}
        else if(m ~ /run_kennel: starting .spawn-/ && open){cstart=t}
        else if(m ~ /run_kennel: workload running/ && open && cstart){print "CONSTRUCT", t-cstart; open=0}
        else if(m ~ /teardown: workload exited/){td=t}
        else if(m ~ /run_kennel: teardown complete .spawn-/ && td){print "TEARDOWN", t-td; td=0}
    }' "$WORK/burst.$idx" > "$WORK/eph_tagged.$idx"
    gawk '$1=="HANDLER"{print $2}'   "$WORK/eph_tagged.$idx" > "$WORK/handler.$idx"
    gawk '$1=="CONSTRUCT"{print $2}' "$WORK/eph_tagged.$idx" > "$WORK/construct.$idx"
    gawk '$1=="TEARDOWN"{print $2}'  "$WORK/eph_tagged.$idx" > "$WORK/teardown.$idx"

    d_n="$(wc -l < "$WORK/direct.$idx")"; s_n="$(wc -l < "$WORK/spawn.$idx")"; td_n="$(wc -l < "$WORK/teardown.$idx")"
    printf '  workload: %s   (control kennel: 1, iterations: %s)\n' "$label" "$N"
    printf '  %-48s %12s %15s\n' '' 'median' 'p90'
    printf '    DIRECT     fork/exec + reap (fully gone)        %s\n' "$(stats "$WORK/direct.$idx")"
    printf '    EPHEMERAL  answer ready (SPAWN → result + EOF)  %s\n' "$(stats "$WORK/spawn.$idx")"
    printf '    EPHEMERAL  teardown (workload exit → reclaimed) %s\n' "$(stats "$WORK/teardown.$idx")"
    printf '      └ EPHEMERAL answer, of which (kenneld trace):\n'
    printf '        · SPAWN handler  (validate→mint)            %s\n' "$(stats "$WORK/handler.$idx")"
    printf '        · construction   (build→workload exec)      %s\n' "$(stats "$WORK/construct.$idx")"
    printf '      (samples: direct %s/%s, answer %s/%s, teardown %s/%s)\n\n' "$d_n" "$N" "$s_n" "$N" "$td_n" "$N"
done

echo "  read: EPHEMERAL − DIRECT = the per-run cost of wrapping the payload in its own fresh,"
echo "  isolated kennel (namespaces, cgroup, seal, binder bus, teardown). The control kennel is"
echo "  spawned once; both loops run inside it, so no per-run CLI launch or policy compile is counted."
