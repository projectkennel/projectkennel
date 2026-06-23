#!/usr/bin/env bash
#
# Run the policy test SUITE against the REAL installed Project Kennel — the standard
# toolchain, not a bespoke daemon. Every case under
# src/crates/kenneld/tests/policy-suite/<case>/ is a self-checking signed policy whose
# [workload] inspects the constructed kennel from the inside and exits 0 iff the slice it
# proves holds; this driver runs each through `kennel run <case>` against the installed,
# systemd-managed `kenneld.service`. The kennel's exit code IS each case's verdict.
#
# WHY drive the installed service (not `systemd-run` + a build-tree kenneld): the spawn
# path threads YAMA / cgroups / AppArmor / userns / Landlock / seccomp, and getting that
# environment right is exactly what install.sh + the kenneld.service unit (Delegate=yes,
# the AppArmor profile, the setuid privhelper) already encode. Re-deriving a slice of it
# in the test harness drifts and breaks; using the production install is both simpler and
# a truer test. (This replaced an earlier systemd-run-based runner that kept dying.)
#
# A skip is not a proof: a missing prerequisite aborts with the precise cause.
#
# What it does:
#   1. build the release, stage it into a flat payload (stage-tree.sh), and run the real
#      `sudo ./install.sh` against it — unless --no-install (use what is already installed);
#   2. provision the admin inputs install.sh deliberately does NOT fabricate: this user's
#      /etc/kennel/subkennel allocation (tag 42) and a suite signing key the daemon trusts;
#   3. (re)start the installed kenneld.service so it runs the just-installed binary;
#   4. stage the shared fixtures a policy cannot carry (the AF_UNIX echo listener + the
#      granted home subtree), then run each case via the installed `kennel` CLI.
#
# Usage:
#   src/tools/policy-e2e.sh [--no-install] [--debug] [case-name ...]   # no cases = all
#     --no-install   skip build+install; use the already-installed kennel
#     --debug        set log_level=debug in /etc/kennel/system.toml for the run

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
SUITE_DIR="$REPO_ROOT/src/crates/kenneld/tests/policy-suite"
LIBEXEC="/usr/libexec/kennel"
KENNEL="$LIBEXEC/kennel"

UID_NUM="$(id -u)"
if [ "$UID_NUM" = "0" ]; then
    echo "Run as the ordinary operator, not root — this proves the UNPRIVILEGED vertical." >&2
    exit 2
fi

DO_INSTALL=1
DEBUG=0
CASES=()
for arg in "$@"; do
    case "$arg" in
        --no-install) DO_INSTALL=0 ;;
        --debug) DEBUG=1 ;;
        -*) echo "unknown flag: $arg" >&2; exit 2 ;;
        *) CASES+=("$arg") ;;
    esac
done

# Constants the cases depend on (the reserved scope the suite policies assume).
SUBKENNEL_TAG=42
SUBKENNEL_NS="kennel-dev"
SUBKENNEL_LINE="${UID_NUM}:${SUBKENNEL_TAG}:0000000002:${SUBKENNEL_NS}"
SUITE_KEY_ID="kennel-suite"
KEY_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/kennel/keys"
SUITE_KEY="$KEY_DIR/$SUITE_KEY_ID.key"
ECHO_SOCK_DIR="/run/kennel-e2e"
ECHO_SOCK="$ECHO_SOCK_DIR/echo.sock"
HOME_FIXTURE="$HOME/kennel-e2e"
SYSTEM_TOML="/etc/kennel/system.toml"

ECHO_PID=""
SUBKENNEL_SAVED=""
SYSTEM_TOML_SAVED=""        # prior /etc/kennel/system.toml contents (restored on exit)
SYSTEM_TOML_EXISTED=0

cleanup() {
    [ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null || true
    if [ -n "$SUBKENNEL_SAVED" ]; then
        sudo sed -i "s|^${UID_NUM}:.*|${SUBKENNEL_SAVED}|" /etc/kennel/subkennel 2>/dev/null || true
    fi
    # Restore the system.toml we may have rewritten for --debug.
    if [ "$DEBUG" = 1 ]; then
        if [ "$SYSTEM_TOML_EXISTED" = 1 ]; then
            printf '%s' "$SYSTEM_TOML_SAVED" | sudo tee "$SYSTEM_TOML" >/dev/null 2>&1 || true
        else
            sudo rm -f "$SYSTEM_TOML" 2>/dev/null || true
        fi
        systemctl --user restart kenneld.service 2>/dev/null || true
    fi
    sudo rm -rf "$ECHO_SOCK_DIR" 2>/dev/null || true
    rm -rf "$HOME_FIXTURE" 2>/dev/null || true
}
trap cleanup EXIT

# 1. Build + install the real thing (the production path), unless told to use the
#    already-installed kennel.
if [ "$DO_INSTALL" = 1 ]; then
    echo "== building release =="
    # Host-side (dynamic) and in-kennel (static-pie) sets, mirroring stage-tree.sh — the in-kennel
    # binaries (launcher, init, facades) must be static to run inside an arbitrary OCI image root.
    HOST_TRIPLE="$(uname -m)-unknown-linux-gnu"
    cargo build --release --offline --frozen --locked \
        -p kenneld -p kennel-cli -p kennel-host-delegate -p kennel-host-dbus \
        || { echo "build failed" >&2; exit 1; }
    RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --offline --frozen --locked \
        --target "$HOST_TRIPLE" \
        -p kennel-bin-oci-entry -p kennel-bin-init -p kennel-facade \
        || { echo "static in-kernel build failed" >&2; exit 1; }
    cargo build --release --offline --frozen --locked -p kennel-privhelper --features bpf-egress \
        || { echo "privhelper build failed" >&2; exit 1; }
    echo "== staging the install payload + installing (sudo ./install.sh) =="
    # install.sh is a pure tarball installer — it never runs from the source tree. Stage the
    # just-built binaries into a flat payload (stage-tree.sh, the same assembler build-release.sh
    # uses) and install THAT, exactly as a user installs an unpacked release.
    # --with-test-bins: the spawn-roundtrip suite's workload is facade-spawn-probe, a test driver a
    # release never ships, so the payload must carry it for this install.
    STAGE="$(mktemp -d)"
    bash "$REPO_ROOT/src/tools/stage-tree.sh" --dest "$STAGE" --with-test-bins || { echo "staging failed" >&2; exit 1; }
    sudo bash "$STAGE/install.sh" || { echo "install failed" >&2; exit 1; }
    rm -rf "$STAGE"
fi
[ -x "$KENNEL" ] || { echo "kennel not installed at $KENNEL — run without --no-install" >&2; exit 2; }

# 2. The admin inputs install.sh deliberately does not fabricate (07-paths §5):
#    the subkennel allocation for this user, and a signing key the daemon trusts.
echo "== /etc/kennel/subkennel allocation for uid $UID_NUM (sudo) =="
sudo touch /etc/kennel/subkennel
EXISTING="$(sudo grep -E "^${UID_NUM}:" /etc/kennel/subkennel 2>/dev/null | head -1 || true)"
if [ -z "$EXISTING" ]; then
    echo "$SUBKENNEL_LINE" | sudo tee -a /etc/kennel/subkennel >/dev/null
elif [ "$EXISTING" != "$SUBKENNEL_LINE" ]; then
    SUBKENNEL_SAVED="$EXISTING"
    sudo sed -i "s|^${UID_NUM}:.*|${SUBKENNEL_LINE}|" /etc/kennel/subkennel
fi
sudo grep -E "^${UID_NUM}:" /etc/kennel/subkennel

echo "== suite signing key (the daemon trusts the user key dir) =="
# `kennel run` compiles+signs each source policy in memory; the daemon verifies against the
# user key dir (trusted alongside /etc/kennel/keys). A dedicated key keeps `--key` unambiguous.
if [ ! -f "$SUITE_KEY" ]; then
    "$KENNEL" keygen "$SUITE_KEY_ID" || { echo "keygen failed" >&2; exit 1; }
fi
[ -f "$SUITE_KEY" ] || { echo "suite key not at $SUITE_KEY after keygen" >&2; exit 1; }

# Optional: turn on spawn-path verbose logging for this run (restored on exit).
if [ "$DEBUG" = 1 ]; then
    echo "== enabling log_level=debug in $SYSTEM_TOML (sudo; restored on exit) =="
    if sudo test -e "$SYSTEM_TOML"; then
        SYSTEM_TOML_EXISTED=1
        SYSTEM_TOML_SAVED="$(sudo cat "$SYSTEM_TOML")"
    fi
    # Preserve any existing keys, then set/replace log_level.
    { [ "$SYSTEM_TOML_EXISTED" = 1 ] && printf '%s\n' "$SYSTEM_TOML_SAVED" | grep -v '^log_level'; \
      echo 'log_level = "debug"'; } | sudo tee "$SYSTEM_TOML" >/dev/null
fi

# 3. Ensure the installed service is running the just-installed binary.
echo "== (re)starting the installed kenneld.service =="
systemctl --user daemon-reload 2>/dev/null || true
systemctl --user restart kenneld.service 2>/dev/null \
    || systemctl --user start kenneld.service 2>/dev/null \
    || { echo "could not start kenneld.service" >&2; exit 1; }
SOCK="${XDG_RUNTIME_DIR:-/run/user/$UID_NUM}/kennel/control.sock"
ok=0
for _ in $(seq 1 50); do [ -S "$SOCK" ] && { ok=1; break; }; sleep 0.1; done
[ "$ok" = 1 ] || { echo "kenneld.service did not bind $SOCK; journalctl --user -u kenneld.service" >&2; exit 1; }
echo "  control socket: $SOCK"

# 4. Shared fixtures a policy cannot carry.
echo "== staging shared fixtures =="
rm -rf "$HOME_FIXTURE"
mkdir -p "$HOME_FIXTURE/granted" "$HOME_FIXTURE/secret"
printf 'OK\n' > "$HOME_FIXTURE/granted/file"
printf 'SECRET\n' > "$HOME_FIXTURE/secret/file"
sudo mkdir -p "$ECHO_SOCK_DIR"
sudo chown "$UID_NUM" "$ECHO_SOCK_DIR"
rm -f "$ECHO_SOCK"
python3 - "$ECHO_SOCK" <<'PY' &
import socket, sys, os
p = sys.argv[1]
try:
    os.unlink(p)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX); s.bind(p); s.listen(16)
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    if c.recv(16) == b'ping':
        c.sendall(b'pong')
    c.close()
PY
ECHO_PID=$!
for _ in $(seq 1 20); do [ -S "$ECHO_SOCK" ] && break; sleep 0.1; done
[ -S "$ECHO_SOCK" ] || { echo "echo listener did not bind $ECHO_SOCK" >&2; exit 1; }

# The cases to run.
if [ "${#CASES[@]}" -eq 0 ]; then
    for d in "$SUITE_DIR"/*/; do CASES+=("$(basename "$d")"); done
fi

# Point the CLI's vendor catalogues (§2.6: the trust-trigger set) at the repo's defaults, so a
# `--no-install` run still resolves them. The daemon's etc-binds catalogue (W14) is read by the
# installed kenneld.service from /usr/lib/kennel, where install.sh places it — the service does
# not inherit this env, so that one rides the install, not this override.
export KENNEL_VENDOR_DIR="$REPO_ROOT/dist/vendor"
export REPO_ROOT SUITE_DIR
echo "== running ${#CASES[@]} case(s) against the installed service =="
pass=0; fail=0; skip=0; results=""
for name in "${CASES[@]}"; do
    pol="$SUITE_DIR/$name/policy.toml"
    printf "== %-16s " "$name"
    # A case is either a `policy.toml` (driven by `kennel run`) or a `run.sh` hook (self-driving,
    # e.g. the OCI-substrate case which uses `kennel oci run` and generates its policy).
    if [ ! -f "$pol" ] && [ ! -x "$SUITE_DIR/$name/run.sh" ]; then
        echo "?? (no such case)"; results="$results\n  ?? $name"; fail=$((fail+1)); continue
    fi
    # Per-case setup hook: a case needing host fixtures it cannot carry ships a setup.sh,
    # run with (case-dir, scratch-dir); it stages the fixtures and prints the policy path to
    # run (a generated copy with host values filled in) on its LAST stdout line. teardown.sh
    # (if any) runs after. A bounded timeout keeps a wedged fixture from hanging the suite.
    run_pol="$pol"
    scratch="/tmp/kennel-suite-$name.scratch"
    # Self-driving hook (`run.sh`): an OCI-substrate case is driven by `kennel oci run`, not
    # `kennel run` (the grammar partition refuses `[rootfs]` under `kennel run`), so it ships a
    # `run.sh` that owns the whole flow — fetch + build the store entry, boot, self-check — and
    # returns the verdict (exit 77 = SKIP, a missing prerequisite reported, never a silent pass).
    if [ -x "$SUITE_DIR/$name/run.sh" ]; then
        rm -rf "$scratch"; mkdir -p "$scratch"
        timeout 120 "$SUITE_DIR/$name/run.sh" "$SUITE_DIR/$name" "$KENNEL" "$SUITE_KEY" "$scratch" \
            </dev/null >"/tmp/kennel-suite-$name.log" 2>&1
        rc=$?
        rm -rf "$scratch"
        if [ "$rc" = 77 ]; then
            echo "SKIP — $(grep -m1 '^SKIP' "/tmp/kennel-suite-$name.log" | sed 's/^SKIP: *//' || echo 'prerequisite missing')"
            results="$results\n  SKIP  $name"; skip=$((skip+1)); continue
        fi
        if [ "$rc" = 0 ]; then echo "PASS"; results="$results\n  PASS  $name"; pass=$((pass+1));
        elif [ "$rc" = 124 ]; then echo "FAIL (timeout) — see /tmp/kennel-suite-$name.log"; results="$results\n  FAIL(timeout) $name"; fail=$((fail+1));
        else echo "FAIL (exit $rc) — see /tmp/kennel-suite-$name.log"; results="$results\n  FAIL($rc) $name"; fail=$((fail+1)); fi
        continue
    fi
    if [ -x "$SUITE_DIR/$name/setup.sh" ]; then
        rm -rf "$scratch"; mkdir -p "$scratch"
        # Capture setup stdout to a FILE, not a `$(...)` pipe. A fixture that backgrounds a
        # daemon (host listener, sshd) which inherits stdout would hold a command-substitution
        # pipe open forever and DEADLOCK the suite — `timeout` bounds setup.sh itself but not
        # its orphaned children. A regular-file fd is never blocking; the last line is the policy.
        if timeout 60 "$SUITE_DIR/$name/setup.sh" "$SUITE_DIR/$name" "$scratch" \
                    >"$scratch/setup.out" 2>"/tmp/kennel-suite-$name.setup.log"; then
            run_pol="$(tail -n1 "$scratch/setup.out")"
        else
            echo "FAIL (setup) — see /tmp/kennel-suite-$name.setup.log"
            results="$results\n  FAIL(setup) $name"; fail=$((fail+1))
            [ -x "$SUITE_DIR/$name/teardown.sh" ] && "$SUITE_DIR/$name/teardown.sh" "$scratch" 2>/dev/null || true
            continue
        fi
    fi
    # Distinct instance name per case; </dev/null = non-interactive. A timeout bounds a
    # wedged spawn. The workload exit code is the run status. Templates resolve from the STANDARD
    # installed cascade (install.sh ships them to /usr/lib/kennel/templates) — never the source tree,
    # so the daemon resolves a spawn target the same way the requester compiled against it.
    timeout 90 "$KENNEL" run "$run_pol" "$name" --key "$SUITE_KEY" \
        --trust-dir "$KEY_DIR" </dev/null \
        >"/tmp/kennel-suite-$name.log" 2>&1
    rc=$?
    [ -x "$SUITE_DIR/$name/teardown.sh" ] && "$SUITE_DIR/$name/teardown.sh" "$scratch" 2>/dev/null || true
    rm -rf "$scratch"
    if [ "$rc" = 0 ]; then
        echo "PASS"; results="$results\n  PASS  $name"; pass=$((pass+1))
    elif [ "$rc" = 124 ]; then
        echo "FAIL (timeout) — see /tmp/kennel-suite-$name.log"
        results="$results\n  FAIL(timeout) $name"; fail=$((fail+1))
    else
        echo "FAIL (exit $rc) — see /tmp/kennel-suite-$name.log"
        results="$results\n  FAIL($rc) $name"; fail=$((fail+1))
    fi
done

echo
echo "== suite summary: $pass passed, $fail failed, $skip skipped =="
printf "%b\n" "$results"
[ "$fail" = 0 ]
