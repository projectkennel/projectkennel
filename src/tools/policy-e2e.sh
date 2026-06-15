#!/usr/bin/env bash
#
# Run the policy test SUITE: every case under src/crates/kenneld/tests/policy-suite/ is
# a self-checking signed policy whose [workload] inspects the constructed kennel from
# the inside and exits 0 iff the slice it proves holds. This runner drives each case
# through the REAL daemon — `kennel run <case> <name>` against a live `kenneld` — so the
# suite exercises the production path end to end (07-2, 08-enforcement §8.2), with no
# hand-built Rust harness. The kennel's exit code IS each case's verdict.
#
# As with the rest of the project: a skip is not a proof. Where a prerequisite cannot be
# met the runner aborts with the precise cause rather than reporting a false pass.
#
# It performs the one-time host setup the unprivileged spawn path requires and then runs
# the cases as the ordinary operator (no sudo for the runs themselves):
#
#   1. builds the helper binaries (privhelper with --features bpf-egress LAST so a later
#      workspace build cannot clobber its embedded BPF objects), the facades, kenneld,
#      kennel, and kennel-bin-init;
#   2. `sudo setcap` the factory caps on the privhelper (the production install posture —
#      07-paths, never sudo at runtime);
#   3. provisions an /etc/kennel/subkennel allocation for the operator's uid (tag 42);
#   4. installs a root-owned kennel-bin-init at the libexec path the privhelper resolves;
#   5. writes /etc/kennel/system.toml pointing libexec_dir at the build tree (so the
#      daemon finds the dev helper binaries — the root-only deployment cascade, 07-paths);
#   6. ensures the operator holds a signing key (the daemon trusts the user key dir);
#   7. loads an AppArmor profile granting `userns` to kenneld + the privhelper;
#   8. stages the fixtures a policy cannot carry (the AF_UNIX echo listener + the granted
#      home subtree), starts kenneld under `systemd-run --user --scope -p Delegate=yes`
#      (a writable delegated cgroup), and runs every case.
#
# The sudo steps are reversible and local; everything is undone on exit. Usage:
#   src/tools/policy-e2e.sh [case-name ...]      # no args = every case

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"
SUITE_DIR="$REPO_ROOT/src/crates/kenneld/tests/policy-suite"

UID_NUM="$(id -u)"
if [ "$UID_NUM" = "0" ]; then
    echo "Run as the ordinary operator, not root — this proves the UNPRIVILEGED vertical." >&2
    exit 2
fi

# --- constants the cases depend on -------------------------------------------
SUBKENNEL_TAG=42
SUBKENNEL_NS="kennel-dev"
SUBKENNEL_LINE="${UID_NUM}:${SUBKENNEL_TAG}:0000000002:${SUBKENNEL_NS}"
AA_PROFILE_NAME="kennel_suite"
AA_PROFILE_FILE="$(mktemp /tmp/kennel-suite-aa.XXXXXX)"
INIT_DEST="/usr/libexec/kennel/kennel-bin-init"
AKC_DEST="/usr/libexec/kennel/kennel-akc"
SYSTEM_TOML="/etc/kennel/system.toml"
ECHO_SOCK_DIR="/run/kennel-e2e"
ECHO_SOCK="$ECHO_SOCK_DIR/echo.sock"
HOME_FIXTURE="$HOME/kennel-e2e"

# Restore state for things we may have swapped in.
SUBKENNEL_SAVED=""
INIT_DEST_BACKUP=""
INIT_DEST_CREATED=""
AKC_DEST_BACKUP=""
AKC_DEST_CREATED=""
SYSTEM_TOML_BACKUP=""
SYSTEM_TOML_CREATED=""
ECHO_PID=""

cleanup() {
    [ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null || true
    if [ -f "$AA_PROFILE_FILE" ]; then
        sudo apparmor_parser -R "$AA_PROFILE_FILE" 2>/dev/null || true
        rm -f "$AA_PROFILE_FILE"
    fi
    if [ -n "$SUBKENNEL_SAVED" ]; then
        sudo sed -i "s|^${UID_NUM}:.*|${SUBKENNEL_SAVED}|" /etc/kennel/subkennel 2>/dev/null || true
    fi
    if [ -n "$INIT_DEST_CREATED" ]; then
        sudo rm -f "$INIT_DEST" 2>/dev/null || true
    elif [ -n "$INIT_DEST_BACKUP" ]; then
        sudo cp -f "$INIT_DEST_BACKUP" "$INIT_DEST" 2>/dev/null || true
        rm -f "$INIT_DEST_BACKUP"
    fi
    if [ -n "$AKC_DEST_CREATED" ]; then
        sudo rm -f "$AKC_DEST" 2>/dev/null || true
    elif [ -n "$AKC_DEST_BACKUP" ]; then
        sudo cp -f "$AKC_DEST_BACKUP" "$AKC_DEST" 2>/dev/null || true
        rm -f "$AKC_DEST_BACKUP"
    fi
    if [ -n "$SYSTEM_TOML_CREATED" ]; then
        sudo rm -f "$SYSTEM_TOML" 2>/dev/null || true
    elif [ -n "$SYSTEM_TOML_BACKUP" ]; then
        sudo cp -f "$SYSTEM_TOML_BACKUP" "$SYSTEM_TOML" 2>/dev/null || true
        rm -f "$SYSTEM_TOML_BACKUP"
    fi
    sudo rm -rf "$ECHO_SOCK_DIR" 2>/dev/null || true
    rm -rf "$HOME_FIXTURE" 2>/dev/null || true
}
trap cleanup EXIT

echo "== building binaries =="
cargo build -p host-netproxy -p facade-socks5 -p facade-afunix -p facade-ssh \
    -p kennel-bin-init || exit 1
cargo build -p kenneld --bin kenneld --bin kennel || exit 1
cargo build -p kennel-privhelper --features bpf-egress || exit 1

PRIVHELPER="$REPO_ROOT/target/debug/kennel-privhelper"
KENNELD="$REPO_ROOT/target/debug/kenneld"
KENNEL="$REPO_ROOT/target/debug/kennel"
for b in "$PRIVHELPER" "$KENNELD" "$KENNEL"; do
    [ -x "$b" ] || { echo "missing built binary: $b" >&2; exit 1; }
done

echo "== factory capabilities on the privhelper (sudo, one-time) =="
sudo setcap cap_net_admin,cap_sys_admin,cap_setgid,cap_setuid,cap_setfcap=ep "$PRIVHELPER"
getcap "$PRIVHELPER"

echo "== /etc/kennel/subkennel allocation for uid $UID_NUM (sudo) =="
sudo mkdir -p /etc/kennel
sudo touch /etc/kennel/subkennel
EXISTING="$(sudo grep -E "^${UID_NUM}:" /etc/kennel/subkennel 2>/dev/null | head -1 || true)"
if [ -z "$EXISTING" ]; then
    echo "$SUBKENNEL_LINE" | sudo tee -a /etc/kennel/subkennel >/dev/null
elif [ "$EXISTING" != "$SUBKENNEL_LINE" ]; then
    SUBKENNEL_SAVED="$EXISTING"
    sudo sed -i "s|^${UID_NUM}:.*|${SUBKENNEL_LINE}|" /etc/kennel/subkennel
fi
sudo grep -E "^${UID_NUM}:" /etc/kennel/subkennel

echo "== root-owned kennel-bin-init at $INIT_DEST (sudo) =="
INIT_SRC="$REPO_ROOT/target/debug/kennel-bin-init"
sudo mkdir -p "$(dirname "$INIT_DEST")"
if [ -e "$INIT_DEST" ]; then
    INIT_DEST_BACKUP="$(mktemp /tmp/kennel-suite-init.XXXXXX)"
    sudo cp -f "$INIT_DEST" "$INIT_DEST_BACKUP"
else
    INIT_DEST_CREATED=1
fi
sudo cp -f "$INIT_SRC" "$INIT_DEST"
sudo chown 0:0 "$INIT_DEST"
sudo chmod 0755 "$INIT_DEST"

echo "== root-owned kennel-akc at $AKC_DEST (sudo) =="
# The SSH bastion's AuthorizedKeysCommand must be root-owned — OpenSSH's safe-path check
# rejects an AKC the unprivileged user could rewrite. The build-tree binary is
# operator-owned, so install a root-owned copy and point the deployment `akc` key at it.
AKC_SRC="$REPO_ROOT/target/debug/kennel-akc"
if [ -x "$AKC_SRC" ]; then
    sudo mkdir -p "$(dirname "$AKC_DEST")"
    if [ -e "$AKC_DEST" ]; then
        AKC_DEST_BACKUP="$(mktemp /tmp/kennel-suite-akc.XXXXXX)"
        sudo cp -f "$AKC_DEST" "$AKC_DEST_BACKUP"
    else
        AKC_DEST_CREATED=1
    fi
    sudo cp -f "$AKC_SRC" "$AKC_DEST"
    sudo chown 0:0 "$AKC_DEST"
    sudo chmod 0755 "$AKC_DEST"
fi

echo "== /etc/kennel/system.toml → build-tree helpers (sudo) =="
# The daemon resolves helper-binary paths only from the root-owned deployment cascade
# (no env override, by design — 07-paths). Point libexec_dir at the build tree so the
# dev kenneld finds the freshly-built privhelper/facades/init.
if [ -e "$SYSTEM_TOML" ]; then
    SYSTEM_TOML_BACKUP="$(mktemp /tmp/kennel-suite-systoml.XXXXXX)"
    sudo cp -f "$SYSTEM_TOML" "$SYSTEM_TOML_BACKUP"
else
    SYSTEM_TOML_CREATED=1
fi
sudo tee "$SYSTEM_TOML" >/dev/null <<EOF
# Written by src/tools/policy-e2e.sh for the dev suite; restored on exit.
libexec_dir = "$REPO_ROOT/target/debug"
init = "$INIT_DEST"
akc = "$AKC_DEST"
EOF
cat "$SYSTEM_TOML"

echo "== operator signing key (the daemon trusts the user key dir) =="
# `kennel run` compiles+signs the source policy in memory; the daemon then verifies the
# signature against the user key dir (which it trusts alongside the system trust dir).
# Use a dedicated suite key so the choice is unambiguous even when the operator holds
# several keys (otherwise `kennel run` refuses with "multiple signing keys").
KEY_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/kennel/keys"
SUITE_KEY="$KEY_DIR/kennel-suite.key"
if [ ! -f "$SUITE_KEY" ]; then
    "$KENNEL" keygen kennel-suite || { echo "keygen failed" >&2; exit 1; }
fi
[ -f "$SUITE_KEY" ] || { echo "suite key not at $SUITE_KEY after keygen" >&2; exit 1; }
echo "  signing key: $SUITE_KEY"

echo "== AppArmor userns profile over kenneld + the privhelper (sudo) =="
cat > "$AA_PROFILE_FILE" <<EOF
abi <abi/4.0>,
include <tunables/global>
profile $AA_PROFILE_NAME $KENNELD flags=(unconfined) {
  userns,
}
profile ${AA_PROFILE_NAME}_privhelper $PRIVHELPER flags=(unconfined) {
  userns,
}
EOF
if [ -e /sys/kernel/security/apparmor ]; then
    sudo apparmor_parser -r -W "$AA_PROFILE_FILE"
    echo "  loaded over kenneld + privhelper"
else
    echo "  (AppArmor not present; relying on unrestricted userns)"
fi

echo "== staging fixtures =="
# The granted ~ subtree (+ a non-granted sibling) the fs cases inspect.
rm -rf "$HOME_FIXTURE"
mkdir -p "$HOME_FIXTURE/granted" "$HOME_FIXTURE/secret"
printf 'OK\n' > "$HOME_FIXTURE/granted/file"
printf 'SECRET\n' > "$HOME_FIXTURE/secret/file"
# The host AF_UNIX echo listener the full-vertical facade brokers (ping -> pong).
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
s = socket.socket(socket.AF_UNIX)
s.bind(p)
s.listen(16)
while True:
    try:
        c, _ = s.accept()
    except OSError:
        break
    data = c.recv(16)
    if data == b'ping':
        c.sendall(b'pong')
    c.close()
PY
ECHO_PID=$!
for _ in $(seq 1 20); do [ -S "$ECHO_SOCK" ] && break; sleep 0.1; done
[ -S "$ECHO_SOCK" ] || { echo "echo listener did not bind $ECHO_SOCK" >&2; exit 1; }
echo "  echo listener: $ECHO_SOCK (pid $ECHO_PID)"

# --- the cases ---------------------------------------------------------------
if [ "$#" -gt 0 ]; then
    CASES=("$@")
else
    CASES=()
    for d in "$SUITE_DIR"/*/; do CASES+=("$(basename "$d")"); done
fi

echo "== running the suite under a delegated cgroup =="
# The whole run happens inside one delegated scope so kenneld has a writable cgroup
# subtree. The scope starts kenneld, runs every case against it via `kennel run`, prints
# a summary, kills kenneld, and exits with the scope's pass/fail status (which becomes
# this script's exit code). Args after `--` are the case names.
systemd-run --user --scope -p Delegate=yes --quiet -- \
  bash -c '
    set -u
    REPO_ROOT="$1"; KENNELD="$2"; KENNEL="$3"; SUITE_DIR="$4"; UID_NUM="$5"; SUITE_KEY="$6"; shift 6
    # Exported so per-case setup.sh hooks inherit them (ssh-egress needs REPO_ROOT).
    export REPO_ROOT SUITE_DIR UID_NUM
    "$KENNELD" >/tmp/kennel-suite-kenneld.log 2>&1 &
    KPID=$!
    trap "kill $KPID 2>/dev/null || true" EXIT
    SOCK="${XDG_RUNTIME_DIR:-/run/user/$UID_NUM}/kennel/control.sock"
    for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 0.1; done
    if [ ! -S "$SOCK" ]; then
        echo "kenneld did not bind its control socket; log:" >&2
        cat /tmp/kennel-suite-kenneld.log >&2
        exit 1
    fi
    pass=0; fail=0; results=""
    for name in "$@"; do
        pol="$SUITE_DIR/$name/policy.toml"
        printf "== %-16s " "$name"
        if [ ! -f "$pol" ]; then
            echo "?? (no such case)"; results="$results\n  ?? $name"; fail=$((fail+1)); continue
        fi
        # Per-case setup hook: a case that needs host fixtures it cannot carry (e.g.
        # ssh-egress: a destination sshd + the operator real key) ships a `setup.sh`. The
        # runner runs it with the case dir + a scratch dir; the hook stages the fixtures
        # and prints the policy path to actually run (a generated copy with host-specific
        # values filled in) on its LAST stdout line. A non-zero hook fails the case. Its
        # `teardown.sh` (if any) runs after the case.
        run_pol="$pol"
        if [ -x "$SUITE_DIR/$name/setup.sh" ]; then
            scratch="/tmp/kennel-suite-$name.scratch"
            rm -rf "$scratch"; mkdir -p "$scratch"
            if ! gen=$("$SUITE_DIR/$name/setup.sh" "$SUITE_DIR/$name" "$scratch" 2>"/tmp/kennel-suite-$name.setup.log"); then
                echo "FAIL (setup) — see /tmp/kennel-suite-$name.setup.log"
                results="$results\n  FAIL(setup) $name"; fail=$((fail+1)); continue
            fi
            # setup.sh prints only the generated policy path to stdout (fixtures + noise go
            # to stderr / files), and `$(...)` already strips the trailing newline, so the
            # capture is the path verbatim.
            run_pol="$gen"
        fi
        # Distinct kennel instance name per case; </dev/null = non-interactive (no pty).
        # The workload exit code is forwarded as the run status.
        "$KENNEL" run "$run_pol" "$name" --key "$SUITE_KEY" --template-dir "$REPO_ROOT/templates" </dev/null \
            >"/tmp/kennel-suite-$name.log" 2>&1
        rc=$?
        [ -x "$SUITE_DIR/$name/teardown.sh" ] && "$SUITE_DIR/$name/teardown.sh" "/tmp/kennel-suite-$name.scratch" 2>/dev/null || true
        if [ "$rc" = 0 ]; then
            echo "PASS"; results="$results\n  PASS  $name"; pass=$((pass+1))
        else
            echo "FAIL (exit $rc) — see /tmp/kennel-suite-$name.log"
            results="$results\n  FAIL($rc) $name"; fail=$((fail+1))
        fi
    done
    echo
    echo "== suite summary: $pass passed, $fail failed =="
    printf "%b\n" "$results"
    [ "$fail" = 0 ]
  ' _ "$REPO_ROOT" "$KENNELD" "$KENNEL" "$SUITE_DIR" "$UID_NUM" "$SUITE_KEY" "${CASES[@]}"
