#!/usr/bin/env bash
#
# Run the UNPRIVILEGED production e2e (kenneld tests/e2e.rs,
# full_vertical_brings_up_and_tears_down_a_kennel_unprivileged) as the ordinary
# operator — no sudo for the test itself. The test builds the whole vertical on the
# user-namespace spawn path: an unprivileged identity-mapped userns constructs the
# sandbox, and the file-caps privhelper adds the loopback addresses, attaches the
# egress BPF, and writes the workload's gid_map to re-grant a supplementary group
# (08-enforcement-architecture.md §8.2/§8.3, 07-2-filesystem.md §7.2.8).
#
# This script performs the one-time host setup the test requires and then runs it,
# matching the project's "a skip is not a proof" rule: where a prerequisite cannot
# be met the test skips with the precise cause rather than passing falsely.
#
#   1. builds the privhelper (--features bpf-egress), netproxy, socks-connect, and
#      the test binary;
#   2. `sudo setcap cap_net_admin,cap_sys_admin,cap_setgid=ep` on the privhelper
#      (the production install posture — 07-paths.md — never sudo at runtime);
#   3. provisions an /etc/kennel/subkennel allocation for the operator's uid;
#   4. loads an AppArmor profile granting `userns` to the test binary (Ubuntu's
#      kernel.apparmor_restrict_unprivileged_userns=1; dist/apparmor/kenneld is the
#      production analogue for the real daemon binary);
#   5. runs the test under `systemd-run --user --scope -p Delegate=yes` so kenneld
#      has a writable delegated cgroup (a plain login session scope is not writable).
#
# The sudo steps (2-4) are reversible and local; the AppArmor profile is unloaded on
# exit. Usage: src/tools/unprivileged-e2e.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

UID_NUM="$(id -u)"
if [ "$UID_NUM" = "0" ]; then
    echo "Run as the ordinary operator, not root — this proves the UNPRIVILEGED vertical." >&2
    exit 2
fi

# The allocation the test expects (matches the TEST_* constants in tests/e2e.rs).
SUBKENNEL_LINE="${UID_NUM}:42:0000000002:kennel-dev"
AA_PROFILE_NAME="kennel_e2e_test"
AA_PROFILE_FILE="$(mktemp /tmp/kennel-e2e-aa.XXXXXX)"

cleanup() {
    # Unload the temporary AppArmor profile (best-effort).
    if [ -f "$AA_PROFILE_FILE" ]; then
        sudo apparmor_parser -R "$AA_PROFILE_FILE" 2>/dev/null || true
        rm -f "$AA_PROFILE_FILE"
    fi
}
trap cleanup EXIT

echo "== building binaries =="
# Build the test binary and the supporting binaries first; the privhelper with
# bpf-egress is built LAST so a later workspace build cannot clobber its embedded
# BPF objects (privhelper-bpf-egress-build-gotcha).
cargo build -p kennel-socks-connect -p kennel-netproxy
cargo test -p kenneld --features root-tests --no-run
cargo build -p kennel-privhelper --features bpf-egress

PRIVHELPER="$REPO_ROOT/target/debug/kennel-privhelper"
TESTBIN="$(ls -t "$REPO_ROOT"/target/debug/deps/e2e-* 2>/dev/null | grep -v '\.d$' | head -1)"
if [ -z "${TESTBIN:-}" ] || [ ! -x "$TESTBIN" ]; then
    echo "could not locate the compiled e2e test binary under target/debug/deps/" >&2
    exit 1
fi
echo "  privhelper: $PRIVHELPER"
echo "  test bin:   $TESTBIN"

echo "== file capabilities on the privhelper (sudo, one-time) =="
sudo setcap cap_net_admin,cap_sys_admin,cap_setgid=ep "$PRIVHELPER"
getcap "$PRIVHELPER"

echo "== /etc/kennel/subkennel allocation for uid $UID_NUM (sudo) =="
sudo mkdir -p /etc/kennel
if ! sudo grep -qE "^${UID_NUM}:" /etc/kennel/subkennel 2>/dev/null; then
    echo "$SUBKENNEL_LINE" | sudo tee -a /etc/kennel/subkennel >/dev/null
fi
sudo grep -E "^${UID_NUM}:" /etc/kennel/subkennel

echo "== AppArmor userns profile over the test binary (sudo) =="
cat > "$AA_PROFILE_FILE" <<EOF
abi <abi/4.0>,
include <tunables/global>
profile $AA_PROFILE_NAME "$TESTBIN" flags=(unconfined) {
  userns,
}
EOF
if [ -e /sys/kernel/security/apparmor ]; then
    sudo apparmor_parser -r -W "$AA_PROFILE_FILE"
else
    echo "  (AppArmor not present; relying on the kernel's userns being unrestricted)"
fi

echo "== running the unprivileged e2e under a delegated cgroup =="
# systemd-run --user --scope -p Delegate=yes runs the test in a transient scope
# under user@<uid>.service whose cgroup subtree the operator may write — so kenneld
# can create the kennel's cgroup. --test-threads=1: one cohesive scenario.
systemd-run --user --scope -p Delegate=yes --quiet -- \
    "$TESTBIN" full_vertical_brings_up_and_tears_down_a_kennel_unprivileged \
    --exact --nocapture --test-threads=1
