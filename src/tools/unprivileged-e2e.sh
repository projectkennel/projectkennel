#!/usr/bin/env bash
#
# Run the UNPRIVILEGED production e2e (kenneld tests/e2e.rs,
# full_vertical_brings_up_and_tears_down_a_kennel_unprivileged) as the ordinary
# operator — no sudo for the test itself. The test builds the whole vertical on the
# user-namespace spawn path: an unprivileged identity-mapped userns constructs the
# sandbox, and the file-caps privhelper adds the loopback addresses, attaches the
# egress BPF, and writes the workload's gid_map to re-grant a supplementary group
# (08-enforcement-architecture.md §8.2/§8.3, 07-4-filesystem.md §7.4.8).
#
# This script performs the one-time host setup the test requires and then runs it,
# matching the project's "a skip is not a proof" rule: where a prerequisite cannot
# be met the test skips with the precise cause rather than passing falsely.
#
#   1. builds the privhelper (--features bpf-egress), netproxy, socks-connect,
#      kennel-init, and the test binary;
#   2. `sudo setcap cap_net_admin,cap_sys_admin,cap_setgid,cap_setuid=ep` on the
#      privhelper (the production install posture — 07-paths.md — never sudo at
#      runtime; cap_setuid is the factory's 0 0 1 uid_map write, 07-2);
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
# Set when the runner temporarily rewrites a pre-existing, mismatched subkennel line
# for this uid (e.g. a real allocation): the original is saved here and restored on exit.
SUBKENNEL_SAVED=""
# The privhelper resolves kennel-init from the root-owned deployment cascade itself and
# verifies it is root-owned + non-writable before fexecve (sec review / design 07-2). The
# build tree is operator-owned, so install a root-owned copy at the default libexec path.
INIT_DEST="/usr/libexec/kennel/kennel-init"
INIT_DEST_BACKUP=""   # tempfile holding a pre-existing kennel-init to restore on exit
INIT_DEST_CREATED=""  # set when WE created it (remove on exit)

cleanup() {
    # Unload the temporary AppArmor profile (best-effort).
    if [ -f "$AA_PROFILE_FILE" ]; then
        sudo apparmor_parser -R "$AA_PROFILE_FILE" 2>/dev/null || true
        rm -f "$AA_PROFILE_FILE"
    fi
    # Restore the operator's original subkennel line if we swapped it in.
    if [ -n "$SUBKENNEL_SAVED" ]; then
        sudo sed -i "s|^${UID_NUM}:.*|${SUBKENNEL_SAVED}|" /etc/kennel/subkennel 2>/dev/null || true
        echo "  restored original subkennel line for uid $UID_NUM"
    fi
    # Restore (or remove) the root-owned kennel-init we installed for the run.
    if [ -n "$INIT_DEST_CREATED" ]; then
        sudo rm -f "$INIT_DEST" 2>/dev/null || true
        echo "  removed test $INIT_DEST"
    elif [ -n "$INIT_DEST_BACKUP" ]; then
        sudo cp -f "$INIT_DEST_BACKUP" "$INIT_DEST" 2>/dev/null || true
        rm -f "$INIT_DEST_BACKUP"
        echo "  restored original $INIT_DEST"
    fi
}
trap cleanup EXIT

echo "== building binaries =="
# Build the test binary and the supporting binaries first; the privhelper with
# bpf-egress is built LAST so a later workspace build cannot clobber its embedded
# BPF objects (privhelper-bpf-egress-build-gotcha).
cargo build -p kennel-socks-connect -p kennel-netproxy -p kennel-afunix-shim -p kennel-init
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
# The factory additions (07-2): cap_setuid maps the operator's id, and — since Linux
# 5.12 — cap_setfcap is ALSO required to map host uid 0 into a new user namespace
# (capabilities(7): "this capability is also needed to map user ID 0 in a new user
# namespace"). Without cap_setfcap the kennel's `0 0 1` uid_map write is EPERM even for
# an escalated-root writer.
sudo setcap cap_net_admin,cap_sys_admin,cap_setgid,cap_setuid,cap_setfcap=ep "$PRIVHELPER"
getcap "$PRIVHELPER"

echo "== /etc/kennel/subkennel allocation for uid $UID_NUM (sudo) =="
sudo mkdir -p /etc/kennel
sudo touch /etc/kennel/subkennel
EXISTING="$(sudo grep -E "^${UID_NUM}:" /etc/kennel/subkennel 2>/dev/null | head -1 || true)"
if [ -z "$EXISTING" ]; then
    # No line for this uid: append the test allocation (left in place — it is ours).
    echo "$SUBKENNEL_LINE" | sudo tee -a /etc/kennel/subkennel >/dev/null
elif [ "$EXISTING" != "$SUBKENNEL_LINE" ]; then
    # A different line exists (likely a real allocation): swap to the test line for the
    # run and restore the original on exit (see cleanup).
    SUBKENNEL_SAVED="$EXISTING"
    echo "  temporarily replacing existing line: $EXISTING"
    sudo sed -i "s|^${UID_NUM}:.*|${SUBKENNEL_LINE}|" /etc/kennel/subkennel
fi
sudo grep -E "^${UID_NUM}:" /etc/kennel/subkennel

echo "== root-owned kennel-init at $INIT_DEST (sudo) =="
# The privhelper factory resolves kennel-init from the root-owned deployment cascade itself
# (it no longer trusts a wire-supplied fd — sec review: trusted init source) and verifies it
# is root-owned + non-writable before fexecve. The build tree is operator-owned, so install a
# root-owned copy at the default libexec path (Deployment::kennel_init, no system.toml needed).
# Back up any pre-existing install and restore it on exit.
INIT_SRC="$REPO_ROOT/target/debug/kennel-init"
if [ ! -x "$INIT_SRC" ]; then
    echo "kennel-init not built at $INIT_SRC" >&2
    exit 1
fi
sudo mkdir -p "$(dirname "$INIT_DEST")"
if [ -e "$INIT_DEST" ]; then
    INIT_DEST_BACKUP="$(mktemp /tmp/kennel-e2e-init.XXXXXX)"
    sudo cp -f "$INIT_DEST" "$INIT_DEST_BACKUP"
    echo "  backed up existing $INIT_DEST"
else
    INIT_DEST_CREATED=1
fi
sudo cp -f "$INIT_SRC" "$INIT_DEST"
sudo chown 0:0 "$INIT_DEST"
sudo chmod 0755 "$INIT_DEST"
ls -l "$INIT_DEST"

echo "== AppArmor userns profile over the test binary (sudo) =="
# flags=(unconfined) { userns, } mirrors the production dist/apparmor/kenneld: the
# profile only GRANTS userns. An enforcing profile cannot work here — the spawn sets
# no-new-privs before exec'ing the workload, under which AppArmor denies every profile
# transition (so the workload could only inherit, gaining the sandbox's mount/userns/
# sys_admin). See dist/apparmor/kenneld for the full rationale.
# The path is left unquoted: apparmor_parser 4.0.1's lexer rejects a quoted path in
# the `profile <name> <path>` form (the build-time deps path has no spaces anyway).
# Two profiles, both granting userns:
#  - the test binary (kenneld's role): creates its own userns on the legacy path.
#  - the PRIVHELPER (factory, 07-2): it calls clone(CLONE_NEWUSER). Without a userns
#    grant the kernel transitions the userns it creates to the restricted
#    `unprivileged_userns` profile, which FORBIDS mapping host uid 0 into it (the
#    `0 0 1` factory map then fails EPERM). Granting the privhelper userns makes the
#    userns it creates "privileged", so host root can be mapped in.
cat > "$AA_PROFILE_FILE" <<EOF
abi <abi/4.0>,
include <tunables/global>
profile $AA_PROFILE_NAME $TESTBIN flags=(unconfined) {
  userns,
}
profile ${AA_PROFILE_NAME}_privhelper $PRIVHELPER flags=(unconfined) {
  userns,
}
EOF
if [ -e /sys/kernel/security/apparmor ]; then
    sudo apparmor_parser -r -W "$AA_PROFILE_FILE"
    echo "  loaded $AA_PROFILE_NAME + _privhelper over the test binary and privhelper"
else
    echo "  (AppArmor not present; relying on the kernel's userns being unrestricted)"
fi

echo "== running the unprivileged e2e under a delegated cgroup =="
# systemd-run --user --scope -p Delegate=yes runs the test in a transient scope
# under user@<uid>.service whose cgroup subtree the operator may write — so kenneld
# can create the kennel's cgroup. --test-threads=1: each test is a cohesive scenario
# that constructs a real kennel, so they must not run concurrently. No name filter —
# run every self-hosting test in the binary (full vertical, no-IPC, …).
systemd-run --user --scope -p Delegate=yes --quiet -- \
    "$TESTBIN" --nocapture --test-threads=1
