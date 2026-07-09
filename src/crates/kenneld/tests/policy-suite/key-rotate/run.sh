#!/usr/bin/env bash
#
# Key-rotation e2e (0.7.0 W4). A self-driving case: the rotation ceremony is a CLI
# ceremony, not a policy slice, so it ships a run.sh instead of a policy.toml. It drives
# the verbatim operator flow on the real installed stack and asserts the ceremony's own
# exit criteria:
#
#   A. USER tier: `key generate` -> compile a leaf under the key -> `key rotate --yes`
#      leaves the leaf re-signed under the successor (same key_id, new material), and the
#      daemon RUNS it (the byte watched across: verification under the successor key).
#   B. HOST tier (root): a host template signed by kennel-host and a host leaf whose
#      lockfile pins that template. `key rotate kennel-host --yes` re-signs the template,
#      re-pins the leaf's lock, recompiles the leaf AND the installed reference policies
#      (their source resolves from the vendor tree), and the unprivileged operator then
#      RUNS the host leaf — successor trust plus downward-inclusive acceptance, through
#      the daemon.
#
#   $1 = case dir   $2 = the installed `kennel`   $3 = the suite signing key   $4 = scratch
#
# Exit 77 = SKIP (no passwordless sudo for part B is NOT a skip: the suite's install step
# already cached sudo credentials; a missing host key on a --no-install host skips B only).
set -uo pipefail

CASE_DIR="$1"; KENNEL="$2"; SUITE_KEY="$3"; SCRATCH="$4"
KEY_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/kennel/keys"
POLICY_REPO="${XDG_CONFIG_HOME:-$HOME/.config}/kennel/policies"
ROT_KEY="kennel-rotate-e2e"
JOB="key-rotate-job"
HOST_KEY_DIR="/etc/kennel/keys"
HOST_TPL="rot-base-e2e"
HOST_LEAF="rot-leaf-e2e"

cleanup() {
    rm -f "$KEY_DIR/$ROT_KEY" "$KEY_DIR/$ROT_KEY.pub" \
          "$KEY_DIR/$ROT_KEY.retired" "$KEY_DIR/$ROT_KEY.pub.retired"
    rm -rf "${POLICY_REPO:?}/$JOB"
    sudo rm -rf "/etc/kennel/templates/$HOST_TPL" "/etc/kennel/policies/$HOST_LEAF" 2>/dev/null || true
    sudo rm -f "$HOST_KEY_DIR/kennel-host.retired" "$HOST_KEY_DIR/kennel-host.pub.retired" 2>/dev/null || true
}
trap cleanup EXIT

sig_of() { grep -m1 '^signature = ' "$1"; }

# ── A. user-tier rotation ────────────────────────────────────────────────────
rm -f "$KEY_DIR/$ROT_KEY" "$KEY_DIR/$ROT_KEY.pub" \
      "$KEY_DIR/$ROT_KEY.retired" "$KEY_DIR/$ROT_KEY.pub.retired"
"$KENNEL" key generate "$ROT_KEY" >/dev/null 2>&1 || { echo "FAIL: key generate"; exit 1; }
OLD_PUB="$(cat "$KEY_DIR/$ROT_KEY.pub")"

mkdir -p "$POLICY_REPO/$JOB"
cp "$CASE_DIR/leaf.toml" "$POLICY_REPO/$JOB/policy.toml"
sed -i "s/@NAME@/$JOB/" "$POLICY_REPO/$JOB/policy.toml"
"$KENNEL" policy compile "$JOB" --key "$ROT_KEY" >"$SCRATCH/compile.log" 2>&1 \
    || { echo "FAIL: user leaf compile — $(tail -2 "$SCRATCH/compile.log")"; exit 1; }
SETTLED="$POLICY_REPO/$JOB/$JOB.settled.toml"
OLD_SIG="$(sig_of "$SETTLED")"
grep -q "^key_id = \"$ROT_KEY\"" "$SETTLED" || { echo "FAIL: leaf not signed by $ROT_KEY"; exit 1; }

"$KENNEL" key rotate "$ROT_KEY" --yes >"$SCRATCH/rotate-user.log" 2>&1 \
    || { echo "FAIL: user rotate — $(tail -3 "$SCRATCH/rotate-user.log")"; exit 1; }

[ "$(cat "$KEY_DIR/$ROT_KEY.pub")" != "$OLD_PUB" ] || { echo "FAIL: pub unchanged after rotate"; exit 1; }
[ -f "$KEY_DIR/$ROT_KEY.retired" ] && [ -f "$KEY_DIR/$ROT_KEY.pub.retired" ] \
    || { echo "FAIL: old pair not retired"; exit 1; }
[ "$(sig_of "$SETTLED")" != "$OLD_SIG" ] || { echo "FAIL: leaf not re-signed"; exit 1; }
grep -q "^key_id = \"$ROT_KEY\"" "$SETTLED" || { echo "FAIL: key_id changed across rotation"; exit 1; }
# The byte watched across: the daemon verifies the re-signed artefact and runs it.
timeout 60 "$KENNEL" run "$JOB" key-rotate-user </dev/null >"$SCRATCH/run-user.log" 2>&1 \
    || { echo "FAIL: run under successor key — $(tail -3 "$SCRATCH/run-user.log")"; exit 1; }
echo "user-tier rotation OK"

# ── B. host-tier rotation: the template re-sign + lock re-pin cascade ────────
if ! sudo test -f "$HOST_KEY_DIR/kennel-host"; then
    echo "SKIP: no host key at $HOST_KEY_DIR/kennel-host (part A passed)"
    exit 77
fi
sudo rm -f "$HOST_KEY_DIR/kennel-host.retired" "$HOST_KEY_DIR/kennel-host.pub.retired"

# A host template signed by kennel-host, and a host leaf pinning it in a lockfile.
sudo install -d -m 0755 "/etc/kennel/templates/$HOST_TPL" "/etc/kennel/policies/$HOST_LEAF"
sed "s/@NAME@/$HOST_TPL/" "$CASE_DIR/template.toml" | sudo tee "/etc/kennel/templates/$HOST_TPL/policy.toml" >/dev/null
sudo "$KENNEL" template sign "/etc/kennel/templates/$HOST_TPL/policy.toml" \
    --key "$HOST_KEY_DIR/kennel-host" >"$SCRATCH/tsign.log" 2>&1 \
    || { echo "FAIL: host template sign — $(tail -2 "$SCRATCH/tsign.log")"; exit 1; }
sed -e "s/@NAME@/$HOST_LEAF/" -e "s/base-confined/$HOST_TPL/" "$CASE_DIR/leaf.toml" \
    | sudo tee "/etc/kennel/policies/$HOST_LEAF/policy.toml" >/dev/null
sudo "$KENNEL" policy compile "/etc/kennel/policies/$HOST_LEAF/policy.toml" \
    --key "$HOST_KEY_DIR/kennel-host" >"$SCRATCH/hcompile.log" 2>&1 \
    || { echo "FAIL: host leaf compile — $(tail -2 "$SCRATCH/hcompile.log")"; exit 1; }
HOST_SETTLED="/etc/kennel/policies/$HOST_LEAF/$HOST_LEAF.settled.toml"
HOST_LOCK="/etc/kennel/policies/$HOST_LEAF/$HOST_LEAF.lock"
sudo test -f "$HOST_LOCK" || { echo "FAIL: host leaf compile wrote no lock"; exit 1; }

OLD_HOST_PUB="$(sudo cat "$HOST_KEY_DIR/kennel-host.pub")"
OLD_TPL_SIG="$(sudo grep -m1 '^signature = ' "/etc/kennel/templates/$HOST_TPL/policy.toml")"
OLD_LOCK="$(sudo cat "$HOST_LOCK")"
OLD_LEAF_SIG="$(sudo grep -m1 '^signature = ' "$HOST_SETTLED")"
# One installed reference artefact, to prove the cascade reaches vendor-sourced settled
# policies (their source lives in /usr/lib/kennel, not beside them).
REF="$(sudo find /etc/kennel/policies -name '*.settled.toml' ! -path "*$HOST_LEAF*" | head -1)"
[ -n "$REF" ] && OLD_REF_SIG="$(sudo grep -m1 '^signature = ' "$REF")" || OLD_REF_SIG=""

sudo "$KENNEL" key rotate kennel-host --yes >"$SCRATCH/rotate-host.log" 2>&1 \
    || { echo "FAIL: host rotate — $(tail -5 "$SCRATCH/rotate-host.log")"; exit 1; }

[ "$(sudo cat "$HOST_KEY_DIR/kennel-host.pub")" != "$OLD_HOST_PUB" ] \
    || { echo "FAIL: host pub unchanged"; exit 1; }
[ "$(sudo grep -m1 '^signature = ' "/etc/kennel/templates/$HOST_TPL/policy.toml")" != "$OLD_TPL_SIG" ] \
    || { echo "FAIL: host template not re-signed"; exit 1; }
[ "$(sudo cat "$HOST_LOCK")" != "$OLD_LOCK" ] \
    || { echo "FAIL: leaf lock not re-pinned after template re-sign"; exit 1; }
[ "$(sudo grep -m1 '^signature = ' "$HOST_SETTLED")" != "$OLD_LEAF_SIG" ] \
    || { echo "FAIL: host leaf not re-signed"; exit 1; }
if [ -n "$OLD_REF_SIG" ]; then
    [ "$(sudo grep -m1 '^signature = ' "$REF")" != "$OLD_REF_SIG" ] \
        || { echo "FAIL: reference artefact $REF not recompiled (vendor-source cascade)"; exit 1; }
fi
# The unprivileged operator runs the host leaf: successor trust + downward-inclusive
# acceptance, verified by the daemon (which re-reads the trust store per spawn).
timeout 60 "$KENNEL" run "$HOST_LEAF" key-rotate-host </dev/null >"$SCRATCH/run-host.log" 2>&1 \
    || { echo "FAIL: run of host leaf under rotated host key — $(tail -3 "$SCRATCH/run-host.log")"; exit 1; }
echo "host-tier rotation cascade OK"
