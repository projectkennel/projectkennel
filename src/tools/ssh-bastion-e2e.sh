#!/usr/bin/env bash
#
# End-to-end proof of the per-kennel SSH re-origination bastion (07-10-ssh.md §7.10).
#
# Stands up, with stock OpenSSH and no root, a hermetic two-hop topology:
#
#     client (synthetic key)  --ssh-->  BASTION sshd  --forced command-->
#         kennel-bin-ssh-reorigin  --ssh (real key from agent)-->  DESTINATION sshd
#
# and asserts the design's load-bearing properties (§7.10.9):
#   1. allow      — a synthetic-key login re-originates to the fixed destination,
#                   forwarding $SSH_ORIGINAL_COMMAND.
#   2. fixed dest — the workload cannot redirect: whatever command it sends, the
#                   connection still terminates at the policy-fixed destination,
#                   and shell metacharacters in the command do not break out.
#   3. non-synthetic key — a key the bastion does not authorise is refused.
#   4. no forwarding — a port-forward request through the bastion is denied.
#
# The bastion sshd_config mirrors `kenneld::sshd::sshd_config` and the authorized_keys
# line mirrors `kenneld::sshd::authorized_keys_line`; those generators are locked by
# unit tests, this script proves stock sshd actually behaves as the design assumes.
#
# Usage: ssh-bastion-e2e.sh [path-to-kennel-bin-ssh-reorigin]
#        (defaults to target/debug/kennel-bin-ssh-reorigin relative to the repo root)

set -euo pipefail

SSHD=/usr/sbin/sshd
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REORIGIN="${1:-$REPO_ROOT/target/debug/kennel-bin-ssh-reorigin}"

[ -x "$SSHD" ]      || { echo "no sshd at $SSHD" >&2; exit 2; }
[ -x "$REORIGIN" ]  || { echo "no kennel-bin-ssh-reorigin at $REORIGIN (build it first)" >&2; exit 2; }

# Stage outside world-writable /tmp: sshd's safe-path check rejects an
# AuthorizedKeysFile whose ancestor is world-writable (08 §8.1, finding 3). The
# per-user runtime dir (0700) is the safe staging ground.
STAGE="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
[ -d "$STAGE" ] && [ -w "$STAGE" ] || { echo "no usable XDG_RUNTIME_DIR ($STAGE); run in a user session" >&2; exit 2; }
WORK="$(mktemp -d "$STAGE/kennel-ssh-e2e.XXXXXX")"
chmod 700 "$WORK"
BASTION_PID="" DEST_PID="" AGENT_PID="" NETPROXY_PID=""

cleanup() {
    [ -n "$BASTION_PID" ]  && kill "$BASTION_PID"  2>/dev/null || true
    [ -n "$DEST_PID" ]     && kill "$DEST_PID"     2>/dev/null || true
    [ -n "$AGENT_PID" ]    && kill "$AGENT_PID"    2>/dev/null || true
    [ -n "$NETPROXY_PID" ] && kill "$NETPROXY_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1" >&2; exit 1; }

# Two free localhost ports (bind to :0, read back, close).
free_port() { python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()'; }
BASTION_PORT="$(free_port)"
DEST_PORT="$(free_port)"

echo "workdir: $WORK   bastion:127.0.0.1:$BASTION_PORT   dest:127.0.0.1:$DEST_PORT"

# ---------------------------------------------------------------------------
# 1. Keys: bastion + destination host keys, the real key (in an agent), a
#    synthetic key (authenticates to the bastion), and a rogue key (unauthorised).
# ---------------------------------------------------------------------------
kg() { ssh-keygen -q -t ed25519 -N "" -C "$2" -f "$1"; }
kg "$WORK/bastion_host"  kennel-bastion
kg "$WORK/dest_host"     kennel-dest
kg "$WORK/real"          real-user-key
kg "$WORK/synthetic"     synthetic-edge
kg "$WORK/rogue"         rogue-key

REAL_FP="$(ssh-keygen -lf "$WORK/real.pub" | awk '{print $2}')"
echo "real key fingerprint: $REAL_FP"

# Agent holding only the real key — the host-side store reorigin signs with.
eval "$(ssh-agent -s -a "$WORK/agent.sock")" >/dev/null
AGENT_PID="$SSH_AGENT_PID"
SSH_AUTH_SOCK="$WORK/agent.sock"
ssh-add "$WORK/real" 2>/dev/null

# ---------------------------------------------------------------------------
# 2. DESTINATION sshd. Accepts the real key; a forced command stamps a marker
#    and echoes the forwarded $SSH_ORIGINAL_COMMAND, so we can prove (a) the
#    connection terminated *here* (re-origination really happened) and (b) the
#    command was forwarded. Listens on its own port.
# ---------------------------------------------------------------------------
cat >"$WORK/dest_cmd.sh" <<EOF
#!/bin/sh
echo "DEST_REACHED cmd=[\${SSH_ORIGINAL_COMMAND:-}]"
EOF
chmod 700 "$WORK/dest_cmd.sh"
printf 'command="%s",restrict %s\n' "$WORK/dest_cmd.sh" "$(cat "$WORK/real.pub")" >"$WORK/dest_authorized_keys"
chmod 600 "$WORK/dest_authorized_keys"

cat >"$WORK/dest_sshd_config" <<EOF
ListenAddress 127.0.0.1
Port $DEST_PORT
HostKey $WORK/dest_host
PidFile $WORK/dest.pid
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AuthorizedKeysFile $WORK/dest_authorized_keys
EOF

"$SSHD" -D -e -f "$WORK/dest_sshd_config" >"$WORK/dest.log" 2>&1 &
DEST_PID=$!

# The bastion's host-side known_hosts for the destination (StrictHostKeyChecking).
printf '[127.0.0.1]:%s %s\n' "$DEST_PORT" "$(cat "$WORK/dest_host.pub")" >"$WORK/bastion_known_hosts"

# ---------------------------------------------------------------------------
# 3. The kenneld-owned outbound ssh_config (reorigin's `ssh -F`, via
#    KENNEL_SSH_CONFIG): maps the fixed destination host to the destination port.
#    In production the destination is a real host on :22; for the test we redirect
#    the port here. This is the host-side, kenneld-owned config seam (§7.10.7) —
#    never anything the kennel can influence.
# ---------------------------------------------------------------------------
cat >"$WORK/outbound_ssh_config" <<EOF
Host 127.0.0.1
    Port $DEST_PORT
EOF
chmod 600 "$WORK/outbound_ssh_config"

# ---------------------------------------------------------------------------
# 4. BASTION sshd. Config mirrors kenneld::sshd::sshd_config; the authorized_keys
#    line mirrors kenneld::sshd::authorized_keys_line — restrict,pty + a forced
#    command baking in --dest (the policy-fixed destination) and --key (the real
#    fingerprint). The destination is 127.0.0.1 (a valid hostname per the strict
#    grammar); the agent and the hermetic HOME reach the forced command via SetEnv.
# ---------------------------------------------------------------------------
FIXED_DEST="127.0.0.1"
cat >"$WORK/bastion_authorized_keys" <<EOF
restrict,pty,command="$REORIGIN --dest $FIXED_DEST --key $REAL_FP" $(cat "$WORK/synthetic.pub")
EOF
chmod 600 "$WORK/bastion_authorized_keys"

cat >"$WORK/bastion_sshd_config" <<EOF
ListenAddress 127.0.0.1
Port $BASTION_PORT
HostKey $WORK/bastion_host
PidFile $WORK/bastion.pid

ExposeAuthInfo yes
SetEnv SSH_AUTH_SOCK=$WORK/agent.sock KENNEL_SSH_KNOWN_HOSTS=$WORK/bastion_known_hosts KENNEL_SSH_CONFIG=$WORK/outbound_ssh_config

PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM no

AuthorizedKeysFile $WORK/bastion_authorized_keys

AllowTcpForwarding no
X11Forwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
PermitOpen none
AllowStreamLocalForwarding no
Subsystem sftp /bin/false
EOF

"$SSHD" -D -e -f "$WORK/bastion_sshd_config" >"$WORK/bastion.log" 2>&1 &
BASTION_PID=$!

# Wait for both daemons to accept connections.
for _ in $(seq 1 50); do
    if 2>/dev/null >/dev/tcp/127.0.0.1/"$BASTION_PORT" && 2>/dev/null >/dev/tcp/127.0.0.1/"$DEST_PORT"; then break; fi
    sleep 0.1
done

# The kennel's client uses ONLY the synthetic key, with the bastion host key pinned
# (as the synthetic ~/.ssh/known_hosts would, under the bastion alias).
printf '[127.0.0.1]:%s %s\n' "$BASTION_PORT" "$(cat "$WORK/bastion_host.pub")" >"$WORK/client_known_hosts"
client() {
    # ssh [options] host [command] — host first, then the remote command.
    ssh -F none -p "$BASTION_PORT" \
        -o IdentitiesOnly=yes -i "$WORK/synthetic" \
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WORK/client_known_hosts" \
        -o BatchMode=yes \
        127.0.0.1 "$@"
}

echo
echo "=== 1. allow: re-origination forwards the command to the fixed destination ==="
OUT="$(client "git-upload-pack 'my/repo.git'" 2>"$WORK/c1.err" || true)"
echo "    client saw: $OUT"
echo "$OUT" | grep -q "DEST_REACHED" || { cat "$WORK/c1.err" "$WORK/bastion.log" >&2; fail "did not reach the destination"; }
echo "$OUT" | grep -q "cmd=\[git-upload-pack 'my/repo.git'\]" || fail "command not forwarded verbatim"
pass "synthetic key re-originated to the destination; \$SSH_ORIGINAL_COMMAND forwarded"

echo
echo "=== 2. fixed dest: a hostile command cannot redirect or break out ==="
# The workload controls only the command; the destination is fixed in the forced
# command. A metacharacter-laden command must still land at the same destination.
OUT="$(client 'x; ssh evil.example "id"; $(touch '"$WORK"'/PWNED)' 2>/dev/null || true)"
echo "    client saw: $OUT"
echo "$OUT" | grep -q "DEST_REACHED" || fail "connection did not terminate at the fixed destination"
[ ! -e "$WORK/PWNED" ] || fail "command-substitution executed on the bastion (injection!)"
pass "destination stays fixed; injected metacharacters did not execute on the bastion"

echo
echo "=== 3. a non-synthetic (rogue) key is refused by the bastion ==="
if ssh -F none -p "$BASTION_PORT" -o IdentitiesOnly=yes -i "$WORK/rogue" \
       -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WORK/client_known_hosts" \
       -o BatchMode=yes 127.0.0.1 "git-upload-pack x" >/dev/null 2>&1; then
    fail "rogue key was accepted"
fi
pass "rogue key rejected (publickey auth failed)"

echo
echo "=== 4. port-forwarding through the bastion is denied ==="
# A -L local forward always binds the client-side port; the bastion's
# `AllowTcpForwarding no` refuses the forwarding *channel*, so no data reaches the
# destination. We prove it by trying to read the destination's SSH banner through
# the forward: if forwarding were allowed we'd see "SSH-2.0-…"; denied ⇒ nothing.
FWD_PORT="$(free_port)"
ssh -F none -p "$BASTION_PORT" -o IdentitiesOnly=yes -i "$WORK/synthetic" \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WORK/client_known_hosts" \
    -o BatchMode=yes \
    -L "$FWD_PORT:127.0.0.1:$DEST_PORT" -N 127.0.0.1 >"$WORK/fwd.err" 2>&1 &
FWD_PID=$!
sleep 0.5
BANNER="$(timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$FWD_PORT 2>/dev/null && head -c 8 <&3" 2>/dev/null || true)"
kill "$FWD_PID" 2>/dev/null || true
echo "    banner through the forward: [${BANNER:-<none>}]"
case "$BANNER" in
    SSH-*) fail "forwarded channel reached the destination (forwarding not denied)" ;;
    *)     pass "forwarding channel refused — no data reached the destination" ;;
esac

echo
# The egress *transport* (ssh's ProxyCommand → kenneld over binder → host-side delegate → bastion)
# is proven by the kenneld e2e (tests/e2e.rs full_vertical: real binder, net-ns, facade-ssh)
# + the INet conduit component tests. This script proves the bastion re-origination itself (steps
# 1-4), which is transport-independent.

echo "ALL CHECKS PASSED — the re-origination bastion behaves as 07-10-ssh.md §7.10 specifies."
