#!/usr/bin/env bash
#
# Per-case fixtures for the ssh-egress suite case: a host destination sshd whose forced
# command echoes a marker, the operator's real key the bastion's outbound `ssh` signs
# with, and the dest host-key pin — none of which a signed policy can carry. Stages them,
# writes a generated policy.toml with the host-specific values filled in, and prints that
# policy's path on the last stdout line (the runner runs THAT). Run inside the suite's
# delegated scope, as the operator.
#
#   $1 = the case dir (where this script + the policy template live)
#   $2 = a scratch dir for the fixtures (removed by the runner / teardown)
set -euo pipefail

CASE_DIR="$1"
SCRATCH="$2"
mkdir -p "$SCRATCH"

command -v sshd >/dev/null 2>&1 || SSHD=/usr/sbin/sshd
SSHD="${SSHD:-$(command -v sshd || echo /usr/sbin/sshd)}"
[ -x "$SSHD" ] || { echo "no sshd at $SSHD" >&2; exit 2; }
for t in ssh ssh-keygen python3; do command -v "$t" >/dev/null || { echo "no $t" >&2; exit 2; }; done

DEST_USER="$(id -un)"

# A free loopback port for the destination sshd.
DEST_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"

# Keys: the destination host key, and the operator's "real" key the bastion signs with.
kg() { ssh-keygen -q -t ed25519 -N "" -C "$2" -f "$1"; }
kg "$SCRATCH/dest_host" kennel-ssh-e2e-dest
kg "$SCRATCH/real"      kennel-ssh-e2e-real

# The destination's forced command: ignore $SSH_ORIGINAL_COMMAND, print the marker. A
# successful re-origination through the whole cascade makes this run and the workload sees it.
cat >"$SCRATCH/dest_cmd.sh" <<'EOF'
#!/bin/sh
echo SSH_EGRESS_OK
EOF
chmod 700 "$SCRATCH/dest_cmd.sh"
printf 'command="%s",restrict %s\n' "$SCRATCH/dest_cmd.sh" "$(cat "$SCRATCH/real.pub")" \
    >"$SCRATCH/dest_authorized_keys"
chmod 600 "$SCRATCH/dest_authorized_keys"

cat >"$SCRATCH/dest_sshd_config" <<EOF
ListenAddress 127.0.0.1
Port $DEST_PORT
HostKey $SCRATCH/dest_host
PidFile $SCRATCH/dest.pid
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
# The scratch dir is under world-writable /tmp; this is a throwaway test destination, so
# relax the StrictModes ancestor check rather than relocate (the bastion itself stages on
# a safe-owned path in production).
StrictModes no
AuthorizedKeysFile $SCRATCH/dest_authorized_keys
EOF

"$SSHD" -D -e -f "$SCRATCH/dest_sshd_config" >"$SCRATCH/dest.log" 2>&1 &
echo "$!" >"$SCRATCH/dest_sshd.pid"

# The bastion's outbound `ssh` (run as the operator) verifies the destination against this
# known_hosts pin — the host-side store the design's §7.10.7 describes, here a one-line pin.
printf '[127.0.0.1]:%s %s\n' "$DEST_PORT" "$(cat "$SCRATCH/dest_host.pub")" \
    >"$SCRATCH/dest_known_hosts"

# Wait for the destination sshd to accept connections.
for _ in $(seq 1 50); do
    if 2>/dev/null >/dev/tcp/127.0.0.1/"$DEST_PORT"; then break; fi
    sleep 0.1
done

# facade-ssh is bound into the kennel view at the deployment path (libexec_dir/facade-ssh,
# = the build tree under the suite's system.toml); the workload's stock ssh execs it as the
# ProxyCommand, so it must be on exec.allow at exactly that path.
FACADE_SSH="$REPO_ROOT/target/debug/facade-ssh"

# Generate the policy with the host-specific values filled in (a copy beside the scratch,
# so the compiler mints the synthetic keypair into <scratch>/ssh/).
GEN="$SCRATCH/policy.toml"
sed \
    -e "s|__DEST_USER__|$DEST_USER|g" \
    -e "s|__DEST_PORT__|$DEST_PORT|g" \
    -e "s|__REAL_KEY__|$SCRATCH/real|g" \
    -e "s|__DEST_KNOWN_HOSTS__|$SCRATCH/dest_known_hosts|g" \
    -e "s|__FACADE_SSH__|$FACADE_SSH|g" \
    "$CASE_DIR/policy.toml" >"$GEN"

# Last stdout line = the policy the runner runs.
echo "$GEN"
