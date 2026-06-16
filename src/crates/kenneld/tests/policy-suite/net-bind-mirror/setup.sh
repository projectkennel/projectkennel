#!/usr/bin/env bash
#
# Per-case fixture for net-bind-mirror: a host-side connector that exercises the §7.5.7 inbound
# mirror. The runner runs setup BEFORE the kennel, so we cannot connect synchronously — the
# host-side mirror listener (host-inetd binding <kennel-ip>:3000 on host lo) only appears once the
# kennel is up. So this BACKGROUNDS a connector that polls for the mirrored listener and, once it
# appears, connects from the host and sends the marker the workload verifies. It runs concurrently
# with the run; teardown.sh kills it.
#
#   $1 = the case dir   $2 = a scratch dir
set -euo pipefail

CASE_DIR="$1"
SCRATCH="$2"
mkdir -p "$SCRATCH"
command -v python3 >/dev/null || { echo "no python3" >&2; exit 2; }
command -v ss >/dev/null || { echo "no ss" >&2; exit 2; }

# Background the connector: poll ss for a NEW 127.x:3000 listener (host-inetd's mirror — not a
# pre-existing host service), connect to it, send MIRROR_OK, read the echo. Bounded so a failed run
# does not leave it spinning forever.
nohup python3 - >"$SCRATCH/connector.log" 2>&1 <<'PY' &
import socket, subprocess, time, re
deadline = time.time() + 60
target = None
while time.time() < deadline and target is None:
    out = subprocess.run(["ss", "-ltn"], capture_output=True, text=True).stdout
    for m in re.finditer(r"\b(127\.\d+\.\d+\.\d+):3000\b", out):
        ip = m.group(1)
        if ip != "127.0.0.1":          # the kennel's own loopback alias, not a stray host service
            target = ip
            break
    if target is None:
        time.sleep(0.2)
if target is None:
    print("connector: no mirrored 127.x:3000 listener appeared")
    raise SystemExit(1)
# Retry the connect briefly (the listener may appear a hair before it accepts).
for _ in range(50):
    try:
        s = socket.socket(); s.settimeout(3); s.connect((target, 3000))
        s.sendall(b"MIRROR_OK")
        print("connector: sent marker to %s:3000, got %r" % (target, s.recv(32)))
        s.close()
        raise SystemExit(0)
    except OSError:
        time.sleep(0.2)
print("connector: never connected to %s:3000" % target)
raise SystemExit(1)
PY
echo "$!" >"$SCRATCH/connector.pid"

# This case carries its policy as-is (no host-specific substitution). Print it for the runner.
echo "$CASE_DIR/policy.toml"
