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

# Background the connector: poll ss for the kennel's mirror listener on :3000, connect to it, send
# MIRROR_OK, read the echo. Kennel loopback addressing is IPv6-only (W10), so host-inetd binds the
# mirror on the kennel's ULA (`fd6b:6e..`) — NOT a v4 `127.x` alias. Bounded so a failed run does
# not leave it spinning forever.
nohup python3 - >"$SCRATCH/connector.log" 2>&1 <<'PY' &
import socket, subprocess, time, re
# Must outlive the whole per-case window: the runner compiles the policy (dogfood flow) and
# then runs with its own 90s bound, so a 60s poll loses the race under full-suite load.
deadline = time.time() + 150
target = None
while time.time() < deadline and target is None:
    out = subprocess.run(["ss", "-ltn"], capture_output=True, text=True).stdout
    # The mirror is the kennel's ULA (`fd6b:6e..`), e.g. `[fd6b:6e9c:691c:1::1]:3000`.
    m = re.search(r"\[(fd6b:[0-9a-f:]+)\]:3000\b", out)
    if m:
        target = m.group(1)
    else:
        time.sleep(0.2)
if target is None:
    print("connector: no mirrored [fd6b:..]:3000 listener appeared")
    raise SystemExit(1)
# Retry the connect briefly (the listener may appear a hair before it accepts).
for _ in range(50):
    try:
        s = socket.socket(socket.AF_INET6); s.settimeout(3); s.connect((target, 3000))
        s.sendall(b"MIRROR_OK")
        print("connector: sent marker to [%s]:3000, got %r" % (target, s.recv(32)))
        s.close()
        raise SystemExit(0)
    except OSError:
        time.sleep(0.2)
print("connector: never connected to [%s]:3000" % target)
raise SystemExit(1)
PY
echo "$!" >"$SCRATCH/connector.pid"

# This case carries its policy as-is (no host-specific substitution). Print it for the runner.
echo "$CASE_DIR/policy.toml"
