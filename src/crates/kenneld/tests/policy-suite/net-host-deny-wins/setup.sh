#!/usr/bin/env bash
#
# Per-case fixture for net-host-deny-wins: TWO host-side loopback listeners on the SAME
# free port — 127.0.0.2 (the policy denies it) and 127.0.0.3 (the policy's *:PORT allows
# it). Both are bound in the host netns; under mode=host the kennel shares that netns, so
# both are routable and the ONLY difference is the BPF connect deny. Substitutes the port
# into a generated policy and prints that policy's path on the last stdout line.
#
#   $1 = the case dir   $2 = a scratch dir for the fixture
set -euo pipefail

CASE_DIR="$1"
SCRATCH="$2"
mkdir -p "$SCRATCH"

command -v python3 >/dev/null || { echo "no python3" >&2; exit 2; }

# One free port, used by BOTH listeners (they differ only by address). Probe-bind on
# 127.0.0.2 (a denied-policy address, but in setup we are the host operator so it is free).
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.2",0));print(s.getsockname()[1]);s.close()')"

# Background a host-side accept/close listener on each address:port (host netns).
for ip in 127.0.0.2 127.0.0.3; do
    python3 - "$ip" "$PORT" <<'PY' &
import socket, sys
ip, port = sys.argv[1], int(sys.argv[2])
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((ip, port))
s.listen(16)
while True:
    try:
        c, _ = s.accept(); c.close()
    except OSError:
        break
PY
    echo "$!" >>"$SCRATCH/host_listeners.pids"
done

# Wait for BOTH listeners to accept host-side (sanity: they MUST be reachable from the
# host, so a kennel failure is attributable to the BPF deny, not a dead listener). Bounded
# python connect with a per-attempt timeout — NOT a bash `>/dev/tcp` redirect.
for ip in 127.0.0.2 127.0.0.3; do
    if ! python3 - "$ip" "$PORT" <<'PY'
import socket, sys, time
ip, port = sys.argv[1], int(sys.argv[2])
for _ in range(50):
    s = socket.socket(); s.settimeout(0.5)
    try:
        s.connect((ip, port)); s.close(); raise SystemExit(0)
    except OSError:
        time.sleep(0.1)
    finally:
        s.close()
raise SystemExit(1)
PY
    then
        echo "host listener never came up on $ip:$PORT" >&2
        exit 2
    fi
done

# Generate the policy with the chosen port filled in.
GEN="$SCRATCH/policy.toml"
sed -e "s/__PORT__/$PORT/g" "$CASE_DIR/policy.toml" >"$GEN"

# Last stdout line = the policy the runner runs.
echo "$GEN"
