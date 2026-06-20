#!/usr/bin/env bash
#
# Per-case fixture for net-isolated: a host-side loopback TCP listener that the kennel
# (in its own net-ns) must NOT be able to reach. Binds it on 127.0.0.1:<free port>,
# records the pid, substitutes the port into a generated policy, and prints that
# policy's path on the last stdout line (the runner runs THAT). Run inside the suite's
# delegated scope, as the operator.
#
#   $1 = the case dir   $2 = a scratch dir for the fixture
set -euo pipefail

CASE_DIR="$1"
SCRATCH="$2"
mkdir -p "$SCRATCH"

command -v python3 >/dev/null || { echo "no python3" >&2; exit 2; }

# A free loopback port for the host listener.
HOST_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"

# Background a host-side listener on that port (host net namespace). It just accepts and
# closes; the point is only that the port is reachable HOST-side, so the kennel failing to
# reach it proves the kennel is in a different net-ns.
# stdout/stderr to a scratch log, NOT the caller's pipe: the harness reads this fixture
# via `gen=$(setup.sh)`, and a backgrounded child that inherited the pipe's write-end would
# hold the command substitution open forever (deadlock). Redirecting releases the pipe.
python3 - "$HOST_PORT" >"$SCRATCH/host_listener.log" 2>&1 <<'PY' &
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(16)
while True:
    try:
        c, _ = s.accept()
        c.close()
    except OSError:
        break
PY
echo "$!" >"$SCRATCH/host_listener.pid"

# Wait for the listener to accept (host-side sanity: it MUST be reachable from the host).
# A bounded python connect with its own per-attempt timeout — NOT a bash `>/dev/tcp`
# redirect, which can block indefinitely if the connect neither succeeds nor refuses.
if ! python3 - "$HOST_PORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(50):
    s = socket.socket(); s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", port)); s.close()
        raise SystemExit(0)
    except OSError:
        time.sleep(0.1)
    finally:
        s.close()
raise SystemExit(1)
PY
then
    echo "host listener never came up on 127.0.0.1:$HOST_PORT" >&2
    exit 2
fi

# Generate the policy with the host port filled in.
GEN="$SCRATCH/policy.toml"
sed -e "s/__HOST_PORT__/$HOST_PORT/g" "$CASE_DIR/policy.toml" >"$GEN"

# Last stdout line = the policy the runner runs.
echo "$GEN"
