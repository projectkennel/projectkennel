#!/usr/bin/env bash
#
# Suite case: mesh-rendezvous-symlink (self-driving). A host socket outside every grant listens;
# the provider leaves a symlink to it at its rendezvous endpoint; a consumer connects. Exit 0
# iff nothing reached the host socket. Also checks that a capability name which is not one safe
# path component is refused at compile.
#
#   $1 = the case dir   $2 = the kennel CLI   $3 = the suite key id   $4 = a scratch dir
set -euo pipefail

. "$1/../suite-lib.sh"
suite_case "$@"
mkdir -p "$SCRATCH"

# 1. A capability name becomes a directory name on the host: one that is not a single safe
#    component must not compile.
sed 's#^name = "test.mesh.rendezvous"#name = "x/../../../../tmp/kennel-e2e-escape"#' \
    "$CASE_DIR/provider.toml" | sed "s#__VICTIM__#/nonexistent#" >"$SCRATCH/bad-name.toml"
if "$KENNEL" policy compile "$SCRATCH/bad-name.toml" --key "$SUITE_KEY" --trust-dir "$KEYS" \
        --no-lock --output "$SCRATCH/bad-name.settled" >"$SCRATCH/bad-name.log" 2>&1; then
    echo "mesh-rendezvous-symlink: FAIL — a capability name with path separators compiled" >&2
    exit 1
fi
grep -q "not a well-formed capability name" "$SCRATCH/bad-name.log" \
    || { echo "mesh-rendezvous-symlink: the bad name was refused, but not for its grammar:" >&2; cat "$SCRATCH/bad-name.log" >&2; exit 1; }

# 2. The host socket no kennel is granted.
victim="$SCRATCH/host.sock"
python3 - "$victim" "$SCRATCH/host-received.log" >"$SCRATCH/fixture.log" 2>&1 <<'PY' &
import socket, sys
s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(8)
log = open(sys.argv[2], "a", buffering=1)
while True:
    c, _ = s.accept(); c.settimeout(3)
    try: d = c.recv(32)
    except OSError: d = b""
    log.write("host socket got %r\n" % d); c.sendall(b"HOST-SOCKET-OUTSIDE-EVERY-GRANT"); c.close()
PY
suite_defer "kill $! 2>/dev/null"
for _ in $(seq 50); do [[ -S "$victim" ]] && break; sleep 0.1; done
[[ -S "$victim" ]] || { echo "mesh-rendezvous-symlink: the host fixture socket did not come up" >&2; exit 2; }

sed "s#__VICTIM__#$victim#" "$CASE_DIR/provider.toml" >"$SCRATCH/provider.toml"
suite_enable_ondemand "$SCRATCH/provider.toml" rendezvous-link-provider

name="$(suite_compile "$CASE_DIR/consumer.toml")"
suite_defer "suite_unstage $name"
"$KENNEL" run "$name" "$name" </dev/null >"$SCRATCH/consumer.log" 2>&1 || true

if [[ -s "$SCRATCH/host-received.log" ]] || grep -q "HOST-SOCKET" "$SCRATCH/consumer.log"; then
    echo "mesh-rendezvous-symlink: FAIL — the consumer was connected to a host socket through the provider's symlink:" >&2
    cat "$SCRATCH/consumer.log" "$SCRATCH/host-received.log" >&2 2>/dev/null
    exit 1
fi
# The control that the set-up was live: the provider did place its link.
rp="$(ls -d /run/user/"$(id -u)"/kennel/mesh/*/test.mesh.rendezvous 2>/dev/null | head -n1)"
[[ -n "$rp" && -L "$rp/echo.sock" ]] \
    || { echo "mesh-rendezvous-symlink: the provider never placed its symlink — nothing was tested" >&2; cat "$SCRATCH/consumer.log" >&2; exit 2; }
echo "mesh-rendezvous-symlink: kenneld refused to connect through the provider's symlink; a path-shaped capability name does not compile"
