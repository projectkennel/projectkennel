#!/usr/bin/env bash
#
# OCI substrate e2e (§7.11). Unlike the `kennel run` cases, an `[rootfs]` policy is driven by
# `kennel oci run`, so this case ships a `run.sh` hook the suite driver invokes instead of the
# default `kennel run <policy>`. It is self-checking: it boots a real OCI image as the kennel root
# and verifies the slice from inside, exiting 0 iff every assertion holds (the suite's contract).
#
# What it proves end to end, on the real installed stack:
#   * an unpacked OCI image boots as a layered-overlay root (§7.11.4a) and its entrypoint runs;
#   * the persona uid is imposed — the image's non-root `config.User` is NOT honored (residual C);
#   * closure-lock (§7.11.4c) is enforced: a non-root image's `/usr` is read-only (write denied),
#     derived at `oci build` from `config.User` and applied as Landlock by the spawn;
#   * the constructed `/tmp` is writable by the persona (the DAC chown), and Kennel's `/etc`
#     wins by layer precedence.
#
#   $1 = case dir   $2 = the installed `kennel`   $3 = the suite signing key   $4 = scratch dir
#
# Exit 77 = SKIP (no skopeo, or the image pull failed — e.g. offline): a missing prerequisite is
# not a failure, but it is reported, never a silent pass.
set -uo pipefail

# shellcheck source=../suite-lib.sh
. "$1/../suite-lib.sh"
suite_case "$@"
NAME="ocie2e"
# A private per-operator store under the scratch dir, so the case never touches the real store.
export XDG_DATA_HOME="$SCRATCH/xdg"
ENTRY="$XDG_DATA_HOME/kennel/images/$NAME"

command -v skopeo  >/dev/null 2>&1 || { echo "SKIP: skopeo not installed"; exit 77; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 77; }

# 1. Pull a tiny image into a `dir:` layout (config blob + layer tarball). Offline ⇒ SKIP.
if ! skopeo copy --quiet "docker://docker.io/library/busybox:latest" "dir:$SCRATCH/img" 2>"$SCRATCH/skopeo.err"; then
    echo "SKIP: image pull failed (offline?) — $(tail -1 "$SCRATCH/skopeo.err" 2>/dev/null)"
    exit 77
fi

# 2. Unpack the layer into rootfs/ and write a NON-ROOT config.json. Two things ride on the
#    non-root User: it makes closure-lock derive the FHS lock, and (being a uid the persona map
#    does not contain) it lets the self-check prove the image User is ignored.
LAYER="$(python3 -c "import json,sys;print(json.load(open('$SCRATCH/img/manifest.json'))['layers'][0]['digest'].split(':')[1])")"
mkdir -p "$ENTRY/rootfs"
tar -xzf "$SCRATCH/img/$LAYER" -C "$ENTRY/rootfs" 2>/dev/null
python3 - "$ENTRY/config.json" <<'PY'
import json, sys
json.dump({"config": {"User": "12345", "Cmd": ["sh"],
                      "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]}},
          open(sys.argv[1], "w"))
PY

# 3. Build the store entry: records the digest and scaffolds policy.toml, deriving the closure-lock
#    `readonly` set from config.User (non-root ⇒ the FHS closure). `--no-fetch`: this case unpacks
#    the rootfs + writes the faked non-root config.json itself (above), so the confined fetch
#    (proven by the oci-confined-fetch case) is skipped here. Then complete `reason`.
IMG="docker.io/library/busybox@sha256:e2e0000000000000000000000000000000000000000000000000000000000000"
"$KENNEL" oci build "$NAME" --image "$IMG" --no-fetch --force >"$SCRATCH/build.log" 2>&1 || {
    echo "FAIL: oci build — $(tail -2 "$SCRATCH/build.log")"; exit 1; }
sed -i 's|^reason = .*|reason = "e2e: boot busybox as an OCI substrate"|' "$ENTRY/policy.toml"
# Assert the build actually derived a live closure-lock (not a commented hint) from the non-root User.
grep -qE '^readonly = \["/usr"' "$ENTRY/policy.toml" || {
    echo "FAIL: oci build did not derive a closure-lock from a non-root config.User"; exit 1; }

# 4. Compile the completed store policy in the AUTHORING house (the dogfood flow: `oci run`
#    boots only the settled artefact), then boot and self-check the slice from inside. `oci run`
#    asserts the digest and drives the overlay-root spawn; it takes no key (the daemon verifies).
"$KENNEL" policy compile "$ENTRY/policy.toml" --key "$SUITE_KEY" --no-lock >"$SCRATCH/compile.log" 2>&1 || {
    echo "FAIL: policy compile — $(tail -2 "$SCRATCH/compile.log")"; exit 1; }
"$KENNEL" oci run "$NAME" -- /bin/sh -c '
    uid=$(id -u)
    [ "$uid" = 12345 ] && { echo "FAIL: image User was honored (uid=$uid)"; exit 21; }
    [ -n "$uid" ] || { echo "FAIL: no uid"; exit 22; }
    # closure-lock: /usr (and the FHS closure) must be read-only for a non-root image. The write
    # probe runs in a subshell so a failed redirect on a special built-in does not exit our shell.
    if ( echo x > /usr/_e2e_probe ) 2>/dev/null; then echo "FAIL: /usr writable (closure-lock absent)"; exit 23; fi
    # /usr still readable + executable (read+exec kept), or the image could not run at all.
    [ -x /bin/sh ] || { echo "FAIL: /bin/sh not executable under the lock"; exit 24; }
    # the persona /tmp is writable (the DAC chown), and Kennel/etc wins by layer precedence.
    ( echo x > /tmp/_e2e_probe ) 2>/dev/null || { echo "FAIL: /tmp not writable"; exit 25; }
    [ -f /etc/resolv.conf ] || { echo "FAIL: Kennel /etc/resolv.conf missing"; exit 26; }
    echo "OCI_SLICE_OK uid=$uid"
    exit 0
'
