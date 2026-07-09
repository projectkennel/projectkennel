#!/usr/bin/env bash
#
# Confined OCI fetch e2e (§7.11.7, W17c). Proves `kennel oci build` runs the image pull + unpack
# INSIDE a kennel under the vendor `oci-fetch` policy — never on the host — and populates the
# store entry, which then boots. The companion `oci-substrate` case proves the overlay/closure-lock
# substrate; this one proves the *fetch*.
#
# What it proves end to end, on the real installed stack:
#   * `kennel oci build` runs skopeo + a no-chown tar extraction confined under oci-fetch
#     (constrained egress to the registry allowlist; the per-build leaf adds only the store write);
#   * the entry is populated: rootfs/ unpacked, config.json (image config) captured, digest pinned;
#   * the rootless unpack flattens every inode to the operator uid (residual C / §7.11.4c);
#   * the fetched substrate boots and runs its entrypoint.
#
#   $1 = case dir   $2 = the installed `kennel`   $3 = the suite signing key   $4 = scratch dir
#
# Exit 77 = SKIP (no skopeo/python3, or the registry is unreachable — a fetch needs egress).
set -uo pipefail

# shellcheck source=../suite-lib.sh
. "$1/../suite-lib.sh"
suite_case "$@"
NAME="ocifetch"

# The store MUST live under $HOME: the fetch writes it via `fs.write`, and the home-persona mapping
# binds it into the fetch kennel's view (a store under /tmp would hit base-confined's private /tmp).
# A self-cleaning per-run dir under $HOME, never the operator's real store.
STORE="$HOME/.kennel-e2e-ocifetch-$$"
export XDG_DATA_HOME="$STORE"
ENTRY="$STORE/kennel/images/$NAME"
suite_defer '"$KENNEL" oci revert "$NAME" >/dev/null 2>&1; rm -rf "$STORE"'

command -v skopeo >/dev/null 2>&1 || { echo "SKIP: skopeo not installed"; exit 77; }
command -v umoci  >/dev/null 2>&1 || { echo "SKIP: umoci not installed"; exit 77; }

# The confined fetch: skopeo + python3 run inside a kennel under oci-fetch; the per-build leaf
# (signed by the suite key) adds fs.write for the store entry. Offline ⇒ SKIP (a fetch needs egress).
if ! "$KENNEL" oci build "$NAME" --image "docker.io/library/busybox:latest" --key "$SUITE_KEY" --force \
        >"$SCRATCH/build.log" 2>&1; then
    if grep -qiE "offline|temporary failure|could not resolve|name resolution|network|dial tcp|no route|connection refused|timeout|unreachable" "$SCRATCH/build.log"; then
        echo "SKIP: confined fetch could not reach the registry (offline?) — $(tail -1 "$SCRATCH/build.log")"
        exit 77
    fi
    echo "FAIL: kennel oci build (confined fetch) — $(tail -3 "$SCRATCH/build.log")"
    exit 1
fi

# The entry is populated by the confined fetch.
[ -e "$ENTRY/rootfs/bin/busybox" ] || [ -e "$ENTRY/rootfs/bin/sh" ] || {
    echo "FAIL: rootfs not unpacked at $ENTRY/rootfs"; exit 1; }
grep -q '"config"' "$ENTRY/config.json" 2>/dev/null || {
    echo "FAIL: config.json missing or not an image config"; exit 1; }
grep -q "@sha256:" "$ENTRY/digest" 2>/dev/null || {
    echo "FAIL: digest not pinned to a sha256 — $(cat "$ENTRY/digest" 2>/dev/null)"; exit 1; }

# Rootless flatten: every unpacked inode is owned by the operator (this uid), not the image's uids.
owner="$(stat -c '%u' "$ENTRY/rootfs/bin" 2>/dev/null)"
[ "$owner" = "$(id -u)" ] || { echo "FAIL: rootfs not flattened to the operator uid (got $owner)"; exit 1; }

# Complete the scaffolded run policy's reason, then boot the fetched substrate. The boot's success
# is its workload EXIT CODE (the suite's contract) — not stdout, which the in-kennel→CLI path does
# not forward; the self-check exits non-zero on any failure, 0 only if the substrate booted clean.
sed -i 's|^reason = .*|reason = "e2e: boot a confined-fetched busybox"|' "$ENTRY/policy.toml"
# Compile the completed store policy in the authoring house (dogfood: `oci run` boots only the
# settled artefact and takes no key — the daemon verifies).
"$KENNEL" policy compile "$ENTRY/policy.toml" --key "$SUITE_KEY" --no-lock >"$SCRATCH/compile.log" 2>&1 || {
    echo "FAIL: policy compile — $(tail -2 "$SCRATCH/compile.log")"; exit 1; }
"$KENNEL" oci run "$NAME" -- /bin/sh -c '
    [ -e /bin/sh ] || exit 31            # the fetched substrate runs its own shell
    [ -x /bin/busybox ] || [ -x /bin/cat ] || exit 32
    [ -e /etc/resolv.conf ] || exit 33   # Kennel /etc is present over the image
    exit 0
' >"$SCRATCH/run.log" 2>&1
rc=$?
[ "$rc" = 0 ] || {
    echo "FAIL: confined-fetched image did not boot cleanly (rc=$rc) — $(tail -3 "$SCRATCH/run.log")"; exit 1; }

echo "CONFINED_FETCH_OK (digest $(cat "$ENTRY/digest"))"
exit 0
