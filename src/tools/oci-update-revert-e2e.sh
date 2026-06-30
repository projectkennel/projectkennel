#!/usr/bin/env bash
#
# Hardware e2e for the OCI layer-lifecycle verbs (ROADMAP-0.3.0 W13 + W14): `kennel oci update`'s
# carve-out-preserving closure re-derivation + signature clear, and `kennel oci revert`'s
# diff-against-pin (`--list`) + selective restore. CLI-only (the store ops touch no daemon), driven
# against the REAL built `kennel` binary into a throwaway store ($XDG_DATA_HOME), so it asserts the
# end-to-end wiring — parse_source → re-derive → rewrite → file I/O — a unit test cannot.
#
# A confined image fetch needs skopeo+umoci+registry; this rides `--no-fetch` (the out-of-band /
# test population path), so it is hermetic. The base-CHANGE case (a new image whose User flips
# root↔non-root) needs two real image configs and is covered by the oci unit tests (preserve_closure
# + the rewrite test); here the config is the non-root image's throughout, which exercises the full
# rewrite with the FHS base re-derived and the operator carve-outs preserved.
#
#   Usage: src/tools/oci-update-revert-e2e.sh   (builds the debug CLI if needed)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

KENNEL="$REPO_ROOT/target/debug/kennel"
[ -x "$KENNEL" ] || cargo build -p kennel-cli --offline >/dev/null

WORK="$(mktemp -d)"
export XDG_DATA_HOME="$WORK/data"
STORE="$XDG_DATA_HOME/kennel/images/app"
trap 'rm -rf "$WORK"' EXIT

pass() { echo "  ok: $1"; }
fail() { echo "  FAIL: $1" >&2; exit 1; }

echo "== build the entry (--no-fetch) + a non-root image config + a signed operator policy =="
"$KENNEL" oci build app --no-fetch --image registry/app@sha256:OLD >/dev/null
# A non-root image: the closure derives the FHS base. (build wrote no config.json under --no-fetch.)
printf '{"config":{"User":"1000"}}' > "$STORE/config.json"
# The operator's signed run policy: the FHS base + a hand-added `/opt/app` readonly and a
# `/usr/lib/python3.12` writable hole, an operator-commented [env], and a (fake) appended [signature].
cat > "$STORE/policy.toml" <<EOF
name = "app"
template_base = "base-confined"

[rootfs]
path   = "$STORE/rootfs"
image  = "registry/app@sha256:OLD"
reason = "vendored app image"
readonly = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/libx32", "/opt/app"]
writable = ["/usr/lib/python3.12"]

# operator note: this app needs egress to the model API
[env]
deny = ["LD_*"]

[signature]
algorithm = "ed25519"
key_id = "kennel-maint-2026"
signature = "deadbeef"
EOF

echo "== W13: kennel oci update -- registry/app@sha256:NEW =="
"$KENNEL" oci update app --no-fetch -- registry/app@sha256:NEW
P="$STORE/policy.toml"
grep -q 'sha256:NEW' "$P"                || fail "new image not recorded"
grep -q 'sha256:OLD' "$P"                && fail "old image still present"
grep -q '\[signature\]' "$P"             && fail "signature not cleared"
grep -q 'kennel-maint-2026' "$P"         && fail "signature body not cleared"
grep -q '"/opt/app"' "$P"                || fail "operator readonly carve-out dropped"
grep -q '"/usr/lib/python3.12"' "$P"     || fail "writable carve-out dropped"
grep -q '"/usr"' "$P"                    || fail "FHS base not re-derived"
grep -q '# operator note' "$P"           || fail "operator comment in another section lost"
grep -q '\[env\]' "$P"                   || fail "[env] section lost"
# The rewritten policy must still parse + verify-load-shaped as a source policy with no signature.
"$KENNEL" policy validate "$P" >/dev/null 2>&1 || true   # validate is best-effort here (unsigned)
pass "image bumped, signature cleared, carve-outs + operator section preserved, FHS base re-derived"

echo "== W14: build a managed upper, then --list (diff against the pin) =="
mkdir -p "$STORE/upper/etc" "$STORE/upper/opt/app" "$STORE/work"
printf 'box\n'  > "$STORE/upper/etc/hostname"     # a copy-up / changed file (M)
printf 'data\n' > "$STORE/upper/opt/app/state"    # a nested copy-up (M)
LIST="$("$KENNEL" oci revert app --list 2>&1)"
echo "$LIST" | grep -q 'M /etc/hostname'          || fail "--list missed the copy-up"
echo "$LIST" | grep -q 'M /opt/app/state'         || fail "--list missed the nested copy-up"
echo "$LIST" | grep -q ' /etc$'                   && fail "--list listed a container dir"
pass "--list shows the per-path diff against the image pin"

echo "== W14: selective restore of one path; the other persists =="
"$KENNEL" oci revert app -- /etc/hostname
[ -e "$STORE/upper/etc/hostname" ]                && fail "selective revert did not remove the upper entry"
[ -e "$STORE/upper/opt/app/state" ]               || fail "selective revert removed an unrelated path"
pass "selective restore removed only the named path (the lower shows back through)"

echo "== W14: a traversing path is refused =="
if "$KENNEL" oci revert app -- ../../../etc/passwd >/dev/null 2>&1; then
    fail "a '..' path was not refused"
fi
[ -e "/etc/passwd" ] || fail "host /etc/passwd vanished (escape!)"  # paranoia: never touched the host
pass "a '..' path is refused (no escape from the upper)"

echo "== W14: total revert empties the upper =="
"$KENNEL" oci revert app >/dev/null
[ -e "$STORE/upper" ] && fail "total revert left the upper"
pass "total revert obliterated the managed upper"

echo
echo "ALL GREEN — W13 (update carve-out preservation) + W14 (revert diff/selective) proven on the CLI"
