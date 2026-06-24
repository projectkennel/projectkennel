#!/usr/bin/env bash
# Project Kennel — assemble the flat install payload that install.sh consumes.
#
# Given the already-built binaries, lay out the tree install.sh expects to sit inside:
#
#   <dest>/
#     install.sh                  the installer (copied verbatim from src/tools/)
#     bin/                        every runtime binary, flat
#     dist/                       config / systemd / apparmor / threats / vendor / kennel-sshd.conf
#     keys/*.pub                  the trust-store public key(s)
#     templates/<n>/*.toml        the signed reference templates (policy + meta)
#     fragments/<n>/policy.toml   the signed composable fragments
#     man/<page>.<section>        the committed man pages
#     SHA256SUMS                  sha256 of every bin/ entry
#
# This is the SINGLE source of truth for the payload's binary list and layout. Both the release
# tarball (build-release.sh, which tars the result) and the dev/e2e install (policy-e2e.sh et al.,
# which run install.sh against the result) stage through here — so the tarball install and the e2e
# install are byte-for-byte the same tree, and install.sh stays a pure placer with no source-tree
# awareness (it never runs from a checkout; it runs from an unpacked payload like this one).
#
# Usage:
#   stage-tree.sh --dest DIR [--rel DIR] [--stat DIR]
#     --dest DIR   the payload root to populate (required)
#     --rel DIR    where the host-dynamic bins + the privhelper were built
#                  (default: <root>/target/release)
#     --stat DIR   where the in-kennel static bins were built
#                  (default: <root>/target/<host-triple>/release)
#     --with-test-bins  also stage the spawn TEST drivers (facade-spawn-probe/-bench) — the spawn
#                  e2e/bench install them to libexec; a release NEVER ships them
#
# A release cross-build puts every binary in one dir (target/<triple>/release), so build-release.sh
# passes that same dir for both --rel and --stat; a dev build splits them, so the e2e path passes
# the two it built into.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HOST_TRIPLE="$(uname -m)-unknown-linux-gnu"
DEST=""
REL="$ROOT/target/release"
STAT="$ROOT/target/$HOST_TRIPLE/release"
WITH_TEST_BINS=0
while [ $# -gt 0 ]; do
	case "$1" in
		--dest) DEST="${2:?--dest needs a directory}"; shift 2 ;;
		--rel)  REL="${2:?--rel needs a directory}"; shift 2 ;;
		--stat) STAT="${2:?--stat needs a directory}"; shift 2 ;;
		--with-test-bins) WITH_TEST_BINS=1; shift ;;
		-h|--help) sed -n '2,34p' "$0"; exit 0 ;;
		*) echo "stage-tree.sh: unknown argument: $1" >&2; exit 2 ;;
	esac
done
[ -n "$DEST" ] || { echo "stage-tree.sh: --dest is required" >&2; exit 2; }

# The payload's binaries, grouped by where the build puts them. REL = host-dynamic (run in the
# operator's context, linked against the host glibc) plus the privhelper. STAT = in-kennel static
# (`+crt-static`: the launcher, the trusted init, and the facades run inside an arbitrary image root
# with no host `ld.so`, so they carry their own libc). Both flatten into one `bin/` for the payload.
REL_BINS="kenneld kennel-akc host-netproxy host-inetd host-dbus kennel-privhelper"
STAT_BINS="kennel-bin-oci-entry kennel-bin-init facade-afunix facade-socks5 facade-client facade-ssh facade-dbus"

# The in-kennel SPAWN test drivers — `kennel-facade` builds them, but they are the TEST SUITE, not
# part of a release: `facade-spawn-probe` is the spawn-roundtrip policy-suite's workload and
# `facade-spawn-bench` drives spawn-spinup.sh. Staged into the payload ONLY under --with-test-bins
# (the spawn e2e/bench install them to libexec); a real release never carries them.
TEST_BINS="facade-spawn-probe facade-spawn-bench facade-mesh-probe"

install -d "$DEST/bin"
for b in $REL_BINS;  do install -m 0755 "$REL/$b"  "$DEST/bin/$b"; done
for b in $STAT_BINS; do install -m 0755 "$STAT/$b" "$DEST/bin/$b"; done

# The unified `kennel` surface (W10): one static shim on PATH dispatches to two execution units.
# The shim and the in-cage spawn unit are static (they run inside a constructed view with no host
# ld.so); the host unit is the dynamic operator CLI. They install under their context names —
# `kennel` (shim), `host`, `spawn` — so the shim's `/usr/libexec/kennel/{host,spawn}` dispatch resolves.
install -m 0755 "$STAT/kennel"       "$DEST/bin/kennel"
install -m 0755 "$REL/kennel-host"   "$DEST/bin/host"
install -m 0755 "$STAT/kennel-spawn" "$DEST/bin/spawn"
if [ "$WITH_TEST_BINS" = 1 ]; then
	for b in $TEST_BINS; do install -m 0755 "$STAT/$b" "$DEST/bin/$b"; done
fi

install -m 0755 "$ROOT/src/tools/install.sh" "$DEST/install.sh"

# Everything under dist/ that install.sh consumes (config, systemd, apparmor, threats, vendor,
# kennel-sshd.conf) — all of dist/ except the release/ output dir, so this never drifts.
install -d "$DEST/dist"
for item in "$ROOT"/dist/*; do
	[ "$(basename "$item")" = "release" ] && continue
	cp -a "$item" "$DEST/dist/"
done

# The trust-store public key(s) — only `*.pub` is ever in the repo (private seeds: MAINTAINERS.md).
install -d "$DEST/keys"
for p in "$ROOT"/keys/*.pub; do
	[ -e "$p" ] || continue
	install -m 0644 "$p" "$DEST/keys/$(basename "$p")"
done

# The signed reference templates (policy.toml + meta.toml; not the README) and the composable
# fragments (policy.toml only). install.sh ships these into the template cascade.
for d in "$ROOT"/templates/*/; do
	[ -f "${d}policy.toml" ] || continue
	n="$(basename "$d")"
	for f in "${d}"*.toml; do
		[ -e "$f" ] || continue
		install -D -m 0644 "$f" "$DEST/templates/$n/$(basename "$f")"
	done
done
for d in "$ROOT"/fragments/*/; do
	[ -f "${d}policy.toml" ] || continue
	install -D -m 0644 "${d}policy.toml" "$DEST/fragments/$(basename "$d")/policy.toml"
done

# The committed man pages (gen-man output; man/README.md).
for p in "$ROOT"/man/*.[1-9]; do
	[ -e "$p" ] || continue
	install -D -m 0644 "$p" "$DEST/man/$(basename "$p")"
done

# The integrity manifest: a sha256 of EVERY file we ship and install — the binaries, the config,
# the systemd/apparmor units, the signed templates and fragments, the man pages, the installer
# itself, and ESPECIALLY the trust-store public key(s). The key is the anchor the whole signature
# chain hangs from; a tampered `keys/*.pub` would silently widen what the daemon trusts, so it is the
# one file the manifest must cover. Verify the unpacked payload before installing: from this dir,
# `sha256sum -c SHA256SUMS`. Relative, C-sorted (reproducible), excluding the manifest itself.
( cd "$DEST" && find . -type f ! -name SHA256SUMS -print0 \
	| LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS )
