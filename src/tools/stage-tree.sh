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
#     policies/<n>/policy.toml    the reference policy sources (compiled host-signed at install)
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

# The payload's binaries, grouped by their INSTALL DESTINATION (the three-dir layout). The build
# puts host-dynamic bins in REL (host glibc) and in-kennel static bins in STAT (`+crt-static`: they
# run inside an arbitrary image root with no host `ld.so`). The payload encodes the destination in
# the staging subdir — install.sh places each verbatim:
#   bin/      → <libexec>            (/usr/libexec/kennel)  host-side ONLY; blacklisted from views.
#   facades/  → <facades_dir>        (/usr/libexec/kennel-facades) the in-cage binaries a view runs.
#   pathbin/  → /usr/bin             the `kennel` shim, the one name on PATH.
#
# Host-side (→ bin/): the daemon, the AKC, the host delegates, the privhelper + its capability-split
# sub-helpers (all dynamic), the trusted init (static, `fexecve`'d from an fd — needs no view path),
# and the host execution unit (`kennel-host` → `host`, dynamic).
HOST_REL_BINS="kenneld kennel-akc host-netproxy host-inetd kennel-privhelper kennel-privhelper-net kennel-privhelper-bpf kennel-privhelper-mounts"
HOST_STAT_BINS="kennel-bin-init"
# In-cage (→ facades/): the conduit facades, the OCI launcher, the spawn execution unit
# (`kennel-spawn` → `spawn`), the standing D-Bus broker (`dbus-broker`, the mediation service
# kennel's workload), the GUI compositor broker (`compositor-broker`, the confined-GUI service
# kennel's workload — it spawns a per-connection nested compositor and relays the consumer
# into it), the L3-egress facade (`facade-tun`, the in-view frame forwarder), the standing tun broker
# (`tun-broker`, the UDP-egress mediation service kennel's workload) and its per-session mediator
# (`tun-flow`, spawned fresh by `tun-broker` for each egress session with that session's grants) —
# all static, all reached by path inside a constructed view.
FACADE_STAT_BINS="facade-afunix facade-socks5 facade-client facade-ssh facade-dbus facade-tun kennel-bin-oci-entry dbus-broker compositor-broker tun-broker tun-flow"

# The in-kennel SPAWN/mesh TEST drivers — `kennel-facade` builds them, but they are the TEST SUITE,
# not part of a release: `facade-spawn-probe` is the spawn-roundtrip policy-suite's workload,
# `facade-spawn-bench` drives spawn-spinup.sh, and `facade-mesh-probe` is the mesh/gui suite's
# headless stand-in. Staged into `facades/` ONLY under --with-test-bins (they run in-cage); a real
# release never carries them.
TEST_BINS="facade-spawn-probe facade-spawn-bench facade-mesh-probe"

install -d "$DEST/bin" "$DEST/facades" "$DEST/pathbin"
for b in $HOST_REL_BINS;    do install -m 0755 "$REL/$b"  "$DEST/bin/$b";     done
for b in $HOST_STAT_BINS;   do install -m 0755 "$STAT/$b" "$DEST/bin/$b";     done
for b in $FACADE_STAT_BINS; do install -m 0755 "$STAT/$b" "$DEST/facades/$b"; done

# The unified `kennel` surface: one static shim on PATH dispatches to two execution units, under
# their context names — `kennel` (shim, → /usr/bin), `host` (dynamic, host-side), `spawn` (static, in-cage).
install -m 0755 "$STAT/kennel"       "$DEST/pathbin/kennel"
install -m 0755 "$REL/kennel-host"   "$DEST/bin/host"
install -m 0755 "$STAT/kennel-spawn" "$DEST/facades/spawn"
# Script facades (shell launchers shipped as source, e.g. the claude run launcher).
SRC_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
for f in "$SRC_ROOT"/src/facades/*.sh; do [ -f "$f" ] && install -m 0755 "$f" "$DEST/facades/$(basename "$f")"; done
# The standalone policy-authoring tool (`kennel-compose`): a host-side CLI on PATH, disjunct from
# the `kennel` dispatch tree and the runtime — dynamic (host glibc), like the other host tools.
install -m 0755 "$REL/kennel-compose" "$DEST/pathbin/kennel-compose"
if [ "$WITH_TEST_BINS" = 1 ]; then
	for b in $TEST_BINS; do install -m 0755 "$STAT/$b" "$DEST/facades/$b"; done
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
for d in "$ROOT"/toml/templates/*/; do
	[ -f "${d}policy.toml" ] || continue
	n="$(basename "$d")"
	for f in "${d}"*.toml; do
		[ -e "$f" ] || continue
		install -D -m 0644 "$f" "$DEST/templates/$n/$(basename "$f")"
	done
done
for d in "$ROOT"/toml/fragments/*/; do
	[ -f "${d}policy.toml" ] || continue
	install -D -m 0644 "${d}policy.toml" "$DEST/fragments/$(basename "$d")/policy.toml"
done

# The reference policy SOURCES — runnable leaves (policies/<n>) and service providers
# (policies/providers/<n>), policy.toml only. They are maintainer-signed sources; install.sh's
# install_reference_policies compiles each to a host-signed settled artefact under
# /etc/kennel/policies (the loader pin is host-specific, so a settled policy cannot be shipped).
for d in "$ROOT"/toml/policies/*/; do
	[ -f "${d}policy.toml" ] || continue
	install -D -m 0644 "${d}policy.toml" "$DEST/policies/$(basename "$d")/policy.toml"
done
for d in "$ROOT"/toml/policies/providers/*/; do
	[ -f "${d}policy.toml" ] || continue
	install -D -m 0644 "${d}policy.toml" "$DEST/policies/providers/$(basename "$d")/policy.toml"
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
