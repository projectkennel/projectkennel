#!/usr/bin/env bash
# Project Kennel — release tarball builder ("the machine that goes bing").
#
# Produces a self-contained, offline-installable tar.xz per target architecture
# (x86_64 and aarch64 by default): the prebuilt release binaries plus the dist
# config / systemd units / AppArmor profile / trust-store public key(s) / signed
# reference templates / the installer. Unpack one on a matching target host and
# run ./install.sh (sudo) — no toolchain, no network, and no clang needed there
# (the BPF objects are embedded into the privhelper here, at build time, by the
# `bpf-egress` feature; that bytecode is arch-independent cgroup-sockaddr code, so
# the host clang builds it for either target).
#
# Cross-compilation uses the rustup target's std plus the `aarch64-linux-gnu-gcc`
# linker configured in .cargo/config.toml (resolved via PATH). Add the target with
# `rustup target add aarch64-unknown-linux-gnu` and have the cross toolchain on PATH.
#
# Determinism: binaries are built through reproducible-build.sh (path remap +
# SOURCE_DATE_EPOCH + the release profile's codegen-units=1), and each tarball is
# packed with fixed owner/mtime/order, so two runs on one source tree byte-match.
#
# Usage:
#   src/tools/build-release.sh [--out DIR] [--arch TRIPLE]...
#     --out DIR       where to write the tarballs (default: dist/release/)
#     --arch TRIPLE   build only this target (repeatable; default: both below)
#
# Reviewed like any other code (CODING-STANDARDS.md §15.4): set -euo pipefail,
# no network, idempotent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/dist/release"
ARCHES=()
while [ $# -gt 0 ]; do
	case "$1" in
		--out) OUT="${2:?--out needs a directory}"; shift 2 ;;
		--arch) ARCHES+=("${2:?--arch needs a target triple}"); shift 2 ;;
		-h|--help) sed -n '2,29p' "$0"; exit 0 ;;
		*) echo "build-release.sh: unknown argument: $1" >&2; exit 2 ;;
	esac
done
# Default: both supported targets, always.
[ "${#ARCHES[@]}" -gt 0 ] || ARCHES=(x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu)

VERSION="$(grep -m1 '^version = ' "$ROOT/Cargo.toml" | cut -d'"' -f2)"
SHA="$(git -C "$ROOT" log -1 --format=%h 2>/dev/null || echo nogit)"
EPOCH="$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || echo 0)"

# The binaries install.sh consumes. `-p kenneld` builds the kenneld, kennel, and
# kennel-akc bins (src/bin/); kennel-bin-init is the trusted uid-0 PID 1 the
# privhelper factory fexecves (07-2); the privhelper is built separately because
# it needs the bpf-egress feature (and thus clang, on the build host).
BINS="kenneld kennel kennel-akc host-netproxy facade-ssh facade-socks5 kennel-bin-init kennel-privhelper"

# The highest GLIBC_x.y symbol version a binary references — the runtime glibc floor.
glibc_floor() {
	readelf --dyn-syms "$1" 2>/dev/null \
		| grep -oE 'GLIBC_[0-9]+\.[0-9]+' | sed 's/GLIBC_//' | sort -V | tail -1
}

build_arch() {
	local triple="$1" arch name rel glibc stage dest b p d n tar
	arch="${triple%%-*}"
	name="kennel-${VERSION}-${SHA}-${arch}-linux-gnu"

	echo "==> [$triple] building release binaries (reproducible, offline, locked)" >&2
	KENNEL_PROFILE=release "$ROOT/src/tools/reproducible-build.sh" --target "$triple" \
		-p kenneld -p host-netproxy -p facade-socks5 -p -p facade-ssh \
		-p kennel-bin-init
	# The privhelper LAST and with its feature, so its build is the bpf-egress one
	# (a plain workspace build would clobber it; see 08-as-built-notes §8.3).
	KENNEL_PROFILE=release "$ROOT/src/tools/reproducible-build.sh" --target "$triple" \
		-p kennel-privhelper --features bpf-egress

	rel="$ROOT/target/$triple/release"
	for b in $BINS; do
		[ -x "$rel/$b" ] || { echo "build-release.sh: missing binary $rel/$b" >&2; exit 1; }
	done
	glibc="$(glibc_floor "$rel/kenneld")"

	echo "==> [$triple] staging $name (glibc floor ${glibc:-unknown})" >&2
	stage="$(mktemp -d)"
	dest="$stage/$name"
	install -d "$dest/src/tools" "$dest/target/release" "$dest/dist" "$dest/keys"

	for b in $BINS; do install -m 0755 "$rel/$b" "$dest/target/release/$b"; done
	install -m 0755 "$ROOT/src/tools/install.sh" "$dest/src/tools/install.sh"
	cp -a "$ROOT/dist/config" "$ROOT/dist/systemd" "$ROOT/dist/apparmor" "$dest/dist/"
	for p in "$ROOT"/keys/*.pub; do install -m 0644 "$p" "$dest/keys/$(basename "$p")"; done
	for d in "$ROOT"/templates/*/; do
		[ -f "${d}policy.toml" ] || continue
		n="$(basename "$d")"
		install -D -m 0644 "${d}policy.toml" "$dest/templates/$n/policy.toml"
	done

	cat > "$dest/install.sh" <<'WRAP'
#!/usr/bin/env bash
# Install Project Kennel from this prebuilt release. Forwards to the real
# installer with --no-build (the binaries are already built and shipped).
exec "$(cd "$(dirname "$0")" && pwd)/src/tools/install.sh" --no-build "$@"
WRAP
	chmod 0755 "$dest/install.sh"

	( cd "$dest/target/release" && sha256sum $BINS > "$dest/SHA256SUMS" )

	cat > "$dest/RELEASE.md" <<EOF
# Project Kennel ${VERSION} — release ${SHA} (${arch}, linux-gnu)

Prebuilt, offline-installable. ${arch} Linux, dynamically linked; built against
glibc ${glibc:-unknown}, so the target host needs a glibc at least that new.

## Install
    sudo ./install.sh

Installs the binaries under /usr/libexec/kennel (the privhelper setuid-root), the
vendor config under /usr/lib/kennel, the per-user systemd units, the AppArmor userns
grant, the maintainer trust-store key, and the signed reference templates under
/etc/kennel/templates. Relocate with --prefix DIR; preview with --dry-run.

## Admin steps (root), then per-user enable
1. Provision /etc/kennel/subkennel — one line per user:
       <uid>:<tag>:<gid>:<namespace>      e.g.  1000:42:0000000001:kennel-alice
2. Add any org policy-signing keys to /etc/kennel/keys/<key_id>.pub.
3. Each user: systemctl --user enable --now kenneld.socket

## Verify
    sha256sum -c SHA256SUMS                       # the shipped binaries
    ls -l /usr/libexec/kennel/kennel-privhelper   # expect -rwsr-xr-x root root

Contents: target/release/ (9 binaries), dist/ (config, systemd, apparmor),
keys/*.pub, templates/<name>/policy.toml, src/tools/install.sh, install.sh.
EOF

	tar="$OUT/$name.tar.xz"
	# Deterministic: sorted entries, zeroed owners, source-derived mtime; xz
	# single-threaded so block boundaries do not depend on the CPU count.
	tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@${EPOCH}" \
		-C "$stage" -cf - "$name" | xz -9e > "$tar"
	( cd "$OUT" && sha256sum "$(basename "$tar")" > "$(basename "$tar").sha256" )
	rm -rf "$stage"
	echo "==> [$triple] → $tar" >&2
}

install -d "$OUT"
for t in "${ARCHES[@]}"; do build_arch "$t"; done

echo >&2
echo "bing! release artefacts in $OUT:" >&2
sha256sum "$OUT"/kennel-"${VERSION}"-"${SHA}"-*.tar.xz
