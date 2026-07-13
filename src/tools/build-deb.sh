#!/usr/bin/env bash
#
# Project Kennel — build a .deb from an unpacked release payload.
#
# The package is a DERIVED artefact with no hand-maintained packaging manifest:
#   * the file list IS the release payload (the same staged tree install.sh places,
#     mapped to its documented destinations — stage-tree.sh is the one source of layout);
#   * DEBIAN/control's Depends/Recommends/Suggests are generated from
#     dist/dependencies.toml (hard+install → Depends, feature → Recommends,
#     provider → Suggests);
#   * the postinst embeds install-lib.sh verbatim — the SAME ceremony the tarball
#     install runs (setcap, binder modload, host-key mint + reference-policy compile).
#
# dpkg natively supplies what install.sh hand-builds for the tarball path: retired-file
# removal on upgrade (the W7 sweep) and seed-if-absent /etc discipline (conffiles).
#
# Usage: build-deb.sh <unpacked-payload-dir> [--out DIR]
#   The payload dir is an unpacked release tarball (or stage-tree.sh output); version
#   and architecture are read from its kennel binary and directory name.

set -euo pipefail

payload=""
outdir="."
while [[ $# -gt 0 ]]; do
	case "$1" in
		--out) outdir="${2:?--out needs a directory}"; shift 2 ;;
		-*) echo "build-deb.sh: unknown argument: $1" >&2; exit 2 ;;
		*) payload="$1"; shift ;;
	esac
done
[[ -n "$payload" && -d "$payload" ]] || { echo "build-deb.sh: payload dir required" >&2; exit 2; }
payload="$(cd "$payload" && pwd)"
[[ -f "$payload/install-lib.sh" ]] || { echo "build-deb.sh: $payload has no install-lib.sh — not a 0.7.0+ payload" >&2; exit 2; }
[[ -f "$payload/dist/dependencies.toml" ]] || { echo "build-deb.sh: $payload/dist/dependencies.toml missing" >&2; exit 2; }

# Version + arch from the payload directory name (kennel-<ver>-<commit>-<triple>),
# the same identity the tarball carries.
base="$(basename "$payload")"
version="$(sed -nE 's/^kennel-([0-9]+\.[0-9]+\.[0-9]+)-([a-f0-9]+)-.*/\1/p' <<<"$base")"
commit="$(sed -nE 's/^kennel-[0-9.]+-([a-f0-9]+)-.*/\1/p' <<<"$base")"
case "$base" in
	*x86_64*)  deb_arch=amd64 ;;
	*aarch64*) deb_arch=arm64 ;;
	*) echo "build-deb.sh: cannot map architecture from '$base'" >&2; exit 2 ;;
esac
[[ -n "$version" ]] || { echo "build-deb.sh: cannot read a version from '$base'" >&2; exit 2; }
deb_version="$version"

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT
pkg="$root/pkg"

place() { # place <mode> <src> <dest-under-pkg>
	install -D -m "$1" "$2" "$pkg$3"
}

# ── the file payload, mapped exactly as install.sh maps it ──────────────────────────
for f in "$payload"/bin/*;     do [[ -f "$f" ]] && place 0755 "$f" "/usr/libexec/kennel/$(basename "$f")"; done
for f in "$payload"/facades/*; do [[ -f "$f" ]] && place 0755 "$f" "/usr/libexec/kennel-facades/$(basename "$f")"; done
for f in "$payload"/pathbin/*; do [[ -f "$f" ]] && place 0755 "$f" "/usr/bin/$(basename "$f")"; done
for f in "$payload"/keys/*.pub; do [[ -f "$f" ]] && place 0644 "$f" "/usr/lib/kennel/keys/$(basename "$f")"; done
for d in "$payload"/templates/*/; do
	[[ -d "$d" ]] || continue
	n="$(basename "$d")"
	for f in "$d"*; do [[ -f "$f" ]] && place 0644 "$f" "/usr/lib/kennel/templates/$n/$(basename "$f")"; done
done
for d in "$payload"/fragments/*/; do
	[[ -f "${d}policy.toml" ]] || continue
	place 0644 "${d}policy.toml" "/usr/lib/kennel/templates/$(basename "$d")/policy.toml"
done
for d in "$payload"/policies/*/ "$payload"/policies/providers/*/; do
	[[ -f "${d}policy.toml" ]] || continue
	rel="${d#"$payload"/policies/}"
	place 0644 "${d}policy.toml" "/usr/lib/kennel/policies/${rel}policy.toml"
done
place 0644 "$payload/dist/threats/catalogue.toml" /usr/lib/kennel/threats/catalogue.toml
place 0644 "$payload/dist/vendor/triggers.catalog" /usr/lib/kennel/triggers.catalog
place 0644 "$payload/dist/vendor/etc-binds.catalog" /usr/lib/kennel/etc-binds.catalog
place 0644 "$payload/dist/dependencies.toml" /usr/lib/kennel/dependencies.toml
place 0644 "$payload/dist/systemd/kenneld.socket" /usr/lib/systemd/user/kenneld.socket
place 0644 "$payload/dist/systemd/kenneld.service" /usr/lib/systemd/user/kenneld.service
# Binder module on every boot — a package file (vendor tier), not a postinst write.
install -d "$pkg/usr/lib/modules-load.d"
echo binder_linux > "$pkg/usr/lib/modules-load.d/kennel.conf"
chmod 0644 "$pkg/usr/lib/modules-load.d/kennel.conf"
# Man pages, gzip -9n per Debian policy.
for page in "$payload"/man/*.[1-9]; do
	[[ -e "$page" ]] || continue
	sect="${page##*.}"
	install -d "$pkg/usr/share/man/man$sect"
	gzip -9n -c "$page" > "$pkg/usr/share/man/man$sect/$(basename "$page").gz"
	chmod 0644 "$pkg/usr/share/man/man$sect/$(basename "$page").gz"
done
# Host-config seeds + AppArmor profile: conffiles (dpkg's seed-if-absent / never-clobber).
place 0644 "$payload/dist/config/system.toml"    /etc/kennel/system.toml
place 0644 "$payload/dist/config/config.toml"    /etc/kennel/config.toml
place 0644 "$payload/dist/kennel-sshd.conf"      /etc/kennel/kennel-sshd.conf
place 0644 "$payload/dist/apparmor/kenneld"      /etc/apparmor.d/kenneld
if [[ -d "$payload/dist/config/gui" ]]; then
	while IFS= read -r -d '' f; do
		place 0644 "$f" "/etc/kennel/config/${f#"$payload"/dist/config/gui/}"
	done < <(find "$payload/dist/config/gui" -type f -print0)
fi
# The admin-tier skeleton dirs install.sh creates (empty dirs ship fine in a deb).
install -d "$pkg/etc/kennel/keys" "$pkg/etc/kennel/templates" "$pkg/etc/kennel/policies"

# ── DEBIAN/ metadata, generated ──────────────────────────────────────────────────────
install -d "$pkg/DEBIAN"

# Depends/Recommends/Suggests from the dependency manifest (debian package names;
# empty = essential, no line). hard+install → Depends; feature → Recommends;
# provider → Suggests.
mapfile -t dep_rows < <(awk '
	function flush() { if (bin != "") printf "%s\t%s\t%s\n", bin, tier, pkg; bin=""; tier=""; pkg="" }
	/^\[\[dep\]\]/    { flush() }
	/^\[\[kernel\]\]/ { flush(); skip = 1; next }
	skip              { next }
	/^bin = /    { gsub(/"/, "", $3); bin = $3 }
	/^tier = /   { gsub(/"/, "", $3); tier = $3 }
	/^debian = / { gsub(/"/, "", $3); pkg = $3 }
	END { flush() }' "$payload/dist/dependencies.toml")
depends="libc6" recommends="" suggests=""
for row in "${dep_rows[@]}"; do
	IFS=$'\t' read -r _bin tier pkgname <<<"$row"
	[[ -n "$pkgname" ]] || continue
	case "$tier" in
		hard|install) [[ ", $depends,"    == *", $pkgname,"* ]] || depends="$depends, $pkgname" ;;
		feature)      [[ ", $recommends," == *", $pkgname,"* ]] || recommends="${recommends:+$recommends, }$pkgname" ;;
		provider)     [[ ", $suggests,"   == *", $pkgname,"* ]] || suggests="${suggests:+$suggests, }$pkgname" ;;
	esac
done

installed_size="$(du -sk --exclude=DEBIAN "$pkg" | cut -f1)"
{
	echo "Package: kennel"
	echo "Version: $deb_version"
	echo "Architecture: $deb_arch"
	echo "Maintainer: Project Kennel <maintainers@projectkennel.org>"
	echo "Section: admin"
	echo "Priority: optional"
	echo "Installed-Size: $installed_size"
	echo "Depends: $depends"
	[[ -n "$recommends" ]] && echo "Recommends: $recommends"
	[[ -n "$suggests" ]] && echo "Suggests: $suggests"
	echo "Homepage: https://github.com/projectkennel/projectkennel"
	echo "Description: policy-confined workload runner (reference monitor)"
	echo " Kennel runs workloads in least-privilege cages defined by signed,"
	echo " human-readable policies: filesystem views, seccomp/Landlock floors,"
	echo " brokered network egress, D-Bus and Wayland mediation, and a"
	echo " capability mesh between cages. Build $commit."
} > "$pkg/DEBIAN/control"

# conffiles: every file the package ships under /etc.
( cd "$pkg" && find etc -type f | sed 's|^|/|' | sort ) > "$pkg/DEBIAN/conffiles"

# postinst: the shared ceremony lib verbatim, then the package's ceremony calls.
{
	echo '#!/bin/bash'
	echo '# Generated by build-deb.sh — the ceremony body is install-lib.sh, verbatim.'
	echo 'set -euo pipefail'
	echo '[ "$1" = configure ] || exit 0'
	cat "$payload/install-lib.sh"
	cat <<'CEREMONY'
kn_setcap_privhelpers /usr/libexec/kennel
kn_binder_modload
if command -v apparmor_parser >/dev/null 2>&1; then
	apparmor_parser -r -W /etc/apparmor.d/kenneld || true
fi
kn_compile_reference_policies /usr/lib/kennel /usr/bin/kennel
echo "kennel: post-install checks:"
kn_post_checks /usr/libexec/kennel
echo "kennel: per-user bring-up: systemctl --user enable --now kenneld.socket"
echo "        then: man kennel"
CEREMONY
} > "$pkg/DEBIAN/postinst"
chmod 0755 "$pkg/DEBIAN/postinst"

# postrm: on purge, remove what the postinst GENERATED (never the admin's own content):
# the host signing key, the host-compiled settled artefacts, the ondemand links that
# point at them, and the modules-load entry the tarball path may have written to /etc.
cat > "$pkg/DEBIAN/postrm" <<'POSTRM'
#!/bin/bash
set -euo pipefail
[ "$1" = purge ] || exit 0
rm -f /etc/kennel/keys/kennel-host /etc/kennel/keys/kennel-host.pub
find /etc/kennel/policies -name '*.settled.toml' -delete 2>/dev/null || true
find /etc/kennel/policies -type d -empty -delete 2>/dev/null || true
for link in /etc/kennel/ondemand/dbus-broker /etc/kennel/ondemand/tun-broker /etc/kennel/ondemand/gui-broker; do
	[ -L "$link" ] && rm -f "$link"
done
rmdir /etc/kennel/ondemand /etc/kennel/keys /etc/kennel/templates /etc/kennel/policies /etc/kennel 2>/dev/null || true
rm -f /etc/modules-load.d/kennel.conf
exit 0
POSTRM
chmod 0755 "$pkg/DEBIAN/postrm"

out="$outdir/kennel_${deb_version}_${deb_arch}.deb"
dpkg-deb --build --root-owner-group "$pkg" "$out" >/dev/null
echo "build-deb.sh: built $out"
dpkg-deb --info "$out" | sed -n '2,14p'
