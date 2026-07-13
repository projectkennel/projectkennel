#!/usr/bin/env bash
#
# Project Kennel — build an .rpm from an unpacked release payload.
#
# The Fedora-family mirror of build-deb.sh, derived from the same two sources:
#   * the file list IS the release payload (stage-tree.sh is the one source of layout);
#   * Requires/Recommends/Suggests are generated from dist/dependencies.toml
#     (hard+install → Requires, feature → Recommends, provider → Suggests);
#   * %post embeds install-lib.sh verbatim — the SAME ceremony as the tarball install
#     and the .deb postinst.
#
# Fedora-family divergences, named (dist/dependencies.toml carries both):
#   * binder: Fedora kernels do not enable CONFIG_ANDROID_BINDERFS, and kennel does not
#     function without it (the kenneld<->kennel control plane). The module comes from
#     the community binder kmod/COPR route (maintainer ruling: not vendored here), so
#     there is NO package-level Requires to encode — the post-install check and the
#     package description carry the requirement (Secure Boot: MOK enrollment).
#   * AppArmor: Fedora is SELinux; the AppArmor defense-in-depth layer does not load
#     there. The profile is not shipped in the rpm; a named gap, not a refusal.
#
# rpm natively supplies the same halves dpkg does: upgrade removal of retired files
# (the W7 sweep) and %config(noreplace) (seed-if-absent /etc).
#
# Usage: build-rpm.sh <unpacked-payload-dir> [--out DIR]

set -euo pipefail

payload=""
outdir="."
while [[ $# -gt 0 ]]; do
	case "$1" in
		--out) outdir="${2:?--out needs a directory}"; shift 2 ;;
		-*) echo "build-rpm.sh: unknown argument: $1" >&2; exit 2 ;;
		*) payload="$1"; shift ;;
	esac
done
[[ -n "$payload" && -d "$payload" ]] || { echo "build-rpm.sh: payload dir required" >&2; exit 2; }
payload="$(cd "$payload" && pwd)"
[[ -f "$payload/install-lib.sh" ]] || { echo "build-rpm.sh: $payload has no install-lib.sh — not a 0.7.0+ payload" >&2; exit 2; }
[[ -f "$payload/dist/dependencies.toml" ]] || { echo "build-rpm.sh: $payload/dist/dependencies.toml missing" >&2; exit 2; }

base="$(basename "$payload")"
version="$(sed -nE 's/^kennel-([0-9]+\.[0-9]+\.[0-9]+)-([a-f0-9]+)-.*/\1/p' <<<"$base")"
commit="$(sed -nE 's/^kennel-[0-9.]+-([a-f0-9]+)-.*/\1/p' <<<"$base")"
case "$base" in
	*x86_64*)  rpm_arch=x86_64 ;;
	*aarch64*) rpm_arch=aarch64 ;;
	*) echo "build-rpm.sh: cannot map architecture from '$base'" >&2; exit 2 ;;
esac
[[ -n "$version" ]] || { echo "build-rpm.sh: cannot read a version from '$base'" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
buildroot="$work/buildroot"

place() { # place <mode> <src> <dest-under-buildroot>
	local mode="$1" src="$2" dest="$3"
	install -D -m "$mode" "$src" "$buildroot$dest"
}

# ── the file payload, mapped exactly as install.sh / build-deb.sh map it ────────────
# (No AppArmor profile: Fedora is SELinux — the named gap above.)
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
install -d "$buildroot/usr/lib/modules-load.d"
echo binder_linux > "$buildroot/usr/lib/modules-load.d/kennel.conf"
chmod 0644 "$buildroot/usr/lib/modules-load.d/kennel.conf"
for page in "$payload"/man/*.[1-9]; do
	[[ -e "$page" ]] || continue
	sect="${page##*.}"
	install -d "$buildroot/usr/share/man/man$sect"
	gzip -9n -c "$page" > "$buildroot/usr/share/man/man$sect/$(basename "$page").gz"
	chmod 0644 "$buildroot/usr/share/man/man$sect/$(basename "$page").gz"
done
place 0644 "$payload/dist/config/system.toml"    /etc/kennel/system.toml
place 0644 "$payload/dist/config/config.toml"    /etc/kennel/config.toml
place 0644 "$payload/dist/kennel-sshd.conf"      /etc/kennel/kennel-sshd.conf
if [[ -d "$payload/dist/config/gui" ]]; then
	while IFS= read -r -d '' f; do
		place 0644 "$f" "/etc/kennel/config/${f#"$payload"/dist/config/gui/}"
	done < <(find "$payload/dist/config/gui" -type f -print0)
fi
install -d "$buildroot/etc/kennel/keys" "$buildroot/etc/kennel/templates" "$buildroot/etc/kennel/policies"

# ── dependency fields from the manifest (fedora package names) ──────────────────────
mapfile -t dep_rows < <(awk '
	function flush() { if (bin != "") printf "%s\t%s\t%s\n", bin, tier, pkg; bin=""; tier=""; pkg="" }
	/^\[\[dep\]\]/    { flush() }
	/^\[\[kernel\]\]/ { flush(); skip = 1; next }
	skip              { next }
	/^bin = /    { gsub(/"/, "", $3); bin = $3 }
	/^tier = /   { gsub(/"/, "", $3); tier = $3 }
	/^fedora = / { gsub(/"/, "", $3); pkg = $3 }
	END { flush() }' "$payload/dist/dependencies.toml")
requires=()
recommends=()
suggests=()
for row in "${dep_rows[@]}"; do
	IFS=$'\t' read -r _bin tier pkgname <<<"$row"
	[[ -n "$pkgname" ]] || continue
	case "$tier" in
		hard|install) requires+=("$pkgname") ;;
		feature)      recommends+=("$pkgname") ;;
		provider)     suggests+=("$pkgname") ;;
		*) ;; # build-tier deps never reach a runtime package field
	esac
done
# Binder is a hard kernel requirement Fedora kernels do not satisfy (see the manifest's
# [[kernel]] entry) — supplied by the community binder kmod route, which has no stable
# package name to Requires; kn_post_checks and %description carry it instead.

# ── the spec, generated ──────────────────────────────────────────────────────────────
spec="$work/kennel.spec"
{
	echo "Name: kennel"
	echo "Version: $version"
	echo "Release: 1%{?dist}"
	echo "Summary: Policy-confined workload runner (reference monitor)"
	echo "License: Apache-2.0"
	echo "URL: https://github.com/projectkennel/projectkennel"
	echo "ExclusiveArch: $rpm_arch"
	printf 'Requires: %s\n' "${requires[@]}" | sort -u
	[[ ${#recommends[@]} -gt 0 ]] && printf 'Recommends: %s\n' "${recommends[@]}" | sort -u
	[[ ${#suggests[@]} -gt 0 ]] && printf 'Suggests: %s\n' "${suggests[@]}" | sort -u
	cat <<DESC
%description
Kennel runs workloads in least-privilege cages defined by signed,
human-readable policies: filesystem views, seccomp/Landlock floors,
brokered network egress, D-Bus and Wayland mediation, and a capability
mesh between cages. Build $commit.

Fedora notes: the binder kernel module is REQUIRED and Fedora kernels do
not build it — install a community binder kmod (the waydroid-ecosystem
binder_linux kmod/akmod COPRs; Secure Boot needs the MOK enrolled). The
AppArmor defense-in-depth layer does not apply on SELinux systems.

%install
cp -a %{getenv:KENNEL_BUILDROOT}/. %{buildroot}/

%post -p /bin/bash
DESC
	cat "$payload/install-lib.sh"
	cat <<'CEREMONY'
kn_setcap_privhelpers /usr/libexec/kennel
kn_binder_modload
kn_compile_reference_policies /usr/lib/kennel /usr/bin/kennel
echo "kennel: post-install checks:"
kn_post_checks /usr/libexec/kennel
echo "kennel: per-user bring-up: systemctl --user enable --now kenneld.socket"
echo "        then: man kennel"

%postun
# On erase (not upgrade), remove what %post GENERATED — never the admin's own content.
if [ "$1" -eq 0 ]; then
	rm -f /etc/kennel/keys/kennel-host /etc/kennel/keys/kennel-host.pub
	find /etc/kennel/policies -name '*.settled.toml' -delete 2>/dev/null || true
	find /etc/kennel/policies -type d -empty -delete 2>/dev/null || true
	for link in /etc/kennel/ondemand/dbus-broker /etc/kennel/ondemand/tun-broker /etc/kennel/ondemand/gui-broker; do
		[ -L "$link" ] && rm -f "$link"
	done
	rmdir /etc/kennel/ondemand /etc/kennel/keys /etc/kennel/templates /etc/kennel/policies /etc/kennel 2>/dev/null || true
	rm -f /etc/modules-load.d/kennel.conf
fi
exit 0

%files
CEREMONY
	# Every payload file, with the /etc tree as noreplace conffiles and the empty
	# admin-tier skeleton dirs owned by the package.
	( cd "$buildroot" && find . -type f ! -path './etc/*' | sed 's|^\.||' )
	( cd "$buildroot" && find etc -type f | sed 's|^|%config(noreplace) /|' )
	printf '%%dir /etc/kennel/keys\n%%dir /etc/kennel/templates\n%%dir /etc/kennel/policies\n'
} > "$spec"

KENNEL_BUILDROOT="$buildroot" rpmbuild -bb \
	--define "_topdir $work/rpm" \
	--define "_rpmdir $work/out" \
	--target "$rpm_arch" \
	"$spec" >/dev/null 2>"$work/rpmbuild.err" || { cat "$work/rpmbuild.err" >&2; exit 1; }

built="$(find "$work/out" -name '*.rpm' | head -1)"
[[ -n "$built" ]] || { echo "build-rpm.sh: rpmbuild produced nothing" >&2; exit 1; }
out="$outdir/$(basename "$built")"
cp "$built" "$out"
echo "build-rpm.sh: built $out"
rpm -qp --info "$out" 2>/dev/null | sed -n '1,10p'
