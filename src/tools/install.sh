#!/usr/bin/env bash
# Project Kennel installer.
#
# Installs the runtime binaries, the capability-gated privhelper, the vendor config, the
# per-user systemd units, the AppArmor userns grant, the /etc/kennel skeleton,
# the maintainer trust-store key, and the signed reference templates. Two halves:
#
#   1. System install (root): all binaries under <libexec> (default
#      /usr/libexec/kennel, the documented non-PATH helper location),
#      the privhelper factory file-capped (cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin)
#      with its capability-split sub-helpers, the vendor INVARIANTS under /usr/lib/kennel (the
#      maintainer trust-anchor key + signed templates/fragments — the `org.projectkennel.*`
#      namespace authority — the reference-policy sources, and the canonical catalogues), the
#      systemd *user* units, the AppArmor profile, and the root-owned /etc/kennel HOST tree
#      (trust store, this host's compiled policies, provider enablement, GUI configs, and the
#      seeded host config defaults system.toml/config.toml/kennel-sshd.conf). Run with sudo.
#   2. Per-user enable (each user, unprivileged): `systemctl --user enable --now
#      kenneld.socket`. No per-user allocation is needed — a kennel's reserved
#      loopback subnet is derived from the caller's kernel-trusted uid. The
#      installer prints the exact command.
#
# The tier IS the reserved-namespace authority (§7.13.5): a template may claim `org.projectkennel.*`
# only from the vendor tier (/usr/lib/kennel, verified by the maintainer key there) and a host
# `[[reserved]]` family (e.g. `com.acme.*`) only from the host tier (/etc/kennel, verified by a host
# key there). So authority-bearing content lives in /usr/lib; host config lives in /etc.
#
# No install path is baked into a binary: kenneld reads the helper-binary locations and the trust
# store from /etc/kennel/system.toml — a seeded host-config default the admin owns (kennel-lib-config,
# falling back to the compiled defaults). A --prefix relocation sets libexec_dir in that file.
#
# The installer does NOT fabricate the security-sensitive admin inputs (the
# trust-store public keys); it creates the directory skeleton and tells the admin
# what to populate. Who may run kennels is not an allocation file: it is governed
# by execute permission on the privhelper under <libexec> — an admin restricts it
# by `chgrp`/`chmod` on that directory (see the admin notes below). See
# CODING-STANDARDS.md §5.
#
# Usage (from an unpacked release tarball):
#   sudo ./install.sh [--prefix DIR] [--mandir DIR] [--dry-run]
#
#   --prefix DIR          libexec dir for the binaries (default: /usr/libexec/kennel)
#   --mandir DIR          man-page root (default: /usr/share/man; pages go in manN/)
#   --dry-run             print the actions without performing them
#
# This script is reviewed like any other code (CODING-STANDARDS.md §15.4):
# POSIX-ish bash, `set -euo pipefail`, no network calls, idempotent.

set -euo pipefail

# The libexec dir holds the HOST-SIDE binaries only (daemon, privhelper, host delegates, the host
# execution unit). This whole tree is blacklisted from constructed views (W10), so nothing a view
# runs may live here. --prefix relocates it.
default_libexec="/usr/libexec/kennel"
libexec="$default_libexec"
# The in-cage facade dir (W10): the binaries a constructed view legitimately runs (the conduit
# facades, the spawn execution unit, the OCI launcher). A sibling of $libexec so the host tree can be
# blacklisted while these stay reachable.
facades_dir="/usr/libexec/kennel-facades"
# The one binary on PATH: the `kennel` shim, which dispatches to the host or in-cage execution unit.
pathbin_dir="/usr/bin"
# Vendor (package-shipped) config dir: the lowest-priority config layer.
vendor_dir="/usr/lib/kennel"
# Man-page root; pages install into $mandir/man{1,5,8}.
mandir="/usr/share/man"
dry_run=0

while [[ $# -gt 0 ]]; do
	case "$1" in
		--prefix) libexec="${2:?--prefix needs a directory}"; shift 2 ;;
		--mandir) mandir="${2:?--mandir needs a directory}"; shift 2 ;;
		--dry-run) dry_run=1; shift ;;
		-h|--help) sed -n '2,36p' "$0"; exit 0 ;;
		*) echo "install.sh: unknown argument: $1" >&2; exit 2 ;;
	esac
done

# This is a PURE installer: it places a prebuilt payload that sits beside it in an unpacked release
# tarball — a flat `bin/` of binaries plus the `dist/ keys/ templates/ fragments/ man/` it ships.
# It does not build (`src/tools/build-release.sh` produces the tarball) and must never run from the
# source tree. No `bin/` beside it → not a release tree, so refuse rather than half-install.
pkg_root="$(cd "$(dirname "$0")" && pwd)"
bindir="$pkg_root/bin"
if [[ ! -d "$bindir" ]]; then
	echo "install.sh: no bin/ beside this installer ($bindir)." >&2
	echo "            Run it from an unpacked release tarball; build one from a source" >&2
	echo "            checkout with src/tools/build-release.sh." >&2
	exit 2
fi

# The systemd user-unit directory (system-wide location for user units).
units_dir="/usr/lib/systemd/user"

# run CMD...: echo under --dry-run, else execute.
run() {
	if [[ "$dry_run" -eq 1 ]]; then
		printf 'DRY-RUN:'; printf ' %q' "$@"; printf '\n'
	else
		"$@"
	fi
}

# The shared install CEREMONY (setcap, binder modload, dependency pre-flight, the
# host-specific reference-policy compile) — one code path with the package maintainer
# scripts, which embed the same lib at package build.
# shellcheck source=install-lib.sh
. "$pkg_root/install-lib.sh"

require_root() {
	[[ "$dry_run" -eq 1 ]] && return 0
	if [[ "$(id -u)" -ne 0 ]]; then
		echo "install.sh: the system install needs root; re-run with sudo" >&2
		exit 1
	fi
}

# Verify the payload against its own manifest BEFORE placing anything. SHA256SUMS covers every
# shipped file — and ESPECIALLY the trust-store public key the daemon will trust forever after. The
# install is the moment that key enters the trust store; a tampered or truncated payload must abort
# here, not after a bad key or binary is already on disk. (stage-tree.sh always writes the manifest,
# so its absence means this is not a real payload.)
verify_payload() {
	local manifest="$pkg_root/SHA256SUMS"
	if [[ ! -f "$manifest" ]]; then
		echo "install.sh: no SHA256SUMS beside the installer — refusing to install an unverifiable payload" >&2
		exit 2
	fi
	echo "install.sh: verifying the payload against SHA256SUMS ($(grep -c . "$manifest") files, incl. the trust key)"
	if ! ( cd "$pkg_root" && sha256sum -c --quiet SHA256SUMS ); then
		echo "install.sh: payload integrity check FAILED — not installing" >&2
		exit 1
	fi
}

install_binaries() {
	run install -d -m 0755 "$libexec" "$facades_dir" "$pathbin_dir"
	# W10's three-dir layout — the payload encodes each binary's destination in its staging subdir
	# (stage-tree.sh): `bin/` is host-side (→ $libexec, blacklisted from views), `facades/` is the
	# in-cage set (→ $facades_dir, reachable in a view), `pathbin/` is the `kennel` shim (→ $pathbin_dir,
	# the one name on PATH). Place each group, then tighten the two trust-sensitive host binaries.
	local f
	for f in "$bindir"/*;          do [ -f "$f" ] && run install -m 0755 "$f" "$libexec/$(basename "$f")"; done
	for f in "$pkg_root/facades"/*; do [ -f "$f" ] && run install -m 0755 "$f" "$facades_dir/$(basename "$f")"; done
	for f in "$pkg_root/pathbin"/*; do [ -f "$f" ] && run install -m 0755 "$f" "$pathbin_dir/$(basename "$f")"; done
	# The four privilege-bearing helpers are placed root-owned here; the capability
	# ceremony itself (file caps per helper, setuid fallback) is the shared lib's
	# (kn_setcap_privhelpers) — one code path with the package postinst, which cannot
	# ship xattrs in the data archive. Rationale per helper lives with the ceremony.
	run install -m 0755 -o root -g root "$bindir/kennel-privhelper" "$libexec/kennel-privhelper"
	run install -m 0755 -o root -g root "$bindir/kennel-privhelper-net" "$libexec/kennel-privhelper-net"
	run install -m 0755 -o root -g root "$bindir/kennel-privhelper-bpf" "$libexec/kennel-privhelper-bpf"
	run install -m 0755 -o root -g root "$bindir/kennel-privhelper-mounts" "$libexec/kennel-privhelper-mounts"
	kn_setcap_privhelpers "$libexec"
	# The trusted init: the privhelper factory fexecves this as the kennel's uid-0
	# PID 1, so it is a trust anchor — install it root-owned and not group/other
	# writable (verify_trusted_init refuses any other owner or a 0o022 bit). It is
	# NOT setuid: it gains uid 0 only inside the kennel's user namespace.
	run install -m 0755 -o root -g root "$bindir/kennel-bin-init" "$libexec/kennel-bin-init"
	# Binder module: now + every boot (kennel does not function without it).
	kn_binder_modload
}

install_config() {
	# The VENDOR tree (/usr/lib/kennel) holds vendor INVARIANTS only — the content that carries
	# reserved-namespace authority and the security baseline, which an admin does NOT reconfigure:
	# the maintainer trust-anchor key + the maintainer-signed templates/fragments here are the sole
	# authority for the built-in `org.projectkennel.*` namespace (a template may claim it only from
	# THIS tier; §7.13.5, tier-gated at compile — the host tier `/etc/kennel` is the authority for a
	# host-declared `[[reserved]]` family like `com.acme.*`). The reference-policy SOURCES and the
	# vendor-canonical threat/trigger/etc-binds catalogues (admin-extensible in /etc) live here too.
	# HOST CONFIGURATION does NOT: system.toml/config.toml/kennel-sshd.conf are seeded as defaults
	# under /etc/kennel (install_etc_skeleton), like any /etc config an admin owns.
	run install -d -m 0755 "$vendor_dir"
	# Vendor cascade layers for keys/templates/policies so the lowest-priority
	# search dir always exists (kennel-lib-config 3-layer cascade). This is the
	# MAINTAINER tree: ALL maintainer-signed content — templates, composable fragments, the
	# reference policy SOURCES (runnable + service providers) and the trust-store public key(s) —
	# ships here, never to /etc/kennel (which is the admin tier). install_reference_policies then
	# compiles the sources to settled artefacts on THIS host (the arch-specific loader pin forbids
	# shipping a settled policy) and places those under /etc/kennel.
	run install -d -m 0755 "$vendor_dir/keys" "$vendor_dir/templates" \
		"$vendor_dir/policies" "$vendor_dir/policies/providers"
	# Ship the reference templates (base-confined — the security foundation policies inherit — and
	# the spawn targets agents instantiate) into the vendor template cascade, so the daemon and the
	# CLI resolve them at the standard path, never the source tree. Source `policy.toml`
	# + meta; a spawn target's signed `<name>.settled.toml` is produced by `kennel policy compile`
	# (the maintainer signs the reference set; the operator their own).
	if [[ -d "$pkg_root/templates" ]]; then
		for tdir in "$pkg_root"/templates/*/; do
			[[ -d "$tdir" ]] || continue
			tname="$(basename "$tdir")"
			run install -d -m 0755 "$vendor_dir/templates/$tname"
			for f in "$tdir"*; do
				[[ -f "$f" ]] || continue
				run install -m 0644 "$f" "$vendor_dir/templates/$tname/$(basename "$f")"
			done
		done
	fi
	# The composable fragments share the template search dir (a leaf's `include = ["gui-desktop",
	# …]` resolves them from template_dirs); ship them alongside the templates in the maintainer tree.
	if [[ -d "$pkg_root/fragments" ]]; then
		for fdir in "$pkg_root"/fragments/*/; do
			[[ -f "${fdir}policy.toml" ]] || continue
			fname="$(basename "$fdir")"
			run install -d -m 0755 "$vendor_dir/templates/$fname"
			run install -m 0644 "${fdir}policy.toml" "$vendor_dir/templates/$fname/policy.toml"
		done
	fi
	# The reference policy SOURCES — runnable leaves (policies/<name>) and service providers
	# (policies/providers/<name>) — maintainer-signed, into the vendor policies tree. They are
	# compiled to settled, host-signed artefacts at install (install_reference_policies).
	if [[ -d "$pkg_root/policies" ]]; then
		for pdir in "$pkg_root"/policies/*/; do
			[[ -f "${pdir}policy.toml" ]] || continue
			pname="$(basename "$pdir")"
			run install -d -m 0755 "$vendor_dir/policies/$pname"
			run install -m 0644 "${pdir}policy.toml" "$vendor_dir/policies/$pname/policy.toml"
		done
		for pdir in "$pkg_root"/policies/providers/*/; do
			[[ -f "${pdir}policy.toml" ]] || continue
			pname="$(basename "$pdir")"
			run install -d -m 0755 "$vendor_dir/policies/providers/$pname"
			run install -m 0644 "${pdir}policy.toml" "$vendor_dir/policies/providers/$pname/policy.toml"
		done
	fi
	# (system.toml / config.toml / kennel-sshd.conf are HOST config → seeded under /etc/kennel by
	# install_etc_skeleton, not shipped here. Only vendor invariants + canonical catalogues below.)
	# The machine-readable threat catalogue `kennel policy risks` reads (the CLI
	# falls back to its embedded copy if absent; this lets an org ship an extended one).
	run install -d -m 0755 "$vendor_dir/threats"
	run install -m 0644 "$pkg_root/dist/threats/catalogue.toml" "$vendor_dir/threats/catalogue.toml"
	# The vendor-default catalogues: the trust-trigger set the CLI pins/watches
	# (T2.8) and the essential /etc subtrees the daemon binds read-only into every view.
	# Both are additive cascades; /etc/kennel overrides this vendor layer.
	run install -m 0644 "$pkg_root/dist/vendor/triggers.catalog" "$vendor_dir/triggers.catalog"
	run install -m 0644 "$pkg_root/dist/vendor/etc-binds.catalog" "$vendor_dir/etc-binds.catalog"
	# Upgrade cleanup: config files lived in the vendor tree before 0.6.0. The daemon now reads them
	# from /etc only (a lingering vendor copy is ignored), but remove the stale package copies so the
	# vendor tree holds invariants exclusively.
	local stale
	for stale in system.toml config.toml kennel-sshd.conf; do
		[[ -f "$vendor_dir/$stale" ]] && run rm -f "$vendor_dir/$stale"
	done
	return 0
}

install_units() {
	# The packaged units install VERBATIM under /usr/lib/systemd/user (vendor, immutable).
	# A --prefix relocation is a HOST fact, so it lands in a drop-in under /etc/systemd/user —
	# never a sed of the packaged unit. The empty ExecStart= resets the vendor value before the
	# override (systemd requires the reset to replace a single-valued directive).
	run install -d -m 0755 "$units_dir"
	run install -m 0644 "$pkg_root/dist/systemd/kenneld.socket" "$units_dir/kenneld.socket"
	run install -m 0644 "$pkg_root/dist/systemd/kenneld.service" "$units_dir/kenneld.service"
	if [[ "$libexec" != "$default_libexec" ]]; then
		local dropin_dir="/etc/systemd/user/kenneld.service.d"
		run install -d -m 0755 "$dropin_dir"
		if [[ "$dry_run" -eq 1 ]]; then
			echo "DRY-RUN: write $dropin_dir/kennel-prefix.conf (ExecStart=$libexec/kenneld)"
		else
			printf '[Service]\nExecStart=\nExecStart=%s/kenneld\n' "$libexec" > "$dropin_dir/kennel-prefix.conf"
		fi
	fi
}

# Install the committed man pages (man/<name>.<section>) into $mandir/man<section>.
# The pages are generated by `gen-man` and committed; see man/README.md.
install_man() {
	local man_src="$pkg_root/man" page sect dest
	if [[ ! -d "$man_src" ]]; then
		echo "install.sh: no man/ directory; skipping man pages" >&2
		return 0
	fi
	for page in "$man_src"/*.[1-9]; do
		[[ -e "$page" ]] || continue          # nullglob-safe: skip if none matched
		sect="${page##*.}"                  # the trailing digit = man section
		dest="$mandir/man$sect"
		run install -d -m 0755 "$dest"
		run install -m 0644 "$page" "$dest/$(basename "$page")"
	done
}

install_apparmor() {
	# Grant kenneld the unprivileged-userns capability on hosts that restrict it
	# (Ubuntu 23.10+: kernel.apparmor_restrict_unprivileged_userns=1). The profile
	# attaches to the kenneld binary by absolute path, so it must match libexec.
	[[ -d /etc/apparmor.d ]] || { echo "install.sh: no /etc/apparmor.d; skipping AppArmor profile"; return 0; }
	run install -m 0644 "$pkg_root/dist/apparmor/kenneld" /etc/apparmor.d/kenneld
	if [[ "$libexec" != "$default_libexec" ]]; then
		run sed -i "s#/usr/libexec/kennel/kenneld#$libexec/kenneld#" /etc/apparmor.d/kenneld
	fi
	if command -v apparmor_parser >/dev/null 2>&1; then
		run apparmor_parser -r -W /etc/apparmor.d/kenneld
	else
		echo "install.sh: apparmor_parser absent; profile staged but not loaded"
	fi
}

# Seed a HOST config default into /etc/kennel, ONLY if absent — the standard /etc conffile
# discipline, so a reinstall never clobbers an admin's edits. Under --dry-run, just report.
seed_etc_config() {
	local rel="$1" dest="$2"
	local src="$pkg_root/$rel"
	if [[ "$dry_run" -eq 1 ]]; then
		echo "DRY-RUN: seed $dest from $rel (only if absent)"
	elif [[ ! -f "$dest" ]]; then
		install -m 0644 "$src" "$dest"
		echo "install.sh: seeded host config default $dest"
	else
		echo "install.sh: kept existing $dest (host config; not clobbered)"
	fi
}

install_etc_skeleton() {
	# Root-owned HOST configuration root — the admin/host tier. Holds this host's generated state
	# (trust store, host-compiled settled policies, provider enablement, GUI configs) AND the seeded
	# HOST config defaults (system.toml/config.toml/kennel-sshd.conf). `keys/` is the trust store:
	# the daemon's signing-key store (system.toml's trust_dir default) and the HOST-tier authority
	# for a host `[[reserved]]` family; `templates/` is the host-tier template dir (host-namespace
	# providers), not scratch. Admin-owned; org keys and host templates go here.
	run install -d -m 0755 /etc/kennel /etc/kennel/keys /etc/kennel/templates /etc/kennel/policies
	# Seed the host config defaults, install-if-ABSENT (the daemon/CLI read them from /etc via the
	# kennel-lib-config cascade, falling back to the compiled defaults; a missing file is fine).
	if [[ "$dry_run" -eq 1 ]] || [[ -d /etc/kennel ]]; then
		seed_etc_config dist/config/system.toml /etc/kennel/system.toml
		seed_etc_config dist/config/config.toml /etc/kennel/config.toml
		seed_etc_config dist/kennel-sshd.conf /etc/kennel/kennel-sshd.conf
	fi
	# A --prefix relocation is a HOST fact: set libexec_dir in the seeded /etc/kennel/system.toml
	# (merge in place — an admin may keep other keys there).
	if [[ "$libexec" != "$default_libexec" ]]; then
		local sys=/etc/kennel/system.toml
		if [[ "$dry_run" -eq 1 ]]; then
			echo "DRY-RUN: set libexec_dir = \"$libexec\" in $sys"
		elif grep -q '^libexec_dir *=' "$sys" 2>/dev/null; then
			sed -i "s#^libexec_dir *=.*#libexec_dir = \"$libexec\"#" "$sys"
		else
			printf 'libexec_dir = "%s"\n' "$libexec" >> "$sys"
		fi
	fi
}

install_keys() {
	# Ship the project's own public key(s) into the VENDOR trust dir
	# (/usr/lib/kennel/keys), so the signed reference templates verify out of the box.
	# The daemon searches the vendor dir first, and a key there is vendor-provenance —
	# the authority for the built-in org.projectkennel.* reserved namespace.
	# The maintainer key belongs here, not in the
	# admin /etc/kennel/keys (which holds org/customer keys an admin adds): an admin or
	# user key cannot claim the project's own namespace. Private seeds are never in the
	# repo (MAINTAINERS.md); only `*.pub` is shipped.
	if [[ -d "$pkg_root/keys" ]]; then
		for pub in "$pkg_root"/keys/*.pub; do
			[[ -e "$pub" ]] || continue
			run install -m 0644 "$pub" "$vendor_dir/keys/$(basename "$pub")"
		done
	fi
}

install_reference_policies() {
	# The reference policy SOURCES are maintainer-signed and ship to the vendor tree
	# (install_config); their SETTLED form is HOST-specific (the executable-closure loader
	# pin), so the shared lib compiles them here, host-signed, and enables the standing
	# brokers — one code path with the package postinst (kn_compile_reference_policies).
	if [[ "$dry_run" -eq 1 ]]; then
		echo "DRY-RUN: mint host key 'kennel-host' in /etc/kennel/keys (if absent), then compile each"
		echo "         vendor policies/* + policies/providers/* source into /etc/kennel/policies/<n>/"
		echo "         <n>.settled.toml and enable the standing brokers ondemand"
		return 0
	fi
	kn_compile_reference_policies "$vendor_dir" "$pathbin_dir/kennel"

	# Kennel-authored app configs, served into a kennel's view by a W15 `source` redirect
	# (`gui-session` overlays /etc/kennel/config/labwc at the view's /etc/xdg/labwc). Host-independent
	# and identical everywhere; a confined desktop never inherits the host's compositor assumptions.
	if [[ -d "$pkg_root/dist/config/gui" ]]; then
		install -d -m 0755 /etc/kennel/config
		cp -a "$pkg_root/dist/config/gui/." /etc/kennel/config/
		echo "install.sh: installed the confined-GUI default configs (/etc/kennel/config)"
	fi
}

# The signed reference templates and fragments are MAINTAINER content: they ship to the vendor
# tree ONLY (/usr/lib/kennel/templates, via install_config) — NEVER to /etc/kennel, which is the
# admin tier. The CLI/daemon template search cascade already includes the vendor dir
# (`<user-config>/templates` + `/etc/kennel/templates` + `/usr/lib/kennel/templates`,
# kennel-lib-config::default_search_dirs), so a leaf deriving `base-confined` or `include`-ing
# `lang-python` resolves out of the box from the vendor copy. `/etc/kennel/templates` is created
# empty by install_etc_skeleton for an admin's own org templates.

# ── The payload manifest (W7) ────────────────────────────────────────────────
# The staged tree IS the manifest: anything in a FULLY KENNEL-MANAGED directory that the
# incoming payload does not ship was placed by an earlier install and has since been
# retired — remove it, and say so (the host-dbus class: retired binaries lingering on
# upgraded hosts). /etc is NEVER swept (host config is the admin's); the vendor keys dir
# IS swept to payload-exact, because a stray .pub there would hold vendor-tier
# (org.projectkennel.*) authority. Under --dry-run the would-remove set prints via run().

# sweep_flat <managed-dir> <payload-src-dir>...: remove files in managed-dir whose
# basename no payload source dir ships.
sweep_flat() {
	local managed="$1"; shift
	[[ -d "$managed" ]] || return 0
	# A payload that ships NONE of the source dirs is declaring nothing about this
	# managed dir — do not sweep it (e.g. a payload without keys/ must not empty the
	# vendor trust store).
	local any=0 src
	for src in "$@"; do [[ -d "$src" ]] && any=1; done
	[[ "$any" -eq 1 ]] || return 0
	local f base found
	for f in "$managed"/*; do
		[[ -f "$f" ]] || continue
		base="$(basename "$f")"
		found=0
		for src in "$@"; do
			[[ -e "$src/$base" ]] && { found=1; break; }
		done
		if [[ "$found" -eq 0 ]]; then
			echo "install.sh: removing retired $f (not in this payload)"
			run rm -f "$f"
		fi
	done
}

# sweep_named_dirs <managed-dir> <payload-src-dir>...: remove per-name subdirs of
# managed-dir that no payload source dir ships, and inside KEPT subdirs remove files the
# payload's same-named dir does not ship. Non-name entries (files, `providers/`) are the
# caller's to handle.
sweep_named_dirs() {
	local managed="$1"; shift
	[[ -d "$managed" ]] || return 0
	local any=0 src
	for src in "$@"; do [[ -d "$src" ]] && any=1; done
	[[ "$any" -eq 1 ]] || return 0
	local d name srcdir f base
	for d in "$managed"/*/; do
		[[ -d "$d" ]] || continue
		name="$(basename "$d")"
		[[ "$name" = "providers" ]] && continue
		srcdir=""
		for src in "$@"; do
			[[ -d "$src/$name" ]] && { srcdir="$src/$name"; break; }
		done
		if [[ -z "$srcdir" ]]; then
			echo "install.sh: removing retired $managed/$name/ (not in this payload)"
			run rm -rf "$managed/$name"
			continue
		fi
		for f in "$d"*; do
			[[ -f "$f" ]] || continue
			base="$(basename "$f")"
			if [[ ! -e "$srcdir/$base" ]]; then
				echo "install.sh: removing retired $f (not in this payload)"
				run rm -f "$f"
			fi
		done
	done
}

sweep_retired_payload() {
	echo "install.sh: sweeping the managed directories against the payload manifest"
	sweep_flat "$libexec" "$bindir"
	sweep_flat "$facades_dir" "$pkg_root/facades"
	# ($pathbin_dir is /usr/bin — shared with the whole OS, never swept; the shim is one file.)
	# Vendor trust anchors: payload-exact (a stray key here is vendor-tier authority).
	sweep_flat "$vendor_dir/keys" "$pkg_root/keys"
	# Vendor sources: templates + fragments share one dir; reference policies + providers.
	sweep_named_dirs "$vendor_dir/templates" "$pkg_root/templates" "$pkg_root/fragments"
	sweep_named_dirs "$vendor_dir/policies" "$pkg_root/policies"
	sweep_named_dirs "$vendor_dir/policies/providers" "$pkg_root/policies/providers"
}

print_next_steps() {
	# Run the post-install checks ourselves and report PASS/ATTN, rather than telling
	# the operator what to go check. Then print a copy-pastable per-user bring-up block,
	# tailored to the invoking (sudo) user so it can be pasted verbatim.
	echo
	echo "Project Kennel: system install complete."
	echo "  binaries:        $libexec (host) + $facades_dir (in-view) + $pathbin_dir/kennel"
	echo "  vendor invariants: $vendor_dir (the maintainer key + signed templates/fragments = org.projectkennel.* authority, reference sources, canonical catalogues)"
	echo "  host config:      /etc/kennel (trust store + host templates = host-namespace authority; host-compiled policies; provider enablement; GUI configs; seeded system.toml/config.toml/kennel-sshd.conf)"
	echo
	echo "Post-install checks:"
	# The make-or-break outcomes (privhelper privilege, binder, AppArmor userns) — the
	# shared lib runs them so the package postinst reports identically.
	kn_post_checks "$libexec"

	# The invoking user (sudo) — tailor the per-user block to them; fall back to a placeholder.
	local u="${SUDO_USER:-}" uid_line=""
	if [[ -n "$u" ]]; then
		local uid; uid="$(id -u "$u" 2>/dev/null || echo '<uid>')"
		uid_line="  # for $u (uid $uid)"
	fi

	cat <<EOF

Per-user bring-up — run these as the user who will run kennels (NOT root):
$uid_line
  # 1. kennel is already on PATH (/usr/bin); the helpers it execs live under libexec and
  #    need no PATH entry. Nothing to export — the commands below work as-is. No per-user
  #    allocation step: a kennel's reserved subnet is derived from your uid.

  # 2. start the per-user daemon (socket-activated on first use):
  systemctl --user enable --now kenneld.socket

  # 3. mint a personal policy-signing key (signs your own leaf policies at compile; when it
  #    is the only key in your key dir, 'kennel policy compile' picks it — no --key needed):
  kennel key generate $u-dev

  # 4. scaffold an interactive shell policy from the shipped template, compile (= sign) it,
  #    then run the settled artefact by name ('kennel run' takes no key — the daemon verifies):
  kennel policy generate my-shell --from interactive
  kennel policy compile my-shell
  kennel run my-shell -- /bin/bash

Admin notes (root):
  * Add org/customer policy-signing public keys to /etc/kennel/keys/<key_id>.pub.
  * Edit a deployment path in /etc/kennel/system.toml (seeded default; the daemon reads it, else compiled defaults).
  * Restrict who may run kennels by group-gating the privhelper: e.g.
      chgrp kennel-users $libexec/kennel-privhelper && chmod 0750 $libexec/kennel-privhelper
    Only members of that group can then invoke the privileged factory (and so start a
    kennel). By default it is world-executable, matching any-user-may-run.

Docs:  man kennel · man kennel-policy · man policy.toml · man kenneld
EOF
}

verify_payload
# Pre-flight the external dependencies (dist/dependencies.toml, verified above as part
# of the payload): a missing hard/install-tier binary aborts with the distro package
# name; a missing feature-tier binary warns and installs anyway.
echo "install.sh: pre-flighting external dependencies"
kn_check_deps "$pkg_root/dist/dependencies.toml"
require_root
install_binaries
install_config
install_units
install_man
install_apparmor
install_etc_skeleton
install_keys
sweep_retired_payload
install_reference_policies
[[ "$dry_run" -eq 1 ]] || print_next_steps
