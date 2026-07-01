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
#      with its capability-split sub-helpers, the vendor deployment config under
#      /usr/lib/kennel, the systemd *user* units, the AppArmor profile, and the
#      root-owned /etc/kennel directory. Run with sudo.
#   2. Per-user enable (each user, unprivileged): `systemctl --user enable --now
#      kenneld.socket`, after an admin has provisioned that user's allocation in
#      /etc/kennel/subkennel. The installer prints the exact command.
#
# No install path is baked into a binary: kenneld reads the helper-binary
# locations and the trust store from the root-owned config cascade
# (/usr/lib/kennel/system.toml then /etc/kennel/system.toml; kennel-lib-config). The
# installer writes the vendor system.toml to match where it actually installs.
#
# The installer does NOT fabricate the security-sensitive admin inputs
# (/etc/kennel/subkennel allocations or the trust-store public keys); it creates
# the directory skeleton and tells the admin what to populate. See
# CODING-STANDARDS.md §5.
#
# Usage (from an unpacked release tarball):
#   sudo ./install.sh [--prefix DIR] [--mandir DIR] [--dry-run]
#                     [--provision-users [GROUP]]
#
#   --prefix DIR          libexec dir for the binaries (default: /usr/libexec/kennel)
#   --mandir DIR          man-page root (default: /usr/share/man; pages go in manN/)
#   --dry-run             print the actions without performing them
#   --provision-users [G] write a /etc/kennel/subkennel allocation for every member of
#                         group G (default `users`) — one per uid that lacks one. We are
#                         root during install, so this saves each user the manual
#                         `kennel subkennel add` + sudo-append. Omit to provision nobody.
#
# This script is reviewed like any other code (CODING-STANDARDS.md §15.4):
# POSIX-ish bash, `set -euo pipefail`, no network calls, idempotent.

set -euo pipefail

# The libexec dir holds the HOST-SIDE binaries only (daemon, privhelper, host delegates, the host
# execution unit). This whole tree is blacklisted from constructed views (W10), so nothing a view
# runs may live here. --prefix relocates it.
libexec="/usr/libexec/kennel"
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
provision_group=""

while [ $# -gt 0 ]; do
	case "$1" in
		--prefix) libexec="${2:?--prefix needs a directory}"; shift 2 ;;
		--mandir) mandir="${2:?--mandir needs a directory}"; shift 2 ;;
		--dry-run) dry_run=1; shift ;;
		# Provision a /etc/kennel/subkennel allocation for every member of GROUP
		# (default `users`). We are root, so we can write the file directly — saving
		# each member the manual `kennel subkennel add` step. Optional GROUP follows.
		--provision-users)
			if [ -n "${2:-}" ] && [ "${2#--}" = "$2" ]; then
				provision_group="$2"; shift 2
			else
				provision_group="users"; shift
			fi ;;
		-h|--help) sed -n '2,38p' "$0"; exit 0 ;;
		*) echo "install.sh: unknown argument: $1" >&2; exit 2 ;;
	esac
done

# This is a PURE installer: it places a prebuilt payload that sits beside it in an unpacked release
# tarball — a flat `bin/` of binaries plus the `dist/ keys/ templates/ fragments/ man/` it ships.
# It does not build (`src/tools/build-release.sh` produces the tarball) and must never run from the
# source tree. No `bin/` beside it → not a release tree, so refuse rather than half-install.
pkg_root="$(cd "$(dirname "$0")" && pwd)"
bindir="$pkg_root/bin"
if [ ! -d "$bindir" ]; then
	echo "install.sh: no bin/ beside this installer ($bindir)." >&2
	echo "            Run it from an unpacked release tarball; build one from a source" >&2
	echo "            checkout with src/tools/build-release.sh." >&2
	exit 2
fi

# The systemd user-unit directory (system-wide location for user units).
units_dir="/usr/lib/systemd/user"

# run CMD...: echo under --dry-run, else execute.
run() {
	if [ "$dry_run" -eq 1 ]; then
		printf 'DRY-RUN:'; printf ' %q' "$@"; printf '\n'
	else
		"$@"
	fi
}

require_root() {
	[ "$dry_run" -eq 1 ] && return 0
	if [ "$(id -u)" -ne 0 ]; then
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
	if [ ! -f "$manifest" ]; then
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
	# The privhelper factory: file capabilities cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin.
	# The identity caps write the kennel's uid/gid maps; cap_sys_admin is what the kernel requires
	# to write a userns map that maps host uid 0 (the `0 0 1` line giving the kennel a real uid 0
	# for its binderfs and root-owned view) — the map-write gate checks CAP_SYS_ADMIN over the new
	# namespace. The namespace/view/binderfs work is userns-scoped, and the host-context steps
	# (host-lo mirror, egress BPF, exclusive over-mount) are delegated to the capability-split
	# sub-helpers, so cap_net_admin/cap_bpf/cap_perfmon never ride the factory. Where the filesystem
	# cannot carry file capabilities (no xattr support), fall back to setuid-root.
	run install -m 0755 -o root -g root "$bindir/kennel-privhelper" "$libexec/kennel-privhelper"
	if setcap cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin+ep "$libexec/kennel-privhelper" 2>/dev/null; then
		echo "   kennel-privhelper: file caps cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin (no setuid)"
	else
		echo "   kennel-privhelper: file caps unsupported here — setuid-root fallback" >&2
		run chmod 4755 "$libexec/kennel-privhelper"
	fi
	# The bind-mirror network sub-helper: NOT setuid — it carries the single file capability
	# cap_net_admin, the only privilege its one scoped op (add/remove a kennel's host-lo
	# loopback address) needs. The main privhelper execs it only when a policy binds mirrored
	# ports, so the common factory holds no network capability.
	run install -m 0755 -o root -g root "$bindir/kennel-privhelper-net" "$libexec/kennel-privhelper-net"
	run setcap cap_net_admin+ep "$libexec/kennel-privhelper-net"
	# The host-mode egress sub-helper: cap_bpf (load), cap_net_admin (cgroup-network attach), and
	# cap_perfmon (the cgroup-sockaddr programs read kernel context, which the verifier gates on
	# CAP_PERFMON under kernel.unprivileged_bpf_disabled). The main privhelper execs it only for
	# net.mode=host, so these stay off the common factory.
	run install -m 0755 -o root -g root "$bindir/kennel-privhelper-bpf" "$libexec/kennel-privhelper-bpf"
	run setcap cap_bpf,cap_net_admin,cap_perfmon+ep "$libexec/kennel-privhelper-bpf"
	# The exclusive-bind sub-helper: cap_sys_admin (the host-mount-namespace over-mount that
	# shadows an fs.exclusive path). The main privhelper execs it only for a policy with
	# exclusive binds, so the near-root capability stays off the common factory.
	run install -m 0755 -o root -g root "$bindir/kennel-privhelper-mounts" "$libexec/kennel-privhelper-mounts"
	run setcap cap_sys_admin+ep "$libexec/kennel-privhelper-mounts"
	# The trusted init: the privhelper factory fexecves this as the kennel's uid-0
	# PID 1, so it is a trust anchor — install it root-owned and not group/other
	# writable (verify_trusted_init refuses any other owner or a 0o022 bit). It is
	# NOT setuid: it gains uid 0 only inside the kennel's user namespace.
	run install -m 0755 -o root -g root "$bindir/kennel-bin-init" "$libexec/kennel-bin-init"
	# Load the binder kernel module the factory's per-kennel binderfs needs — now, and on every
	# boot via modules-load.d. The factory does not modprobe at runtime (that needs CAP_SYS_MODULE,
	# which the file-capability factory does not carry). Best-effort: a host with binder built-in
	# already lists it; a genuinely binder-less host fails construction later with a clear error.
	modprobe binder_linux 2>/dev/null || true
	printf 'binder_linux\n' > /etc/modules-load.d/kennel.conf 2>/dev/null || true
}

install_config() {
	# Vendor deployment + user config (the lowest-priority cascade layer). The
	# deployment file's libexec_dir is rewritten to wherever we actually
	# installed, so a --prefix relocation stays coherent without hand-editing.
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
	if [ -d "$pkg_root/templates" ]; then
		for tdir in "$pkg_root"/templates/*/; do
			[ -d "$tdir" ] || continue
			tname="$(basename "$tdir")"
			run install -d -m 0755 "$vendor_dir/templates/$tname"
			for f in "$tdir"*; do
				[ -f "$f" ] || continue
				run install -m 0644 "$f" "$vendor_dir/templates/$tname/$(basename "$f")"
			done
		done
	fi
	# The composable fragments share the template search dir (a leaf's `include = ["gui-desktop",
	# …]` resolves them from template_dirs); ship them alongside the templates in the maintainer tree.
	if [ -d "$pkg_root/fragments" ]; then
		for fdir in "$pkg_root"/fragments/*/; do
			[ -f "${fdir}policy.toml" ] || continue
			fname="$(basename "$fdir")"
			run install -d -m 0755 "$vendor_dir/templates/$fname"
			run install -m 0644 "${fdir}policy.toml" "$vendor_dir/templates/$fname/policy.toml"
		done
	fi
	# The reference policy SOURCES — runnable leaves (policies/<name>) and service providers
	# (policies/providers/<name>) — maintainer-signed, into the vendor policies tree. They are
	# compiled to settled, host-signed artefacts at install (install_reference_policies).
	if [ -d "$pkg_root/policies" ]; then
		for pdir in "$pkg_root"/policies/*/; do
			[ -f "${pdir}policy.toml" ] || continue
			pname="$(basename "$pdir")"
			run install -d -m 0755 "$vendor_dir/policies/$pname"
			run install -m 0644 "${pdir}policy.toml" "$vendor_dir/policies/$pname/policy.toml"
		done
		for pdir in "$pkg_root"/policies/providers/*/; do
			[ -f "${pdir}policy.toml" ] || continue
			pname="$(basename "$pdir")"
			run install -d -m 0755 "$vendor_dir/policies/providers/$pname"
			run install -m 0644 "${pdir}policy.toml" "$vendor_dir/policies/providers/$pname/policy.toml"
		done
	fi
	run install -m 0644 "$pkg_root/dist/config/system.toml" "$vendor_dir/system.toml"
	# The bastion's hardened sshd_config template (W18): surfaced root-owned in the vendor layer so
	# its lockdown is legible and admin-tunable (override at /etc/kennel/kennel-sshd.conf), not baked
	# into the daemon. kenneld renders it per bastion; a missing file falls back to the compiled copy.
	run install -m 0644 "$pkg_root/dist/kennel-sshd.conf" "$vendor_dir/kennel-sshd.conf"
	run install -m 0644 "$pkg_root/dist/config/config.toml" "$vendor_dir/config.toml"
	# The machine-readable threat catalogue `kennel policy risks` reads (the CLI
	# falls back to its embedded copy if absent; this lets an org ship an extended one).
	run install -d -m 0755 "$vendor_dir/threats"
	run install -m 0644 "$pkg_root/dist/threats/catalogue.toml" "$vendor_dir/threats/catalogue.toml"
	# The vendor-default catalogues: the trust-trigger set the CLI pins/watches
	# (T2.8) and the essential /etc subtrees the daemon binds read-only into every view.
	# Both are additive cascades; /etc/kennel overrides this vendor layer.
	run install -m 0644 "$pkg_root/dist/vendor/triggers.catalog" "$vendor_dir/triggers.catalog"
	run install -m 0644 "$pkg_root/dist/vendor/etc-binds.catalog" "$vendor_dir/etc-binds.catalog"
	if [ "$libexec" != "/usr/libexec/kennel" ]; then
		run sed -i "s#^libexec_dir = .*#libexec_dir = \"$libexec\"#" "$vendor_dir/system.toml"
	fi
}

install_units() {
	run install -d -m 0755 "$units_dir"
	run install -m 0644 "$pkg_root/dist/systemd/kenneld.socket" "$units_dir/kenneld.socket"
	run install -m 0644 "$pkg_root/dist/systemd/kenneld.service" "$units_dir/kenneld.service"
	if [ "$libexec" != "/usr/libexec/kennel" ]; then
		run sed -i "s#^ExecStart=.*#ExecStart=$libexec/kenneld#" "$units_dir/kenneld.service"
	fi
}

# Install the committed man pages (man/<name>.<section>) into $mandir/man<section>.
# The pages are generated by `gen-man` and committed; see man/README.md.
install_man() {
	local man_src="$pkg_root/man" page sect dest
	if [ ! -d "$man_src" ]; then
		echo "install.sh: no man/ directory; skipping man pages" >&2
		return 0
	fi
	for page in "$man_src"/*.[1-9]; do
		[ -e "$page" ] || continue          # nullglob-safe: skip if none matched
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
	[ -d /etc/apparmor.d ] || { echo "install.sh: no /etc/apparmor.d; skipping AppArmor profile"; return 0; }
	run install -m 0644 "$pkg_root/dist/apparmor/kenneld" /etc/apparmor.d/kenneld
	if [ "$libexec" != "/usr/libexec/kennel" ]; then
		run sed -i "s#/usr/libexec/kennel/kenneld#$libexec/kenneld#" /etc/apparmor.d/kenneld
	fi
	if command -v apparmor_parser >/dev/null 2>&1; then
		run apparmor_parser -r -W /etc/apparmor.d/kenneld
	else
		echo "install.sh: apparmor_parser absent; profile staged but not loaded"
	fi
}

install_etc_skeleton() {
	# Root-owned configuration root. `keys/` is the trust store:
	# the daemon's signing-key store (system.toml's trust_dir default) and the CLI's
	# authoring search dir. Admin-owned; org keys and per-user allocations go here.
	run install -d -m 0755 /etc/kennel /etc/kennel/keys /etc/kennel/templates /etc/kennel/policies
	if [ ! -e /etc/kennel/subkennel ]; then
		echo "install.sh: /etc/kennel/subkennel is absent — the admin must create it"
		echo "            (one line per user: <uid>:<tag>:<gid>:<namespace>, e.g. 1000:42:0000000001:kennel-alice)"
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
	if [ -d "$pkg_root/keys" ]; then
		for pub in "$pkg_root"/keys/*.pub; do
			[ -e "$pub" ] || continue
			run install -m 0644 "$pub" "$vendor_dir/keys/$(basename "$pub")"
		done
	fi
}

install_reference_policies() {
	# The reference policy SOURCES (policies/<n>, policies/providers/<n>) are maintainer-signed and
	# ship to the vendor tree (install_config). Their SETTLED form is HOST-specific — the
	# executable-closure loader pin embeds THIS host's library closure, so a settled policy cannot be
	# shipped — so we compile each source HERE and sign it with a HOST key the daemon trusts. The host
	# key is minted once into the admin trust dir (/etc/kennel/keys) and reused on every reinstall; the
	# `<name>.settled.toml` land under /etc/kennel/policies, which the policy search cascade resolves.
	# A missing ssh-keygen or a single failing compile is non-fatal (warn + skip).
	[ -d "$pkg_root/policies" ] || return 0
	local kbin="$pathbin_dir/kennel" host_id="kennel-host" key_dir="/etc/kennel/keys"
	if [ "$dry_run" -eq 1 ]; then
		echo "DRY-RUN: mint host key '$host_id' in $key_dir (if absent), then compile each policies/* +"
		echo "         policies/providers/* source --key it into /etc/kennel/policies/<n>/<n>.settled.toml"
		return 0
	fi
	[ -x "$kbin" ] || { echo "install.sh: $kbin not found; skipping reference-policy compile" >&2; return 0; }
	if ! command -v ssh-keygen >/dev/null 2>&1; then
		echo "install.sh: ssh-keygen absent — cannot mint a host signing key; skipping reference-policy compile" >&2
		return 0
	fi
	# Reuse an existing host key, else mint one. keygen writes the private key + its .pub into key_dir;
	# the daemon trusts the .pub (trust_dir = /etc/kennel/keys), so host-signed policies verify. The
	# private key stays root-only in the root-owned key dir.
	if [ ! -f "$key_dir/$host_id" ]; then
		echo "install.sh: minting host policy-signing key '$host_id' in $key_dir"
		"$kbin" keygen "$host_id" --dir "$key_dir" >/dev/null \
			|| { echo "install.sh: host keygen failed; skipping reference-policy compile" >&2; return 0; }
	else
		echo "install.sh: reusing host policy-signing key '$host_id'"
	fi
	# Compile every leaf + provider source → host-signed settled artefact, verifying the maintainer-
	# signed templates/fragments it derives from against the vendor trust + template dirs.
	local src rel name out count=0
	for src in "$pkg_root"/policies/*/policy.toml "$pkg_root"/policies/providers/*/policy.toml; do
		[ -f "$src" ] || continue
		rel="${src#"$pkg_root"/policies/}"; rel="${rel%/policy.toml}"   # "gui-session" or "providers/gui-broker"
		name="$(basename "$rel")"
		out="/etc/kennel/policies/$rel/$name.settled.toml"
		install -d -m 0755 "$(dirname "$out")"
		if "$kbin" policy compile "$src" --key "$key_dir/$host_id" --key-id "$host_id" \
				--trust-dir "$vendor_dir/keys" --template-dir "$vendor_dir/templates" \
				--no-lock --output "$out" >/dev/null 2>&1; then
			echo "  + $rel → $out"; count=$((count + 1))
		else
			echo "  ! $rel: compile failed (skipped)" >&2
		fi
	done
	echo "install.sh: compiled $count reference policies into /etc/kennel/policies"
}

# The signed reference templates and fragments are MAINTAINER content: they ship to the vendor
# tree ONLY (/usr/lib/kennel/templates, via install_config) — NEVER to /etc/kennel, which is the
# admin tier. The CLI/daemon template search cascade already includes the vendor dir
# (`<user-config>/templates` + `/etc/kennel/templates` + `/usr/lib/kennel/templates`,
# kennel-lib-config::default_search_dirs), so a leaf deriving `base-confined` or `include`-ing
# `lang-python` resolves out of the box from the vendor copy. `/etc/kennel/templates` is created
# empty by install_etc_skeleton for an admin's own org templates.

provision_subkennel_users() {
	# For every member of $provision_group, append a /etc/kennel/subkennel allocation
	# (one per uid that lacks one). We drive `kennel subkennel add --uid N`, which owns
	# the allocation invariants — lowest free 12-bit tag, a fresh non-colliding 40-bit
	# ULA gid, and skip-if-already-present — and prints the file line on stdout. We
	# append after EACH user so the next invocation sees it and never reuses a tag.
	[ -n "$provision_group" ] || return 0
	local sub=/etc/kennel/subkennel kbin="$pathbin_dir/kennel"
	if [ ! -x "$kbin" ]; then
		echo "install.sh: $kbin not found; cannot auto-provision subkennel" >&2
		return 0
	fi
	local members uid name line
	# Group members = the group line's comma list PLUS anyone whose PRIMARY gid is it.
	local gid; gid="$(getent group "$provision_group" | cut -d: -f3)"
	if [ -z "$gid" ]; then
		echo "install.sh: group '$provision_group' not found; skipping auto-provision" >&2
		return 0
	fi
	members="$(
		{ getent group "$provision_group" | cut -d: -f4 | tr ',' '\n'
		  getent passwd | awk -F: -v g="$gid" '$4==g {print $1}'
		} | sed '/^$/d' | sort -u
	)"
	run install -d -m 0755 /etc/kennel
	[ -e "$sub" ] || run touch "$sub"
	echo "install.sh: provisioning subkennel allocations for group '$provision_group'"
	local count=0
	for name in $members; do
		uid="$(id -u "$name" 2>/dev/null)" || continue
		if grep -q "^${uid}:" "$sub" 2>/dev/null; then
			echo "  - $name (uid $uid): already allocated"
			continue
		fi
		if [ "$dry_run" -eq 1 ]; then
			echo "  DRY-RUN: kennel subkennel add --uid $uid  >> $sub"
			continue
		fi
		# Capture only stdout (the line); the human guidance goes to stderr.
		if line="$("$kbin" subkennel add --uid "$uid" --file "$sub" 2>/dev/null)" && [ -n "$line" ]; then
			printf '%s\n' "$line" >> "$sub"
			echo "  + $name (uid $uid): $line"
			count=$((count + 1))
		else
			echo "  ! $name (uid $uid): allocation failed (tags exhausted?)" >&2
		fi
	done
	echo "install.sh: provisioned $count new allocation(s) in $sub"
}

print_next_steps() {
	# Run the post-install checks ourselves and report PASS/ATTN, rather than telling
	# the operator what to go check. Then print a copy-pastable per-user bring-up block,
	# tailored to the invoking (sudo) user so it can be pasted verbatim.
	echo
	echo "Project Kennel: system install complete (binaries under $libexec, config under $vendor_dir)."
	echo
	echo "Post-install checks:"

	# 1. privhelper factory privilege — the one thing that must be exactly right. Normally the
	#    file caps cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin; setuid-root is the no-xattr
	#    fallback. Either is acceptable; no privilege at all means kennels cannot construct.
	local ph="$libexec/kennel-privhelper" perms owner caps
	perms="$(stat -c '%A' "$ph" 2>/dev/null || echo '?')"
	owner="$(stat -c '%U' "$ph" 2>/dev/null || echo '?')"
	caps="$(getcap "$ph" 2>/dev/null | sed 's|^[^ ]* ||')"
	if [ -n "$caps" ]; then
		echo "  [ok]   privhelper factory has file caps ($caps)"
	elif [ "$owner" = root ] && [ "${perms:3:1}" = s ]; then
		echo "  [ok]   privhelper factory is setuid-root ($perms $owner) — no-xattr fallback"
	else
		echo "  [ATTN] privhelper factory has NO privilege ($perms $owner) — kennels will fail to construct"
		echo "         fix: sudo setcap cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin+ep $ph"
	fi

	# 2. binder filesystem available (the kennel bus). Loaded here and on boot
	#    (/etc/modules-load.d/kennel.conf); flag it now so a binder-less kernel is obvious up front.
	if grep -qw binder /proc/filesystems 2>/dev/null; then
		echo "  [ok]   binder filesystem registered"
	elif modinfo binder_linux >/dev/null 2>&1; then
		echo "  [ok]   binder_linux module available (loaded on first kennel)"
	else
		echo "  [ATTN] no binder filesystem and no binder_linux module — the kernel needs"
		echo "         CONFIG_ANDROID_BINDERFS; kennels cannot start without it"
	fi

	# 3. AppArmor userns restriction (Ubuntu 23.10+): our profile handles it, just report.
	if [ -e /etc/apparmor.d/kenneld ]; then
		echo "  [ok]   AppArmor userns profile installed"
	elif [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = 1 ]; then
		echo "  [ATTN] unprivileged userns is AppArmor-restricted but no profile was installed"
		echo "         (no /etc/apparmor.d on this host?) — kenneld may be denied CLONE_NEWUSER"
	else
		echo "  [ok]   unprivileged userns is not AppArmor-restricted"
	fi

	# The invoking user (sudo) — tailor the per-user block to them; fall back to a placeholder.
	local u="${SUDO_USER:-}" uid_line=""
	if [ -n "$u" ]; then
		local uid; uid="$(id -u "$u" 2>/dev/null || echo '<uid>')"
		uid_line="  # for $u (uid $uid)"
		if grep -q "^${uid}:" /etc/kennel/subkennel 2>/dev/null; then
			echo "  [ok]   /etc/kennel/subkennel has an allocation for $u (uid $uid)"
		fi
	fi

	# Step 2 (claim an allocation) is unnecessary for users we just auto-provisioned.
	local step2
	if [ -n "$provision_group" ]; then
		step2="  # (subkennel allocations were auto-provisioned for group '$provision_group' — skip this)
  # kennel subkennel add   # only if your uid is NOT in that group"
	else
		step2="  # 2. claim a subkennel allocation. This prints the exact 'sudo' line to append it
  #    (the file is root-owned, so the CLI cannot write it itself) — paste that next:
  kennel subkennel add"
	fi

	cat <<EOF

Per-user bring-up — run these as the user who will run kennels (NOT root):
$uid_line
  # 1. kennel is already on PATH (/usr/bin); the helpers it execs live under libexec and
  #    need no PATH entry. Nothing to export — the commands below work as-is.

$step2

  # 3. start the per-user daemon (socket-activated on first use):
  systemctl --user enable --now kenneld.socket

  # 4. mint a personal policy-signing key (compiles your own leaf policies; when it is
  #    the only key in your key dir, 'kennel run' picks it automatically — no --key needed):
  kennel keygen $u-dev

  # 5. scaffold an interactive shell policy from the shipped template, then run it:
  kennel policy generate my-shell --from interactive
  kennel run my-shell -- /bin/bash

Admin notes (root):
  * Add org/customer policy-signing public keys to /etc/kennel/keys/<key_id>.pub.
  * Override a deployment path in /etc/kennel/system.toml (wins over $vendor_dir/system.toml).

Docs:  man kennel · man kennel-policy · man policy.toml · man kenneld
EOF
}

verify_payload
require_root
install_binaries
install_config
install_units
install_man
install_apparmor
install_etc_skeleton
install_keys
install_reference_policies
provision_subkennel_users
[ "$dry_run" -eq 1 ] || print_next_steps
