#!/usr/bin/env bash
# Project Kennel installer.
#
# Installs the runtime binaries, the setuid privhelper, the vendor config, the
# per-user systemd units, the AppArmor userns grant, the /etc/kennel skeleton,
# the maintainer trust-store key, and the signed reference templates. Two halves:
#
#   1. System install (root): all binaries under <libexec> (default
#      /usr/libexec/kennel, the documented non-PATH helper location, 07-paths.md),
#      the privhelper setuid-root, the vendor deployment config under
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
# CODING-STANDARDS.md §5 and docs/architecture/07-paths.md.
#
# Usage:
#   sudo tools/install.sh [--prefix DIR] [--no-build] [--dry-run]
#                         [--provision-users [GROUP]]
#
#   --prefix DIR          libexec dir for the binaries (default: /usr/libexec/kennel)
#   --mandir DIR          man-page root (default: /usr/share/man; pages go in manN/)
#   --no-build            install the binaries already in target/release (skip cargo)
#   --dry-run             print the actions without performing them
#   --provision-users [G] write a /etc/kennel/subkennel allocation for every member of
#                         group G (default `users`) — one per uid that lacks one. We are
#                         root during install, so this saves each user the manual
#                         `kennel subkennel add` + sudo-append. Omit to provision nobody.
#
# This script is reviewed like any other code (CODING-STANDARDS.md §15.4):
# POSIX-ish bash, `set -euo pipefail`, no network calls, idempotent.

set -euo pipefail

# The libexec dir holds every kennel binary (all non-PATH helpers located by
# absolute path from kenneld via the config). --prefix relocates it.
libexec="/usr/libexec/kennel"
# Vendor (package-shipped) config dir: the lowest-priority config layer.
vendor_dir="/usr/lib/kennel"
# Man-page root; pages install into $mandir/man{1,5,8}.
mandir="/usr/share/man"
do_build=1
dry_run=0
provision_group=""

while [ $# -gt 0 ]; do
	case "$1" in
		--prefix) libexec="${2:?--prefix needs a directory}"; shift 2 ;;
		--mandir) mandir="${2:?--mandir needs a directory}"; shift 2 ;;
		--no-build) do_build=0; shift ;;
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
		-h|--help) sed -n '2,40p' "$0"; exit 0 ;;
		*) echo "install.sh: unknown argument: $1" >&2; exit 2 ;;
	esac
done

# Repo root = the directory above tools/ (this script's location).
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

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

# Host-side binaries: run in the operator's context where the host libc is present, so they link
# dynamically. kenneld + the CLI + the host-side delegates (netproxy/inetd/dbus) + the AKC.
HOST_BINS="kenneld kennel host-netproxy host-inetd host-dbus kennel-akc"

# In-kennel binaries: the seal runs these INSIDE the kennel's root, which for an OCI substrate
# (§7.11) is an arbitrary image's filesystem — possibly musl, distroless, or scratch with no host
# `ld.so`/`libc`. A dynamically-linked host binary would fail to load there (`libgcc_s.so.1: cannot
# open shared object`). So the launcher and the in-kennel facades are built **statically**
# (glibc `+crt-static` → static-pie, no interpreter, no NEEDED libs) and run in any root. The
# trusted init `kennel-bin-init` is the same class but installed root-owned (below).
INKERNEL_BINS="kennel-bin-oci-entry facade-socks5 facade-client facade-afunix facade-ssh facade-dbus facade-spawn-probe"

# The host triple, so the static `--target` build lands in a separate `target/<triple>/release`
# (specifying `--target` always uses the triple subdir, even when it equals the host default).
# Derived from `uname` rather than `rustc` so it also resolves under a `sudo` install where the
# rustup shim is not on root's PATH; a glibc Linux host is always `<arch>-unknown-linux-gnu`.
HOST_TRIPLE="$(uname -m)-unknown-linux-gnu"
STATIC_RUSTFLAGS="-C target-feature=+crt-static"

build_binaries() {
	[ "$do_build" -eq 1 ] || { echo "install.sh: --no-build, using target/release"; return 0; }
	echo "install.sh: building release binaries (offline, frozen, locked)"
	# Host-side (dynamic): -p kenneld builds kenneld + kennel-akc; -p kennel-cli the `kennel` CLI;
	# -p kennel-host-delegate host-netproxy + host-inetd; -p kennel-host-dbus host-dbus.
	run cargo build --release --offline --frozen --locked \
		-p kenneld -p kennel-cli -p kennel-host-delegate -p kennel-host-dbus
	# In-kennel (static-pie): the launcher, the trusted init, and all facade-* bins (kennel-facade).
	run env RUSTFLAGS="$STATIC_RUSTFLAGS" cargo build --release --offline --frozen --locked \
		--target "$HOST_TRIPLE" \
		-p kennel-bin-oci-entry -p kennel-bin-init -p kennel-facade
	# The privhelper needs its BPF feature; build it separately (host-side, dynamic).
	run cargo build --release --offline --frozen --locked \
		-p kennel-privhelper --features bpf-egress
}

require_root() {
	[ "$dry_run" -eq 1 ] && return 0
	if [ "$(id -u)" -ne 0 ]; then
		echo "install.sh: the system install needs root; re-run with sudo" >&2
		exit 1
	fi
}

install_binaries() {
	local rel="$repo_root/target/release"
	local stat="$repo_root/target/$HOST_TRIPLE/release"
	run install -d -m 0755 "$libexec"
	# Host-side dynamic binaries (mode 0755) from the default target dir.
	local b
	for b in $HOST_BINS; do
		run install -m 0755 "$rel/$b" "$libexec/$b"
	done
	# In-kennel static binaries (mode 0755) from the `+crt-static` target dir — they run inside
	# an arbitrary image root, so they carry their own libc (no `ld.so` to find).
	for b in $INKERNEL_BINS; do
		run install -m 0755 "$stat/$b" "$libexec/$b"
	done
	# The privhelper: setuid root (mode 4755, owner root). This is the one
	# privilege boundary; everything else runs as the user.
	run install -m 0755 -o root -g root "$rel/kennel-privhelper" "$libexec/kennel-privhelper"
	run chmod 4755 "$libexec/kennel-privhelper"
	# The trusted init: the privhelper factory fexecves this as the kennel's uid-0
	# PID 1, so it is a trust anchor — install it root-owned and not group/other
	# writable (verify_trusted_init refuses any other owner or a 0o022 bit). It is
	# NOT setuid: it gains uid 0 only inside the kennel's user namespace. Static (in-kennel).
	run install -m 0755 -o root -g root "$stat/kennel-bin-init" "$libexec/kennel-bin-init"
}

install_config() {
	# Vendor deployment + user config (the lowest-priority cascade layer). The
	# deployment file's libexec_dir is rewritten to wherever we actually
	# installed, so a --prefix relocation stays coherent without hand-editing.
	run install -d -m 0755 "$vendor_dir"
	# Vendor cascade layers for keys/templates/policies so the lowest-priority
	# search dir always exists (kennel-lib-config 3-layer cascade; 07-paths). No
	# reference policies are shipped — policies are user/org content.
	run install -d -m 0755 "$vendor_dir/keys" "$vendor_dir/templates" "$vendor_dir/policies"
	run install -m 0644 "$repo_root/dist/config/system.toml" "$vendor_dir/system.toml"
	run install -m 0644 "$repo_root/dist/config/config.toml" "$vendor_dir/config.toml"
	# The machine-readable threat catalogue `kennel policy risks` reads (the CLI
	# falls back to its embedded copy if absent; this lets an org ship an extended one).
	run install -d -m 0755 "$vendor_dir/threats"
	run install -m 0644 "$repo_root/dist/threats/catalogue.toml" "$vendor_dir/threats/catalogue.toml"
	# The vendor-default catalogues (§2.6 / §7.4): the trust-trigger set the CLI pins/watches
	# (T2.8) and the essential /etc subtrees the daemon binds read-only into every view (W14).
	# Both are additive cascades; /etc/kennel overrides this vendor layer.
	run install -m 0644 "$repo_root/dist/vendor/triggers.catalog" "$vendor_dir/triggers.catalog"
	run install -m 0644 "$repo_root/dist/vendor/etc-binds.catalog" "$vendor_dir/etc-binds.catalog"
	if [ "$libexec" != "/usr/libexec/kennel" ]; then
		run sed -i "s#^libexec_dir = .*#libexec_dir = \"$libexec\"#" "$vendor_dir/system.toml"
	fi
}

install_units() {
	run install -d -m 0755 "$units_dir"
	run install -m 0644 "$repo_root/dist/systemd/kenneld.socket" "$units_dir/kenneld.socket"
	run install -m 0644 "$repo_root/dist/systemd/kenneld.service" "$units_dir/kenneld.service"
	if [ "$libexec" != "/usr/libexec/kennel" ]; then
		run sed -i "s#^ExecStart=.*#ExecStart=$libexec/kenneld#" "$units_dir/kenneld.service"
	fi
}

# Install the committed man pages (man/<name>.<section>) into $mandir/man<section>.
# The pages are generated by `gen-man` and committed; see man/README.md.
install_man() {
	local man_src="$repo_root/man" page sect dest
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
	run install -m 0644 "$repo_root/dist/apparmor/kenneld" /etc/apparmor.d/kenneld
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
	# Root-owned configuration root. `keys/` is the trust store (07-paths.md §/etc):
	# the daemon's signing-key store (system.toml's trust_dir default) and the CLI's
	# authoring search dir. Admin-owned; org keys and per-user allocations go here.
	run install -d -m 0755 /etc/kennel /etc/kennel/keys /etc/kennel/templates /etc/kennel/policies
	if [ ! -e /etc/kennel/subkennel ]; then
		echo "install.sh: /etc/kennel/subkennel is absent — the admin must create it"
		echo "            (one line per user: <uid>:<tag>:<gid>:<namespace>, e.g. 1000:42:0000000001:kennel-alice)"
	fi
}

install_keys() {
	# Ship the project's own template-signing public key(s) into the trust store,
	# so the signed reference templates verify out of the box. Private seeds are
	# never in the repo (MAINTAINERS.md); only `*.pub` is shipped. Org/customer
	# keys are added alongside these by the admin.
	if [ -d "$repo_root/keys" ]; then
		for pub in "$repo_root"/keys/*.pub; do
			[ -e "$pub" ] || continue
			run install -m 0644 "$pub" "/etc/kennel/keys/$(basename "$pub")"
		done
	fi
}

install_templates() {
	# Ship the signed reference templates into the CLI's default template search
	# dir (/etc/kennel/templates, per dist/config/config.toml), so a leaf that
	# derives e.g. base-confined@v1 resolves and verifies out of the box (the
	# maintainer public key is installed above). Org templates are added alongside.
	[ -d "$repo_root/templates" ] || return 0
	local d n
	for d in "$repo_root"/templates/*/; do
		[ -f "${d}policy.toml" ] || continue
		n="$(basename "$d")"
		run install -d -m 0755 "/etc/kennel/templates/$n"
		run install -m 0644 "${d}policy.toml" "/etc/kennel/templates/$n/policy.toml"
	done
}

install_fragments() {
	# Ship the signed composable fragments (05-templates.md §5.10) into the SAME
	# template search dir, so a leaf's `include = ["lang-python@v1", ...]` resolves and
	# verifies out of the box. Fragments and templates are both signed includes; sharing
	# the dir means no extra search-path config, and `kennel policy list` labels each one
	# `(fragment)`. Org fragments are added alongside.
	[ -d "$repo_root/fragments" ] || return 0
	local d n
	for d in "$repo_root"/fragments/*/; do
		[ -f "${d}policy.toml" ] || continue
		n="$(basename "$d")"
		run install -d -m 0755 "/etc/kennel/templates/$n"
		run install -m 0644 "${d}policy.toml" "/etc/kennel/templates/$n/policy.toml"
	done
}

provision_subkennel_users() {
	# For every member of $provision_group, append a /etc/kennel/subkennel allocation
	# (one per uid that lacks one). We drive `kennel subkennel add --uid N`, which owns
	# the allocation invariants — lowest free 12-bit tag, a fresh non-colliding 40-bit
	# ULA gid, and skip-if-already-present — and prints the file line on stdout. We
	# append after EACH user so the next invocation sees it and never reuses a tag.
	[ -n "$provision_group" ] || return 0
	local sub=/etc/kennel/subkennel kbin="$libexec/kennel"
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
	local kennel_bin="$libexec/kennel"

	echo
	echo "Project Kennel: system install complete (binaries under $libexec, config under $vendor_dir)."
	echo
	echo "Post-install checks:"

	# 1. privhelper setuid-root — the one thing that must be exactly right.
	local ph="$libexec/kennel-privhelper" perms owner
	perms="$(stat -c '%A' "$ph" 2>/dev/null || echo '?')"
	owner="$(stat -c '%U' "$ph" 2>/dev/null || echo '?')"
	if [ "$owner" = root ] && [ "${perms:3:1}" = s ]; then
		echo "  [ok]   privhelper is setuid-root ($perms $owner)"
	else
		echo "  [ATTN] privhelper is NOT setuid-root ($perms $owner) — kennels will fail to construct"
		echo "         fix: sudo chown root $ph && sudo chmod u+s $ph"
	fi

	# 2. binder filesystem available (the kennel bus). The privhelper modprobes it at
	#    construct time, but flag it now so a binder-less kernel is obvious up front.
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
  # 1. reach the helper binaries (kennel lives under libexec, off PATH by design):
  export PATH="\$PATH:$libexec"

$step2

  # 3. start the per-user daemon (socket-activated on first use):
  systemctl --user enable --now kenneld.socket

  # 4. mint a personal policy-signing key (compiles your own leaf policies; when it is
  #    the only key in your key dir, 'kennel run' picks it automatically — no --key needed):
  kennel keygen $u-dev

  # 5. scaffold an interactive shell policy from the shipped template, then run it:
  kennel policy generate my-shell --from interactive@v1
  kennel run my-shell -- /bin/bash

To make PATH permanent, add the export above to ~/.bashrc (or ~/.profile).

Admin notes (root):
  * Add org/customer policy-signing public keys to /etc/kennel/keys/<key_id>.pub.
  * Override a deployment path in /etc/kennel/system.toml (wins over $vendor_dir/system.toml).

Docs:  man kennel · man kennel-policy · man policy.toml · man kenneld
EOF
}

build_binaries
require_root
install_binaries
install_config
install_units
install_man
install_apparmor
install_etc_skeleton
install_keys
install_templates
install_fragments
provision_subkennel_users
[ "$dry_run" -eq 1 ] || print_next_steps
