# Project Kennel — the install CEREMONY, shared between install.sh and the package
# maintainer scripts (the .deb postinst embeds this file at package build).
#
# File PLACEMENT is the caller's affair: install.sh places the payload by hand and
# sweeps retired files (W7); a package manager does both natively (data archive +
# upgrade removal + conffile discipline). What packages cannot carry as files is the
# ceremony below — file capabilities (dpkg strips xattrs), the binder module load, and
# the host-specific reference-policy compile (the executable-closure loader pin embeds
# THIS host's library closure, so a settled artefact can never ship).
#
# Callers define run() (install.sh: dry-run aware). Absent one, commands run directly.
# shellcheck shell=bash

if ! type run >/dev/null 2>&1; then
	run() {
		"$@"
		return
	}
fi

# kn_detect_family: echo "debian" | "fedora" | "" from os-release.
kn_detect_family() {
	local id=""
	# shellcheck disable=SC1091
	[[ -r /etc/os-release ]] && { id="$(. /etc/os-release; echo "${ID:-} ${ID_LIKE:-}")"; }
	case " $id " in
		*debian*|*ubuntu*) echo debian ;;
		*fedora*|*rhel*|*centos*) echo fedora ;;
		*) echo "" ;;
	esac
	return 0
}

# kn_check_deps <dependencies.toml>: pre-flight the external dependencies.
# hard/install tiers missing → report with the distro package name and return 1;
# feature/provider tiers missing → warn (the feature refuses cleanly at use).
kn_check_deps() {
	local manifest="$1"
	[[ -f "$manifest" ]] || { echo "install: no $manifest — cannot pre-flight dependencies" >&2; return 0; }
	local fam; fam="$(kn_detect_family)"
	local missing_hard=0 bin tier pkg
	# The manifest's [[dep]] entries, flattened to "bin<TAB>tier<TAB>package-for-family".
	while IFS=$'\t' read -r bin tier pkg; do
		[[ -n "$bin" ]] || continue
		command -v "$bin" >/dev/null 2>&1 && continue
		case "$tier" in
			hard|install)
				echo "  [MISSING] $bin (${pkg:-part of the base system}) — required" >&2
				missing_hard=1 ;;
			feature|provider)
				echo "  [absent]  $bin (${pkg:-$bin}) — optional; the feature it serves refuses without it" ;;
			*) ;; # build/unknown tiers are not host requirements
		esac
	done < <(awk -v fam="${fam:-debian}" '
		function flush() { if (bin != "") printf "%s\t%s\t%s\n", bin, tier, pkg[fam]; bin=""; tier=""; delete pkg }
		/^\[\[dep\]\]/  { flush() }
		/^\[\[kernel\]\]/ { flush(); skip=1; next }
		skip { next }
		/^bin = /    { gsub(/"/, "", $3); bin = $3 }
		/^tier = /   { gsub(/"/, "", $3); tier = $3 }
		/^debian = / { gsub(/"/, "", $3); pkg["debian"] = $3 }
		/^fedora = / { gsub(/"/, "", $3); pkg["fedora"] = $3 }
		END { flush() }' "$manifest")
	if [[ "$missing_hard" -eq 1 ]]; then
		echo "install: required dependencies are missing (see above) — install them and re-run" >&2
		return 1
	fi
	echo "  [ok]   all required external dependencies present"
	return 0
}

# kn_setcap_privhelpers <libexec>: the privilege ceremony on the already-placed helpers.
# The factory: cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin (identity maps + the
# `0 0 1` map-write gate); setuid-root only where the filesystem cannot carry xattrs.
# The sub-helpers each carry exactly the capability their one scoped op needs, so
# nothing beyond the factory's set ever rides the common path.
kn_setcap_privhelpers() {
	local libexec="$1"
	# Through run() so a dry-run prints rather than probes; a real run takes the true
	# setcap status (no-xattr filesystems fail here → the setuid-root fallback).
	if run setcap cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin+ep "$libexec/kennel-privhelper" 2>/dev/null; then
		echo "   kennel-privhelper: file caps cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin (no setuid)"
	else
		echo "   kennel-privhelper: file caps unsupported here — setuid-root fallback" >&2
		run chmod 4755 "$libexec/kennel-privhelper"
	fi
	run setcap cap_net_admin+ep "$libexec/kennel-privhelper-net"
	run setcap cap_bpf,cap_net_admin,cap_perfmon+ep "$libexec/kennel-privhelper-bpf"
	run setcap cap_sys_admin+ep "$libexec/kennel-privhelper-mounts"
	return 0
}

# kn_binder_modload: load the binder module now and on every boot. The factory does not
# modprobe at runtime (no CAP_SYS_MODULE on the file-capability factory). Best-effort:
# built-in binder already lists in /proc/filesystems; a binder-less kernel is reported
# by kn_post_checks — kennel does not function without it.
kn_binder_modload() {
	run modprobe binder_linux 2>/dev/null || true
	run sh -c 'echo binder_linux > /etc/modules-load.d/kennel.conf' 2>/dev/null || true
	return 0
}

# kn_compile_reference_policies <vendor_dir> <kennel_bin>: mint the host signing key
# (once) and compile every vendor reference source — leaves (policies/<n>) and providers
# (policies/providers/<n>) — into host-signed settled artefacts under
# /etc/kennel/policies, then enable the standing brokers ondemand at the per-host layer.
# Compiles FROM the installed vendor tree, so the tarball and package paths are one code
# path. A missing ssh-keygen or a single failing compile is non-fatal (warn + skip).
kn_compile_reference_policies() {
	local vendor_dir="$1" kbin="$2" host_id="kennel-host" key_dir="/etc/kennel/keys"
	[[ -d "$vendor_dir/policies" ]] || return 0
	[[ -x "$kbin" ]] || { echo "install: $kbin not found; skipping reference-policy compile" >&2; return 0; }
	if ! command -v ssh-keygen >/dev/null 2>&1; then
		echo "install: ssh-keygen absent — cannot mint a host signing key; skipping reference-policy compile" >&2
		return 0
	fi
	if [[ ! -f "$key_dir/$host_id" ]]; then
		echo "install: minting host policy-signing key '$host_id' in $key_dir"
		"$kbin" key generate "$host_id" >/dev/null 2>&1 \
			|| { echo "install: host key generate failed; skipping reference-policy compile" >&2; return 0; }
	else
		echo "install: reusing host policy-signing key '$host_id'"
	fi
	local src rel name out count=0
	for src in "$vendor_dir"/policies/*/policy.toml "$vendor_dir"/policies/providers/*/policy.toml; do
		[[ -f "$src" ]] || continue
		rel="${src#"$vendor_dir"/policies/}"; rel="${rel%/policy.toml}"
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
	echo "install: compiled $count reference policies into /etc/kennel/policies"
	# Standing-broker enablement (admin-tier, ondemand: socket-activated on first
	# consume, so a host with no consumer pays nothing; a per-user link overrides).
	local settled
	settled="/etc/kennel/policies/providers/dbus-broker/dbus-broker.settled.toml"
	if [[ -f "$settled" ]]; then
		install -d -m 0755 /etc/kennel/ondemand
		ln -sf "$settled" /etc/kennel/ondemand/dbus-broker
		echo "install: enabled the dbus-broker provider (ondemand, per-host)"
	fi
	settled="/etc/kennel/policies/providers/tun-broker/tun-broker.settled.toml"
	if [[ -f "$settled" ]]; then
		install -d -m 0755 /etc/kennel/ondemand
		ln -sf "$settled" /etc/kennel/ondemand/tun-broker
		echo "install: enabled the tun-broker provider (ondemand, per-host)"
	fi
	# ONE confined-GUI display broker: weston (decorated host window) is the default;
	# the cage kiosk ships too — switch by repointing the link.
	settled="/etc/kennel/policies/providers/gui-broker-weston/gui-broker-weston.settled.toml"
	if [[ -f "$settled" ]]; then
		install -d -m 0755 /etc/kennel/ondemand
		ln -sf "$settled" /etc/kennel/ondemand/gui-broker
		echo "install: enabled the gui-broker-weston provider (ondemand, per-host; cage kiosk also shipped)"
	fi
}

# kn_post_checks <libexec>: verify the two make-or-break outcomes and report [ok]/[ATTN]
# — run the checks ourselves rather than telling the operator what to go check.
kn_post_checks() {
	local libexec="$1"
	local ph="$libexec/kennel-privhelper" perms owner caps
	perms="$(stat -c '%A' "$ph" 2>/dev/null || echo '?')"
	owner="$(stat -c '%U' "$ph" 2>/dev/null || echo '?')"
	caps="$(getcap "$ph" 2>/dev/null | sed 's|^[^ ]* ||')"
	if [[ -n "$caps" ]]; then
		echo "  [ok]   privhelper factory has file caps ($caps)"
	elif [[ "$owner" = root ]] && [[ "${perms:3:1}" = s ]]; then
		echo "  [ok]   privhelper factory is setuid-root ($perms $owner) — no-xattr fallback"
	else
		echo "  [ATTN] privhelper factory has NO privilege ($perms $owner) — kennels will fail to construct"
		echo "         fix: sudo setcap cap_setuid,cap_setgid,cap_setfcap,cap_sys_admin+ep $ph"
	fi
	if grep -qw binder /proc/filesystems 2>/dev/null; then
		echo "  [ok]   binder filesystem registered"
	elif modinfo binder_linux >/dev/null 2>&1; then
		echo "  [ok]   binder_linux module available (loaded on first kennel)"
	else
		echo "  [ATTN] no binder filesystem and no binder_linux module — kennel DOES NOT FUNCTION"
		echo "         without binder (the kenneld<->kennel control plane rides on it)."
		if [[ "$(kn_detect_family)" = fedora ]]; then
			echo "         Fedora kernels do not enable binder: install kennel-binder-dkms"
			echo "         (Secure Boot: enroll the MOK or the module will not load)."
		else
			echo "         The kernel needs CONFIG_ANDROID_BINDERFS."
		fi
	fi
	if [[ -e /etc/apparmor.d/kenneld ]]; then
		echo "  [ok]   AppArmor userns profile installed"
	elif [[ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = 1 ]]; then
		echo "  [ATTN] unprivileged userns is AppArmor-restricted but no profile was installed"
		echo "         (no /etc/apparmor.d on this host?) — kenneld may be denied CLONE_NEWUSER"
	else
		echo "  [ok]   unprivileged userns is not AppArmor-restricted"
	fi
	return 0
}
