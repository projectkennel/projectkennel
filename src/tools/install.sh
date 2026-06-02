#!/usr/bin/env bash
# Project Kennel installer.
#
# Installs the runtime binaries, the setuid privhelper, the per-user systemd
# units, and the /etc/kennel skeleton. Two halves:
#
#   1. System install (root): binaries under <prefix> (default /opt/kennel), the
#      privhelper setuid-root, the systemd *user* units, and the root-owned
#      /etc/kennel directory. Run with sudo.
#   2. Per-user enable (each user, unprivileged): `systemctl --user enable --now
#      kenneld.socket`, after an admin has provisioned that user's allocation in
#      /etc/kennel/subkennel. The installer prints the exact command.
#
# The installer does NOT fabricate the security-sensitive admin inputs
# (/etc/kennel/subkennel allocations, /etc/kennel/scope installation constants,
# or the trust-store public keys); it creates the directory skeleton and tells
# the admin what to populate. See CODING-STANDARDS.md §5 and docs/architecture/07-paths.md.
#
# Usage:
#   sudo tools/install.sh [--prefix DIR] [--no-build] [--dry-run]
#
#   --prefix DIR   install root for the binaries (default: /opt/kennel)
#   --no-build     install the binaries already in target/release (skip cargo)
#   --dry-run      print the actions without performing them
#
# This script is reviewed like any other code (CODING-STANDARDS.md §15.4):
# POSIX-ish bash, `set -euo pipefail`, no network calls, idempotent.

set -euo pipefail

prefix="/opt/kennel"
do_build=1
dry_run=0

while [ $# -gt 0 ]; do
	case "$1" in
		--prefix) prefix="${2:?--prefix needs a directory}"; shift 2 ;;
		--no-build) do_build=0; shift ;;
		--dry-run) dry_run=1; shift ;;
		-h|--help) sed -n '2,33p' "$0"; exit 0 ;;
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

# The binaries: (source-relative-to-target/release  destination-subdir  feature-args...)
# The privhelper is built with --features bpf-egress so live egress works
# (CODING-STANDARDS / the bpf-egress build gotcha); it lands in sbin, setuid.

build_binaries() {
	[ "$do_build" -eq 1 ] || { echo "install.sh: --no-build, using target/release"; return 0; }
	echo "install.sh: building release binaries (offline, frozen, locked)"
	run cargo build --release --offline --frozen --locked \
		-p kenneld -p kennel-netproxy
	# The privhelper needs its BPF feature; build it separately.
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
	run install -d -m 0755 "$prefix/bin" "$prefix/sbin"
	# Unprivileged binaries (mode 0755).
	local b
	for b in kenneld kennel kennel-netproxy; do
		run install -m 0755 "$rel/$b" "$prefix/bin/$b"
	done
	# The privhelper: setuid root (mode 4755, owner root). This is the one
	# privilege boundary; everything else runs as the user.
	run install -m 0755 -o root -g root "$rel/kennel-privhelper" "$prefix/sbin/kennel-privhelper"
	run chmod 4755 "$prefix/sbin/kennel-privhelper"
}

install_units() {
	run install -d -m 0755 "$units_dir"
	run install -m 0644 "$repo_root/dist/systemd/kenneld.socket" "$units_dir/kenneld.socket"
	run install -m 0644 "$repo_root/dist/systemd/kenneld.service" "$units_dir/kenneld.service"
}

install_etc_skeleton() {
	# Root-owned configuration root. `keys/` is the runtime trust store
	# (07-paths.md §/etc, consumed by the CLI's load_trust_store); org-specific
	# keys and the per-user allocations are provisioned by the admin.
	run install -d -m 0755 /etc/kennel /etc/kennel/keys /etc/kennel/policies
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

print_next_steps() {
	cat <<EOF

Project Kennel: system install complete under $prefix.

Remaining admin steps (root):
  1. Provision /etc/kennel/subkennel with one allocation line per user:
       <uid>:<tag>:<gid>:<namespace>      e.g.  1000:42:0000000001:kennel-alice
  2. Install the installation constants in /etc/kennel/scope (the tag + ULA GID
     the privhelper validates against).
  3. Add any org/customer policy-signing public keys to /etc/kennel/keys/<key_id>.pub.
     (The project's own template-signing key is already installed there.)

Per-user enable (each user, unprivileged):
       systemctl --user enable --now kenneld.socket

Verify the privhelper is setuid-root:
       ls -l $prefix/sbin/kennel-privhelper      # expect -rwsr-xr-x root root
EOF
}

build_binaries
require_root
install_binaries
install_units
install_etc_skeleton
install_keys
[ "$dry_run" -eq 1 ] || print_next_steps
