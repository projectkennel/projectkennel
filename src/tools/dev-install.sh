#!/usr/bin/env bash
# Project Kennel — dev rebuild + reinstall, in one command.
#
# The fast path that is ALSO the correct path. The release payload needs each binary built a
# specific way, and `stage-tree.sh` routes each from the right directory:
#
#   * host-side bins (kenneld, the delegates, the privhelper, the `kennel-host` unit) — DYNAMIC
#     (glibc), from target/release;
#   * in-view bins (the facades, kennel-bin-init, the `kennel` shim, the brokers) — STATIC
#     (`+crt-static`: they run inside a constructed view with no host ld.so), from
#     target/<triple>/release;
#   * the privhelper additionally with `bpf-egress`, so its cgroup BPF is embedded (needs clang).
#
# Getting that dynamic/static split wrong by hand — or forgetting `kennel-host` installs as `host`
# — is the per-iteration puzzle this script removes. It builds the workspace BOTH ways (native,
# NOT byte-reproducible — this is dev, not a release), then hands off to the SAME stage-tree.sh +
# install.sh a real install uses. stage-tree.sh stays the single source of truth for the layout.
#
# For a byte-reproducible, cross-arch, packaged tarball, use build-release.sh; this is its dev sibling.
#
# Usage:
#   src/tools/dev-install.sh [--with-test-bins]
#     --with-test-bins   also stage the e2e probe binaries (facade-spawn-probe, …)
#
# Builds run as you; the install step calls sudo. Reviewed like any other code
# (CODING-STANDARDS.md §15.4): set -euo pipefail, no network, idempotent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TRIPLE="$(uname -m)-unknown-linux-gnu"
STAGE_ARGS=()
while [ $# -gt 0 ]; do
	case "$1" in
		--with-test-bins) STAGE_ARGS+=(--with-test-bins); shift ;;
		-h|--help) sed -n '2,26p' "$0"; exit 0 ;;
		*) echo "dev-install.sh: unknown argument: $1" >&2; exit 2 ;;
	esac
done

cd "$ROOT/src"

echo "==> host-side bins, dynamic (→ target/release)"
cargo build --release --offline --frozen --locked

echo "==> privhelper with bpf-egress (→ target/release; embeds its cgroup BPF, needs clang)"
cargo build --release --offline --frozen --locked -p kennel-privhelper --features bpf-egress

echo "==> in-view bins, static +crt-static (→ target/$TRIPLE/release)"
RUSTFLAGS="-C target-feature=+crt-static" \
	cargo build --release --offline --frozen --locked --target "$TRIPLE"

# Assemble the flat payload exactly as a release does — stage-tree.sh owns which binary comes from
# which dir. Its defaults (--rel target/release, --stat target/<triple>/release) match the two
# builds above, so no --rel/--stat is passed here.
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
"$ROOT/src/tools/stage-tree.sh" --dest "$stage" "${STAGE_ARGS[@]}"

echo "==> installing (sudo)"
sudo bash "$stage/install.sh"

# The running daemon holds the OLD binary open; restart so the freshly-installed one serves.
systemctl --user restart kenneld.service 2>/dev/null || true
echo "==> dev-install complete; kenneld restarted."
