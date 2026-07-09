#!/usr/bin/env bash
#
# W15 grep gate: keep designed-on-paper-but-never-built mechanisms out of the corpus.
#
# These three names denote mechanisms that were sketched in early design notes and then
# never built (and never will be), each superseded by a real, shipped mechanism:
#
#   xdg-dbus-proxy     → the D-Bus carrier is the org.projectkennel.IDBus facade (§7.7)
#   per-kennel ssh-agent → SSH egress is the §7.10 re-origination bastion
#   IGpgAgent          → GPG signing is not brokered (§11.2)
#
# Per the docs standard, a never-built mechanism is deleted outright — no tombstone, no
# "we don't do X" marker (the marker is itself the apology pattern). This gate fails CI if
# any reappear, so the cleanup does not silently regress.
#
# The ROADMAP and CHANGELOG are excluded: they are the legitimate historical record of the
# purge (the ROADMAP's W15 entry defines this very gate).

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$repo_root"

# The forbidden literals. `per-kennel ssh-agent` (not bare `ssh-agent`): forwarding an
# ssh-agent through [unix].allow is a real, deliberately-permitted footgun that is loudly
# warned, so the bare term legitimately appears in that footgun documentation and code.
patterns=("xdg-dbus-proxy" "per-kennel ssh-agent" "IGpgAgent")

status=0
for pat in "${patterns[@]}"; do
    # Search docs/ and src/, excluding the historical record.
    hits="$(grep -rn -- "$pat" docs/ src/ 2>/dev/null \
        | grep -vE 'docs/governance/ROADMAP-0\.2\.0\.md|CHANGELOG\.md|no-never-built-mechanisms\.sh' || true)"
    if [[ -n "$hits" ]]; then
        echo "FAIL: never-built mechanism '$pat' found (deleted outright, no tombstone):" >&2
        echo "$hits" >&2
        status=1
    fi
done

if [[ "$status" -eq 0 ]]; then
    echo "ok: no never-built-mechanism residue (${patterns[*]})"
fi
exit "$status"
