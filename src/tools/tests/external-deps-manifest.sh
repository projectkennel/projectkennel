#!/usr/bin/env bash
#
# Guard: every external binary kennel invokes is declared in dist/dependencies.toml.
#
# The rot this catches: the dependency list lived nowhere — install.sh assumed apt-world
# binaries, the OCI path shelled out to skopeo/umoci that no document mentioned, and the
# packaging manifests would each have grown their own hand-maintained copy. This gate pins
# one source of truth: a shell-out added to the code without a manifest entry fails CI.
#
# Two mines, both build-free:
#   * `Command::new("...")` call sites in non-test crate sources (string literals only;
#     paths reduce to their basename);
#   * command-position binaries in embedded ceremony scripts (the `if ! <bin> ` shape the
#     OCI fetch script uses).
# Test-only invocations (tests/ trees) are CI's affair, not a user-machine dependency, and
# are excluded. The reverse direction is checked too: a manifest [[dep]] whose binary no
# call site nor provider policy references any more is stale and fails, so the manifest
# cannot rot into fiction.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$repo_root"

manifest="dist/dependencies.toml"
[[ -f "$manifest" ]] || { echo "FAIL: $manifest missing"; exit 1; }

# Binaries declared in the manifest ([[dep]] bin = "..." lines).
declared="$(grep -oP '^bin = "\K[^"]+' "$manifest" | sort -u)"

# ── mine 1: Command::new string literals in non-test sources ────────────────────────
# In-file `#[cfg(test)]` modules are last in every file here (clippy-enforced), so
# truncating each file at the first `#[cfg(test)]` excludes in-file test scaffolding.
mined_cmd="$(find src/crates src/tools -name '*.rs' -not -path '*/tests/*' -print0 \
	| xargs -0 python3 -c '
import re, sys
seen = set()
for path in sys.argv[1:]:
    text = open(path, encoding="utf-8").read().split("#[cfg(test)]")[0]
    for m in re.finditer(r"Command::new\(\s*\"([^\"]+)\"", text):
        seen.add(m.group(1).rsplit("/", 1)[-1])
print("\n".join(sorted(seen)))
' | sort -u)"

# ── mine 2: embedded-script shapes inside .rs strings ───────────────────────────────
# `if ! <bin> ` command positions (the OCI fetch script), plus interpreter argv
# literals (`"/bin/sh"`) that exec inside the cage without Command::new.
mined_script="$({ grep -rhoP 'if ! \K[a-z][a-z0-9_-]+(?= )' src/crates --include='*.rs' \
	--exclude-dir=tests;
	grep -rhoP '"/bin/\K(sh|dash|bash)(?="\.to_owned)' src/crates --include='*.rs' \
	--exclude-dir=tests; } | sort -u)"

# ── mine 3: installer ceremony binaries install.sh + install-lib.sh invoke ──────────
# Command positions only (line start, `run` wrapper, && / || / if), not prose or paths.
mined_install="$(grep -ohP '(^|\t| {2,}|run |&& |\|\| |if ! |if )\K(systemctl|setcap|modprobe|apparmor_parser|ssh-keygen|semodule|restorecon)(?= )' \
	src/tools/install.sh src/tools/install-lib.sh | sort -u)"

fail=0

# Forward: every mined binary must be declared (or be a workspace-internal binary).
kennel_bins="$(cargo metadata --no-deps --format-version 1 2>/dev/null \
	| python3 -c 'import json,sys; d=json.load(sys.stdin); print("\n".join(t["name"] for p in d["packages"] for t in p["targets"] if "bin" in t["kind"]))' \
	2>/dev/null || true)"

for bin in $mined_cmd $mined_script $mined_install; do
	if grep -qxF "$bin" <<<"$kennel_bins"; then
		continue # our own binary, not an external dependency
	fi
	if ! grep -qxF "$bin" <<<"$declared"; then
		echo "FAIL: '$bin' is invoked by the code/installer but not declared in $manifest"
		fail=1
	fi
done

# Reverse: every declared binary must still be referenced somewhere real.
all_mined="$(printf '%s\n%s\n%s\n' "$mined_cmd" "$mined_script" "$mined_install" | sort -u)"
provider_bins="$(grep -rhoP '"/usr/bin/\K[a-z0-9_-]+(?=")' toml/policies/providers/ | sort -u)"
for bin in $declared; do
	if grep -qxF "$bin" <<<"$all_mined" || grep -qxF "$bin" <<<"$provider_bins"; then
		continue
	fi
	echo "FAIL: manifest declares '$bin' but no call site nor provider policy references it (stale entry?)"
	fail=1
done

[[ $fail -eq 0 ]] && echo "OK: dependency manifest matches the call sites (forward + reverse)"
exit $fail
