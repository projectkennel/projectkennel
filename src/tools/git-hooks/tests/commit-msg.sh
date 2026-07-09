#!/usr/bin/env bash
# Integration tests for the commit-msg hook (CODING-STANDARDS.md §15.4).
#
# Runs the hook against known-good and known-bad messages and asserts its exit
# status. Self-contained: no git repository state is needed for the message-
# format rules (the secret scan, which needs staged content, is covered by the
# hook's own guards and is not exercised here).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
HOOK="$HERE/../commit-msg"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

# expect <0|1> <name> <message...>
expect() {
	local want="$1" name="$2"
	local msg="$3"
	local file="$TMP/msg"
	printf '%s' "$msg" >"$file"
	local got=0
	"$HOOK" "$file" >/dev/null 2>&1 || got=$?
	# Normalise any nonzero to 1 (we only care accept vs reject).
	[[ "$got" -ne 0 ]] && got=1
	if [[ "$got" -eq "$want" ]]; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1))
		echo "FAIL: $name (wanted exit $want, got $got)" >&2
	fi
}

# ---- accepted ----
expect 0 "feat with body" "feat(text): add sanitisers

Body explaining the why."
expect 0 "fix with body" "fix(bpf): correct v6 ctx access

Verifier rejected the memcpy."
expect 0 "docs no body" "docs: expand the build-env notes"
expect 0 "test no body" "test(syscall): canonicalise_path scaffold"
expect 0 "scope with dot" "build(release-image): pin digest"
expect 0 "breaking change marker" "feat(ipc)!: change the frame header

Drops the legacy field."

# ---- rejected ----
expect 1 "unknown type" "feature: add a thing"
expect 1 "no type" "just did some stuff"
expect 1 "feat without body" "feat(text): add sanitisers"
expect 1 "fix without body" "fix: a thing"
expect 1 "empty message" ""
expect 1 "summary too long" "feat: $(printf 'x%.0s' $(seq 1 80))"

# ---- body line length ----
expect 1 "body line too long" "docs: tweak

$(printf 'y%.0s' $(seq 1 120))"

echo "commit-msg tests: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
