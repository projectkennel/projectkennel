# Shared dogfood helpers for the policy-suite `run.sh` hooks (0.7.0 W1).
#
# Every workload boots via the operator's golden path, verbatim: stage the case source into
# the user policy repo, `kennel policy compile <name>` (the authoring house; `--key` and
# `--trust-dir` are compile-house flags), then `kennel run <name>` on the SETTLED artefact by
# name. No compile-side flags ever appear on `kennel run` — the settled pass-through is
# exactly the path production runs.
#
# Callers (sourced, not executed) provide: $KENNEL, $SUITE_KEY; optionally $KEYS (an extra
# trust dir for suite-signed spawn targets).

SUITE_POLICY_REPO="${XDG_CONFIG_HOME:-$HOME/.config}/kennel/policies"

# suite_compile <source.toml> — stage into the user repo + compile; prints the policy name.
# The staged name is the policy's OWN `name`/`template_name` (the settled artefact and the
# run-by-name lookup both key on it).
suite_compile() {
	local src="$1" name
	name=$(sed -n -E 's/^(template_)?name = "(.*)"/\2/p' "$src" | head -n1)
	[ -n "$name" ] || { echo "suite-lib: no name/template_name in $src" >&2; return 1; }
	rm -rf "${SUITE_POLICY_REPO:?}/$name"
	mkdir -p "$SUITE_POLICY_REPO/$name"
	cp "$src" "$SUITE_POLICY_REPO/$name/policy.toml"
	"$KENNEL" policy compile "$name" --key "$SUITE_KEY" ${KEYS:+--trust-dir "$KEYS"} >&2 || return 1
	echo "$name"
}

# suite_unstage <name> — remove a staged policy from the user repo (cleanup: a dirty repo
# makes the NEXT run resolve stale artefacts).
suite_unstage() {
	rm -rf "${SUITE_POLICY_REPO:?}/$1"
}
