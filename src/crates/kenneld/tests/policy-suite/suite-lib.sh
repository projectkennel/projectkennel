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
	[[ -n "$name" ]] || { echo "suite-lib: no name/template_name in $src" >&2; return 1; }
	rm -rf "${SUITE_POLICY_REPO:?}/$name"
	mkdir -p "$SUITE_POLICY_REPO/$name"
	cp "$src" "$SUITE_POLICY_REPO/$name/policy.toml"
	"$KENNEL" policy compile "$name" --key "$SUITE_KEY" ${KEYS:+--trust-dir "$KEYS"} >&2 || return 1
	echo "$name"
	return 0
}

# suite_unstage <name> — remove a staged policy from the user repo (cleanup: a dirty repo
# makes the NEXT run resolve stale artefacts).
suite_unstage() {
	local name="$1"
	rm -rf "${SUITE_POLICY_REPO:?}/$name"
}

# ── The shared hook scaffolding (0.7.0) ─────────────────────────────────────
#
# Every self-driving `run.sh` used to hand-roll the same four shapes: the argv prologue,
# a monolithic cleanup trap, the ondemand-provider enablement + teardown, and the
# stage-consumer-and-run tail whose exit code is the verdict. One implementation each.

# suite_case "$@" — the standard hook prologue. Unpacks the driver's argv
# (case-dir, installed CLI, suite key, scratch) into CASE_DIR/KENNEL/SUITE_KEY/SCRATCH,
# derives CFG/KEYS/ONDEMAND, and arms the composable cleanup trap (see suite_defer).
suite_case() {
	CASE_DIR="$1"
	KENNEL="$2"
	SUITE_KEY="$3"
	SCRATCH="${4:-$(mktemp -d)}"
	CFG="${XDG_CONFIG_HOME:-$HOME/.config}/kennel"
	KEYS="$CFG/keys"
	ONDEMAND="$CFG/ondemand"
	SUITE_CLEANUPS=()
	trap suite_run_cleanups EXIT
}

# suite_defer <command…> — push a cleanup command, run LIFO at exit, failures ignored
# (cleanup must never mask the case verdict). Composable: every fixture registers its
# own teardown instead of growing one monolithic cleanup().
suite_defer() {
	local command="$*"
	SUITE_CLEANUPS+=("$command")
}

suite_run_cleanups() {
	local i
	for ((i = ${#SUITE_CLEANUPS[@]} - 1; i >= 0; i--)); do
		eval "${SUITE_CLEANUPS[$i]}" 2>/dev/null || true
	done
}

# suite_enable_ondemand <source.toml> <provider-name> — compile + sign a provider to its
# settled form AT the ondemand enablement link (the entry IS the signed settled policy the
# daemon load-verifies, §7.13.6), refresh the catalogue, and defer the teardown: stop the
# activated instance BEFORE unlinking (a still-running provider would sit on the name and
# starve later cases), unlink, reload.
suite_enable_ondemand() {
	local src="$1" name="$2"
	mkdir -p "$ONDEMAND"
	"$KENNEL" policy compile "$src" --key "$SUITE_KEY" --trust-dir "$KEYS" 		--no-lock --output "$ONDEMAND/$name"
	"$KENNEL" daemon-reload
	suite_defer "\"$KENNEL\" stop $name >/dev/null 2>&1; rm -f \"$ONDEMAND/$name\"; \"$KENNEL\" daemon-reload >/dev/null 2>&1"
	return 0
}

# suite_vendor_trust_suite_key — the vendor-provenance fixture (§7.13.5): a test provider
# claiming `org.projectkennel.*` needs a VENDOR-tier signature. The real deployment ships
# maintainer-signed brokers; the suite authorizes its own key as vendor instead — the
# fixture equivalent of "the project signs the broker". Removal deferred.
suite_vendor_trust_suite_key() {
	sudo install -m 0644 "$SUITE_KEY.pub" /usr/lib/kennel/keys/kennel-suite.pub
	suite_defer "sudo rm -f /usr/lib/kennel/keys/kennel-suite.pub"
}

# suite_run_consumer <source.toml> — stage + compile the consumer leaf (unstage deferred)
# and run it by name; the workload exit code — the suite verdict — passes through.
# No `exec`: the cleanup trap must fire when the consumer exits.
suite_run_consumer() {
	local src="$1" name
	name="$(suite_compile "$src")" || return 1
	suite_defer "suite_unstage $name"
	"$KENNEL" run "$name" "$name" </dev/null
	return "$?"
}
