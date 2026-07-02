#!/bin/sh
# run-claude.sh — in-view launcher for the `claude` reference policy.
#
# The pinned [workload] of policies/claude. Runs INSIDE the kennel: the view already
# contains only what the policy granted, so this script's job is discovery, not
# restriction — find the claude entry point across install layouts and exec it with
# the caller's appended args (allowed_args).
set -eu

if [ -x "$HOME/.local/bin/claude" ]; then
	exec "$HOME/.local/bin/claude" "$@"
fi
for m in /usr/lib/node_modules /usr/local/lib/node_modules; do
	if [ -e "$m/@anthropic-ai/claude-code/cli.js" ]; then
		exec /usr/bin/node "$m/@anthropic-ai/claude-code/cli.js" "$@"
	fi
done
echo "run-claude: no claude install found in the view" >&2
echo "run-claude: the shipped policy grants ~/.local/{bin,share}/claude and the npm layout;" >&2
echo "run-claude: install Claude Code, or derive a leaf granting your install location" >&2
exit 127
