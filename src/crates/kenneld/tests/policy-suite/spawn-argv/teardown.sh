#!/usr/bin/env bash
#
# Remove the suite-signed settled argv-tool the case installed into the user template cascade.
#   $1 = scratch dir (unused).
set -uo pipefail
rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/kennel/templates/argv-tool"
