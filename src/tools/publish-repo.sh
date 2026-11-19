#!/usr/bin/env bash
#
# Project Kennel — publish the signed repo tree to Cloudflare R2 (S3 API).
#
# Runs on the operator's machine as the last release step, AFTER build-repo.sh has signed
# everything. R2 only ever receives already-signed bytes: the signing key is never here,
# and the R2 credentials sign nothing — a leak of them can serve stale or denied content,
# never a forged package (that would need the offline GPG key). The bucket is fronted by a
# Cloudflare custom domain (packages.projectkennel.org); cache tiering and the root→index
# redirect are Cloudflare Rules on that domain, NOT object metadata (see below / the
# release ceremony).
#
# Credentials come from the environment, or a gitignored `.env` (auto-loaded from the repo
# root, or --env-file). Either the R2/AWS names or the natural R2 names work:
#   R2_ENDPOINT   | S3_API_URL          the R2 S3 endpoint (https://<accountid>.r2…com)
#   R2_BUCKET     | S3_BUCKET_NAME      the bucket (projectkennel-packages)
#   AWS_ACCESS_KEY_ID     | ACCESS_KEY_ID       the R2 API token's Access Key ID
#   AWS_SECRET_ACCESS_KEY | SECRET_ACCESS_KEY   the R2 API token's Secret (sha256 of the token)
# The token is bucket-scoped Object Read & Write; it SIGNS NOTHING (see above).
#
# Usage:
#   publish-repo.sh [--repo dist/repo] [--env-file .env] [--dry-run]
#
# Requires the AWS CLI (`aws`, S3-compatible; talks to R2 via --endpoint-url).

set -euo pipefail

repo="dist/repo"
dry=""
env_file=""

while [[ $# -gt 0 ]]; do
	case "$1" in
		--repo)     repo="${2:?}"; shift 2 ;;
		--env-file) env_file="${2:?}"; shift 2 ;;
		--dry-run)  dry="--dryrun"; shift ;;
		-*) echo "publish-repo.sh: unknown argument: $1" >&2; exit 2 ;;
		*)  echo "publish-repo.sh: unexpected argument: $1" >&2; exit 2 ;;
	esac
done

# Load an env file if given, or the repo-root .env if present (gitignored secrets). KEY=VALUE
# lines only — sourced with `set -a` so the values export to the aws CLI.
[[ -z "$env_file" && -f ".env" ]] && env_file=".env"
if [[ -n "$env_file" ]]; then
	[[ -f "$env_file" ]] || { echo "publish-repo.sh: --env-file '$env_file' not found" >&2; exit 2; }
	set -a; . "$env_file"; set +a
fi

# Accept the natural R2 naming (as in .env) and map to what the aws CLI + this script expect,
# without overriding anything already set explicitly. Exported so the aws child inherits the
# credentials (a bare assignment would not reach it).
export R2_ENDPOINT="${R2_ENDPOINT:-${S3_API_URL:-}}"
export R2_BUCKET="${R2_BUCKET:-${S3_BUCKET_NAME:-}}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-${ACCESS_KEY_ID:-}}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-${SECRET_ACCESS_KEY:-}}"

[[ -d "$repo" ]] || { echo "publish-repo.sh: '$repo' not found — run build-repo.sh first" >&2; exit 2; }
[[ -f "$repo/deb/dists"/*/InRelease ]] 2>/dev/null || [[ -n "$(find "$repo/deb/dists" -name InRelease 2>/dev/null)" ]] \
	|| { echo "publish-repo.sh: '$repo' has no signed APT InRelease — is this a build-repo.sh tree?" >&2; exit 1; }
command -v aws >/dev/null 2>&1 || { echo "publish-repo.sh: the AWS CLI (aws) is required to talk to R2" >&2; exit 1; }
: "${R2_ENDPOINT:?set R2_ENDPOINT to the R2 S3 endpoint (https://<accountid>.r2.cloudflarestorage.com)}"
: "${R2_BUCKET:?set R2_BUCKET to the bucket name (projectkennel-packages)}"
: "${AWS_ACCESS_KEY_ID:?set AWS_ACCESS_KEY_ID to the R2 API token's Access Key ID}"
: "${AWS_SECRET_ACCESS_KEY:?set AWS_SECRET_ACCESS_KEY to the R2 API token's Secret Access Key}"

# R2 S3-API compatibility, defaulted so a fresh operator box just works:
#  - R2 requires the region to be `auto`;
#  - aws-cli v2 >= 2.23 sends CRC integrity checksums R2 rejects (HTTP 400 / "not
#    implemented") — request/validate them only when the operation actually needs one.
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-auto}"
export AWS_REQUEST_CHECKSUM_CALCULATION="${AWS_REQUEST_CHECKSUM_CALCULATION:-when_required}"
export AWS_RESPONSE_CHECKSUM_VALIDATION="${AWS_RESPONSE_CHECKSUM_VALIDATION:-when_required}"

# Every object gets a SAFE uniform cache header: metadata and the key MUST revalidate so a
# fresh publish is seen; packages may be cached far longer, but that is an OPTIMISATION
# applied by a Cloudflare Cache Rule on the custom domain (match /deb/pool/* and
# /rpm/*/*.rpm → Edge TTL 1y, immutable), never a shorter-is-wrong default here. Correctness
# (metadata freshness) lives in the object header; performance (package longevity) lives in
# the Cache Rule. R2 has no per-file size cap, so large packages are fine.
#
# Three steps, never `aws s3 sync --delete`. Over a live tree, aws-cli's sync compares the
# local and remote listings in different orders and planned to upload AND THEN delete the
# same key for `Release`, `Packages` and `repomd.xml` (they sort next to `Release.gpg` and
# `Packages.gz`). That would leave the repo without its signed metadata: every `apt update`
# and `dnf` refresh fails. So:
#   1. upload the packages and the content-addressed repodata, which nothing names yet;
#   2. upload everything else: the signed metadata that names them, the key, the index;
#   3. delete, one by one, only the remote keys absent from the new tree.
# A client therefore never sees metadata that points at a missing file, and a key the new
# tree contains is never deleted.
cache="public, max-age=300, must-revalidate"
s3_sync() {
	aws s3 sync "$repo" "s3://$R2_BUCKET" \
		--endpoint-url "$R2_ENDPOINT" \
		--no-progress \
		--cache-control "$cache" \
		$dry "$@"
}

echo "publish-repo.sh: [1/3] packages + repodata → s3://$R2_BUCKET (R2) ${dry:+[dry-run]}"
s3_sync --exclude '*' --include '*.deb' --include '*.rpm' --include '*/repodata/*.xml.zst'

echo "publish-repo.sh: [2/3] signed metadata, key, index → s3://$R2_BUCKET ${dry:+[dry-run]}"
s3_sync

# The bucket listing comes from `aws s3 ls --recursive` ("<date> <time> <size> <key>"), not
# `aws s3api`, which fails outright on some aws-cli builds ("badly formed help string").
# A failed listing stops here: treating it as an empty bucket would silently retire nothing.
# Byte-order (C) collation on both sides, so the set difference is exact.
local_keys="$(cd "$repo" && find . -type f | sed 's#^\./##' | LC_ALL=C sort)"
if ! listing="$(aws s3 ls "s3://$R2_BUCKET/" --recursive --endpoint-url "$R2_ENDPOINT")"; then
	echo "publish-repo.sh: could not list s3://$R2_BUCKET; uploaded, but retired nothing" >&2
	exit 1
fi
remote_keys="$(printf '%s\n' "$listing" | sed -nE 's/^[0-9-]+ [0-9:]+ +[0-9]+ //p' | LC_ALL=C sort)"
retired="$(LC_ALL=C comm -23 <(printf '%s\n' "$remote_keys" | sed '/^$/d') \
	<(printf '%s\n' "$local_keys"))"

echo "publish-repo.sh: [3/3] retiring $(printf '%s' "$retired" | grep -c . || true) object(s) absent from $repo ${dry:+[dry-run]}"
while IFS= read -r key; do
	[[ -n "$key" ]] || continue
	if [[ -e "$repo/$key" ]]; then
		echo "publish-repo.sh: refusing to delete '$key': it is in the new tree" >&2
		exit 1
	fi
	if [[ -n "$dry" ]]; then
		echo "(dryrun) delete: s3://$R2_BUCKET/$key"
	else
		aws s3 rm "s3://$R2_BUCKET/$key" --endpoint-url "$R2_ENDPOINT"
	fi
done <<<"$retired"

echo "publish-repo.sh: done. Verify the live repo before announcing:"
echo "  apt:  add the repo on a clean box and 'apt update' (fails closed if the signature is wrong)"
echo "  dnf:  'dnf install kennel' with gpgcheck=1 + repo_gpgcheck=1"
