#!/usr/bin/env bash
# Tests for tools/publish-repo.sh (CODING-STANDARDS.md §15.4 spirit).
#
# Drives the publisher against a fake `aws` on PATH that records every call and serves a
# fixture bucket listing, so no network or R2 account is needed. What it pins down:
#
#   * no `aws s3 sync --delete`: aws-cli's sync compares the local and remote listings in
#     different orders, and on an update over a live tree it planned to upload AND THEN
#     delete `Release`, `Packages` and `repomd.xml` (the 0.8.0 publish, where `Release`
#     sorts next to `Release.gpg` and `Packages` next to `Packages.gz`). A live repo
#     without its signed metadata fails every `apt update` and `dnf` refresh;
#   * the packages and content-addressed repodata go up before the signed metadata that
#     names them, so a client never sees metadata pointing at a missing file;
#   * only keys absent from the new tree are deleted, one by one, after both uploads;
#   * --dry-run uploads nothing for real and deletes nothing.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PUBLISH="$HERE/../publish-repo.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

check() {
	local name="$1"
	shift
	if "$@"; then
		pass=$((pass + 1))
	else
		fail=$((fail + 1))
		echo "FAIL: $name" >&2
	fi
}

# A build-repo.sh-shaped tree: the 0.8.0 packages, their repodata, and the signed metadata.
make_tree() {
	local r="$1" f
	for f in \
		deb/dists/stable/InRelease \
		deb/dists/stable/Release \
		deb/dists/stable/Release.gpg \
		deb/dists/stable/main/binary-amd64/Packages \
		deb/dists/stable/main/binary-amd64/Packages.gz \
		deb/dists/stable/main/binary-amd64/Release \
		deb/pool/main/k/kennel/kennel_0.8.0_amd64.deb \
		rpm/kennel.repo \
		rpm/x86_64/kennel-0.8.0-1.x86_64.rpm \
		rpm/x86_64/repodata/aaaa-primary.xml.zst \
		rpm/x86_64/repodata/repomd.xml \
		rpm/x86_64/repodata/repomd.xml.asc \
		fingerprint.txt \
		index.html \
		kennel-archive-keyring.asc; do
		mkdir -p "$r/$(dirname "$f")"
		echo "$f" >"$r/$f"
	done
}

# The live bucket before the publish: the same metadata names, plus the 0.7.1 packages and
# their old repodata, which the publish must retire.
cat >"$TMP/remote.keys" <<-'EOF'
	deb/dists/stable/InRelease
	deb/dists/stable/Release
	deb/dists/stable/Release.gpg
	deb/dists/stable/main/binary-amd64/Packages
	deb/dists/stable/main/binary-amd64/Packages.gz
	deb/dists/stable/main/binary-amd64/Release
	deb/pool/main/k/kennel/kennel_0.7.1_amd64.deb
	rpm/kennel.repo
	rpm/x86_64/kennel-0.7.1-1.x86_64.rpm
	rpm/x86_64/repodata/zzzz-primary.xml.zst
	rpm/x86_64/repodata/repomd.xml
	rpm/x86_64/repodata/repomd.xml.asc
	fingerprint.txt
	index.html
	kennel-archive-keyring.asc
EOF

# The fake aws: log each call (one line, args joined by a unit separator) and answer the
# recursive bucket listing from remote.keys in `aws s3 ls --recursive` format
# ("<date> <time> <size> <key>"). FAKE_AWS_LS_FAIL=1 makes the listing fail, as `aws s3api`
# does on some aws-cli builds ("badly formed help string") — the publisher must stop then,
# not take the failure for an empty bucket.
mkdir -p "$TMP/bin"
cat >"$TMP/bin/aws" <<-'EOF'
	#!/usr/bin/env bash
	( IFS=$'\x1f'; echo "$*" ) >>"$FAKE_AWS_LOG"
	if [[ "$1 $2" = "s3 ls" ]]; then
		if [[ "${FAKE_AWS_LS_FAIL:-0}" = 1 ]]; then
			echo "simulated listing failure" >&2
			exit 255
		fi
		while IFS= read -r key; do
			[[ -n "$key" ]] && printf '2026-07-15 15:07:08 %10d %s\n' 42 "$key"
		done <"$FAKE_AWS_REMOTE"
	fi
	exit 0
EOF
chmod +x "$TMP/bin/aws"

# run_publish <log> [args…] — publish the fixture tree with the fake aws and dummy creds.
run_publish() {
	local log="$1"
	shift
	: >"$log"
	(
		cd "$TMP"
		PATH="$TMP/bin:$PATH" FAKE_AWS_LOG="$log" FAKE_AWS_REMOTE="$TMP/remote.keys" \
			R2_ENDPOINT=https://example.invalid R2_BUCKET=test-bucket \
			AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
			"$PUBLISH" --repo "$TMP/repo" "$@" >"$log.out" 2>&1
	)
}

make_tree "$TMP/repo"

# ── a real publish ────────────────────────────────────────────────────────────────────
LOG="$TMP/real.log"
check "publish exits 0" run_publish "$LOG"

# Line numbers of each kind of call, in order.
syncs() { { grep -n $'^s3\x1fsync' "$LOG" || true; } | cut -d: -f1; }
rms() { { grep -n $'^s3\x1frm' "$LOG" || true; } | cut -d: -f1; }
first_sync="$(syncs | sed -n 1p)"
second_sync="$(syncs | sed -n 2p)"
first_rm="$(rms | sed -n 1p)"

no_delete_flag() { ! grep -q $'\x1f--delete' "$LOG"; }
check "no aws call uses --delete" no_delete_flag

two_syncs() { [[ "$(syncs | wc -l)" -eq 2 ]]; }
check "exactly two syncs" two_syncs

packages_first() {
	local line
	[[ -n "$first_sync" ]] || return 1
	line="$(sed -n "${first_sync}p" "$LOG")"
	[[ "$line" == *$'\x1f--exclude\x1f*'* && "$line" == *'*.deb'* && "$line" == *'*.rpm'* \
		&& "$line" == *'repodata/*.xml.zst'* ]]
}
check "the first sync uploads only packages and repodata" packages_first

metadata_second() {
	local line
	[[ -n "$second_sync" ]] || return 1
	line="$(sed -n "${second_sync}p" "$LOG")"
	[[ -n "$second_sync" && "$second_sync" -gt "$first_sync" && "$line" != *'--exclude'* ]]
}
check "the second sync uploads the rest, after the packages" metadata_second

deletes_last() { [[ -n "$first_rm" && "$first_rm" -gt "$second_sync" ]]; }
check "deletes come after both uploads" deletes_last

deleted_keys() {
	{ grep $'^s3\x1frm' "$LOG" || true; } | tr $'\x1f' '\n' | sed -n 's#^s3://test-bucket/##p' | LC_ALL=C sort
}
retires_exactly_the_stale_keys() {
	diff <(deleted_keys) <(LC_ALL=C sort <<-'EOF'
		deb/pool/main/k/kennel/kennel_0.7.1_amd64.deb
		rpm/x86_64/kennel-0.7.1-1.x86_64.rpm
		rpm/x86_64/repodata/zzzz-primary.xml.zst
	EOF
	) >/dev/null
}
check "deletes exactly the keys absent from the new tree" retires_exactly_the_stale_keys

never_deletes_metadata() { ! deleted_keys | grep -qE '(Release|Release\.gpg|InRelease|Packages|Packages\.gz|repomd\.xml)$'; }
check "never deletes Release, Packages or repomd.xml" never_deletes_metadata

# ── a dry run ─────────────────────────────────────────────────────────────────────────
DRY="$TMP/dry.log"
check "dry run exits 0" run_publish "$DRY" --dry-run

dry_syncs_are_dry() {
	[[ "$(grep -c $'^s3\x1fsync' "$DRY")" -eq 2 && "$(grep $'^s3\x1fsync' "$DRY" | grep -vc $'\x1f--dryrun')" -eq 0 ]]
}
check "dry run passes --dryrun to both syncs" dry_syncs_are_dry

dry_deletes_nothing() { ! grep -q $'^s3\x1frm' "$DRY"; }
check "dry run deletes nothing" dry_deletes_nothing

dry_names_the_retired_keys() { grep -q 'kennel_0.7.1_amd64.deb' "$DRY.out"; }
check "dry run names the keys it would delete" dry_names_the_retired_keys

# ── an empty bucket (the first publish) ───────────────────────────────────────────────
: >"$TMP/remote.keys"
FIRST="$TMP/first.log"
check "first publish into an empty bucket exits 0" run_publish "$FIRST"
first_deletes_nothing() { ! grep -q $'^s3\x1frm' "$FIRST"; }
check "first publish deletes nothing" first_deletes_nothing

# ── the bucket listing fails ──────────────────────────────────────────────────────────
printf '%s\n' deb/pool/main/k/kennel/kennel_0.7.1_amd64.deb >"$TMP/remote.keys"
LSFAIL="$TMP/lsfail.log"
listing_failure_fails() { ! FAKE_AWS_LS_FAIL=1 run_publish "$LSFAIL"; }
check "a failed bucket listing fails the publish" listing_failure_fails
listing_failure_deletes_nothing() { ! grep -q $'^s3\x1frm' "$LSFAIL"; }
check "a failed bucket listing deletes nothing" listing_failure_deletes_nothing

echo "publish-repo.sh tests: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
