#!/usr/bin/env bash
#
# Project Kennel — build the self-hosted, self-signed APT + DNF package repositories.
#
# The trust path is entirely the project's own: no third-party build service, no
# community mirror, no `curl | sh`. A user adds the repo, imports ONE public key whose
# fingerprint is cross-checkable against the website, the GitHub release, and DNS, and
# thereafter apt/dnf verify every byte against it. Cloudflare Pages (or any static host)
# only ever serves ALREADY-SIGNED bytes — the signing key never touches the CDN or CI.
#
# What that buys, in threat terms: a compromise of the hosting/CDN can serve stale signed
# content or deny service, but cannot forge or alter a package — it holds no key. The blast
# radius that must be defended is the signing key itself (arbitrary code as root on every
# install), so it is signed locally on a trusted machine and this script never generates or
# transmits it: it signs with a key already in the caller's GNUPGHOME.
#
# Layout produced under --out (served at --base-url):
#   deb/                         APT repo (reprepro): dists/ + pool/, Release InRelease Release.gpg
#   rpm/<arch>/                  DNF repo per arch: signed *.rpm + repodata/ + repomd.xml.asc
#   rpm/kennel.repo              the DNF .repo file (gpgcheck=1, repo_gpgcheck=1)
#   kennel-archive-keyring.asc   the public signing key (armored)
#   fingerprint.txt              the key fingerprint, for out-of-band cross-check
#   index.html                   landing page (fingerprint + install snippets)
#
# The signed tree is host-agnostic static content. `publish-repo.sh` syncs it to a
# Cloudflare R2 bucket (S3 API); cache tiering and root/index redirects are Cloudflare
# Rules on the custom domain (see docs/governance/RELEASE-CEREMONY.md).
#
# Usage:
#   build-repo.sh --key <gpg-key-id-or-fingerprint> [--assets dist/release] [--out dist/repo]
#                 [--base-url https://packages.projectkennel.org] [--codename stable]
#
# The signing identity is a GnuPG key in the caller's GNUPGHOME (set GNUPGHOME to use a
# dedicated keyring). It is NEVER created here.

set -euo pipefail

key=""
assets="dist/release"
out="dist/repo"
base_url="https://packages.projectkennel.org"
codename="stable"
component="main"

while [[ $# -gt 0 ]]; do
	case "$1" in
		--key)      key="${2:?--key needs a gpg key id}"; shift 2 ;;
		--assets)   assets="${2:?}"; shift 2 ;;
		--out)      out="${2:?}"; shift 2 ;;
		--base-url) base_url="${2:?}"; shift 2 ;;
		--codename) codename="${2:?}"; shift 2 ;;
		-*) echo "build-repo.sh: unknown argument: $1" >&2; exit 2 ;;
		*)  echo "build-repo.sh: unexpected argument: $1" >&2; exit 2 ;;
	esac
done

[[ -n "$key" ]] || { echo "build-repo.sh: --key <gpg-key-id> is required (the release signing key, from your GNUPGHOME)" >&2; exit 2; }
[[ -d "$assets" ]] || { echo "build-repo.sh: assets dir '$assets' not found (run build-release.sh + build-deb.sh + build-rpm.sh first)" >&2; exit 2; }

# Resolve the key to a stable long fingerprint, and fail early if it is not present or has no secret.
fpr="$(gpg --with-colons --fingerprint "$key" 2>/dev/null | awk -F: '/^fpr:/{print $10; exit}')"
[[ -n "$fpr" ]] || { echo "build-repo.sh: no such GPG key in GNUPGHOME: $key" >&2; exit 1; }
gpg --with-colons --list-secret-keys "$fpr" >/dev/null 2>&1 || { echo "build-repo.sh: no SECRET key for $fpr — cannot sign" >&2; exit 1; }
echo "build-repo.sh: signing with $fpr"

debs=( "$assets"/*.deb )
rpms=( "$assets"/*.rpm )
[[ -e "${debs[0]}" ]] || { echo "build-repo.sh: no .deb in $assets" >&2; exit 1; }
[[ -e "${rpms[0]}" ]] || { echo "build-repo.sh: no .rpm in $assets" >&2; exit 1; }

rm -rf "$out"
mkdir -p "$out"

# ── APT repository (reprepro) ────────────────────────────────────────────────────────
# reprepro builds the pool + dists tree and clearsigns/detach-signs the Release file with
# SignWith. apt then verifies InRelease against the imported key, and each .deb against the
# SHA256 in the signed Packages index — the signature chains to every package.
echo "build-repo.sh: building the APT repo (reprepro)"
debroot="$out/deb"
mkdir -p "$debroot/conf"
cat > "$debroot/conf/distributions" <<EOF
Origin: Project Kennel
Label: Project Kennel
Codename: $codename
Architectures: amd64 arm64
Components: $component
Description: Project Kennel — policy-confined workload runner
SignWith: $fpr
EOF
for d in "${debs[@]}"; do
	reprepro -b "$debroot" includedeb "$codename" "$d" >/dev/null
done
rm -rf "$debroot/conf" "$debroot/db"   # ship only the served tree (dists/ + pool/)

# ── DNF repository (rpmsign + createrepo_c) ──────────────────────────────────────────
# Two independent signatures: each package is GPG-signed (rpm --addsign, dnf's gpgcheck),
# and the repo metadata repomd.xml is detach-signed (repo_gpgcheck). dnf verifies both
# against gpgkey= before installing anything.
echo "build-repo.sh: building the DNF repo (rpmsign + createrepo_c)"
export GNUPGHOME="${GNUPGHOME:-$HOME/.gnupg}"
for r in "${rpms[@]}"; do
	arch="$(rpm -qp --qf '%{ARCH}' "$r" 2>/dev/null)"
	[[ -n "$arch" ]] || { echo "build-repo.sh: cannot read arch of $r" >&2; exit 1; }
	dst="$out/rpm/$arch"
	mkdir -p "$dst"
	cp "$r" "$dst/"
	# Sign with the release key. The signer is passed explicitly via --define (a %_gpg_name
	# from a --macros file is not reliably honoured by --addsign); the passphrase, if any,
	# comes from gpg-agent (loopback would bypass the agent cache and need it inline).
	rpm --define "_gpg_name $fpr" --define "__gpg $(command -v gpg)" \
		--addsign "$dst/$(basename "$r")" >/dev/null 2>&1 \
		|| { echo "build-repo.sh: rpm --addsign failed for $(basename "$r") — is the key's passphrase cached? (echo | gpg -u $fpr --sign -o /dev/null)" >&2; exit 1; }
done
for dst in "$out"/rpm/*/; do
	createrepo_c --quiet "$dst"
	gpg --batch --yes --local-user "$fpr" --detach-sign --armor "$dst/repodata/repomd.xml"
done

# The DNF .repo file the user drops into /etc/yum.repos.d/.
cat > "$out/rpm/kennel.repo" <<EOF
[kennel]
name=Project Kennel
baseurl=$base_url/rpm/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$base_url/kennel-archive-keyring.asc
EOF

# ── The public key + fingerprint (the trust root) ────────────────────────────────────
gpg --armor --export "$fpr" > "$out/kennel-archive-keyring.asc"
printf '%s\n' "$fpr" > "$out/fingerprint.txt"

short="${fpr: -16}"
cat > "$out/index.html" <<EOF
<!doctype html><meta charset=utf-8><title>Project Kennel packages</title>
<h1>Project Kennel — package repositories</h1>
<p>Signing key fingerprint (verify this out of band — GitHub release, this page, DNS TXT):</p>
<pre>$fpr</pre>
<h2>Debian / Ubuntu</h2>
<pre>curl -fsSL $base_url/kennel-archive-keyring.asc | gpg --dearmor | sudo tee /usr/share/keyrings/kennel.gpg >/dev/null
# verify the fingerprint BEFORE trusting:
gpg --show-keys /usr/share/keyrings/kennel.gpg   # must show $short
echo "deb [signed-by=/usr/share/keyrings/kennel.gpg] $base_url/deb $codename $component" | sudo tee /etc/apt/sources.list.d/kennel.list
sudo apt update && sudo apt install kennel</pre>
<h2>Fedora / RHEL</h2>
<pre>sudo curl -fsSL $base_url/rpm/kennel.repo -o /etc/yum.repos.d/kennel.repo
sudo rpm --import $base_url/kennel-archive-keyring.asc   # verify: rpm -qi gpg-pubkey shows $short
sudo dnf install kennel</pre>
EOF

echo "build-repo.sh: done → $out (base URL $base_url)"
echo "  APT:  $out/deb/dists/$codename/{InRelease,Release,Release.gpg}"
echo "  DNF:  $out/rpm/{aarch64,x86_64}/repodata/repomd.xml{,.asc}"
echo "  key:  $out/kennel-archive-keyring.asc  ($fpr)"
