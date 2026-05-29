# Maintainers

This file lists the people who may approve and merge changes, sign releases, and sign templates under the project's key. It is referenced normatively by [CODING-STANDARDS.md](CODING-STANDARDS.md) §13 (reviews and releases) and §4 (`unsafe` review).

## Current maintainers

| Name | Contact | Release signing key | Areas |
|---|---|---|---|
| Remco van Mook | remco.vanmook@gmail.com | *[TBD — key to be published]* | Founding maintainer; all areas |

The maintainer set is intentionally small at this stage. It grows as the project does; additions are themselves maintainer decisions, recorded here in a signed commit.

## What a maintainer does

- Reviews and approves PRs per CODING-STANDARDS.md §13.2. PRs touching `unsafe` or BPF C need two maintainer approvals (§4, §4.1).
- Signs release tags with a key listed above (§13.3).
- Signs official templates and fragments, or operates the key that does (design doc §5.10).
- Adjudicates deviations from the standards (Appendix A) and updates the standards when a deviation becomes permanent.
- Maintains the dependency posture: `CHECKSUMS.toml`, `DEPENDENCIES.md`, `RELEASE-WATCH.toml`, `KEYS.md` (§5).

## Release signing keys

Release tags and official templates are signed by the keys recorded above. The public keys are published *[TBD — location to be decided: in-repo under keys/, plus an out-of-band channel]*. Project Kennel refuses to load templates with invalid signatures; verifying a release means verifying its tag signature against a key in this file.

Key rotation, when it happens, is announced in [CHANGELOG.md](CHANGELOG.md) and the old key is retained here marked retired, so historical tags and templates remain verifiable.

## Trusted contributors

Repeat contributors who have demonstrated understanding of the project are listed separately in [CONTRIBUTORS.md](CONTRIBUTORS.md). Trusted-contributor status is not maintainer status; it relaxes the close-on-arrival rules (CODING-STANDARDS.md §13.4) but confers no merge, signing, or review authority.
