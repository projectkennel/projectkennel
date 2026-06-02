# Pinned upstream signing keys

The project's record of the upstream maintainer keys used to verify signed release tags during dependency auditing, referenced by [CODING-STANDARDS.md](../docs/governance/CODING-STANDARDS.md) §5.5. When `tools/audit-helper` checks out an upstream repository at a release tag and that upstream signs its tags, the signature is verified against a key recorded here.

This is distinct from:

- **Project Kennel's own release/template signing keys** — those are in [MAINTAINERS.md](../docs/governance/MAINTAINERS.md).
- **The trust store consumed at runtime** — the public keys under `~/.config/kennel/keys/` and `/etc/kennel/keys/` that verify templates and settled policies (`docs/architecture/07-paths.md`).

This file records the keys *we* trust when auditing *upstream dependencies*.

## Status

No dependencies yet — the reference runtime is not implemented. This file is the policy and an empty register; keys are added when the dependency they verify is first audited.

## Register format

Each pinned upstream key:

```
## <upstream project / crate>

- **Key holder:** who controls this key (the crate's release authority).
- **Fingerprint:** the full key fingerprint.
- **Source of trust:** how we obtained and corroborated the key (the project's published key page, a keyserver cross-check, a maintainer's verified identity).
- **Pinned-by:** the maintainer who recorded it.
- **Pinned-on:** ISO date.
```

A key that the upstream rotates is updated here with the old fingerprint retained and marked superseded, so historical-tag verification remains possible. An upstream *ownership change* is treated as a supply-chain signal (§5.7): the new key is corroborated independently before it is trusted, and the dependency is re-audited.

## Pinned keys

*(none yet)*
