# Dependencies

The ledger of every direct external dependency, required by [CODING-STANDARDS.md](CODING-STANDARDS.md) §5.2. The default answer to "should we add a dependency?" is **no** (§5.1); each entry here is a justified exception.

This ledger pairs with:

- `CHECKSUMS.toml` — the human-verified content-hash manifest and integrity ground truth (§5.5).
- `Cargo.lock` — Cargo's working lockfile.
- `crates-archive/` — the vendored `.crate` artefacts.
- `RELEASE-WATCH.toml` — upstream-release monitoring for non-CVE maintenance (§5.7).

## Status

No dependencies yet — the reference runtime is not yet implemented. This ledger is structured and ready; entries are added with the PR that introduces each dependency, following the procedure in §5.2.

## Entry format

Each direct dependency gets an entry:

```
## <crate-name>

- **Version:** =X.Y.Z (exact pin; no ^, >=, or *)
- **Justification:** what it does; why we use it instead of writing it (§5.1).
- **Licence:** MIT / BSD-2 / BSD-3 / Apache-2.0 / ISC (GPL/AGPL needs maintainer ratification).
- **Reviewer:** the maintainer who has read enough of this crate to vouch for it.
- **Transitive deps added:** the crates this pulls in.
- **Proc-macros / build.rs:** note any, with the §5.3 justification if applicable.
```

## Sanctioned categories

The short list of things we use a dependency for rather than writing ourselves (§5.1); expanding it is a maintainer decision:

- Cryptography (e.g. `ring`, `ed25519-dalek`, `rustls`).
- TOML and JSON (`serde`, `toml`, `serde_json`).
- Landlock, seccomp, and eBPF bindings where the kernel ABI is non-trivial (`landlock`, `seccompiler`, `libbpf-rs`/`libbpf-sys`).
- One async runtime, in the proxy and server crates only — never in the privhelper.
- Hashing for the checksum verifier (`sha2`), itself bootstrapped per §5.5.1.

Anything outside this list requires a maintainer decision recorded in the PR.

## Direct dependencies

*(none yet)*
