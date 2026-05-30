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

### libc

- **Version:** =0.2.186 (exact pin)
- **Justification:** The Rust bindings to the system C library and raw syscalls. `kennel-syscall` is the one crate permitted `unsafe` (§4); it wraps libc behind safe APIs (`unistd::effective_uid`, and the namespace/Landlock/seccomp/prctl wrappers to follow). Writing our own FFI declarations for the full syscall surface we need would be a larger, less-reviewed `unsafe` surface than depending on the canonical, widely-audited bindings.
- **Licence:** MIT OR Apache-2.0 (we take Apache-2.0; compatible with the project licence).
- **Reviewer:** remco (2026-05-30). Provenance verified independent of crates.io via `tools/audit-source.sh`: the `.crate` source is byte-identical to `github.com/rust-lang/libc` at the published commit, which is tag 0.2.186.
- **Transitive deps added:** none. libc's only dependency (`rustc-std-workspace-core`) is optional and used solely when libc is built as part of the standard library; it is not in our dependency graph.
- **Proc-macros / build.rs:** libc ships a `build.rs` (it probes the target/toolchain to set `cfg` flags). No proc-macros. The reviewer should confirm the build script does only target detection as part of the §5.5 read.
