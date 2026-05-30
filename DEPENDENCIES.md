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
- **Justification:** The Rust bindings to the system C library — the foundation the syscall layer rests on (nix builds on it). `kennel-syscall` retains it as a direct dependency (the architecture lists `nix, libc, libbpf-sys`) for the raw constants and types the higher-level crates do not expose, used directly as the namespace/mount/seccomp wrappers land. The safe wrappers themselves go through nix where possible (§4 — prefer a vetted crate to our own `unsafe`).
- **Licence:** MIT OR Apache-2.0 (we take Apache-2.0; compatible with the project licence).
- **Reviewer:** remco (2026-05-30). Provenance verified independent of crates.io via `tools/audit-source.sh`: the `.crate` source is byte-identical to `github.com/rust-lang/libc` at the published commit, which is tag 0.2.186.
- **Transitive deps added:** none. libc's only dependency (`rustc-std-workspace-core`) is optional and used solely when libc is built as part of the standard library; it is not in our dependency graph.
- **Proc-macros / build.rs:** libc ships a `build.rs` (it probes the target/toolchain to set `cfg` flags). No proc-macros. The reviewer should confirm the build script does only target detection as part of the §5.5 read.

### nix

- **Version:** =0.31.3 (exact pin), `default-features = false`, `features = ["user", "process"]`.
- **Justification:** Safe, typed wrappers over the syscalls `kennel-syscall` would otherwise hand-roll `unsafe` — namespaces, mounts, `pivot_root`, credentials, `no_new_privs`, and the rest of the spawn sequence (`docs/08`). Per §4 ("don't roll your own `unsafe`"), a vetted, widely-used crate is preferable to our own FFI for these. Features are enabled pay-as-you-go as each wrapper lands, to keep the compiled surface (and transitive set) minimal; `process` (added for `set_no_new_privs`, `fork`/`waitpid` in tests) pulls no new crate.
- **Licence:** MIT.
- **Reviewer:** remco (2026-05-30). Provenance verified independent of crates.io via `tools/audit-source.sh`: byte-identical to `github.com/nix-rust/nix` at the published commit, tag v0.31.3. Transitives likewise (bitflags, cfg-if, cfg_aliases).
- **Transitive deps added:** `bitflags` =2.11.1, `cfg-if` =1.0.4 (normal); `cfg_aliases` =0.2.1 (build-dependency of nix's `build.rs`). `libc` is shared with the direct dependency above. Each is vendored and recorded in `CHECKSUMS.toml` with its own GitHub-provenance check.
- **Proc-macros / build.rs:** nix has a `build.rs` that uses `cfg_aliases` to define `cfg` aliases from the target; `cfg_aliases` is a small macro crate (no proc-macro). No proc-macros in this set. The reviewer should confirm nix's `build.rs` does only cfg-alias setup.

### bitflags

- **Version:** =2.11.1 (exact pin).
- **Justification:** Typed access-right sets for the hand-rolled Landlock bindings (`AccessFs` / `AccessNet` in `kennel-syscall::landlock`). Already in the graph as a transitive of nix; promoted to a direct dependency because `landlock.rs` uses it directly. A flag-set macro avoids a hand-written, error-prone set of `u64` bit operations.
- **Licence:** MIT OR Apache-2.0 (we take Apache-2.0).
- **Reviewer:** remco (2026-05-30) — audited as part of the nix adoption. Provenance verified via `tools/audit-source.sh`: byte-identical to `github.com/bitflags/bitflags` at tag 2.11.1.
- **Transitive deps added:** none new (already present via nix).
- **Proc-macros / build.rs:** none. (The optional `derive` proc-macro feature is **not** enabled.)
