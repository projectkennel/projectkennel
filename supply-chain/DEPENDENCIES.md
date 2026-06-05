# Dependencies

The ledger of every direct external dependency, required by [CODING-STANDARDS.md](../docs/governance/CODING-STANDARDS.md) §5.2. The default answer to "should we add a dependency?" is **no** (§5.1); each entry here is a justified exception.

This ledger pairs with:

- `CHECKSUMS.toml` — the human-verified content-hash manifest and integrity ground truth (§5.5).
- `Cargo.lock` — Cargo's working lockfile.
- `src/vendor/` — the vendored `.crate` artefacts.
- `RELEASE-WATCH.toml` — upstream-release monitoring for non-CVE maintenance (§5.7).

## Status

Six direct dependencies are recorded below (`libc`, `nix`, `bitflags`, `object`, `seccompiler`, `ed25519-compact`), each a justified §5.1 exception adopted via the §5.2/§5.5 procedure. Counting transitive crates, `CHECKSUMS.toml` pins the shipped artefacts plus `arbitrary` (fuzz-only, §5.5-approved; used only by the non-shipped `fuzz/` crate). Further entries are added with the PR that introduces each dependency.

## System libraries (linked, not vendored)

These are platform C libraries linked via FFI, not crates.io dependencies — there is no `.crate` to vendor or checksum; they are vetted as the host's own packages and gated so the default build links none of them.

- **libsystemd** — linked by `kennel-syscall::journal` (the `sd_journal_sendv` FFI) **only** under the `audit-journald` feature, for the `kennel-audit` journald sink. The default build does not reference it; the feature is off by default. Build-time: `libsystemd-dev`; run-time: `libsystemd` (present on every systemd host). The FFI is one non-variadic function reading caller-owned `iovec`s; see the `SAFETY` note at the call site.

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
- TOML, for every config artefact including the settled policy (`serde`, `basic-toml`). There is **no** JSON config: the audit log is JSON Lines (a fixed-schema output stream) written by a small hand-rolled emitter, not `serde_json`.
- Security-ABI helpers where the kernel ABI is genuinely non-trivial: `seccompiler` (seccomp-BPF bytecode). Landlock and the BPF loader were instead hand-rolled (their vetted crates' cost — proc-macros/TCB for `landlock`; ~1435 vendored C files for `libbpf-sys`, 19 crates for `aya` — outweighed the small `unsafe` they save); the BPF loader uses `object` for ELF parsing only.
- One async runtime, in the proxy and server crates only — never in the privhelper.
- Hashing for the checksum verifier (`sha2`), itself bootstrapped per §5.5.1.

Anything outside this list requires a maintainer decision recorded in the PR.

## Direct dependencies

### libc

- **Version:** =0.2.186 (exact pin)
- **Justification:** The Rust bindings to the system C library — the foundation the syscall layer rests on (nix builds on it). `kennel-syscall` retains it as a direct dependency (the architecture lists `nix, libc`) for the raw constants and types the higher-level crates do not expose, used directly as the namespace/mount/seccomp wrappers land. The safe wrappers themselves go through nix where possible (§4 — prefer a vetted crate to our own `unsafe`).
- **Licence:** MIT OR Apache-2.0 (we take Apache-2.0; compatible with the project licence).
- **Reviewer:** remco (2026-05-30). Provenance verified independent of crates.io via `tools/audit-source.sh`: the `.crate` source is byte-identical to `github.com/rust-lang/libc` at the published commit, which is tag 0.2.186.
- **Transitive deps added:** none. libc's only dependency (`rustc-std-workspace-core`) is optional and used solely when libc is built as part of the standard library; it is not in our dependency graph.
- **Proc-macros / build.rs:** libc ships a `build.rs` (it probes the target/toolchain to set `cfg` flags). No proc-macros. The reviewer should confirm the build script does only target detection as part of the §5.5 read.

### nix

- **Version:** =0.31.3 (exact pin), `default-features = false`, `features = ["user", "process", "sched", "mount", "fs", "poll", "socket"]`.
- **Justification:** Safe, typed wrappers over the syscalls `kennel-syscall` would otherwise hand-roll `unsafe` — namespaces, mounts, `pivot_root`, credentials, `no_new_privs`, and the rest of the spawn sequence (`docs/design/08`). Per §4 ("don't roll your own `unsafe`"), a vetted, widely-used crate is preferable to our own FFI for these. Features are enabled pay-as-you-go as each wrapper lands, to keep the compiled surface (and transitive set) minimal; `process` / `sched` / `mount` / `fs` pull no new crate. `poll` (for the cancellable `gid_map` handshake) pulls nothing. `socket` (for the SCM_RIGHTS fd-passing in `scm.rs` and the AF_NETLINK sockets in `netlink.rs`, replacing hand-rolled `sendmsg`/`recvmsg`/CMSG `unsafe`) pulls `memoffset`, which in turn build-depends on `autocfg`.
- **Licence:** MIT.
- **Reviewer:** remco (2026-05-30; `poll`/`socket` features + memoffset/autocfg transitives 2026-06-05). Provenance verified independent of crates.io via `tools/audit-source.sh`: byte-identical to `github.com/nix-rust/nix` at the published commit, tag v0.31.3. Transitives likewise (bitflags, cfg-if, cfg_aliases, memoffset, autocfg).
- **Transitive deps added:** `bitflags` =2.11.1, `cfg-if` =1.0.4, `memoffset` =0.9.1 (normal, the last via the `socket` feature); `cfg_aliases` =0.2.1 and `autocfg` =1.5.1 (build-dependencies — of nix's and memoffset's `build.rs` respectively). `libc` is shared with the direct dependency above. Each is vendored and recorded in `CHECKSUMS.toml` with its own GitHub-provenance check.
- **Proc-macros / build.rs:** nix has a `build.rs` that uses `cfg_aliases` to define `cfg` aliases from the target; `memoffset` has a `build.rs` that uses `autocfg` to probe for `offset_of!`/const-fn support. Both `cfg_aliases` and `autocfg` are small build-only crates (no proc-macro, nothing ships in any binary). No proc-macros in this set.

### bitflags

- **Version:** =2.11.1 (exact pin).
- **Justification:** Typed access-right sets for the hand-rolled Landlock bindings (`AccessFs` / `AccessNet` in `kennel-syscall::landlock`). Already in the graph as a transitive of nix; promoted to a direct dependency because `landlock.rs` uses it directly. A flag-set macro avoids a hand-written, error-prone set of `u64` bit operations.
- **Licence:** MIT OR Apache-2.0 (we take Apache-2.0).
- **Reviewer:** remco (2026-05-30) — audited as part of the nix adoption. Provenance verified via `tools/audit-source.sh`: byte-identical to `github.com/bitflags/bitflags` at tag 2.11.1.
- **Transitive deps added:** none new (already present via nix).
- **Proc-macros / build.rs:** none. (The optional `derive` proc-macro feature is **not** enabled.)

### object

- **Version:** =0.36.7 (exact pin), `default-features = false`, `features = ["read_core", "elf"]`.
- **Justification:** ELF parsing for the BPF loader (`kennel-bpf`) — sections, symbols, relocations. The generic, error-prone-but-not-security-specific part, delegated to a vetted crate (gimli-rs/object) exactly as `seccompiler` handles BPF bytecode. The security-bearing loader (the `bpf(2)` syscalls, map creation, relocation patching, cgroup attach) is hand-rolled over `libc`. This replaces `libbpf-rs`/`libbpf-sys` (which would vendor zlib+libelf+libbpf C, ~1435 files) and `aya` (19 crates) with a single dependency.
- **Licence:** Apache-2.0 OR MIT (we take Apache-2.0).
- **Reviewer:** remco (2026-05-31). Provenance verified independent of crates.io via `tools/audit-source.sh`: byte-identical to `github.com/gimli-rs/object` at tag 0.36.7.
- **Transitive deps added:** none new — with `read_core, elf` only, its sole dependency `memchr` is already vendored.
- **Proc-macros / build.rs:** none.

### seccompiler

- **Version:** =0.5.0 (exact pin), default features (the `json` feature, which would pull `serde`/`serde_json`, is **not** enabled).
- **Justification:** Compiles a programmatic filter description into a seccomp-BPF program and installs it (`seccomp(2)`). Hand-rolling the BPF bytecode is exactly the "don't roll your own `unsafe`" case (§4) — a subtly-wrong filter is a silent hole — so the vetted `rust-vmm` crate is used. (Contrast Landlock, whose tiny ABI we own.)
- **Licence:** Apache-2.0 OR BSD-3-Clause (we take Apache-2.0; both permissive).
- **Reviewer:** remco (2026-05-30). Provenance verified independent of crates.io via `tools/audit-source.sh`: byte-identical to `github.com/rust-vmm/seccompiler` at tag v0.5.0.
- **Transitive deps added:** none new. seccompiler's only dependency is `libc`, already a direct dependency above.
- **Proc-macros / build.rs:** none.

### ed25519-compact

- **Version:** =2.3.0 (exact pin), `default-features = false`, `features = ["std"]`.
- **Justification:** Ed25519 signature verification for `kennel-policy` — the runtime spawn path verifies one signature over the settled policy against a pinned key (`docs/architecture/02-2-config-schema.md` §Signatures); the compiler signs settled policies. "Don't roll your own crypto" (§4) — a vetted Ed25519 is mandatory. Chosen over `ed25519-dalek` (≈9× the code, a ~6–9-crate tree) and `ring` (bundles BoringSSL C/asm): a self-contained pure-Rust implementation whose Curve25519 field arithmetic is fiat-crypto formally-verified code, with zero transitive deps under our feature set. Base64 of the signature envelope is decoded in our own code (encoding, not crypto; the bytes are public), so `pem`/`ct-codecs` stays off.
- **Licence:** MIT.
- **Reviewer:** remco (2026-05-31). Provenance verified independent of crates.io via `tools/audit-source.sh`: 15 source files byte-identical to `github.com/jedisct1/rust-ed25519-compact` at tag 2.3.0. Source read for backdoors: no FFI/asm/process/net/fs/env; the single `unsafe` is the volatile secret-wipe; verification rejects non-canonical `S` (malleability) and weak/identity keys.
- **Transitive deps added:** none. `getrandom`, `ct-codecs`, and `ed25519` are optional dependencies, gated behind the `random`/`pem`/`traits` features, none of which we enable. `x25519.rs` and `pem.rs` are not compiled.
- **Proc-macros / build.rs:** none.

### arbitrary (fuzz-only)

- **Version:** =1.4.1 (exact pin), `default-features = false` (no `derive`).
- **Justification:** Turns a flat fuzzer seed into byte/structured inputs for the fuzz harnesses (`fuzz/`, §10.6). **Not a dependency of any shipped crate** — it is used only by `kennel-fuzz`, a non-shipped crate in its own separate workspace (`fuzz/`), so it is in no release artefact and no shipped `Cargo.lock`. Chosen as the lightest fuzzing approach ("Path C"): with no `derive` feature it has zero transitive deps and no native runtime, versus the `cargo-fuzz`/`libfuzzer-sys` path (a C++-compiling `build.rs` + bundled LLVM + ~5 crates).
- **Licence:** MIT OR Apache-2.0 (we take Apache-2.0).
- **Reviewer:** remco (2026-06-01). Provenance verified via `tools/audit-helper.sh` + `tools/audit-source.sh`: `.crate` sha256 matches an independent re-download and the crates.io index `cksum`; 60 source files byte-identical to `github.com/rust-fuzz/arbitrary` @ the published commit `690db067`, `Cargo.toml.orig == upstream`. `audit-source.sh` tag note (explained): the `v1.4.1` tag is one commit ahead of the published commit and that commit only bumps the sibling `derive_arbitrary` crate's version (`derive/Cargo.toml` 1.4.0→1.4.1) — it does not touch the `arbitrary` crate's source.
- **Transitive deps added:** none (with `default-features = false`; the optional `derive_arbitrary` and the dev-only `exhaustigen` are not pulled).
- **Proc-macros / build.rs:** none.
