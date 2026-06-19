# Dependencies

The ledger of every direct external dependency, required by [CODING-STANDARDS.md](../docs/governance/CODING-STANDARDS.md) §5.2. The default answer to "should we add a dependency?" is **no** (§5.1); each entry here is a justified exception.

This ledger pairs with:

- `CHECKSUMS.toml` — the human-verified content-hash manifest and integrity ground truth (§5.5).
- `Cargo.lock` — Cargo's working lockfile.
- `src/vendor/` — the vendored `.crate` artefacts.
- `RELEASE-WATCH.toml` — upstream-release monitoring for non-CVE maintenance (§5.7).

## Status

Seven direct dependencies are recorded below (`libc`, `nix`, `bitflags`, `object`, `seccompiler`, `ed25519-compact`, `lexopt`), each a justified §5.1 exception adopted via the §5.2/§5.5 procedure. Counting transitive crates, `CHECKSUMS.toml` pins the shipped artefacts plus `arbitrary` (fuzz-only, §5.5-approved; used only by the non-shipped `fuzz/` crate). Further entries are added with the PR that introduces each dependency.

## System libraries (linked, not vendored)

These are platform C libraries linked via FFI, not crates.io dependencies — there is no `.crate` to vendor or checksum; they are vetted as the host's own packages and gated so the default build links none of them.

- **libsystemd** — linked by `kennel-lib-syscall::journal` (the `sd_journal_sendv` FFI) **only** under the `audit-journald` feature, for the `kennel-lib-audit` journald sink. The default build does not reference it; the feature is off by default. Build-time: `libsystemd-dev`; run-time: `libsystemd` (present on every systemd host). The FFI is one non-variadic function reading caller-owned `iovec`s; see the `SAFETY` note at the call site.

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
- CLI argument parsing for the `kennel` front-end (`lexopt`). A correct getopt-style parser
  (clustered short flags, `--opt=val` vs `--opt val`, `--`, `-` , non-UTF-8 `OsString` values)
  is fiddly to hand-roll and security-irrelevant; `lexopt` is the minimal choice — one
  `#![forbid(unsafe_code)]` file, zero transitive deps, no build.rs/proc-macro — over `clap`
  (multiple unvendored transitives). Added 2026-06-15 (maintainer decision, this entry).
- Parsing **untrusted terminal escape sequences** for the PTY filter (`vte`). A correct ANSI
  escape parser (the Paul Williams state machine; OSC/CSI/DCS/APC/PM/SOS framing, split-sequence
  resumption) is precisely the hostile-input parser the no-hand-roll rule targets — delegated to
  the vetted alacritty crate, default-features-off (core deps `arrayvec` + `memchr` only).
  Maintainer decision, this entry.

Anything outside this list requires a maintainer decision recorded in the PR.

## Direct dependencies

### libc

- **Version:** =0.2.186 (exact pin)
- **Justification:** The Rust bindings to the system C library — the foundation the syscall layer rests on (nix builds on it). `kennel-lib-syscall` retains it as a direct dependency (the architecture lists `nix, libc`) for the raw constants and types the higher-level crates do not expose, used directly as the namespace/mount/seccomp wrappers land. The safe wrappers themselves go through nix where possible (§4 — prefer a vetted crate to our own `unsafe`).
- **Licence:** MIT OR Apache-2.0 (we take Apache-2.0; compatible with the project licence).
- **Reviewer:** remco (2026-05-30). Provenance verified independent of crates.io via `tools/audit-source.sh`: the `.crate` source is byte-identical to `github.com/rust-lang/libc` at the published commit, which is tag 0.2.186.
- **Transitive deps added:** none. libc's only dependency (`rustc-std-workspace-core`) is optional and used solely when libc is built as part of the standard library; it is not in our dependency graph.
- **Proc-macros / build.rs:** libc ships a `build.rs` (it probes the target/toolchain to set `cfg` flags). No proc-macros. The reviewer should confirm the build script does only target detection as part of the §5.5 read.

### nix

- **Version:** =0.31.3 (exact pin), `default-features = false`, `features = ["user", "process", "sched", "mount", "fs", "poll", "socket", "net"]`.
- **Justification:** Safe, typed wrappers over the syscalls `kennel-lib-syscall` would otherwise hand-roll `unsafe` — namespaces, mounts, `pivot_root`, credentials, `no_new_privs`, and the rest of the spawn sequence (`docs/design/08`). Per §4 ("don't roll your own `unsafe`"), a vetted, widely-used crate is preferable to our own FFI for these. Features are enabled pay-as-you-go as each wrapper lands, to keep the compiled surface (and transitive set) minimal; `process` / `sched` / `mount` / `fs` pull no new crate. `poll` (for the cancellable `gid_map` handshake) pulls nothing. `socket` (for the SCM_RIGHTS fd-passing in `scm.rs` and the AF_NETLINK sockets in `netlink.rs`, replacing hand-rolled `sendmsg`/`recvmsg`/CMSG `unsafe`) pulls `memoffset`, which in turn build-depends on `autocfg`. `net` (for `if_nametoindex` in `netlink.rs`) only turns on `socket`, so it adds no further crate.
- **Licence:** MIT.
- **Reviewer:** remco (2026-05-30; `poll`/`socket` features + memoffset/autocfg transitives 2026-06-05). Provenance verified independent of crates.io via `tools/audit-source.sh`: byte-identical to `github.com/nix-rust/nix` at the published commit, tag v0.31.3. Transitives likewise (bitflags, cfg-if, cfg_aliases, memoffset, autocfg).
- **Transitive deps added:** `bitflags` =2.11.1, `cfg-if` =1.0.4, `memoffset` =0.9.1 (normal, the last via the `socket` feature); `cfg_aliases` =0.2.1 and `autocfg` =1.5.1 (build-dependencies — of nix's and memoffset's `build.rs` respectively). `libc` is shared with the direct dependency above. Each is vendored and recorded in `CHECKSUMS.toml` with its own GitHub-provenance check.
- **Proc-macros / build.rs:** nix has a `build.rs` that uses `cfg_aliases` to define `cfg` aliases from the target; `memoffset` has a `build.rs` that uses `autocfg` to probe for `offset_of!`/const-fn support. Both `cfg_aliases` and `autocfg` are small build-only crates (no proc-macro, nothing ships in any binary). No proc-macros in this set.

### bitflags

- **Version:** =2.11.1 (exact pin).
- **Justification:** Typed access-right sets for the hand-rolled Landlock bindings (`AccessFs` / `AccessNet` in `kennel-lib-syscall::landlock`). Already in the graph as a transitive of nix; promoted to a direct dependency because `landlock.rs` uses it directly. A flag-set macro avoids a hand-written, error-prone set of `u64` bit operations.
- **Licence:** MIT OR Apache-2.0 (we take Apache-2.0).
- **Reviewer:** remco (2026-05-30) — audited as part of the nix adoption. Provenance verified via `tools/audit-source.sh`: byte-identical to `github.com/bitflags/bitflags` at tag 2.11.1.
- **Transitive deps added:** none new (already present via nix).
- **Proc-macros / build.rs:** none. (The optional `derive` proc-macro feature is **not** enabled.)

### object

- **Version:** =0.36.7 (exact pin), `default-features = false`, `features = ["read_core", "elf"]`.
- **Justification:** ELF parsing for the BPF loader (`kennel-lib-bpf`) — sections, symbols, relocations. The generic, error-prone-but-not-security-specific part, delegated to a vetted crate (gimli-rs/object) exactly as `seccompiler` handles BPF bytecode. The security-bearing loader (the `bpf(2)` syscalls, map creation, relocation patching, cgroup attach) is hand-rolled over `libc`. This replaces `libbpf-rs`/`libbpf-sys` (which would vendor zlib+libelf+libbpf C, ~1435 files) and `aya` (19 crates) with a single dependency.
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
- **Justification:** Ed25519 signature verification for `kennel-lib-policy` — the runtime spawn path verifies one signature over the settled policy against a pinned key (`docs/architecture/02-2-config-schema.md` §Signatures); the compiler signs settled policies. "Don't roll your own crypto" (§4) — a vetted Ed25519 is mandatory. Chosen over `ed25519-dalek` (≈9× the code, a ~6–9-crate tree) and `ring` (bundles BoringSSL C/asm): a self-contained pure-Rust implementation whose Curve25519 field arithmetic is fiat-crypto formally-verified code, with zero transitive deps under our feature set. Base64 of the signature envelope is decoded in our own code (encoding, not crypto; the bytes are public), so `pem`/`ct-codecs` stays off.
- **Licence:** MIT.
- **Reviewer:** remco (2026-05-31). Provenance verified independent of crates.io via `tools/audit-source.sh`: 15 source files byte-identical to `github.com/jedisct1/rust-ed25519-compact` at tag 2.3.0. Source read for backdoors: no FFI/asm/process/net/fs/env; the single `unsafe` is the volatile secret-wipe; verification rejects non-canonical `S` (malleability) and weak/identity keys.
- **Transitive deps added:** none. `getrandom`, `ct-codecs`, and `ed25519` are optional dependencies, gated behind the `random`/`pem`/`traits` features, none of which we enable. `x25519.rs` and `pem.rs` are not compiled.
- **Proc-macros / build.rs:** none.

### lexopt

- **Version:** =0.3.2 (exact pin), default features.
- **Justification:** The argument parser for the `kennel` CLI. A correct getopt-style parser — clustered short flags, `--opt=val` vs `--opt val`, the `--` separator, `-`, and non-UTF-8 `OsString` values — is fiddly and easy to get subtly wrong by hand across nine subcommands; `lexopt` is the minimal vetted option (§5.1 sanctioned category "CLI argument parsing"). Chosen over `clap` (which pulls multiple unvendored transitives — `clap_derive`/`anstyle`/`is_terminal` — and a proc-macro), per the "smallest dependency that does the job" rule: `lexopt` is a single `#![forbid(unsafe_code)]` file with zero transitive deps.
- **Licence:** MIT.
- **Reviewer:** remco (2026-06-15). Provenance verified independent of crates.io via `tools/audit-source.sh`: 11 source files byte-identical to `github.com/blyxxyz/lexopt` at tag v0.3.2 (recorded in `CHECKSUMS.toml`). Source read for backdoors: one ~2k-line `lib.rs`, `#![forbid(unsafe_code)]`, the sole `std::env` use is `args_os()` (the parser's input); no FFI/asm/process/net/fs.
- **Transitive deps added:** none (empty `[dependencies]`).
- **Proc-macros / build.rs:** none (`build = false`).

### arbitrary (fuzz-only)

- **Version:** =1.4.1 (exact pin), `default-features = false` (no `derive`).
- **Justification:** Turns a flat fuzzer seed into byte/structured inputs for the fuzz harnesses (`fuzz/`, §10.6). **Not a dependency of any shipped crate** — it is used only by `kennel-fuzz`, a non-shipped crate in its own separate workspace (`fuzz/`), so it is in no release artefact and no shipped `Cargo.lock`. Chosen as the lightest fuzzing approach ("Path C"): with no `derive` feature it has zero transitive deps and no native runtime, versus the `cargo-fuzz`/`libfuzzer-sys` path (a C++-compiling `build.rs` + bundled LLVM + ~5 crates).
- **Licence:** MIT OR Apache-2.0 (we take Apache-2.0).
- **Reviewer:** remco (2026-06-01). Provenance verified via `tools/audit-helper.sh` + `tools/audit-source.sh`: `.crate` sha256 matches an independent re-download and the crates.io index `cksum`; 60 source files byte-identical to `github.com/rust-fuzz/arbitrary` @ the published commit `690db067`, `Cargo.toml.orig == upstream`. `audit-source.sh` tag note (explained): the `v1.4.1` tag is one commit ahead of the published commit and that commit only bumps the sibling `derive_arbitrary` crate's version (`derive/Cargo.toml` 1.4.0→1.4.1) — it does not touch the `arbitrary` crate's source.
- **Transitive deps added:** none (with `default-features = false`; the optional `derive_arbitrary` and the dev-only `exhaustigen` are not pulled).
- **Proc-macros / build.rs:** none.

### vte

- **Version:** =0.15.0 (exact pin), `default-features = false` (the `std` feature only).
- **Justification:** The alacritty terminal-escape parser — Paul Williams' ANSI state machine. `kennel-lib-term` uses it to recognise and neutralise the dangerous escape sequences a confined workload can write toward the operator's real terminal (OSC 52 clipboard, OSC 9/777 notifications, DCS/APC/PM/SOS bands), passing benign ones through (the PTY filter; closes the terminal-escape half of T2.6). This is the **reuse-not-hand-roll** call for an untrusted-input parser (§5.1, and the project's no-hand-rolled-parsers rule): a terminal escape parser is exactly the category to delegate to a vetted crate — hand-rolling is what desync attacks exploit. The optional `ansi` feature (which would pull `log`/`cursor-icon`/`bitflags`) and `serde` are **not** enabled.
- **Licence:** Apache-2.0 OR MIT (we take Apache-2.0).
- **Reviewer:** remco (2026-06-16). Provenance: byte-identical to `github.com/alacritty/vte` @ `3b3da71c34cc1256c7e20981cf03f8eb95e08ffc` (tag v0.15.0), 13 source files + `Cargo.toml.orig`, via `tools/audit-source.sh`; `.crate` sha256 matches the independent re-download and the crates.io index `cksum`. Red-flag scan clean (no build.rs/proc-macro/FFI/asm/process/net/fs/env); 5 unsafe sites, all idiomatic (a MaybeUninit OSC-params array cast over its initialised prefix; `from_utf8_unchecked`/`unwrap_unchecked` guarded by prior `valid_up_to()`/`valid_bytes` checks). The source review was performed by the assistant and accepted by the maintainer on review of those findings.
- **Transitive deps added:** `arrayvec` (new, below) and `memchr` (already vendored). Nothing else with the chosen features.
- **Proc-macros / build.rs:** none.

### arrayvec

- **Version:** =0.7.6 (exact pin), `default-features = false` (the `std` path vte needs).
- **Justification:** A fixed-capacity stack vector; pulled in **transitively by `vte`** (its only non-optional dep besides `memchr`). Not used directly by any first-party crate. Recorded here because it is a new vendored crate in the shipped graph.
- **Licence:** MIT OR Apache-2.0 (we take Apache-2.0).
- **Reviewer:** remco (2026-06-16). Provenance: byte-identical to `github.com/bluss/arrayvec` @ `0aede877fe0bfb1ba5e3c2024df8c0958d503a83` (tag 0.7.6), 18 source files + `Cargo.toml.orig`, via `tools/audit-source.sh`; `.crate` sha256 matches the independent re-download and the crates.io index `cksum`. Red-flag scan clean (no build.rs/proc-macro/FFI/asm/process/net/fs/env); unsafe is the crate's purpose (MaybeUninit-backed fixed-capacity storage). Source review by the assistant, accepted by the maintainer.
- **Transitive deps added:** none (with `default-features = false`; the optional `borsh`/`serde`/`zeroize` are not enabled, and `bencher`/`matches`/`serde_test` are dev-only).
- **Proc-macros / build.rs:** none.

### serde_json

- **Version:** =1.0.150 (exact pin), `default-features = false` + the `std` feature only.
- **Justification:** The JSON parser/serializer state machine (dtolnay/serde-rs). `kennel-lib-manifest` uses it to read, validate, generate, and re-pin the masked workspace manifest (`.trust-manifest.json`) — the cryptographic trust marker host IDEs read against the published schema, masked invisible inside the kennel (closes **T2.8**, workspace-trigger tampering). JSON (not TOML) is mandated by the goal of zero-friction native host-IDE/LSP validation. This is the **reuse-not-hand-roll** call for an untrusted-input parser (§5.1, no-hand-rolled-parsers). The optional `preserve_order`/`indexmap`, `arbitrary_precision`, `float_roundtrip`, `raw_value`, and `unbounded_depth` features are **not** enabled.
- **Licence:** MIT OR Apache-2.0 (we take Apache-2.0).
- **Reviewer:** remco (2026-06-16). Provenance: byte-identical to `github.com/serde-rs/json` @ `a1ae73ac6a6940a4a57c673aebaa13ed4dfe3e8c` (tag v1.0.150), 85 source files + `Cargo.toml.orig`, via `tools/audit-source.sh`; `.crate` sha256 matches the independent re-download and the crates.io index `cksum`. Red-flag scan clean (no build.rs/proc-macro/FFI/asm). The source review was performed by the assistant and accepted by the maintainer.
- **Transitive deps added:** `zmij` (new, below); `serde`, `serde_core`, `itoa`, `memchr` were already vendored. `indexmap` is optional and not enabled.
- **Shipped into:** the `kennel` CLI only (via `kennel-lib-manifest`); **not** linked into `kenneld` — the enforcement TCB carries no JSON parser.
- **Proc-macros / build.rs:** none.

### zmij

- **Version:** =1.0.21 (exact pin).
- **Justification:** A pure-math Schubfach float-to-decimal formatter (dtolnay) — serde_json's float code path (it replaced `ryu`). **Required, not optional:** serde_json 1.0.150 depends on `zmij ^1.0` as a normal dependency, so vendoring serde_json forces it. The masked manifest itself carries **no float fields** (it is strings, objects, arrays), so this code path is never exercised at runtime; it is vendored only because serde_json links it unconditionally. Recorded here because it is a new vendored crate in the shipped graph.
- **Licence:** MIT OR Apache-2.0 (we take Apache-2.0).
- **Reviewer:** remco (2026-06-16). Provenance: byte-identical to `github.com/dtolnay/zmij` @ `6531ba31ccf5d14b604ca41f6e2414a8dd779af0` (tag 1.0.21), 14 source files + `Cargo.toml.orig`, via `tools/audit-source.sh`; `.crate` sha256 matches the independent re-download and the crates.io index `cksum`. Red-flag scan clean (no build.rs/proc-macro/FFI). Source review by the assistant, accepted by the maintainer.
- **Transitive deps added:** none (zero normal dependencies).
- **Proc-macros / build.rs:** none.

### mini-sansio-dbus

- **Version:** =5.0.1 (exact pin).
- **Justification:** The D-Bus wire marshalling for `facade-dbus` (the in-kennel `org.projectkennel.IDBus` facade, §7.7) — it decodes incoming D-Bus messages (header + the header-fields the allowlist matches on: destination/path/interface/member/signature) and encodes replies, and its client-side sans-IO connector is what the `host-dbus` delegate uses to reach the real bus. This is the **reuse-not-hand-roll** call for an untrusted-input parser (§5.1, the project's no-hand-rolled-parsers rule): the alternative full libraries (zvariant, rustbus) double the vendored tree and pull overlapping versions / proc-macros, while this is a small, self-contained marshalling subsystem we put a thin facade on top of. Lives in `kennel-facade` — **outside the daemon TCB** (the facades run confined in the kennel, not in kenneld/privhelper/bin-init). Only the marshalling core (`encoder`/`incoming`/`types`, ~1.4k SLOC, self-contained) is linked; the app-specific `messages/` tree (network-manager, StatusNotifier, ~1.7k SLOC) is dead code.
- **Licence:** MIT.
- **Reviewer:** remco (2026-06-19). Provenance: byte-identical to `github.com/iliabylich/mini-sansio-dbus` @ `b1adcf603bd6705313decd65dece865894d74e3b` (tag v5.0.1), 77 source files + `Cargo.toml.orig`, via `tools/audit-source.sh`; `.crate` sha256 matches the independent re-download and the crates.io index `cksum`. `#![forbid(unsafe_code)]` — no unsafe. Red-flag scan clean: no build.rs, no proc-macro, no FFI/asm; sans-IO, so no `std::process`/`net`/`fs`/`env` (the caller owns all I/O). The `incoming` decoder parses adversarial workload wire and carries a fuzz target (`fuzz/`). Young/low-adoption upstream, mitigated by the exact pin + CHECKSUMS + the fuzz target. Source review by the assistant, accepted by the maintainer.
- **Transitive deps added:** none. The index lists `anyhow` and `rustix` but both are `dev`-dependencies (its examples/tests only), never built when the crate is consumed.
- **Proc-macros / build.rs:** none (`build = false`).
