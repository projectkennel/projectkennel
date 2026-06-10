# Crate decomposition

This chapter describes the Cargo workspace layout: which crates exist, what each owns, how they depend on each other, and what build-time choices they expose. The *public APIs* of each crate are in `02-8-internal-api.md`; this chapter is the structural view — how the code is cut up, not what each piece exposes.

The workspace has **16 crates**: `kennel-policy`, `kennel-syscall`, `kennel-os`, `kennel-bpf`, `kennel-binder`, `kennel-audit`, `kennel-config`, `kennel-spawn`, `kennel-netproxy`, `kennel-privhelper`, `kennel-init`, `kenneld`, `kennel-afunix-shim`, `kennel-text`, `kennel-ssh-reorigin`, and `kennel-socks-connect`. `kennel-os` holds the **safe** OS primitives — path canonicalisation, uid/gid identity, per-kennel netlink address management, and the userns-map pipe handshake — split out of `kennel-syscall` (the only `unsafe`-bearing crate besides the BPF/binder FFI) so that crate carries *only* genuinely-unsafe code and stays reviewable in one sitting (CODING-STANDARDS §4). `kennel-syscall` depends on `kennel-os` and re-exports its modules, so callers reach them as `kennel_syscall::{path, unistd, netlink, handshake}` unchanged. `kennel-afunix-shim` is the in-kennel half of the `org.projectkennel.IAfUnix/default` facade (`07-6-afunix.md`): the small proxy `kennel-init` launches inside the view that brokers the workload's AF_UNIX connect through the binder gateway to kenneld. `kennel-binder` is the third unsafe-bearing crate — the hand-rolled binder ioctl ABI (the per-kennel inter-namespace gateway, `02-4-binder.md`), parallel in every structural respect to `kennel-bpf`; binder is load-bearing, so every kennel links it through kenneld and `kennel-init`. `kennel-init` is the root-owned PID-1 binary the privhelper `fexecve`s to construct and supervise each kennel (`07-2-kennel-init.md`). `kennel-audit` is a first-class crate — the unified audit writer (the canonical event, one sanitisation pass, per-class level filtering, and the `Sink` fan-out). `kennel-config` is a first-class crate too — the layered deployment/user configuration (`system.toml` / `config.toml` cascades) that keeps install paths out of the binaries. The last two crates are standalone, std-only SSH helpers (`07-10-ssh.md` §7.10.4) that depend on no other Project Kennel crate by design — they must stay minimal and self-contained: `kennel-ssh-reorigin` is the bastion's re-origination forced command, and `kennel-socks-connect` is the `ssh` `ProxyCommand` that SOCKS5s through the egress proxy to reach the bastion. The CLI and the control/wire IPC are folded rather than carved into their own crates: the control protocol lives in `kenneld::control`, the privhelper wire in `kennel-privhelper::wire`, and the `kennel` CLI is a binary inside `kenneld` (`src/bin/kennel.rs`). A wire protocol shared by exactly two binaries is a module in one of them, not a third crate, and the CLI and daemon ship from the same crate so their protocol cannot drift. The whole workspace is blocking, thread-per-connection; no async runtime is linked.

---

## Workspace layout

```
kennel/
├── Cargo.toml                       workspace root, [workspace] section, shared profile
├── Cargo.lock
├── rust-toolchain.toml
├── deny.toml                        cargo-deny config
├── supply-chain/
│   └── CHECKSUMS.toml               vendored-dep checksum manifest (§5.5 CODING-STANDARDS)
├── src/                             all first-party code lives under src/
│   ├── vendor/                      vendored .crate tarballs (§5.5 CODING-STANDARDS)
│   ├── bpf/                         BPF C source
│   │   ├── connect4.bpf.c
│   │   ├── connect6.bpf.c
│   │   ├── bind4.bpf.c
│   │   ├── bind6.bpf.c
│   │   ├── setsockopt.bpf.c
│   │   ├── sock_create.bpf.c
│   │   ├── sendmsg4.bpf.c
│   │   ├── sendmsg6.bpf.c
│   │   ├── maps.h                   single source of truth for map layouts
│   │   ├── audit_events.h           ringbuf event struct declarations
│   │   ├── kennel.bpf.h             shared helpers (UAPI-based; no vmlinux.h/CO-RE)
│   │   ├── README.md                why no CO-RE; build/inspect instructions
│   │   └── HELPERS.md               whitelist of permitted BPF helper functions
│   ├── crates/                      Rust workspace members (16)
│   │   ├── kennel-syscall/          the only unsafe-bearing crate (besides BPF/binder FFI)
│   │   ├── kennel-os/               safe OS helpers (path, uid/gid, netlink, handshake); re-exported by kennel-syscall
│   │   ├── kennel-text/             sanitisation helpers
│   │   ├── kennel-policy/           TOML parsing, signature verification (settled-policy core)
│   │   ├── kennel-bpf/              hand-rolled bpf(2) loader (object for ELF), .o, ringbuf reader
│   │   ├── kennel-binder/           hand-rolled binder ioctl ABI (unsafe; the inter-namespace gateway)
│   │   ├── kennel-audit/            unified audit writer: event, sanitise pass, levels, Sink fan-out
│   │   ├── kennel-config/           layered deployment/user config (system.toml / config.toml cascades)
│   │   ├── kennel-spawn/            policy → Plan → setup sequence (incl. the pivot_root view) → execve
│   │   ├── kennel-netproxy/         binary + lib: SOCKS5/HTTP egress proxy (blocking, thread-per-conn)
│   │   ├── kennel-privhelper/       binary + lib: privileged operations helper (wire format in src/wire.rs)
│   │   ├── kennel-init/             binary: root-owned kennel PID 1 (constructor handoff target, lifecycle consumer)
│   │   ├── kennel-ssh-reorigin/     binary + lib: SSH re-origination forced command (std-only; §7.10.4)
│   │   ├── kennel-socks-connect/    binary + lib: SOCKS5 stdio connector for ssh ProxyCommand (std-only; §7.10.4)
│   │   └── kenneld/                 lib + binaries: per-user supervisor (src/bin/kenneld.rs),
│   │                                CLI (src/bin/kennel.rs), bastion AKC (src/bin/kennel-akc.rs);
│   │                                control protocol in src/control.rs
│   │       (folded in, no separate crate: IPC → kenneld::control + kennel-privhelper::wire;
│   │        CLI → kenneld/src/bin/kennel.rs. Audit IS its own crate: kennel-audit.)
│   ├── tools/
│   │   ├── install.sh               installer
│   │   ├── install-hooks.sh         git hooks installer
│   │   ├── verify-checksums.sh      shell checksum-manifest verifier
│   │   ├── audit-helper.sh          helper for §5.5 dep audit
│   │   └── git-hooks/               in-tree git hook scripts
│   └── fuzz/                        cargo-fuzz targets
├── docs/                            architecture/, design/, governance/ doc streams
├── dist/                            packaging (apparmor profile, units, etc.)
├── templates/                       in-tree policy templates
├── keys/                            project signing keys
└── .github/                         CI, community-health
```

Every Rust crate in `crates/` is prefixed `kennel-` per CODING-STANDARDS.md §3. The binary-bearing crates are `kennel-netproxy` (`src/main.rs`), `kennel-privhelper` (`src/main.rs` + a library half for `wire`/`validate`), `kennel-init` (`src/main.rs` — the root-owned PID-1 supervisor, no library half), `kennel-ssh-reorigin` (`src/main.rs` + a library half holding the tested re-origination core), `kennel-socks-connect` (`src/main.rs` + a library half holding the tested SOCKS5 wire codec), and `kenneld` (a library half in `src/lib.rs` providing the orchestration its binaries share, plus `src/bin/kenneld.rs` for the daemon, `src/bin/kennel.rs` for the CLI, and `src/bin/kennel-akc.rs` for the SSH bastion's root-owned `AuthorizedKeysCommand`, which reuses `kenneld::control` to query the daemon — §7.10.7). The remaining crates are libraries (`src/lib.rs`).

---

## Dependency direction

The workspace is acyclic and layered. Lower-level crates do not depend on higher-level ones. The control protocol and the CLI are folded into kenneld rather than carved out separately; audit is its own crate (`kennel-audit`) and config its own (`kennel-config`):

```
        kenneld (lib + bin kenneld + bin kennel + bin kennel-akc)
          |  owns control.rs (CLI<->daemon wire) + proxy.rs config writer
          |  deps: spawn, privhelper, policy, netproxy, audit, config, syscall, binder
          +----------------+----------------+----------------+--------------+
          |                |                |                |              |
   kennel-netproxy   kennel-spawn   kennel-privhelper   kennel-audit  kennel-config
          |          (deps: bpf,    (lib+bin; wire.rs;       |          (leaf)
          | (deps:    policy,        deps: syscall,          | (deps:
          |  audit)   syscall)       bpf [opt])              |  text,
          |                |                |                |  syscall [opt])
          |          +-----+-------+--------+                |
          |          |     |       |                         |
          |     kennel-bpf |  kennel-policy            kennel-text
          |  kennel-binder |    (leaf)                   (leaf)
          |     (leaf*)    |                                 |
          |                |                                 |
          +----------------+----------- kennel-syscall ------+
                                              |
                  (libc, nix; kennel-bpf adds object; kennel-binder adds nothing)

  kennel-init (bin)           ← root-owned PID 1. deps: kennel-binder (lifecycle
                                consumer over node 0) + reuses the kennel-spawn seal
                                (no_new_privs/seccomp/Landlock/ulimits) for the workload
                                child it forks. The only binder participant besides kenneld.

  * kennel-bpf, kennel-binder and kennel-syscall are the three unsafe-bearing crates;
    all three are leaves among the Project Kennel crates (kennel-bpf and kennel-binder
    depend on no kennel crate except, for kennel-binder, optionally kennel-syscall for
    shared raw-fd helpers).

  kennel-ssh-reorigin (bin)   ← stands alone: std-only, no Project Kennel deps.
                                The bastion's forced command must stay minimal
                                and self-contained (§7.10.4).
  kennel-socks-connect (bin)  ← stands alone: std-only. The ssh ProxyCommand that
                                SOCKS5s through the egress proxy to the bastion.
```

Rules:

- **No cycles.** Enforced by Cargo (a cycle is a build error).
- **No depth skipping in spirit.** A crate may depend on any layer below it, but a binary depending directly on `kennel-syscall` to bypass the safe wrappers in `kennel-spawn` is a smell that warrants a review note.
- **`kennel-syscall` is the primary `unsafe`-bearing crate**, alongside `kennel-bpf` (hand-rolled `bpf(2)` FFI) and `kennel-binder` (hand-rolled binder `ioctl(2)` FFI). Every other crate carries `#![forbid(unsafe_code)]` per CODING-STANDARDS.md §4.
- **Binder is confined to two participants.** `kennel-binder` (the binder ABI) is linked only by `kenneld` (node 0 / context manager) and `kennel-init` (PID-1 lifecycle consumer pulling its plan over node 0); no other crate links it. The roadmap `kennel-netshim` (below) becomes a third linker when the network crossing is built. The workload never links `kennel-binder`.
- **`kennel-text` is a leaf-side utility crate** (no Project Kennel deps; stdlib only). Its single direct consumer is `kennel-audit`, which runs the one sanitisation pass on every event; other crates' untrusted text reaches that pass by emitting through the audit writer rather than by linking `kennel-text` themselves.
- **`kennel-policy`** does not depend on `kennel-spawn`, `kennel-bpf`, or any binary crate. The policy module is purely functional: same input, same output, no runtime side-effects.

---

## Per-crate notes

The full public-API description for each crate lives in `02-8-internal-api.md`. This section adds the structural and build-side notes that do not belong with the API description.

### `kennel-syscall`

- **Size ceiling: 1500 lines of Rust.** Reviewable in one sitting per CODING-STANDARDS.md §4.
- Carries `#![allow(unsafe_code)]` (the only library crate that does, alongside `kennel-bpf`).
- Listed in `UNSAFE-CRATES.md` at the workspace root.
- Per-feature `cfg`s for kernel-version conditional code paths; documented as the only crate where this is acceptable.

### `kennel-text`

- Tiny crate, ~200 lines target.
- Has its own fuzz target under `fuzz/text/`.

### `kennel-policy`

- Largest non-binary crate. Owns the schema types and the resolver.
- Builds with no I/O (file reading is the caller's responsibility); takes `&[u8]` for parsing.
- Has fuzz targets for the parser and the resolver.

### `kennel-config`

- Pure, I/O-light layered configuration (`#![forbid(unsafe_code)]`). No install-specific path is baked into a binary; deployment paths (privhelper, helper binaries, the daemon's trust store) come from TOML resolved through a cascade with compiled-in fallbacks.
- Two trust levels, two files, two search paths: `Deployment` (`system.toml`) is integrity-sensitive and resolved from **root-owned** dirs only (`/usr/lib/kennel` then `/etc/kennel`, never `~/.config`, no env override); `User` (`config.toml`) is convenience for the CLI (template/key search dirs) and resolved from `~/.config/kennel` then `/etc/kennel` then `/usr/lib/kennel`.
- A higher layer overrides a lower one per key; anything left unset falls back to the compiled defaults (`trust_dir` → `/etc/kennel/keys`, helpers → `/usr/libexec/kennel/<name>`).

### Audit (`kennel-audit`)

`kennel-audit` (`#![forbid(unsafe_code)]`) is the unified writer: the canonical `Event`, one `kennel-text` sanitisation pass, per-class level filtering, and a `Sink` trait fanning each event out to the file, stdout, syslog, and (feature `audit-journald`) journald sinks. The journald sink and the UUIDv7's randomness are the only parts needing FFI/`unsafe`; they live in `kennel-syscall` (`journal`, `random`). kenneld builds the writer from the settled `AuditRuntime` and emits lifecycle events through it; the egress proxy builds its own writer from the per-kennel proxy config and emits each `net.egress` record through it (`kennel-netproxy::audit` → `kennel_audit::Writer`). See `02-3-audit-schema.md` for the schema. Not yet routed through the writer: the BPF events — `kennel-bpf::ringbuf` provides the kernel-ringbuf reader (drops on full), but nothing in kenneld yet drains it into the writer. A roadmap remnant.

### `kennel-bpf`

- Carries `#![allow(unsafe_code)]` for the hand-rolled `bpf(2)` FFI surface (confined to `sys.rs`); same review discipline as `kennel-syscall`. ELF parsing is delegated to `object`; we do **not** use libbpf-rs/libbpf-sys or aya.
- The `bpf/` programs compile against the kernel UAPI (no CO-RE/`vmlinux.h`); `object` parses the `.o` and the loader resolves map relocations by symbol name (see `06-build-and-test.md`, `bpf/README.md`).
- The compiled `.bpf.o` files are embedded into the crate (no skeleton generation); `KENNEL_MAPS`/`KENNEL_PROGRAMS` describe the maps and programs in Rust, mirroring `bpf/maps.h`.

### `kennel-binder`

- The third `#![allow(unsafe_code)]` crate, parallel in every structural respect to `kennel-bpf`. `unsafe` is confined to a single `sys.rs` holding the `ioctl(2)` FFI (`BINDER_WRITE_READ`, `BINDER_SET_CONTEXT_MGR`, `BINDER_SET_MAX_THREADS`, `BINDER_VERSION`, the binderfs control `BINDER_CTL_ADD`); same review discipline as `kennel-bpf`/`kennel-syscall`. Listed in `UNSAFE-CRATES.md`. See `02-4-binder.md` for the full ABI surface.
- **No libbinder/libbinder-ndk.** The crate binds the stable binder UAPI directly (`linux/android/{binder,binderfs}.h`), the same way `bpf/` compiles against `<linux/bpf.h>` with no CO-RE. This is the second reason it is its own crate rather than a `kennel-syscall` addition: `kennel-syscall` carries the 1500-line reviewable-in-one-sitting ceiling and no kernel-header surface. If the build vendors the binder UAPI headers, they live alongside the crate under the same pinning discipline as `bpf/` headers (`BUILD-ENV.md`).
- **Near-leaf.** Like `kennel-bpf`, it depends on no other Project Kennel crate except (optionally) `kennel-syscall` for shared raw-fd helpers; it links `libc`/`nix` for the syscalls. No `object` (binder is an ioctl ABI, not an object format).
- It owns mechanism only (the `binder_write_read` command/return loop, transaction framing); kenneld owns all policy. Its `BC`/`BR` decoder is a natural fuzz-target home (`06-build-and-test.md`).

### IPC (folded — no `kennel-ipc-*` crates)

The control protocol (CLI ↔ kenneld) lives in `kenneld::control` (`Request`/`Response` + length-prefixed `read_frame`, native-endian, `MAX_MESSAGE`-bounded) and the privhelper protocol in `kennel-privhelper::wire` (fixed-size packed structs). Each protocol is shared by exactly two binaries that ship from the same crate, so it is a module there rather than a standalone crate. Both are sync/blocking; there is no async runtime anywhere. The wire parsers are the natural fuzz-target homes.

### `kennel-spawn`

- The largest crate by line count. Coordinates everything: policy validation, BPF map population, namespace setup, mount construction, Landlock sealing, seccomp installation, capability drop, environment construction, execve.
- The namespace and mount phases are built in-crate over `kennel-syscall` (bubblewrap-style, identity-mapped user namespace); there is no subprocess delegation to an external composer.
- Has integration tests that require root, gated behind `#[cfg(feature = "e2e")]` (which also pulls the embedded BPF programs via `kennel-bpf/embed-programs`).

### `kennel-netproxy`

- Binary crate with a library half. **Sync, blocking — one thread per connection. No async runtime.**
- The SOCKS5/HTTP server lives in `src/server.rs` (`socks5.rs`/`http.rs`); the allowlist evaluator in `src/allow.rs`; the JSONL audit formatter in `src/audit.rs`. All are unit-tested without the network.
- **Roadmap (per-kennel net-ns, `02-5-binder-net.md`):** when the network crossing is built, the proxy is no longer reached by a TCP loopback listener — it becomes a host-net-ns CONNECT delegate behind the `org.projectkennel.INet` node, dropping its SOCKS5 *server* and gaining a delegate-socketpair reader. The SOCKS5 *server* role moves into the roadmap `kennel-netshim` crate (next item). Not built — the kennel still shares the host network namespace.

### `kennel-netshim` (roadmap — not built)

- A **roadmap** crate (`02-5-binder-net.md`, `07-11-binder-netns.md`): the per-kennel network shim that runs inside the kennel net-ns when the network crossing is built. It holds the **fuzzed SOCKS5** server the workload egresses through, translating to `org.projectkennel.INet` `CONNECT` transactions over the binder bus (kenneld then dispatches to the `kennel-netproxy` host-net-ns delegate). It would become the **third** binder participant after kenneld and `kennel-init`. Not built — there is no `kennel-netshim` crate in the workspace today, and the kennel still shares the host network namespace.

### `kennel-privhelper`

- Binary crate. Sync, no async runtime.
- `panic = "abort"` for release builds (inherited from the workspace `[profile.release]`, not a per-crate block); the test profile keeps cargo's default unwinding (CODING-STANDARDS.md §8.5).
- Has its own dep list distinct from the workspace, kept deliberately small: `kennel-syscall`, and an *optional* `kennel-bpf` pulled in only under the `bpf-egress` feature (which also drags in clang at build time for the embedded `.o`). A plain build of the helper links neither `kennel-bpf` nor clang. No `serde`, no `serde_json` — the wire format is fixed-size packed structs hand-packed field-by-field (`src/wire.rs`). No async, no proc-macros.

### `kennel-init`

- Binary crate, no library half. The **root-owned PID 1** of every kennel: the privhelper factory `fexecve`s it (with empty argv/envp) as the trusted uid-0 process *after* `pivot_root`, so it is trapped in the sealed view from its first instruction (`07-2-kennel-init.md`). It does no policy decisions, no mount/netlink/device/fs-lookup/env code, and holds no ambient host caps — deliberately tiny and auditable, the same binary for every kennel.
- **Links `kennel-binder`** as a lifecycle consumer: it `open`s the per-kennel binderfs device and pulls its supervision-half plan from kenneld (node 0) via `GET_SANDBOX_PLAN`, then rides node 0 for the `NOTIFY_*` lifecycle verbs. This makes it the second binder participant alongside kenneld.
- **Reuses the `kennel-spawn` seal** — `no_new_privs` + seccomp + Landlock + ulimits + identity drop (`set_gid`/`set_uid`) — applied to the **workload child** it forks and drops to the operator, *not* to itself or the facades (which must remain free to fork, `waitpid`, and reach the bus). Only `kennel-init` stays uid 0 — a different uid from the operator-uid workload/facades, so they cannot signal or `ptrace` PID 1.

### `kennel-ssh-reorigin`

- Binary crate with a library half; **std-only, no Project Kennel deps and no external crates** — the SSH bastion's forced command must stay minimal and auditable (`07-10-ssh.md` §7.10.4).
- The library (`src/lib.rs`) holds the security-load-bearing core, all pure and unit-tested: strict `--dest`/`--key` parsing (option-injection-proof), the hostname and `SHA256:` grammars, `$SSH_USER_AUTH` publickey confirmation (fail-closed), exact fingerprint→agent-identity selection, and outbound-`ssh` argv construction (`--`-terminated so the attacker-controlled `$SSH_ORIGINAL_COMMAND` can never be read as a flag). `main.rs` is the thin IO tail (`ssh-add` enumeration, identity-file write, `execvp ssh`).
- Carries no key material: only the *public* half of the selected key is written (to a `0600` temp file), the private key stays in the user's agent/token.

### `kennel-socks-connect`

- Binary crate with a library half; **std-only, no Project Kennel deps and no external crates**. The `ssh` `ProxyCommand` a confined kennel uses to reach the bastion: a kennel can `connect()` only to its egress proxy (§7.5.2), and `ssh` has no built-in SOCKS client, so this speaks SOCKS5 CONNECT to `$KENNEL_SOCKS_PROXY` and splices stdio to the stream — without depending on `nc`/`ncat` being present in the workload image.
- The library (`src/lib.rs`) holds the pure SOCKS5 wire codec (greeting, CONNECT request for IPv4/IPv6/domain, reply parsing), unit-tested. `main.rs` does the TCP + bidirectional splice; the downlink flushes per chunk (stdout is a `LineWriter` and SSH key-exchange carries no newlines — left buffered it would stall the handshake).

### `kenneld`

- Library + binaries. **Sync, blocking — `serve()` accepts and spawns one thread per connection. No async runtime.**
- Owns the in-memory kennel registry, the per-kennel orchestration (`lib.rs`), the control protocol (`control.rs`), and the synthetic `/etc` (`etc.rs`) and synthetic `~/.ssh` (`ssh.rs`) generators. Draining the BPF ringbuf into the audit writer is not yet wired here — `kennel-bpf::ringbuf` provides the reader, but kenneld does not drive it (a roadmap remnant; see the `kennel-audit` note above).

### CLI (folded into `kenneld` as `src/bin/kennel.rs`)

- The `kennel` binary lives inside `kenneld`, not a separate crate. It is a thin sync Unix-socket client of the control protocol in `kenneld::control`. Shipping the CLI and the daemon from one crate keeps the protocol from drifting between them.
- Argument parsing is hand-rolled over `std::env::args` (dispatch on the first argument, each subcommand parsing its own flags); no `clap` and no proc-macro arg-parser is linked.

### Checksum verification (shell witness; no Rust crate)

- The checksum-manifest verifier is the shell script `src/tools/verify-checksums.sh` (system `sha256sum`), checking `supply-chain/CHECKSUMS.toml`. A Rust twin (with a tiny `sha2`/`serde`/`toml` dep graph) is a roadmap item; when it lands, both must agree and CI runs both.

---

## Build-time feature flags

A small set of feature flags allows distribution variation without forking. Each flag is documented at the use site and listed here.

| Flag | Crate | Default | Effect |
|---|---|---|---|
| `bpf-egress` | `kennel-privhelper` | off | Compile the BPF load/attach path into the privhelper. Pulls `kennel-bpf` with `embed-programs`. Required for live egress; rebuild before root tests (`06-build-and-test.md`). |
| `embed-programs` | `kennel-bpf` | off | Compile `bpf/*.bpf.c` with clang at build time (`build.rs`) and embed the objects, so a plain `cargo build` needs no clang. Enabled transitively by `bpf-egress` and by `e2e`. |
| `audit-journald` | `kennel-audit` | off | Link the journald sink (`libsystemd` FFI via `kennel-syscall`); off by default so the common build pulls no FFI surface. |
| `e2e` | several (`kennel-spawn`, `kennel-bpf`, `kennel-syscall`, `kennel-privhelper`, `kenneld`) | off | Compile and run tests that require root (cgroup creation, namespace ops, Landlock sealing, the kenneld e2e). Defined per-crate, not workspace-wide; run via `sudo -E … cargo test -p <crate> --features e2e`. |

Feature combinations tested in CI are listed in `06-build-and-test.md`. The default feature set is the minimum that produces a working binary for the most-common installation (single-user developer workstation, no journald requirement).

---

## Workspace `Cargo.toml`

The root `Cargo.toml` carries:

- `[workspace]` section listing every crate in `crates/`.
- `[workspace.package]` shared metadata: `version`, `edition`, `rust-version`, `license`, `authors`, `repository`, `publish` — inherited per member by `<field>.workspace = true`.
- `[workspace.lints]` shared `rust`/`clippy` lint config — inherited per member by `[lints] workspace = true`.
- `[profile.release]`: `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`, `panic = "abort"`. The `panic = "abort"` is workspace-wide for release builds; the test profile retains cargo's default unwinding (CODING-STANDARDS.md §8.5).

There is no `[workspace.dependencies]` table: members declare their own external dependencies with explicit version pins (e.g. `serde = "=1.0.228"` in `kennel-policy` and `kenneld`), so each crate's dep list is self-contained and reviewable on its own. There is likewise no `[profile.release-with-debuginfo]` profile; the release profile is the single shipped profile.

---

## Where to add new crates

- **A new sink** for the audit stream → `kennel-audit` (implement the `Sink` trait; gate any new system-library link behind a feature, as `audit-journald` does).
- **A new BPF program** → C source in `bpf/`, loader code in `kennel-bpf`. No new crate.
- **A new privileged operation** → a new operation type in `kennel-privhelper`. No new crate; the privhelper's scope is bounded by its review burden, not by line count.
- **A new external integration** (e.g., an MCP server to expose audit events via MCP) → a separate binary crate `kennel-<integration>`. Adding such an integration is itself an architectural decision and needs a doc update.

---

## What this chapter does not cover

- Per-crate public APIs and trait surfaces: `02-8-internal-api.md`.
- Build commands, CI matrix, test taxonomy: `06-build-and-test.md`.
- Dependency-policy rules (when to add a dep, audit cadence): CODING-STANDARDS.md §5.
- Specific dependency versions: `Cargo.toml` and `CHECKSUMS.toml`.
- Workspace boundaries vs published crates: nothing is currently published to crates.io; the workspace is internal.
