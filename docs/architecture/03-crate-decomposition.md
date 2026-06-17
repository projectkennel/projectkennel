# Crate decomposition

This chapter describes the Cargo workspace layout: which crates exist, what each owns, how they depend on each other, and what build-time choices they expose. The *public APIs* of each crate are in `02-8-internal-api.md`; this chapter is the structural view — how the code is cut up, not what each piece exposes.

The workspace has **22 crates**: `kennel-lib-policy`, `kennel-lib-syscall`, `kennel-lib-os`, `kennel-lib-landlock`, `kennel-lib-scm`, `kennel-lib-bpf`, `kennel-lib-binder`, `kennel-lib-audit`, `kennel-lib-config`, `kennel-lib-control`, `kennel-lib-spawn`, `kennel-lib-text`, `host-netproxy`, `host-inetd`, `kennel-privhelper`, `kennel-bin-init`, `kenneld`, `kennel-cli`, `facade-afunix`, `facade-socks5`, `facade-client`, and `facade-ssh`. `kennel-lib-os` holds the **safe** OS primitives — path canonicalisation, uid/gid identity, per-kennel netlink address management, and the userns-map pipe handshake — split out of `kennel-lib-syscall` so that crate carries *only* genuinely-unsafe code and stays reviewable in one sitting (CODING-STANDARDS §4). `kennel-lib-landlock` is the hand-rolled Landlock ABI, the largest single unsafe module, likewise split out of `kennel-lib-syscall`. `kennel-lib-scm` is the small `SCM_RIGHTS` fd-passing helper, also split out so a dumb delegate like `host-netproxy` can receive a conduit fd without pulling the whole unsafe crate. `kennel-lib-syscall` depends on these and re-exports them, so callers reach them as `kennel_lib_syscall::{path, unistd, netlink, handshake, landlock, scm}` unchanged. `facade-afunix`, `facade-socks5`, `facade-client`, and `facade-ssh` are the in-kennel ends of the binder connectors: small proxies `kennel-bin-init` launches inside the view. `facade-afunix` / `facade-socks5` / `facade-ssh` push the workload's outbound AF_UNIX / SOCKS5-or-HTTP / `ssh` traffic across the binder gateway to kenneld (`07-6-afunix.md`, `07-5-network.md` §7.5.2, `07-10-ssh.md`); `facade-socks5` serves both SOCKS5 and HTTP-proxy on one listener (first-byte detection). `facade-client` is the *inbound* mirror's in-kennel end: it pulls each host-side connection to a policy-mirrored bind port (the `BIND_INET` verb) and connects the workload's native listener (`07-5-network.md` §7.5.7). `host-netproxy` and `host-inetd` are the matching *host-side* delegates — the dumb outbound dialer and the dumb inbound binder/accepter respectively — each a glorified netcat that receives a conduit fd over an owner-only `AF_UNIX` socket while kenneld holds all the policy. `kennel-lib-binder` is the hand-rolled binder ioctl ABI (the per-kennel inter-namespace gateway, `02-4-binder.md`), parallel in every structural respect to `kennel-lib-bpf`; binder is load-bearing, so every kennel links it through kenneld, `kennel-bin-init`, and the facades. `kennel-bin-init` is the root-owned PID-1 binary the privhelper `fexecve`s to construct and supervise each kennel (`07-2-kennel-bin-init.md`). `kennel-lib-audit` is a first-class crate — the unified audit writer (the canonical event, one sanitisation pass, per-class level filtering, and the `Sink` fan-out). `kennel-lib-config` is a first-class crate too — the layered deployment/user configuration (`system.toml` / `config.toml` cascades) that keeps install paths out of the binaries. The operator CLI and the control protocol are their own crates so the unprivileged CLI is **outside the daemon's TCB**: `kennel-cli` is the `kennel` binary, and `kennel-lib-control` holds the CLI↔daemon wire protocol (`Request`/`Response` + framing + the socket-path resolver), re-exported as `kenneld::{control, socket}` so the daemon side is unchanged. The split keeps the CLI's dependencies — `serde_json` (via the `kennel-lib-manifest` trust-manifest reader) and the `lexopt` arg parser — out of `kenneld`'s dependency closure entirely, a hard crate boundary in place of the earlier "the daemon binary happens not to reference them". The protocol cannot drift because both sides depend on the one `kennel-lib-control` crate. The privhelper wire stays in `kennel-privhelper::wire` (it is privhelper↔daemon, both in the TCB). The whole workspace is blocking, thread-per-connection; no async runtime is linked.

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
│   ├── crates/                      Rust workspace members
│   │   ├── kennel-lib-syscall/          syscalls/namespaces/seccomp/FFI (unsafe); re-exports kennel-lib-os + kennel-lib-landlock + kennel-lib-scm
│   │   ├── kennel-lib-os/               safe OS helpers (path, uid/gid, netlink, handshake); re-exported by kennel-lib-syscall
│   │   ├── kennel-lib-landlock/         hand-rolled Landlock ABI (unsafe); re-exported by kennel-lib-syscall
│   │   ├── kennel-lib-scm/              SCM_RIGHTS fd-passing helper (unsafe); re-exported by kennel-lib-syscall
│   │   ├── kennel-lib-text/             sanitisation helpers
│   │   ├── kennel-lib-control/          CLI<->daemon control wire protocol + socket path (shared; no enforcement code)
│   │   ├── kennel-lib-policy/           TOML parsing, signature verification (settled-policy core)
│   │   ├── kennel-lib-bpf/              hand-rolled bpf(2) loader (object for ELF), .o, ringbuf reader
│   │   ├── kennel-lib-binder/           hand-rolled binder ioctl ABI (unsafe; the inter-namespace gateway)
│   │   ├── kennel-lib-audit/            unified audit writer: event, sanitise pass, levels, Sink fan-out
│   │   ├── kennel-lib-config/           layered deployment/user config (system.toml / config.toml cascades)
│   │   ├── kennel-lib-spawn/            policy → Plan → setup sequence (incl. the pivot_root view) → execve
│   │   ├── host-netproxy/         binary + lib: host-side egress dial delegate (dumb netcat; §7.5)
│   │   ├── host-inetd/            binary + lib: host-side inbound BIND delegate (dumb accepter; §7.5.7)
│   │   ├── kennel-privhelper/       binary + lib: privileged operations helper (wire format in src/wire.rs)
│   │   ├── kennel-bin-init/             binary: root-owned kennel PID 1 (constructor handoff target, lifecycle consumer)
│   │   ├── facade-afunix/           binary: in-kennel AF_UNIX broker → binder IAfUnix CONNECT (§7.6)
│   │   ├── facade-socks5/           binary: in-kennel SOCKS5 + HTTP-proxy front-end → binder INet CONNECT (§7.5)
│   │   ├── facade-client/          binary: in-kennel inbound facade → binder INet BIND (§7.5.7)
│   │   ├── facade-ssh/              binary: in-kennel ssh ProxyCommand → binder INet CONNECT (§7.10)
│   │   ├── kenneld/                 lib + binaries: per-user supervisor (src/bin/kenneld.rs)
│   │   │                            + bastion AKC (src/bin/kennel-akc.rs); re-exports
│   │   │                            kennel-lib-control as kenneld::{control, socket}
│   │   └── kennel-cli/              binary: the `kennel` operator CLI (src/main.rs); unprivileged,
│   │                                outside the daemon TCB (its serde_json/lexopt deps stay here)
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

Every Rust crate in `crates/` is prefixed `kennel-` (or `facade-`) per CODING-STANDARDS.md §3. The binary-bearing crates are `host-netproxy` / `host-inetd` (each `src/main.rs` + a library half for the conduit wire — the host-side egress/inbound delegates), `kennel-privhelper` (`src/main.rs` + a library half for `wire`/`validate`), `kennel-bin-init` (`src/main.rs` — the root-owned PID-1 supervisor, no library half), `facade-afunix` / `facade-socks5` / `facade-client` / `facade-ssh` (each `src/main.rs` — the in-kennel ends of the binder connectors), `kennel-cli` (`src/main.rs` — the unprivileged `kennel` operator CLI), and `kenneld` (a library half in `src/lib.rs` providing the orchestration its binaries share, plus `src/bin/kenneld.rs` for the daemon and `src/bin/kennel-akc.rs` for the SSH bastion's root-owned `AuthorizedKeysCommand`, which reuses `kenneld::control` — re-exported from `kennel-lib-control` — to query the daemon, §7.10.7). The remaining crates are libraries (`src/lib.rs`).

---

## Dependency direction

The workspace is acyclic and layered. Lower-level crates do not depend on higher-level ones. The control protocol is its own crate (`kennel-lib-control`, shared by the daemon and the CLI), the CLI is its own crate (`kennel-cli`, unprivileged — outside the daemon TCB), audit is its own crate (`kennel-lib-audit`) and config its own (`kennel-lib-config`):

```
  kennel-cli (bin `kennel`)  ← the unprivileged operator CLI. deps: kennel-lib-control,
                                policy, config, manifest (serde_json), audit, syscall, lexopt.
                                NOT in the daemon TCB; dials the socket kenneld serves.
          |
          v  (control wire only)
        kennel-lib-control  ← Request/Response framing + socket path (deps: syscall). Shared:
          ^                   kenneld re-exports it as kenneld::{control, socket}.
          |
        kenneld (lib + bin kenneld + bin kennel-akc)
          |  serves kennel-lib-control + owns proxy.rs config writer
          |  deps: control, spawn, privhelper, policy, netproxy, inetd, audit, config, syscall, binder
          +----------------+----------------+----------------+--------------+
          |                |                |                |              |
   host-netproxy   kennel-lib-spawn   kennel-privhelper   kennel-lib-audit  kennel-lib-config
          |          (deps: bpf,    (lib+bin; wire.rs;       |          (leaf)
          | (deps:    policy,        deps: syscall,          | (deps:
          |  audit)   syscall)       bpf [opt])              |  text,
          |                |                |                |  syscall [opt])
          |          +-----+-------+--------+                |
          |          |     |       |                         |
          |     kennel-lib-bpf |  kennel-lib-policy            kennel-lib-text
          |  kennel-lib-binder |    (leaf)                   (leaf)
          |     (leaf*)    |                                 |
          |                |                                 |
          +----------------+----------- kennel-lib-syscall ------+
                                              |
                  (libc, nix; kennel-lib-bpf adds object; kennel-lib-binder adds nothing)

  kennel-bin-init (bin)           ← root-owned PID 1. deps: kennel-lib-binder (lifecycle
                                consumer over node 0) + reuses the kennel-lib-spawn seal
                                (no_new_privs/seccomp/Landlock/ulimits) for the workload
                                child it forks. A binder participant alongside kenneld
                                and the in-kennel facades.

  * kennel-lib-bpf, kennel-lib-binder and kennel-lib-syscall are the three unsafe-bearing crates;
    all three are leaves among the Project Kennel crates (kennel-lib-bpf and kennel-lib-binder
    depend on no kennel crate except, for kennel-lib-binder, optionally kennel-lib-syscall for
    shared raw-fd helpers).

  facade-afunix / facade-socks5 / facade-client / facade-ssh (bins)  ← the in-kennel ends of the
                                binder connectors. deps: kennel-lib-binder (the client
                                transaction surface); launched inside the view by
                                kennel-bin-init, they push the workload's AF_UNIX / SOCKS5 /
                                ssh traffic across the binder gateway to kenneld (§7.6, §7.5, §7.10).
```

Rules:

- **No cycles.** Enforced by Cargo (a cycle is a build error).
- **No depth skipping in spirit.** A crate may depend on any layer below it, but a binary depending directly on `kennel-lib-syscall` to bypass the safe wrappers in `kennel-lib-spawn` is a smell that warrants a review note.
- **`kennel-lib-syscall` is the primary `unsafe`-bearing crate**, alongside `kennel-lib-bpf` (hand-rolled `bpf(2)` FFI), `kennel-lib-binder` (hand-rolled binder `ioctl(2)` FFI), `kennel-lib-landlock` (the hand-rolled Landlock ABI), and `kennel-lib-scm` (the `SCM_RIGHTS` fd adoption). Every other crate carries `#![forbid(unsafe_code)]` per CODING-STANDARDS.md §4.
- **Binder linkers are a closed set.** `kennel-lib-binder` (the binder ABI) is linked only by `kenneld` (node 0 / context manager), `kennel-bin-init` (PID-1 lifecycle consumer pulling its plan over node 0), and the in-kennel facades `facade-afunix` / `facade-socks5` / `facade-client` / `facade-ssh` (the connector clients that transact to node 0). No other crate links it; the workload never links `kennel-lib-binder`.
- **`kennel-lib-text` is a leaf-side utility crate** (no Project Kennel deps; stdlib only). Its single direct consumer is `kennel-lib-audit`, which runs the one sanitisation pass on every event; other crates' untrusted text reaches that pass by emitting through the audit writer rather than by linking `kennel-lib-text` themselves.
- **`kennel-lib-policy`** does not depend on `kennel-lib-spawn`, `kennel-lib-bpf`, or any binary crate. The policy module is purely functional: same input, same output, no runtime side-effects.

---

## Per-crate notes

The full public-API description for each crate lives in `02-8-internal-api.md`. This section adds the structural and build-side notes that do not belong with the API description.

### `kennel-lib-syscall`

- **Size ceiling: 1500 lines of Rust.** Reviewable in one sitting per CODING-STANDARDS.md §4.
- Carries `#![allow(unsafe_code)]` (the only library crate that does, alongside `kennel-lib-bpf`).
- Listed in `UNSAFE-CRATES.md` at the workspace root.
- Per-feature `cfg`s for kernel-version conditional code paths; documented as the only crate where this is acceptable.

### `kennel-lib-text`

- Tiny crate, ~200 lines target.
- Has its own fuzz target under `fuzz/text/`.

### `kennel-lib-policy`

- Largest non-binary crate. Owns the schema types and the resolver.
- Builds with no I/O (file reading is the caller's responsibility); takes `&[u8]` for parsing.
- Has fuzz targets for the parser and the resolver.

### `kennel-lib-config`

- Pure, I/O-light layered configuration (`#![forbid(unsafe_code)]`). No install-specific path is baked into a binary; deployment paths (privhelper, helper binaries, the daemon's trust store) come from TOML resolved through a cascade with compiled-in fallbacks.
- Two trust levels, two files, two search paths: `Deployment` (`system.toml`) is integrity-sensitive and resolved from **root-owned** dirs only (`/usr/lib/kennel` then `/etc/kennel`, never `~/.config`, no env override); `User` (`config.toml`) is convenience for the CLI (template/key search dirs) and resolved from `~/.config/kennel` then `/etc/kennel` then `/usr/lib/kennel`.
- A higher layer overrides a lower one per key; anything left unset falls back to the compiled defaults (`trust_dir` → `/etc/kennel/keys`, helpers → `/usr/libexec/kennel/<name>`).

### Audit (`kennel-lib-audit`)

`kennel-lib-audit` (`#![forbid(unsafe_code)]`) is the unified writer: the canonical `Event`, one `kennel-lib-text` sanitisation pass, per-class level filtering, and a `Sink` trait fanning each event out to the file, stdout, syslog, and (feature `audit-journald`) journald sinks. The journald sink and the UUIDv7's randomness are the only parts needing FFI/`unsafe`; they live in `kennel-lib-syscall` (`journal`, `random`). kenneld builds the writer from the settled `AuditRuntime` and emits lifecycle events through it; the egress proxy builds its own writer from the per-kennel proxy config and emits each `net.egress` record through it (`host-netproxy::audit` → `kennel_lib_audit::Writer`). See `02-3-audit-schema.md` for the schema. The BPF events route through the same writer: `kennel-lib-bpf::ringbuf` provides the kernel-ringbuf reader (drops on full), and `kenneld::bpf_audit` reopens the privhelper-pinned per-kennel buffer with `BPF_OBJ_GET` and drains it into the writer with `source: bpf` (proven end to end by `kenneld/tests/bpf_drain.rs`).

### `kennel-lib-bpf`

- Carries `#![allow(unsafe_code)]` for the hand-rolled `bpf(2)` FFI surface (confined to `sys.rs`); same review discipline as `kennel-lib-syscall`. ELF parsing is delegated to `object`; we do **not** use libbpf-rs/libbpf-sys or aya.
- The `bpf/` programs compile against the kernel UAPI (no CO-RE/`vmlinux.h`); `object` parses the `.o` and the loader resolves map relocations by symbol name (see `06-build-and-test.md`, `bpf/README.md`).
- The compiled `.bpf.o` files are embedded into the crate (no skeleton generation); `KENNEL_MAPS`/`KENNEL_PROGRAMS` describe the maps and programs in Rust, mirroring `bpf/maps.h`.

### `kennel-lib-binder`

- The third `#![allow(unsafe_code)]` crate, parallel in every structural respect to `kennel-lib-bpf`. `unsafe` is confined to a single `sys.rs` holding the `ioctl(2)` FFI (`BINDER_WRITE_READ`, `BINDER_SET_CONTEXT_MGR`, `BINDER_SET_MAX_THREADS`, `BINDER_VERSION`, the binderfs control `BINDER_CTL_ADD`); same review discipline as `kennel-lib-bpf`/`kennel-lib-syscall`. Listed in `UNSAFE-CRATES.md`. See `02-4-binder.md` for the full ABI surface.
- **No libbinder/libbinder-ndk.** The crate binds the stable binder UAPI directly (`linux/android/{binder,binderfs}.h`), the same way `bpf/` compiles against `<linux/bpf.h>` with no CO-RE. This is the second reason it is its own crate rather than a `kennel-lib-syscall` addition: `kennel-lib-syscall` carries the 1500-line reviewable-in-one-sitting ceiling and no kernel-header surface. If the build vendors the binder UAPI headers, they live alongside the crate under the same pinning discipline as `bpf/` headers (`BUILD-ENV.md`).
- **Near-leaf.** Like `kennel-lib-bpf`, it depends on no other Project Kennel crate except (optionally) `kennel-lib-syscall` for shared raw-fd helpers; it links `libc`/`nix` for the syscalls. No `object` (binder is an ioctl ABI, not an object format).
- It owns mechanism only (the `binder_write_read` command/return loop, transaction framing); kenneld owns all policy. Its `BC`/`BR` decoder is a natural fuzz-target home (`06-build-and-test.md`).

### IPC (`kennel-lib-control` + `kennel-privhelper::wire`)

The control protocol (CLI ↔ kenneld) lives in its own crate `kennel-lib-control` (`Request`/`Response` + length-prefixed `read_frame`, native-endian, `MAX_MESSAGE`-bounded), shared by both sides: `kenneld` serves it and re-exports it as `kenneld::{control, socket}`, while the unprivileged `kennel-cli` dials it. It is a separate crate so the CLI links the wire types **without** the daemon's enforcement code, keeping the CLI's `serde_json`/`lexopt` deps out of the daemon's TCB closure. The privhelper protocol stays in `kennel-privhelper::wire` (fixed-size packed structs) — it is privhelper↔daemon, both inside the TCB, so a shared crate buys no boundary. Both are sync/blocking; there is no async runtime anywhere. The wire parsers are the natural fuzz-target homes.

### `kennel-lib-spawn`

- The largest crate by line count. Coordinates everything: policy validation, BPF map population, namespace setup, mount construction, Landlock sealing, seccomp installation, capability drop, environment construction, execve.
- The namespace and mount phases are built in-crate over `kennel-lib-syscall` (bubblewrap-style, identity-mapped user namespace); there is no subprocess delegation to an external composer.
- Has integration tests that require root, gated behind `#[cfg(feature = "e2e")]` (which also pulls the embedded BPF programs via `kennel-lib-bpf/embed-programs`).

### `host-netproxy`

- Binary crate with a library half. **Sync, blocking — one thread per connection. No async runtime.**
- The host-side **egress dial delegate** (`07-5-network.md` §7.5.2): a glorified `netcat`. kenneld owns the entire egress decision (allow/deny, DNS resolve, address pin — `kenneld::inet`); this delegate binds one owner-only `AF_UNIX` command socket and, per command kenneld sends `(port, pinned IPs)` + a conduit fd over `SCM_RIGHTS`, dials the pinned address from the host stack and splices. No TCP listener, no SOCKS5/HTTP server, no resolver, no policy, no config — the conduit relay logic is in `src/conduit.rs`. (The SOCKS5/HTTP *server* role lives in `facade-socks5`, inside the kennel.)

### `host-inetd`

- Binary crate with a library half. **Sync, blocking — one thread per connection.**
- The host-side **inbound BIND delegate** (`07-5-network.md` §7.5.7), the reverse of `host-netproxy`: it binds each policy-mirrored `ip:port` on the host loopback alias, accepts, mints the conduit socketpair, splices the accepted connection to the host end locally, and pushes the kennel end (+ port) back to kenneld over the owner-only command socket. kenneld registers the ports and routes the conduit; it makes no inbound policy decision (the `bind4`/`6` cgroup ACL already gated the bind). The bind/accept/notify logic is in `src/listen.rs`.

### `facade-socks5`

- In-kennel binary (`07-5-network.md` §7.5.2/§7.5.6): the workload's egress endpoint. One loopback listener serves **both SOCKS5 and HTTP-proxy** (first-byte detection — `src/protocol.rs`); the HTTP-proxy parser (CONNECT tunnel + absolute-form forward) is `src/http.rs`. Each request transacts `CONNECT_INET` to binder node 0; kenneld decides under `[net.proxy]`, resolves+pins, drives the `host-netproxy` delegate, and returns the conduit fd, which the shim splices. No policy, no resolver, no host socket — the name (never a resolved address) crosses to kenneld. A binder participant alongside kenneld, `kennel-bin-init`, and the other facades.

### `facade-client`

- In-kennel binary (`07-5-network.md` §7.5.7): the inbound mirror's in-kennel end, the reverse of `facade-socks5`. For each policy-mirrored bind port it transacts `BIND_INET` to node 0 (pull-based — re-arming on `AGAIN`), and on a delivered conduit connects the workload's native listener at `<kennel-ip>:<port>` and splices. No policy; kenneld brokers the host-side accept.

### `kennel-privhelper`

- Binary crate. Sync, no async runtime.
- `panic = "abort"` for release builds (inherited from the workspace `[profile.release]`, not a per-crate block); the test profile keeps cargo's default unwinding (CODING-STANDARDS.md §8.5).
- Has its own dep list distinct from the workspace, kept deliberately small: `kennel-lib-syscall`, and an *optional* `kennel-lib-bpf` pulled in only under the `bpf-egress` feature (which also drags in clang at build time for the embedded `.o`). A plain build of the helper links neither `kennel-lib-bpf` nor clang. No `serde`, no `serde_json` — the wire format is fixed-size packed structs hand-packed field-by-field (`src/wire.rs`). No async, no proc-macros.

### `kennel-bin-init`

- Binary crate, no library half. The **root-owned PID 1** of every kennel: the privhelper factory `fexecve`s it (with empty argv/envp) as the trusted uid-0 process *after* `pivot_root`, so it is trapped in the sealed view from its first instruction (`07-2-kennel-bin-init.md`). It does no policy decisions, no mount/netlink/device/fs-lookup/env code, and holds no ambient host caps — deliberately tiny and auditable, the same binary for every kennel.
- **Links `kennel-lib-binder`** as a lifecycle consumer: it `open`s the per-kennel binderfs device and pulls its supervision-half plan from kenneld (node 0) via `GET_SANDBOX_PLAN`, then rides node 0 for the `NOTIFY_*` lifecycle verbs. This makes it the second binder participant alongside kenneld.
- **Reuses the `kennel-lib-spawn` seal** — `no_new_privs` + seccomp + Landlock + ulimits + identity drop (`set_gid`/`set_uid`) — applied to the **workload child** it forks and drops to the operator, *not* to itself or the facades (which must remain free to fork, `waitpid`, and reach the bus). Only `kennel-bin-init` stays uid 0 — a different uid from the operator-uid workload/facades, so they cannot signal or `ptrace` PID 1.

### `facade-afunix` / `facade-socks5` / `facade-ssh`

- The in-kennel ends of the binder connectors (`#![forbid(unsafe_code)]`): small `kennel-bin-init`-launched proxies that push the workload's AF_UNIX (`07-6-afunix.md`), SOCKS5 (§7.5), and `ssh` (`07-10-ssh.md`) traffic across the binder gateway to kenneld. Each opens the in-view binderfs device and transacts to node 0; any failure exits non-zero so the workload's client sees a dead connector and fails closed.
- **`facade-ssh`** is the `ssh` `ProxyCommand` (`ProxyCommand facade-ssh %h %p`): a confined kennel has no network path off its loopback, so `ssh` reaches the bastion by issuing an `INet` `CONNECT_INET` to kenneld, which has `host-netproxy` dial the bastion on the kennel's behalf, and splicing the returned fd to stdio. There is no re-origination binary, no agent, and no fingerprint selection — the bastion's `kennel-akc` bakes the forced command `ssh <options> -- <dest>` straight into the `authorized_keys` line, run as the operator. The workload's `~/.ssh` carries only a compile-minted synthetic key whose public half is pinned into the signed grant.
- **`facade-socks5`** is the SOCKS5 front-end (§7.5): it accepts the workload's SOCKS5 CONNECT and translates each to an `INet` `CONNECT_INET` over the binder bus.
- **`facade-afunix`** brokers the workload's AF_UNIX connect through the `org.projectkennel.IAfUnix/default` facade (`07-6-afunix.md`).
- Each links only `kennel-lib-binder` (the client transaction surface); none links any other Project Kennel crate.

### `kenneld`

- Library + binaries. **Sync, blocking — `serve()` accepts and spawns one thread per connection. No async runtime.**
- Owns the in-memory kennel registry, the per-kennel orchestration (`lib.rs`), the control protocol (`control.rs`), and the synthetic `/etc` (`etc.rs`) and synthetic `~/.ssh` (`ssh.rs`) generators. It drains each kennel's pinned BPF audit ringbuf into the unified writer (`bpf_audit.rs`, `source: bpf`) — `kennel-lib-bpf::ringbuf` provides the reader, `bpf_audit` drives it per kennel.

### `kennel-cli` (the `kennel` operator CLI)

- Its own crate (`src/main.rs`), **outside the daemon TCB**: the unprivileged CLI links the control wire types via `kennel-lib-control` but none of the daemon's enforcement code, so its `serde_json` (trust-manifest reader) and `lexopt` (arg parser) deps stay out of `kenneld`'s dependency closure. The protocol cannot drift because both sides depend on the one `kennel-lib-control` crate.
- A thin sync Unix-socket client of the control protocol. Argument parsing is `lexopt` over `std::env::args` (dispatch on the first argument, each subcommand parsing its own flags); no `clap` and no proc-macro arg-parser is linked.

### Checksum verification (shell witness; no Rust crate)

- The checksum-manifest verifier is the shell script `src/tools/verify-checksums.sh` (system `sha256sum`), checking `supply-chain/CHECKSUMS.toml`. A Rust twin (with a tiny `sha2`/`serde`/`toml` dep graph) is a roadmap item; when it lands, both must agree and CI runs both.

---

## Build-time feature flags

A small set of feature flags allows distribution variation without forking. Each flag is documented at the use site and listed here.

| Flag | Crate | Default | Effect |
|---|---|---|---|
| `bpf-egress` | `kennel-privhelper` | off | Compile the BPF load/attach path into the privhelper. Pulls `kennel-lib-bpf` with `embed-programs`. Required for live egress; rebuild before root tests (`06-build-and-test.md`). |
| `embed-programs` | `kennel-lib-bpf` | off | Compile `bpf/*.bpf.c` with clang at build time (`build.rs`) and embed the objects, so a plain `cargo build` needs no clang. Enabled transitively by `bpf-egress` and by `e2e`. |
| `audit-journald` | `kennel-lib-audit` | off | Link the journald sink (`libsystemd` FFI via `kennel-lib-syscall`); off by default so the common build pulls no FFI surface. |
| `e2e` | several (`kennel-lib-spawn`, `kennel-lib-bpf`, `kennel-lib-syscall`, `kennel-privhelper`, `kenneld`) | off | Compile and run tests that require root (cgroup creation, namespace ops, Landlock sealing, the kenneld e2e). Defined per-crate, not workspace-wide; run via `sudo -E … cargo test -p <crate> --features e2e`. |

Feature combinations tested in CI are listed in `06-build-and-test.md`. The default feature set is the minimum that produces a working binary for the most-common installation (single-user developer workstation, no journald requirement).

---

## Workspace `Cargo.toml`

The root `Cargo.toml` carries:

- `[workspace]` section listing every crate in `crates/`.
- `[workspace.package]` shared metadata: `version`, `edition`, `rust-version`, `license`, `authors`, `repository`, `publish` — inherited per member by `<field>.workspace = true`.
- `[workspace.lints]` shared `rust`/`clippy` lint config — inherited per member by `[lints] workspace = true`.
- `[profile.release]`: `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`, `panic = "abort"`. The `panic = "abort"` is workspace-wide for release builds; the test profile retains cargo's default unwinding (CODING-STANDARDS.md §8.5).

There is no `[workspace.dependencies]` table: members declare their own external dependencies with explicit version pins (e.g. `serde = "=1.0.228"` in `kennel-lib-policy` and `kenneld`), so each crate's dep list is self-contained and reviewable on its own. There is likewise no `[profile.release-with-debuginfo]` profile; the release profile is the single shipped profile.

---

## Where to add new crates

- **A new sink** for the audit stream → `kennel-lib-audit` (implement the `Sink` trait; gate any new system-library link behind a feature, as `audit-journald` does).
- **A new BPF program** → C source in `bpf/`, loader code in `kennel-lib-bpf`. No new crate.
- **A new privileged operation** → a new operation type in `kennel-privhelper`. No new crate; the privhelper's scope is bounded by its review burden, not by line count.
- **A new external integration** (e.g., an MCP server to expose audit events via MCP) → a separate binary crate `kennel-<integration>`. Adding such an integration is itself an architectural decision and needs a doc update.

---

## What this chapter does not cover

- Per-crate public APIs and trait surfaces: `02-8-internal-api.md`.
- Build commands, CI matrix, test taxonomy: `06-build-and-test.md`.
- Dependency-policy rules (when to add a dep, audit cadence): CODING-STANDARDS.md §5.
- Specific dependency versions: `Cargo.toml` and `CHECKSUMS.toml`.
- Workspace boundaries vs published crates: nothing is currently published to crates.io; the workspace is internal.
