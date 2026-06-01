# §8 As-built notes: divergences, decisions, and lessons

This document is the running ledger of where the **implementation** has
deliberately diverged from the **design corpus** (the `docs/` chapters and the
other `architecture/` chapters), why, and what the implementation experience has
taught us. It exists because the design was written ahead of the code, and a
reader who audits the design as if it were the implementation will find gaps that
are not real (one such review, generated against the docs in mid-2026, reported
four "critical" bugs that were all either already-defended or describing code
that does not exist). Keep this file current as the build proceeds: when an
increment changes a decision the design recorded, add a row here in the same PR.

The design chapters remain the authoritative statement of *intent*. This chapter
is authoritative for *what is built today*. Where they conflict, the code wins
and this file says so.

## 8.1 Decisions that diverged from the design (with rationale)

| # | Design said | As built | Why | Where |
|---|---|---|---|---|
| 1 | netproxy + kenneld "use the async runtime (tokio)" | **Blocking, thread-per-connection.** No tokio anywhere in the workspace. | Matches the OpenSSH/libpam bar; keeps an async runtime out of the privileged-adjacent path; smaller TCB. | `kennel-netproxy/src/server.rs`, `kenneld/src/server.rs` |
| 2 | Settled policy is canonical **JSON** | **TOML** (`basic-toml`), canonical form = deterministic TOML in struct-field order | `serde_json`'s closure needs an unvendored float formatter (`zmij`); TOML is the config format anyway and we control both signer and verifier. | `kennel-policy/src/{settled,canonical}.rs` |
| 3 | BPF loader via libbpf-rs/libbpf-sys or aya | **Hand-rolled `bpf(2)` over `libc`, `object` for ELF parsing only** | ~1435 vendored C files / a 19-crate tree versus a small reviewed FFI. | `kennel-bpf/src/{sys,loader}.rs` |
| 4 | BPF compiled with `vmlinux.h` / CO-RE / BTF | **Compiled against kernel UAPI (`<linux/bpf.h>`), no BTF** | The programs touch only stable hook-context structs and our own maps; no CO-RE machinery needed. | `bpf/*.bpf.c`, `BUILD-ENV.md` |
| 5 | Landlock via the `landlock` crate | **Hand-rolled UAPI bindings** | Keeps `syn` and the first proc-macros out of the privileged build. | `kennel-syscall/src/landlock.rs` |
| 6 | Separate `kennel-ipc-shared` / `-client` / `-server`, `kennel-cli`, and `kennel-audit` crates | **Folded.** Control protocol in `kenneld::control`; privhelper wire in `kennel-privhelper::wire`; the `kennel` CLI is `kenneld/src/bin/kennel.rs`; audit is split between the BPF ringbuf drain and the netproxy's JSONL formatter. | The workspace has **8** crates, not the ~13 the decomposition diagram drew. Smaller surface; the protocols are small enough to live beside their owners. The unified audit *writer/sinks* are deferred (see §8.2). | `kenneld/`, `kennel-privhelper/` |
| 7 | Control IPC: `u32` **big-endian** length prefix; JSON handshake | **Native-endian** length prefix (local same-host UDS), bounded by `MAX_MESSAGE = 1 MiB` before allocation; **no handshake** (request/response directly) | Both ends are the same host/arch; a handshake buys nothing yet. The bound is the DoS guard the design wanted. | `kenneld/src/control.rs` (`read_frame`) |
| 8 | Privhelper request "292-byte struct" | **294-byte** fixed packed struct (`REQUEST_LEN = 294`), 6-byte response; not serde, not length-prefixed | Field layout settled at 294 (op/family/prefix/reserved/ctx/addr/interface/cgroup_path). | `kennel-privhelper/src/wire.rs` |
| 9 | `[net.dns]` resolver/mode/cache_ttl in the policy | **Dropped.** The proxy uses the OS resolver and vets the answers by policy. | No hand-rolled DNS, no resolver dependency, no tokio; the answer-vetting is the security property. | `kennel-netproxy/src/dns.rs` |
| 10 | Per-rule `tls.required` / `tls.pin_sha256` | **Not built.** TLS inspection is an enterprise/future layer. | Out of scope for v1; `NameRule` carries only `name`/`ports`/`protocol`. | `kennel-policy/src/settled.rs` (`NameRule`) |
| 11 | `kennel_meta` = 62 bytes, `proxy_addr_v6` at offset 12, `proxy_port` at 28 | **64 bytes**: `proxy_addr_v4`@8, `proxy_port`@12, `_pad0`@14, `proxy_addr_v6`@16, `policy_hash`@32 | Natural alignment + the proxy fields settled in this order. The loader's `value_size` is 64. | `bpf/maps.h`, `kennel-bpf/src/loader.rs` |
| 12 | `allow_entry_v4` (v4-specific value struct) | **`allow_entry`** — one value layout shared by the v4 and v6 tries (they differ only in key width); carries a `flags` byte (`KENNEL_ALLOW_FLAG_PROXY`) | The proxy allow-entry is flagged so the audit/readers can distinguish it. | `bpf/maps.h` |
| 13 | Abstract-AF_UNIX denial via seccomp `connect()` filter / AppArmor; signal isolation via PID-ns + AppArmor | **Landlock ABI-6 scoping** (`SCOPE_ABSTRACT_UNIX_SOCKET` + `SCOPE_SIGNAL`), default-on where the kernel supports it (6.12+; the dev/CI box is 6.17 = ABI 7) | Native, no userspace `sun_path` inspection, no AppArmor dependency. The seccomp/AppArmor path remains the documented fallback below ABI 6. | `kennel-syscall/src/landlock.rs` (`Scope`) |
| 14 | (design did not detail) | **Constructed-`$HOME` view via `pivot_root` is built**: fresh tmpfs root, granted system paths bound in place, `~/…` paths remapped beneath `shim_root`, `/etc` **constructed (not host-bound)**, `/dev` constructed from `fs.dev.allow` with the nodes Landlock-granted r/w/`IOCTL_DEV`, `/proc` with `hidepid=2`, private `/tmp`. Writable binds resolve to **persistent host inodes**. | This is the §7.2.5 view; see §8.3 for the inode subtlety. | `kennel-spawn/src/{lib,plan}.rs`, `kenneld/src/etc.rs` |

## 8.2 Deferred — designed but not yet built

These are real design intent, not dead ideas; they are simply not implemented, so
the design chapters that describe them should read as roadmap, not as-built:

- **The audit writer + sinks** (`02-3-audit-schema.md`): the journald/syslog/stdout
  sinks, the `[audit]` policy section / `audit.toml`, the per-sink 50 ms timeout,
  and a centralised `kennel-audit` writer. **Today:** BPF events go to a lock-free
  ring buffer that drops on full (`kennel-bpf/src/ringbuf.rs`, `bpf/kennel.bpf.h`),
  and the netproxy *formats* one JSONL record per request (`kennel-netproxy/src/audit.rs`)
  with the server owning the sink (stderr/file). No journald, no `sd_journal_send`.
- **The IPC handshake** (`02-4-ipc.md`): the JSON `kind`/`client_version`/`protocol_version`
  exchange. Today the control socket goes straight to request/response.
- **`kennel-checksum-verify`** (the Rust verifier of `03-crate-decomposition.md` / §5.5):
  the shell witness (`tools/verify-checksums.sh`) exists; the Rust crate lands at/after
  the first vendored-dep milestone.
- **Source-policy-only sections** (`02-2-config-schema.md`): `[unix]`, `[dbus]`,
  `[x11]`, `[env]`, `[ptrace]`, `[signal]`, `[audit]` are compile-time/source-policy
  concerns; the **settled** `EffectivePolicy` carries only `net`, `fs`, `exec`,
  `proc`, `cap`, `seccomp`, `lifecycle`. "Every section" in the settled doc means
  the resolved runtime-relevant subset.

## 8.3 Implementation lessons (apply these to the rest)

- **The Landlock ruleset must be built *after* `pivot_root`, in the child.** A rule
  opens an `O_PATH` fd at build time and is keyed to that inode. Bind mounts preserve
  inodes (so system/home/dev rules match a parent-built ruleset), but the constructed
  `/etc` has fresh tmpfs inodes a host-opened fd would never match — libc would be
  denied `/etc`. So the seal builds the ruleset post-pivot with a *skip-missing* pass
  (a grant for a path the view doesn't contain is vacuous). See `kennel-spawn::spawn`.
- **The process is ephemeral; the work is not.** The new root is a throwaway tmpfs,
  but every *writable* bind resolves to a persistent host inode (the agent's real
  project tree), so work survives teardown. Any new writable surface must keep this
  property — never let something the workload means to keep live only on the tmpfs.
- **Fail closed, and prove it adversarially.** Every BPF decision path defaults to
  `KENNEL_DENY`; every new scope/right ships with a test that shows the *denied*
  case actually denies on the running kernel (the IPv4-mapped-IPv6 connect, the
  abstract-socket scope, the device ioctl). A test that only shows the allow path
  is half a test.
- **Landlock denial errnos differ by class.** Filesystem/network rules deny with
  `EACCES`; scoping (`SCOPE_*`) denies with `EPERM`. Accept both when asserting "the
  scope bit fired".
- **Keep the docs reconciled per increment.** Doc drift is not cosmetic: it produces
  phantom-gap reviews that cost real time to refute. When an increment changes a
  decision recorded in `docs/`/`architecture/`, update that chapter (or add a row to
  §8.1) in the same PR.

## 8.4 Build and test gotchas

- **Rebuild the BPF privhelper before root tests.** A workspace `cargo test` /
  `cargo clippy --all-targets` rebuilds `kennel-privhelper` with default features,
  clobbering the `--features bpf-egress` binary; the `kenneld` e2e then fails with
  `ENOSYS`. Always `cargo build -p kennel-privhelper --features bpf-egress` (and
  `kennel-netproxy`) immediately before running the gated binaries.
- **Run the gated test *binaries* directly under sudo**, not `sudo cargo` (which
  leaves root-owned files in `target/`). Compile with `--features root-tests
  --no-run`, then `sudo ./target/debug/deps/<name>-<hash>`. Use `pkill -x kenneld`,
  never `pkill -f` (which matches the harness wrapper and kills the shell).
- **Stage shim / `/etc` / new-root dirs outside `/tmp`.** The seal mounts a fresh
  tmpfs over `/tmp` before the shadow binds; a `/tmp`-staged source vanishes.
  Production stages under `$XDG_RUNTIME_DIR`; tests under `/run`.
- **Do not run `cargo fmt`.** There is no `rustfmt.toml` and the installed rustfmt
  reflows the maintainer's wider-line hand-formatting across the whole corpus. New
  code matches the surrounding style by hand.
- **A required new settled-schema field touches every fixture.** Adding a
  non-defaulted field to a policy struct forces every `FsPolicy`/`Plan` literal
  across crates into the same commit (and interactive hunk-staging is unavailable
  in the agent environment), so the test-first phases fold for those changes.

## 8.5 Verify baseline (kernel 6.17, ABI 7)

As of this writing: `cargo test --workspace --offline` = 258 unprivileged tests,
clippy-clean under `-D warnings`. Root under sudo: kennel-syscall mount+landlock,
kennel-spawn 21/21, kenneld e2e 1/1 (the full vertical: addresses + BPF + real
netproxy on **both** v4+v6 listeners + synthetic `/etc` + constructed view +
teardown).
