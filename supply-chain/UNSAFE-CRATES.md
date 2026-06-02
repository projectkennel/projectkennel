# Crates permitted to contain `unsafe`

By default every crate in the workspace carries `#![forbid(unsafe_code)]` ([CODING-STANDARDS.md](../docs/governance/CODING-STANDARDS.md) §3, §4). This file lists the crates that do **not** — the ones permitted to contain `unsafe` blocks. The list is short by design and changing it is a significant review event: adding a crate here requires the all-maintainers review described in §4.

Every `unsafe` block in a listed crate follows the `SAFETY:` / `INVARIANTS UPHELD:` / `FAILURE MODE:` comment template of §4, and every PR touching `unsafe` needs two maintainer approvals.

## Principle: prefer a vetted crate to our own `unsafe`

"Don't roll your own crypto" extends to `unsafe`. Where a well-audited crate
already wraps a syscall or ABI soundly, we use it rather than writing the
`unsafe` ourselves — `nix` for the general syscalls, `seccompiler` for the
seccomp-BPF filter (hand-rolling BPF bytecode is the genuinely dangerous case),
and `object` for ELF parsing. The converse also applies: where the vetted
crate's *cost* outweighs the `unsafe` it saves, we hand-roll the narrow ABI
instead. Two deliberate exceptions: **Landlock** (the `landlock` crate would
pull `syn`/proc-macros into the privileged TCB; its ABI is three syscalls) and
the **`bpf(2)` loader** (libbpf-sys vendors ~1435 C files, aya pulls 19 crates;
we use `object` for ELF and hand-roll the small, security-bearing loader).
This keeps the `unsafe` in purpose-built code or in small, reviewed blocks of
ours. The crates below are *permitted* `unsafe`; the goal is for them to own as
little of it as possible.

## Status

`kennel-syscall` carries `#![allow(unsafe_code)]` for exactly one deliberate
reason: the hand-rolled **Landlock** bindings (`src/landlock.rs`). The
`landlock` crate would pull `syn` and the first proc-macros into the privileged
dependency tree, while the Landlock ABI is three syscalls and a few packed
structs — small enough to own. Everything else in the crate is safe: the
credential wrappers go through `nix::unistd`, and seccomp will go through
`seccompiler` (hand-rolling BPF bytecode is the genuinely dangerous case).
The `unsafe` is confined to `landlock.rs`'s raw syscall wrappers. `kennel-bpf`
is now also active (the `bpf(2)` FFI). Every other crate is
`#![forbid(unsafe_code)]`.

## Permitted crates

| Crate | Why it may need `unsafe` | Size ceiling |
|---|---|---|
| `kennel-syscall` *(allow; owns the Landlock bindings, the spawn hook, the netlink calls)* | The single point for namespaces, mounts, Landlock/seccomp, capabilities, credentials, child spawning, and interface-address management. Delegates `unsafe` to vetted crates (nix, seccompiler). Owns three `unsafe` sites, each §4-commented: the Landlock syscall wrappers (`src/landlock.rs`), a deliberate exception to keep `syn`/proc-macros out of the privileged TCB; one `CommandExt::pre_exec` call (`src/spawn.rs`) registering the post-`fork`/pre-`execve` seal hook, wrapped here so `kennel-spawn` stays `#![forbid(unsafe_code)]`; and the three `NETLINK_ROUTE` socket syscalls (`src/netlink.rs`, `socket`/`sendto`/`recv`) for adding/removing the per-kennel loopback addresses — the message is a plain byte buffer (no `transmute`), and `rtnetlink`/`ioctl`/`ip` were all rejected (see the module docs). | ~1500 lines (reviewable in one sitting) |
| `kennel-bpf` *(active)* | The `bpf(2)` FFI for loading/attaching the cgroup BPF programs, plus the audit-ringbuf reader. ELF parsing is delegated to `object`; the `unsafe` is confined to `src/sys.rs` (the `bpf()` syscalls — map create/update, prog load, cgroup attach/detach, object pin/get — plus the `OwnedFd` wrap) and `src/ringbuf.rs` (the two `mmap`/`munmap` calls and the lock-free single-consumer drain, which reads the kernel's ringbuf positions and record headers via aligned atomics). Each block is §4-commented. We do **not** use libbpf-rs/libbpf-sys (which would vendor zlib+libelf+libbpf C, ~1435 files); `object` (one crate) does the generic ELF parsing and we hand-roll the narrow, security-bearing loader and reader. | — |

The C in `bpf/` is governed separately by §4.1 (BPF C code) — C is `unsafe` by construction and reviewed under matching rules, but it is not Rust `unsafe` and is not listed here.

## Adding a crate to this list

1. Demonstrate the `unsafe` cannot live in `kennel-syscall` (or `kennel-bpf`) instead. The default is to route all `unsafe` through those; a new entry needs a reason the existing crates cannot serve.
2. All-maintainers review of the proposed `unsafe` (§4).
3. The crate's `lib.rs` documents that it contains `unsafe`, and why, in its module-level doc comment (§6.1).
4. Record the addition here and in [CHANGELOG.md](../CHANGELOG.md).
