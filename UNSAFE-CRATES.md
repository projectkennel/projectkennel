# Crates permitted to contain `unsafe`

By default every crate in the workspace carries `#![forbid(unsafe_code)]` ([CODING-STANDARDS.md](CODING-STANDARDS.md) §3, §4). This file lists the crates that do **not** — the ones permitted to contain `unsafe` blocks. The list is short by design and changing it is a significant review event: adding a crate here requires the all-maintainers review described in §4.

Every `unsafe` block in a listed crate follows the `SAFETY:` / `INVARIANTS UPHELD:` / `FAILURE MODE:` comment template of §4, and every PR touching `unsafe` needs two maintainer approvals.

## Principle: prefer a vetted crate to our own `unsafe`

"Don't roll your own crypto" extends to `unsafe`. Where a well-audited crate
already wraps a syscall or ABI soundly, we use it rather than writing the
`unsafe` ourselves — `nix` for the general syscalls, `landlock` and
`seccompiler` for the non-trivial security ABIs, `libbpf-rs` for the BPF FFI.
This moves the `unsafe` into purpose-built, widely-reviewed code and out of
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
is still planned. Every other crate is `#![forbid(unsafe_code)]`.

## Permitted crates

| Crate | Why it may need `unsafe` | Size ceiling |
|---|---|---|
| `kennel-syscall` *(allow; owns the Landlock bindings)* | The single point for namespaces, mounts, Landlock/seccomp, capabilities, and credentials. Delegates `unsafe` to vetted crates (nix, seccompiler) and owns only the Landlock syscall wrappers (`src/landlock.rs`), a deliberate exception to keep `syn`/proc-macros out of the privileged TCB. | ~1500 lines (reviewable in one sitting) |
| `kennel-bpf` *(planned)* | The libbpf-rs / `libbpf-sys` FFI surface for loading and attaching BPF programs. `unsafe` confined to the FFI boundary. | — |

The C in `bpf/` is governed separately by §4.1 (BPF C code) — C is `unsafe` by construction and reviewed under matching rules, but it is not Rust `unsafe` and is not listed here.

## Adding a crate to this list

1. Demonstrate the `unsafe` cannot live in `kennel-syscall` (or `kennel-bpf`) instead. The default is to route all `unsafe` through those; a new entry needs a reason the existing crates cannot serve.
2. All-maintainers review of the proposed `unsafe` (§4).
3. The crate's `lib.rs` documents that it contains `unsafe`, and why, in its module-level doc comment (§6.1).
4. Record the addition here and in [CHANGELOG.md](CHANGELOG.md).
