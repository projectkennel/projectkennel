# Crates permitted to contain `unsafe`

By default every crate in the workspace carries `#![forbid(unsafe_code)]` ([CODING-STANDARDS.md](CODING-STANDARDS.md) §3, §4). This file lists the crates that do **not** — the ones permitted to contain `unsafe` blocks. The list is short by design and changing it is a significant review event: adding a crate here requires the all-maintainers review described in §4.

Every `unsafe` block in a listed crate follows the `SAFETY:` / `INVARIANTS UPHELD:` / `FAILURE MODE:` comment template of §4, and every PR touching `unsafe` needs two maintainer approvals.

## Status

No crates exist yet — the reference runtime is not implemented. This file is the policy and the (currently empty) list; entries are added when the crates are created.

## Permitted crates

| Crate | Why it needs `unsafe` | Size ceiling |
|---|---|---|
| `kennel-syscall` *(planned)* | Raw Linux syscalls, namespace operations, Landlock/seccomp primitives, capability manipulation, and FFI. The single crate that wraps everything unsafe behind safe APIs. | ~1500 lines (reviewable in one sitting) |
| `kennel-bpf` *(planned)* | The libbpf-rs / `libbpf-sys` FFI surface for loading and attaching BPF programs. `unsafe` confined to the FFI boundary. | — |

The C in `bpf/` is governed separately by §4.1 (BPF C code) — C is `unsafe` by construction and reviewed under matching rules, but it is not Rust `unsafe` and is not listed here.

## Adding a crate to this list

1. Demonstrate the `unsafe` cannot live in `kennel-syscall` (or `kennel-bpf`) instead. The default is to route all `unsafe` through those; a new entry needs a reason the existing crates cannot serve.
2. All-maintainers review of the proposed `unsafe` (§4).
3. The crate's `lib.rs` documents that it contains `unsafe`, and why, in its module-level doc comment (§6.1).
4. Record the addition here and in [CHANGELOG.md](CHANGELOG.md).
