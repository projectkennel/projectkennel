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

**Five** crates carry `#![allow(unsafe_code)]`; every other crate in the workspace is
`#![forbid(unsafe_code)]`. The five are split by concern so each owns a small, single-
purpose `unsafe` surface rather than one crate accreting all of it:

- `kennel-lib-syscall` — namespaces, mounts, seccomp, credentials, the spawn `pre_exec`
  hook (delegates most `unsafe` to `nix`/`seccompiler`).
- `kennel-lib-landlock` — the hand-rolled Landlock syscall bindings (split out of
  `kennel-lib-syscall` so that crate's surface stays smaller).
- `kennel-lib-bpf` — the `bpf(2)` FFI and the audit-ringbuf reader.
- `kennel-lib-binder` — the `binder(7)` ioctl / `mmap` / binderfs ABI.
- `kennel-lib-scm` — one site: adopting `SCM_RIGHTS`-received raw fds into `OwnedFd`.

The split is deliberate: a consumer that only needs (say) fd-passing pulls in
`kennel-lib-scm` (one `unsafe` line) rather than the whole syscall surface. Each block
carries the §4 `SAFETY:` / `INVARIANTS UPHELD:` / `FAILURE MODE:` comment template, and
every PR touching `unsafe` needs two maintainer approvals.

## Permitted crates

| Crate | Why it may need `unsafe` | Surface |
|---|---|---|
| `kennel-lib-syscall` | The single point for namespaces, mounts, seccomp, capabilities, credentials, and child spawning. Delegates most `unsafe` to vetted crates (`nix`, `seccompiler`). The hand-rolled exception is the `CommandExt::pre_exec` call (`src/spawn.rs`) registering the post-`fork`/pre-`execve` seal hook, wrapped here so `kennel-lib-spawn` stays `#![forbid(unsafe_code)]`. | small; reviewable in one sitting |
| `kennel-lib-landlock` | The hand-rolled **Landlock** bindings — `landlock_create_ruleset` / `landlock_restrict_self` / `prctl(NO_NEW_PRIVS)`, a few packed UAPI structs (`src/lib.rs`). The `landlock` crate would pull `syn` + the first proc-macros into the privileged TCB; the ABI is three syscalls, small enough to own. Non-test `unsafe` is the three syscall wrappers; the bulk of the file's `unsafe` is `#[cfg(test)]` harness (fork/socket/ioctl to prove the rules bite). | a handful of wrappers |
| `kennel-lib-bpf` | The `bpf(2)` FFI for loading/attaching the cgroup BPF programs, plus the audit-ringbuf reader. ELF parsing is delegated to `object`; the `unsafe` is confined to `src/sys.rs` (the `bpf()` syscalls — map create/update, prog load, cgroup attach/detach, object pin/get — plus the `OwnedFd` wrap) and `src/ringbuf.rs` (the `mmap`/`munmap` calls and the lock-free single-consumer drain over aligned atomics). We do **not** use libbpf-rs/libbpf-sys (which would vendor zlib+libelf+libbpf C, ~1435 files); `object` does the generic ELF parsing and we hand-roll the narrow, security-bearing loader and reader. | `sys.rs` + `ringbuf.rs` |
| `kennel-lib-binder` | The `binder(7)` ioctl / `mmap` / binderfs-mount ABI (`<linux/android/binder.h>`), with **no** libbinder/libbinder-ndk. The `unsafe` is confined to `src/sys.rs` (the `BINDER_*` ioctls, the shared-buffer `mmap`, the `Send`/`Sync` for the mapping) plus a few `OwnedFd`/`fcntl` wraps in `src/client.rs`. The decoder (`proto.rs`) and the context-manager state machine hold no `unsafe`. | `sys.rs` (+ a few `client.rs` wraps) |
| `kennel-lib-scm` | **One** `unsafe` site: adopting each `SCM_RIGHTS`-received raw fd into an `OwnedFd` (`src/lib.rs`). `nix` owns the `sendmsg`/`recvmsg` control-message marshalling; only the kernel-installed fd needs the raw-to-owned wrap. Split out so a connector end can pass fds without pulling the whole syscall surface. | one line |

The C in `bpf/` is governed separately by §4.1 (BPF C code) — C is `unsafe` by construction and reviewed under matching rules, but it is not Rust `unsafe` and is not listed here.

## Adding a crate to this list

1. Demonstrate the `unsafe` cannot live in `kennel-lib-syscall` (or `kennel-lib-bpf`) instead. The default is to route all `unsafe` through those; a new entry needs a reason the existing crates cannot serve.
2. All-maintainers review of the proposed `unsafe` (§4).
3. The crate's `lib.rs` documents that it contains `unsafe`, and why, in its module-level doc comment (§6.1).
4. Record the addition here and in [CHANGELOG.md](../CHANGELOG.md).
