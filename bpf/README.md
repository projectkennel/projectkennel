# Project Kennel BPF programs

The cgroup-attached BPF programs that enforce Project Kennel's network
constraints, plus the map/event ABI shared with the Rust loader
(`kennel-bpf`). The authoritative description of this surface is
[architecture/02-5-bpf-abi.md](../architecture/02-5-bpf-abi.md); the C-code
discipline is [CODING-STANDARDS.md](../CODING-STANDARDS.md) §4.1.

## Build status: compiled + verifier-clean on Linux 6.8.0

First compile-and-verify pass done on **2026-05-30**, Linux 6.8.0-110-generic
(x86_64, Ubuntu 24.04.4), clang 18.1.3, bpftool v7.4.0, libbpf 1.3.0 headers.
The originally blind-authored draft has now seen a real compiler and the kernel
verifier.

| Check | Result |
|---|---|
| `clang -O2 -g -Wall -Wextra -Werror -target bpf` (all 8 programs) | clean |
| `bpftool prog load` (kernel verifier, all 8) | all load; program/attach and map types match the `SEC()` names |
| connect4 runtime (live cgroup attach) | allow-match, default-deny, deny-first override, and `EPERM`-on-deny all confirmed |
| `user_port` byte order (the flagged unknown) | **confirmed**: an allow entry for port 9999 matches a connect to :9999 and rejects :8888 |
| map ABI (`maps.h`) | validated via bpftool BTF decode of live map contents |
| audit ABI (`audit_events.h`) | validated by draining live ringbuf events (magic `AEVN`, kind, connect payload) |

One verifier fix was needed versus the blind draft: the IPv6 programs
(connect6, bind6, sendmsg6) read/wrote `ctx->user_ip6` via
`__builtin_memcpy(&ctx->user_ip6, …)`, which the verifier rejects as a
"dereference of modified ctx ptr". They now go through `kennel_ctx_load_ip6` /
`kennel_ctx_store_ip6` (word-by-word direct context accesses) in `kennel.bpf.h`.

### Still pending (not yet done here)

- **Runtime exercise of the other seven programs.** Only connect4 was driven
  end-to-end through a live cgroup. connect6/sendmsg4/sendmsg6 share the same
  `kennel_decide_*` paths and bind4/bind6/setsockopt/sock_create are
  verifier-clean, but their runtime behaviour (the bind rewrite, the V6ONLY
  force, the family allowlist, the v6 decision) has not been individually
  exercised. That belongs with the `kennel-bpf` loader's integration tests.
- **The full kernel matrix.** Verified only on the local 6.8.0 kernel, which is
  *below* the project floor of 6.10 (BUILD-ENV.md) — a useful lower bound, but
  CI's ≥6.10 LTS/stable/mainline `bpftool prog load` matrix is still owed.

## Contents

| File | What |
|---|---|
| `maps.h` | Map definitions and the per-kennel map value structs. Single source of truth for the map ABI; the Rust side's types are generated to match (architecture/02-5). |
| `audit_events.h` | Ringbuf event header and per-kind payload structs. |
| `kennel.bpf.h` | Shared inline helpers (meta lookup, deny/allow evaluation, audit emit). Not a documented ABI surface; an implementation detail to keep each program small and the lookup logic in one reviewed place. |
| `connect4.bpf.c`, `connect6.bpf.c` | Egress allowlist enforcement (the central programs). |
| `bind4.bpf.c`, `bind6.bpf.c` | `INADDR_ANY` rewrite to the kennel's loopback; deny others. |
| `setsockopt.bpf.c` | Force `IPV6_V6ONLY=1` to close the dual-stack escape. |
| `sock_create.bpf.c` | Socket-family allowlist. |
| `sendmsg4.bpf.c`, `sendmsg6.bpf.c` | Connectionless (UDP) destination check; DNS only via the proxy. |
| `vmlinux.h` | CO-RE BTF type dump, generated from the build kernel (see below). Committed per BUILD-ENV.md. |
| `HELPERS.md` | The whitelist of permitted BPF helper functions (§4.1). |

## vmlinux.h

`vmlinux.h` is a CO-RE BTF dump of the target kernel's types. It is generated,
not hand-written, and is too large and kernel-specific to author blind. Generate
it on a Linux host with a BTF-enabled kernel:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

The committed `vmlinux.h` and its source kernel are recorded in BUILD-ENV.md.
The current copy was generated from Linux 6.8.0-110-generic (Ubuntu 24.04.4).
CO-RE relocations make the programs portable across kernels regardless of which
kernel's types `vmlinux.h` was dumped from, so this is a build-time type source,
not a runtime pin; per BUILD-ENV.md, regenerating it is a maintainer operation.

## Building (on Linux, once vmlinux.h exists)

The Rust loader crate `kennel-bpf` drives the build (its `build.rs` invokes the
pinned `clang` and `bpftool gen skeleton`; see architecture/02-5 and
03-crate-decomposition.md). Rough manual form for reference:

```sh
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -c connect4.bpf.c -o connect4.bpf.o
bpftool gen skeleton connect4.bpf.o > connect4.skel.h   # (Rust skeleton via libbpf-cargo)
```

## Conventions

- C11, libbpf + CO-RE idioms, `-Wall -Wextra -Werror` (§4.1).
- cgroup hook return convention: `1` allows the operation, `0` denies it
  (the kernel fails the syscall, typically `EPERM`/`ECONNREFUSED`).
- Lookup order in the connect/sendmsg programs is **deny-first**: the invariant
  deny trie is consulted before the allow trie, so an allow rule can never
  cover an invariant-denied range (architecture/02-5).
- Every pointer dereference is preceded by an explicit bounds check; loops are
  bounded; only whitelisted helpers (`HELPERS.md`) are called; `bpf_printk` is
  forbidden in shipped programs.
