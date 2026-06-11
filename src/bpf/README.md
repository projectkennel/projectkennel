# Project Kennel BPF programs

The cgroup-attached BPF programs that enforce Project Kennel's network
constraints, plus the map/event ABI shared with the Rust loader
(`kennel-lib-bpf`). The authoritative description of this surface is
[docs/architecture/02-7-bpf-abi.md](../../docs/architecture/02-7-bpf-abi.md); the C-code
discipline is [CODING-STANDARDS.md](../../docs/governance/CODING-STANDARDS.md) §4.1.

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
  exercised. That belongs with the `kennel-lib-bpf` loader's integration tests.
- **The full kernel matrix.** Verified only on the local 6.8.0 kernel, which is
  *below* the project floor of 6.10 (BUILD-ENV.md) — a useful lower bound, but
  CI's ≥6.10 LTS/stable/mainline `bpftool prog load` matrix is still owed.

## Contents

| File | What |
|---|---|
| `maps.h` | Map definitions and the per-kennel map value structs. Single source of truth for the map ABI; the Rust side's types are generated to match (docs/architecture/02-7). |
| `audit_events.h` | Ringbuf event header and per-kind payload structs. |
| `kennel.bpf.h` | Shared inline helpers (meta lookup, deny/allow evaluation, audit emit). Not a documented ABI surface; an implementation detail to keep each program small and the lookup logic in one reviewed place. |
| `connect4.bpf.c`, `connect6.bpf.c` | Egress allowlist enforcement (the central programs). |
| `bind4.bpf.c`, `bind6.bpf.c` | `INADDR_ANY` rewrite to the kennel's loopback; deny others. |
| `setsockopt.bpf.c` | Force `IPV6_V6ONLY=1` to close the dual-stack escape. |
| `sock_create.bpf.c` | Socket-family allowlist. |
| `sendmsg4.bpf.c`, `sendmsg6.bpf.c` | Connectionless (UDP) destination check; DNS only via the proxy. |
| `HELPERS.md` | The whitelist of permitted BPF helper functions (§4.1). |

## No CO-RE / no vmlinux.h

These programs are compiled against the kernel **UAPI** (`<linux/bpf.h>`), not a
`vmlinux.h` CO-RE dump. They touch only the *stable* hook-context structs
(`bpf_sock_addr`, `bpf_sock`, `bpf_sockopt`) and our own maps — nothing whose
layout drifts across kernels — so CO-RE buys nothing here. Dropping it means no
BTF/CO-RE relocation to resolve at load: the only relocations are `R_BPF_64_64`
references from instructions to map symbols, which the loader (`kennel-lib-bpf`)
resolves by symbol name against `maps.h`. (`-g` still emits BTF, so the objects
remain `bpftool`-loadable too.) The previously-committed 3 MB `vmlinux.h` is
gone.

## Building (on Linux)

The Rust loader crate `kennel-lib-bpf` loads these via a hand-rolled `bpf(2)` loader
over `libc`, using `object` only for ELF parsing — **not** libbpf-rs/libbpf-sys
(see `docs/architecture/02-7`, `03-crate-decomposition.md`). Manual compile:

```sh
clang -O2 -g -Wall -Wextra -Werror -target bpf -D__TARGET_ARCH_x86 \
      -I. -I/usr/include -I/usr/include/x86_64-linux-gnu \
      -c connect4.bpf.c -o connect4.bpf.o
```

The multiarch include path (`/usr/include/x86_64-linux-gnu`) is where
`<asm/types.h>` lives; `<linux/bpf.h>` comes from `linux-libc-dev`.

## Conventions

- C11, libbpf map/helper idioms (no CO-RE), `-Wall -Wextra -Werror` (§4.1).
- cgroup hook return convention: `1` allows the operation, `0` denies it
  (the kernel fails the syscall, typically `EPERM`/`ECONNREFUSED`).
- Lookup order in the connect/sendmsg programs is **deny-first**: the invariant
  deny trie is consulted before the allow trie, so an allow rule can never
  cover an invariant-denied range (docs/architecture/02-7).
- Every pointer dereference is preceded by an explicit bounds check; loops are
  bounded; only whitelisted helpers (`HELPERS.md`) are called; `bpf_printk` is
  forbidden in shipped programs.
