# Project Kennel BPF programs

The cgroup-attached BPF programs that enforce Project Kennel's network
constraints, plus the map/event ABI shared with the Rust loader
(`kennel-bpf`). The authoritative description of this surface is
[architecture/02-5-bpf-abi.md](../architecture/02-5-bpf-abi.md); the C-code
discipline is [CODING-STANDARDS.md](../CODING-STANDARDS.md) §4.1.

## Build status: UNBUILT / UNVERIFIED

**These C files have not been compiled or verified.** They were authored on a
host with no BPF toolchain (no `clang -target bpf`, no `vmlinux.h`, no
`libbpf`, no kernel). They are reviewable design source written to the §4.1
discipline; they are **not** known to compile, and crucially they have **not**
been through the kernel verifier — the one check §4.1 cares about most.

Treat every program here as a draft pending a first compile-and-verify pass on
Linux. Do not assume any of it loads until CI's `bpftool prog load` matrix
(BUILD-ENV.md) has run against it.

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
| `vmlinux.h` | **Not committed here.** Must be generated on the target kernel (see below). |
| `HELPERS.md` | The whitelist of permitted BPF helper functions (§4.1). |

## vmlinux.h

`vmlinux.h` is a CO-RE BTF dump of the target kernel's types. It is generated,
not hand-written, and is too large and kernel-specific to author blind. Generate
it on a Linux host with a BTF-enabled kernel:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

The committed `vmlinux.h` and the source kernel are recorded per BUILD-ENV.md.
Until it is generated, none of the `.bpf.c` files compile.

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
