# API surfaces — BPF ABI

## Stability commitment

**Internal-stable** per `02-0-overview.md`. The BPF map ABI is internal: the loader and the BPF programs are built from the same source within a release, so version skew is impossible inside a release. Across releases, the loader carries a magic-number-and-version check at attach time; mismatched binaries refuse to attach with a structured error.

External parties do not write BPF programs against our maps or consume our ringbuf events. If a third-party integration ever needs that surface, it is added to the external CLI (`kennel audit --follow` already streams equivalent events) or to a stable JSON channel; we do not promote internal BPF types to external stability.

This chapter documents the surface for review and audit. It is not a contract to BPF authors outside Project Kennel.

---

## Programs and attach points

Project Kennel ships the following BPF programs. Each is in `bpf/<name>.bpf.c` and is compiled per CODING-STANDARDS.md §4.1.

| Program | Attach point | Purpose |
|---|---|---|
| `connect4` | `cgroup/connect4` | Enforce IPv4 destination allowlist. |
| `connect6` | `cgroup/connect6` | Enforce IPv6 destination allowlist. |
| `bind4` | `cgroup/bind4` | Rewrite `INADDR_ANY` binds to the kennel's loopback; deny others. |
| `bind6` | `cgroup/bind6` | Same for IPv6. |
| `setsockopt` | `cgroup/setsockopt` | Force `IPV6_V6ONLY=1`; prevent dual-stack escape. |
| `sock_create` | `cgroup/sock_create` | Family allowlist (no `AF_PACKET`, no `AF_NETLINK` from workload). |
| `sendmsg4` | `cgroup/sendmsg4` | UDP destination check (DNS via proxy only). |
| `sendmsg6` | `cgroup/sendmsg6` | Same for IPv6. |

All programs attach to per-kennel cgroups (one cgroup per kennel under `/sys/fs/cgroup/kennel/<id>/`). The same compiled `.o` is attached to every kennel's cgroup; per-kennel configuration is in maps, not in the program text.

Programs are written in C against the kernel UAPI (`<linux/bpf.h>` plus our own `bpf/kennel.bpf.h` helpers) — **no** `vmlinux.h`, no CO-RE relocations (see `bpf/README.md` for why). The build environment is pinned per `CODING-STANDARDS.md §2.2`.

---

## Kernel requirements

Each program has a minimum kernel version derived from the attach point and helpers used.

| Program | Minimum kernel | Reason |
|---|---|---|
| `connect4`, `connect6` | 4.10 | `cgroup/connect*` attach points. |
| `bind4`, `bind6` | 5.7 | `cgroup/bind*` attach points; address rewrite from BPF. |
| `setsockopt` | 5.7 | `cgroup/setsockopt`. |
| `sock_create` | 4.10 | `cgroup/sock_create`. |
| `sendmsg4`, `sendmsg6` | 4.18 | `cgroup/sendmsg*`. |

Project Kennel's overall kernel floor is 6.10 (per design doc §8.2; required for Landlock `FS_EXECUTE`). The BPF programs themselves run on older kernels; the floor is set by Landlock, not by BPF.

Required BPF features beyond the attach points:

- **BPF ringbuf** (kernel 5.8+). Used for audit-event delivery; replaces perfbuf.
- **No CO-RE.** The programs touch only stable hook-context structs and our own maps, so they compile against the kernel UAPI (`<linux/bpf.h>`) rather than a `vmlinux.h` BTF dump. `kennel-bpf`'s `bpf(2)` loader resolves map relocations by symbol name; there is no BTF/CO-RE relocation step.
- **LPM trie maps** (kernel 4.11+). Used for CIDR-based allowlists.
- **`bpf_loop`** (kernel 5.17+, optional). Replaces some `#pragma unroll` loops; programs fall back to unrolling when unavailable.

The loader checks kernel-feature availability at attach time and refuses to attach if any required feature is missing, with a structured error naming the missing feature.

---

## Maps

Each kennel has its own copy of the per-kennel maps; the project-wide audit ringbuf is shared.

### Per-kennel maps

**`kennel_meta`** (BPF_MAP_TYPE_ARRAY, capacity 1)

A single-element array carrying per-kennel metadata. Read by every program at every invocation; updated by the loader at kennel start (and never again — the map is marked read-only via `BPF_F_RDONLY_PROG` once populated).

```c
struct kennel_meta {
    __u32 magic;             // 0x4B4E454C ("KNEL"); sentinel for ABI version detect
    __u16 abi_version;       // currently 1; bump on incompatible change
    __u16 ctx_byte;          // the <ctx> for this kennel
    __u32 proxy_addr_v4;     // the proxy listen address (network byte order)
    __u8  proxy_addr_v6[16]; // IPv6
    __u16 proxy_port;        // network byte order
    __u8  policy_hash[32];   // SHA-256 of the resolved policy; for audit correlation
};
```

The loader verifies `magic` and `abi_version` after population by reading the map back. Mismatch indicates a corrupted build; the kennel fails to start.

**`allow_v4`** (BPF_MAP_TYPE_LPM_TRIE)

LPM trie keyed by `(prefix_len, addr_v4)`. Value:

```c
struct allow_entry_v4 {
    __u16 port_min;       // inclusive
    __u16 port_max;       // inclusive
    __u8  protocol;       // IPPROTO_TCP, IPPROTO_UDP, or 0 for any
    __u8  flags;          // bit 0: this entry is the proxy (special-case)
    __u8  reserved[2];
};
```

Capacity: 1024 entries default; configurable per kennel via policy.

**`allow_v6`** (BPF_MAP_TYPE_LPM_TRIE)

Same shape with `addr_v6`. Value identical (struct alignment lays out the same).

**`deny_v4`** / **`deny_v6`** (BPF_MAP_TYPE_LPM_TRIE)

Invariant deny entries (cloud metadata, RFC1918, link-local) installed by the loader as framework invariants. Same key/value layout as `allow_*`.

The lookup order in the connect programs:

1. Lookup destination in `deny_*`. If matched, reject.
2. Lookup destination in `allow_*`. If matched and protocol/port match, allow.
3. Otherwise reject.

Deny is checked first so an `allow` rule cannot accidentally cover an invariant-denied range.

**`bind_subnet`** (BPF_MAP_TYPE_ARRAY, capacity 1)

The kennel's bind subnet for `INADDR_ANY` rewriting:

```c
struct bind_subnet {
    __u32 v4_addr;       // network byte order
    __u32 v4_prefix;     // host order, expected 24
    __u8  v6_addr[16];
    __u8  v6_prefix;     // expected 64
    __u8  reserved[3];
};
```

### Shared maps

**`audit_ringbuf`** (BPF_MAP_TYPE_RINGBUF, capacity 1 MiB default)

One shared ringbuf. The audit reader in kenneld drains it; events carry the originating kennel's `kennel_uuid` (resolved from `ctx_byte` via kenneld's in-memory registry).

Capacity is configurable per kennel via `[audit].ringbuf_bytes`, capped at 16 MiB to prevent operator misconfiguration causing memory pressure.

---

## Ringbuf event format

Every event in the ringbuf is a packed struct. The reader in kenneld parses these, enriches with the kennel name (via `ctx_byte` lookup), sanitises any string fields, and writes JSONL to the appropriate audit file.

The base header (every event):

```c
struct audit_hdr {
    __u32 magic;        // 0x4145564E ("AEVN")
    __u16 version;      // currently 1
    __u16 kind;         // event-kind enum, see below
    __u64 ts_ns;        // CLOCK_MONOTONIC at event time
    __u16 ctx_byte;     // kennel context byte
    __u16 length;       // total event length including header
    __u32 pid;          // workload PID at event time
    __u8  comm[16];     // task->comm; null-padded
};
```

Event kinds and their payload structs are declared in `bpf/audit_events.h`. The header is followed immediately by the kind-specific payload.

Selected payloads:

```c
enum audit_kind {
    AUDIT_NET_CONNECT_DENY = 1,
    AUDIT_NET_CONNECT_ALLOW = 2,
    AUDIT_NET_BIND_REWRITE = 3,
    AUDIT_NET_BIND_DENY = 4,
    AUDIT_NET_SOCK_DENY = 5,
    AUDIT_NET_SETSOCKOPT_FORCED = 6,
};

struct audit_payload_connect {
    __u8  family;       // AF_INET, AF_INET6
    __u8  protocol;     // IPPROTO_TCP, IPPROTO_UDP
    __u16 port;         // network byte order
    union {
        __u32 v4;
        __u8  v6[16];
    } addr;
};
```

Strings — destination names, paths — are not included in BPF events. The kernel side has the address; name resolution to a hostname happens in the netproxy (which sees the SOCKS5 request) or in the resolver, both userspace. Audit-log enrichment correlates by the `ts_ns` and the `(addr, port)` tuple.

---

## Configuration flow

The loader's setup for one kennel:

1. Open the embedded BPF object (`include_bytes!` into the loader binary).
2. Create the per-kennel maps. Pin them under `/sys/fs/bpf/kennel/<id>/` for inspection (read-only to the user; not in the workload's view).
3. Populate `kennel_meta`, `allow_v4`, `allow_v6`, `deny_v4`, `deny_v6`, `bind_subnet` from the resolved policy.
4. Mark `kennel_meta` read-only.
5. Load the programs, attaching to the kennel's cgroup at `/sys/fs/cgroup/kennel/<id>/`.
6. The cgroup is then ready; the workload can be moved into it.

The audit ringbuf is created once at kenneld start, not per kennel. Per-kennel events carry the `ctx_byte` so the reader can route to the right log file.

---

## Programs do not allocate

Per the BPF restrictions described in CODING-STANDARDS.md §4.1: no recursion, no unbounded loops, no general allocation, no string operations beyond `bpf_probe_read_kernel_str` with explicit bounds. Programs read from maps, branch on the values, return a verdict (allow/deny via return code or socket-context modification), and optionally write to the audit ringbuf.

Programs do not call back into userspace synchronously. The audit ringbuf is the only data flow from BPF to userspace; it is asynchronous and lossy under pressure (events may be dropped when the ringbuf is full, with a counter recording the drop).

---

## Verifier complexity

Each program is sized to fit comfortably within the kernel's BPF complexity limit (default 1M instructions per program post-5.2). Target ceiling for any single program: 10k instructions. Programs that grow beyond this trigger a review note.

The `connect4`/`connect6` programs are the most complex (LPM lookup + deny lookup + allow lookup + per-port check + audit emit); they currently sit at ~2k instructions on a representative kernel.

CI runs the BPF programs through `bpftool prog load` on the kernel-version matrix declared in `BUILD-ENV.md`. Verifier rejection on any matrix entry blocks merge.

---

## ABI versioning

The `abi_version` field in `kennel_meta` is the cross-release compatibility check. Bumping it is a minor-version event with both the loader and the programs landing together (which is the default — they are built from the same source).

A non-matching `abi_version` between the loader and the maps it created would indicate a build bug; we do not expect users to mix loader and program binaries across releases. The check exists for review-time assurance, not for operator-facing version negotiation.

---

## Map pinning and inspection

Per-kennel maps are pinned under `/sys/fs/bpf/kennel/<id>/`. The pins are owned by root with mode 0640 and group `kennel-readers` (created at install time). This makes the maps inspectable for debugging (`bpftool map dump pinned /sys/fs/bpf/kennel/ai-coding/allow_v4`) without exposing them to write attacks.

The workload's view never includes `/sys/fs/bpf` — the constructed shim does not mount it.

---

## What this chapter does not cover

- The C source patterns required of BPF programs (bounds checks, helper whitelist, `#pragma unroll` discipline): CODING-STANDARDS.md §4.1.
- The Rust loader's `bpf(2)` interface (`object` for ELF, hand-rolled syscalls): `02-6-internal-api.md`.
- How the cgroup is created and the workload moved into it: design doc §8.3 and `01-process-model.md`.
- The audit JSONL events produced from these ringbuf events: `02-3-audit-schema.md`.
- The kernel-feature checks at startup: design doc §8.2 and `05-state-and-supervision.md`.
