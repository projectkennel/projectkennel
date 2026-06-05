# API surfaces — BPF ABI

## Stability commitment

**Internal-stable** per `02-0-overview.md`. The BPF map ABI is internal: the loader and the BPF programs are built from the same source within a release, so version skew is impossible inside a release. Across releases, a magic-number-and-version check at attach time is designed to make mismatched binaries refuse to attach with a structured error. **Status: not yet built (roadmap)** — the `magic` and `abi_version` constants exist on the C side, but the loader does not read the map back to validate them (see the `kennel_meta` and ABI-versioning sections).

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

The loader is designed to check kernel-feature availability at attach time and refuse to attach if any required feature is missing, with a structured error naming the missing feature.

**Status: not yet built (roadmap).** The as-built attach path goes straight to `load_program` then `attach`; a missing feature currently surfaces as a raw kernel errno from `map_create`/`prog_load`/`attach`, not a structured named-feature error. The only feature gating in place is the build-time `bpf-egress` cfg, which returns `ENOSYS` when the program is not embedded.

---

## Maps

Each kennel has its own copy of the per-kennel maps; the project-wide audit ringbuf is shared.

### Per-kennel maps

**`kennel_meta`** (BPF_MAP_TYPE_ARRAY, capacity 1)

A single-element array carrying per-kennel metadata. Read by every program at every invocation; updated by the loader at kennel start and not written again thereafter.

> **Status: read-only sealing not yet built (roadmap).** The map is intended to be marked read-only via `BPF_F_RDONLY_PROG` once populated. As built, `kennel_meta_map` is created with `map_flags = 0` and is never frozen; the write-once property is upheld by the loader convention, not enforced by the kernel.

```c
struct kennel_meta {           // 64 bytes (loader value_size); bpf/maps.h is authoritative
    __u32 magic;             // 0  0x4B4E454C ("KNEL"); sentinel for ABI version detect
    __u16 abi_version;       // 4  currently 1; bump on incompatible change
    __u16 ctx_byte;          // 6  the <ctx> for this kennel
    __u32 proxy_addr_v4;     // 8  the proxy listen address (network byte order)
    __u16 proxy_port;        // 12 network byte order
    __u16 _pad0;             // 14
    __u8  proxy_addr_v6[16]; // 16 IPv6
    __u8  policy_hash[32];   // 32 SHA-256 of the resolved policy; for audit correlation
};
```

The loader is designed to verify `magic` and `abi_version` after population by reading the map back; a mismatch indicates a corrupted build and fails the kennel to start. **Status: readback verification not yet built (roadmap)** — the `magic` (`0x4B4E454C`) and `KENNEL_ABI_VERSION` constants exist on the C side (`bpf/maps.h`), but no Rust code reads the map back to validate them; the value is written from the payload `meta` without a post-write check. The proxy fields are ordered `proxy_port` before `proxy_addr_v6`, with an explicit `_pad0`, for natural alignment; the BPF enforcement path reads the deny/allow tries, not these fields.

**`allow_v4`** (BPF_MAP_TYPE_LPM_TRIE)

LPM trie keyed by `(prefix_len, addr_v4)`. Value (`struct allow_entry` — one layout shared by the v4 and v6 tries; they differ only in key width):

```c
struct allow_entry {
    __u16 port_min;       // inclusive
    __u16 port_max;       // inclusive
    __u8  protocol;       // IPPROTO_TCP, IPPROTO_UDP, or 0 for any
    __u8  flags;          // bit 0 (KENNEL_ALLOW_FLAG_PROXY): this entry is the proxy
    __u8  _pad[2];
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
    __u32 v4_prefix;     // host order, expected 28 (per-kennel /28 allocation)
    __u8  v6_addr[16];
    __u8  v6_prefix;     // expected 64
    __u8  reserved[3];
};
```

### Shared maps

**`audit_ringbuf`** (BPF_MAP_TYPE_RINGBUF, capacity 1 MiB default)

The audit reader in kenneld drains it; events carry the originating kennel's `kennel_uuid` (resolved from `ctx_byte` via kenneld's in-memory registry), and route through the unified audit writer (`02-3-audit-schema.md` §Scope) with `source: bpf`.

As built, there is exactly *one* `audit_ringbuf` per kennel: the privhelper creates the kennel's map set once (`kennel_bpf::create_maps`) and loads every program against it (`load_program_against`), so all of a kennel's programs share the one buffer. The privhelper pins it to `/run/kennel/bpf/<id>/audit_ringbuf` (`07-paths.md`); the unprivileged kenneld reopens it with `BPF_OBJ_GET` and drains it on a per-kennel thread (`kenneld::bpf_audit`). (The design once said "one buffer created at kenneld start"; kenneld is unprivileged and cannot create BPF maps, so the privileged helper creates and pins it instead, one per kennel, and kenneld reopens it.)

Capacity is configurable per kennel via `[audit].ringbuf_bytes`, capped at 16 MiB to prevent operator misconfiguration causing memory pressure.

---

## Ringbuf event format

Every event in the ringbuf is a packed struct. The reader in kenneld (`kenneld::bpf_audit`) parses these, attributes each to its kennel by `ctx_byte` (dropping a foreign/corrupt one), carries `comm` as untrusted (writer-sanitised), and emits the canonical event through the unified writer (to JSONL and any other configured sink) with `source: bpf`. The drain is proven end to end by `kenneld/tests/bpf_drain.rs`: a denied connect's `net.connect-deny` lands in `network.jsonl`.

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
    AUDIT_NET_SENDMSG_DENY = 7,   // sendmsg4/sendmsg6 UDP destination denial
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

Strings — destination names, paths — are not included in BPF events. The kernel side has the address; name resolution to a hostname happens in the netproxy, which sees the SOCKS5 request and resolves names through the OS resolver in userspace. Audit-log enrichment correlates by the `ts_ns` and the `(addr, port)` tuple.

---

## Configuration flow

The loader's setup for one kennel:

1. Open the embedded BPF object (`include_bytes!` into the loader binary).
2. Create the per-kennel map set *once* (`create_maps`).
3. Populate `kennel_meta`, `allow_v4`, `allow_v6`, `deny_v4`, `deny_v6`, `bind_subnet` from the resolved policy.
4. Load every program against that shared set (`load_program_against`), attaching to the kennel's cgroup (under `/sys/fs/cgroup/<namespace>/<ctx>/`, where `<namespace>` defaults to `kennel`).
5. Pin the shared maps under `/run/kennel/bpf/<id>/` (Map pinning, below).
6. The cgroup is then ready; the workload can be moved into it.

> **Status: `kennel_meta` read-only sealing not yet built (roadmap).** The attach path creates, populates, attaches, and pins the maps; it does not yet freeze `kennel_meta` against further writes (`BPF_MAP_FREEZE`). The explicit "mark `kennel_meta` read-only" step is designed but unwired.

The audit ringbuf is one per kennel, shared across that kennel's programs, so per-kennel events (carrying the `ctx_byte`) route through one drain to the right log file. (It was once designed as a single buffer created at kenneld start; kenneld is unprivileged and cannot create BPF maps, so the privhelper creates and pins it per kennel — see the `audit_ringbuf` section above.)

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

A non-matching `abi_version` between the loader and the maps it created would indicate a build bug; we do not expect users to mix loader and program binaries across releases. The check is designed for review-time assurance, not for operator-facing version negotiation.

**Status: not yet built (roadmap).** As built, the loader writes the `meta` payload (including `abi_version`) into the map without reading it back to compare against a compiled-in constant; there is no runtime ABI check.

---

## Map pinning and inspection

Per-kennel maps are pinned under `/run/kennel/bpf/<uid>/<id>/` (`07-paths.md`), on a bpffs the privhelper mounts at `/run/kennel/bpf/` (root, `0711` — traverse-only). Kennel is a **per-user** tool and `<id>` (the kennel name) is unique only *within* a user, so the pins are partitioned by the owner's **uid** (the helper's real uid, never the wire) and are **owner-only**: `<uid>/` and the per-kennel dir are `0700`, pins `0600`, no shared OS group. The `<uid>/` dir keeps per-user names non-colliding, confines this root-privileged helper to its own caller's subtree (it can never clobber another user's pins), and hides even a guessable `<id>` from other users. This lets the unprivileged kenneld reopen the `audit_ringbuf` to drain it and the owner inspect the maps (`bpftool map dump pinned /run/kennel/bpf/1000/ai-coding/allow_v4`); the `0711` root blocks another user from listing or squatting it.

Not `/sys/fs/bpf/kennel/`: systemd mounts `/sys/fs/bpf` `mode=700`, which an unprivileged kenneld cannot traverse to `BPF_OBJ_GET` the ring buffer. The pin step is best-effort — a pin failure degrades to "no BPF audit drain / no inspection" but never fails egress setup.

The workload's view never includes `/run/kennel/bpf` — the constructed shim does not mount it.

---

## What this chapter does not cover

- The C source patterns required of BPF programs (bounds checks, helper whitelist, `#pragma unroll` discipline): CODING-STANDARDS.md §4.1.
- The Rust loader's `bpf(2)` interface (`object` for ELF, hand-rolled syscalls): `02-6-internal-api.md`.
- How the cgroup is created and the workload moved into it: design doc §8.3 and `01-process-model.md`.
- The audit JSONL events produced from these ringbuf events: `02-3-audit-schema.md`.
- The kernel-feature checks at startup: design doc §8.2 and `05-state-and-supervision.md`.
