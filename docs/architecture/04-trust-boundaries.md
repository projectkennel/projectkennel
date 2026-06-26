# Trust boundaries

Project Kennel's implementation crosses several trust boundaries: between processes at different privilege levels, between trusted code and untrusted input, between userspace and the kernel. This chapter enumerates the boundaries, names the sanitisation and validation discipline that applies at each, and points at the code that owns the enforcement.

The discipline itself — *what* sanitisation looks like — is in CODING-STANDARDS.md §10 (Input handling) and §4 (`unsafe` code). This chapter is the catalogue: *which* boundaries exist, *who* enforces them, *what* the threat model is at each.

---

## Boundary inventory

| # | Boundary | Direction | Enforced by |
|---|---|---|---|
| 1 | Operator → privhelper (construction) | command + construction-half `Plan` → privileged kennel build | `kennel-privhelper` (factory) |
| 2 | Disk → policy parser | untrusted bytes → typed `Policy` | `kennel-lib-policy` |
| 3 | Untrusted template → signature verifier | bytes + claimed signature → verified bytes | `kennel-lib-policy` (signature module) |
| 4 | Workload → BPF programs | syscall args → kernel verdict | BPF programs in `bpf/` |
| 5 | BPF → userspace audit reader | ringbuf bytes → typed `AuditEvent` | `kennel-lib-bpf` (ringbuf parser) |
| 6 | CLI → kenneld | wire-format bytes → typed request | kenneld (`control` decoder) |
| 7 | Untrusted client → kenneld socket | connecting process → authenticated user | kenneld (SO_PEERCRED check) |
| 8 | Workload → D-Bus facade | D-Bus method call → mediated bus access | kenneld (`IDBus` facade, §7.7) |
| 9 | Workload → netproxy | SOCKS5 bytes → resolved destination | `host-netproxy` |
| 10 | Kernel-side string → audit log | bytes from `task->comm`, paths → sanitised text | `kennel-lib-text` (sanitiser) |
| 11 | Network bytes → DNS resolver | resolver response → allowlist decision | `host-netproxy` |
| 12 | Workload → audit log files | file system access to its own audit dir | constructed shim (no access by default) |
| 13 | Settled policy → runtime | signed settled artefact → enforced policy | `kennel-lib-spawn` (settled verifier) |
| 14 | Workload/facade → kenneld over binder | binder transaction on node 0 → registry/facade decision | kenneld (`binder` looper, sender-identity gate) |
| 15 | `kennel-bin-init` → kenneld (lifecycle) | binder lifecycle/config verb → supervised action | kenneld (init-host-pid gate) |
| 16 *(roadmap)* | Cross-kennel transaction → kenneld relay | provider/consumer transaction → relayed payload | kenneld (`binder` relay; → `02-4-binder.md`) |
| 17 | Kennel net-ns ↔ host net-ns | binder `INet` crossing + host loopback mirror | kenneld + delegates (→ `02-5-binder-net.md`) |

Each boundary is described in its own section below. The descriptions follow a common shape: what crosses, what is trusted on each side, what the validator does, what the failure mode is.

**Compile-time vs runtime.** Boundaries 2 and 3 (policy parsing, template/fragment signature and lockfile verification) are *compile-time* boundaries — they are crossed when `kennel compile` resolves a source policy into a settled policy (`02-2-config-schema.md` §The settled policy). Boundary 13 is the *runtime* boundary: what the spawn path trusts when it enforces a settled policy. In an attested fleet deployment, the workstation crosses only boundary 13 (plus the operational ones — the per-spawn construction boundary 1 and the runtime boundaries 4–12, 14, 15, 17); boundaries 2 and 3 were crossed earlier, centrally, at compile time. This is the point of compilation — the complex, fallible parsing-and-verification surface is exercised once at compile time, not on every spawn.

---

## 1. Operator → privhelper (construction)

**What crosses.** Two distinct things, both from kenneld (or, in degraded mode, the CLI) to the privhelper:

- the per-operation requests — `add-addr` / `del-addr`, `setup-egress`, `set-gid-map` — described below; and
- the **construction-half of the kennel `Plan`**, carried by the `ConstructKennel` operation over a `SOCK_SEQPACKET` socketpair (with `SCM_RIGHTS` fds), encoding the uid/gid maps, the loopback config, the binderfs params, the view bind list, and the pivot target (`kennel-lib-spawn::wire`; `07-2-kennel-bin-init.md` §7.2.3, `02-6-ipc.md`).

`ConstructKennel` makes the privhelper the kennel **factory** (`07-2-kennel-bin-init.md` §7.2.1): it `clone`s the namespaces *as the operator* (so the user namespace is operator-owned), its post-`clone` child self-escalates to the kennel's uid 0, writes the maps, builds the root-owned surfaces (view, `/dev`, RO library binds, binderfs), mounts binderfs and chowns the device to the operator, `pivot_root`s, drops to the operator, and `fexecve`s the trusted root-owned `kennel-bin-init` (PID 1). This is the **largest root-parses-operator-input surface in the system** — the construction-half decoder runs in the privileged host context — and is bounded and fuzzed (`07-2-kennel-bin-init.md` §7.2.5, §10.6).

**Privilege held.** The privhelper **factory** is installed with **file capabilities** `{cap_setuid, cap_setgid, cap_setfcap, cap_sys_admin}` (`src/tools/install.sh`; setuid-root, mode 4755, is the fallback only where the filesystem cannot carry file caps). It runs at the operator's uid with only that set, briefly raising euid to 0 (via `cap_setuid`) for the identity-map write. `cap_sys_admin` is what the kernel's `uid_map` write gate requires to map host uid 0 into the new namespace; `cap_setfcap` (single-`write(2)`, since Linux 5.12) covers the host-uid-0 line of the precise multi-line identity map — `0 0 1` (host root mapped to the kennel's uid 0) plus `<operator> <operator> 1`, plus one line per granted gid — with **no subuid/subgid** and no `0 0 N` range. The host-context caps the construction once needed inline are **not** on the factory: each is delegated to a single-purpose sub-helper the factory execs only when a policy needs it — `kennel-privhelper-net` `{cap_net_admin}` (host-`lo` mirror), `kennel-privhelper-bpf` `{cap_bpf, cap_net_admin, cap_perfmon}` (host-mode egress BPF), `kennel-privhelper-mounts` `{cap_sys_admin}` (exclusive over-mount). The privhelper is the kennel **factory**: it builds the namespaces, writes the identity map, and `fexecve`s the root-owned `kennel-bin-init` (`01-process-model.md`, `02-4-binder.md` §Privilege).

**Trusted side.** Nothing on either side. The privhelper does not trust the caller's claim that operation parameters are within Project Kennel's reserved range, nor that a `Plan` is well-formed; it validates every field and bounds the construction-half decode. The caller does not trust the privhelper's response semantics beyond what the wire protocol declares.

### Escalation-window analysis (the `0 0 1` map is safe)

Mapping host root into the userns is a privilege-escalation hazard *only if operator code can run as userns-uid-0*. It cannot, by construction:

- The userns is **operator-owned** (the child `clone`s as the operator), which is what lets the operator `kenneld` later reach the instance via `/proc/<init>/root`; ownership of the userns is not the same as running uid-0 code in it.
- The **factory child is the only transient uid-0 actor**. It self-escalates inside the new userns to build root-owned surfaces, and it **never runs while the host filesystem is visible**: it `pivot_root`s and detaches the old host root *before* control leaves privhelper code. There is therefore no window in which a uid-0-mapped process can exercise host DAC against host-root-owned files.
- The only uid-0 process that outlives construction is `kennel-bin-init`, and it is `execve`'d **after** `pivot_root` — trapped in the sealed view from its first instruction, holding no ambient host caps (only userns-scoped `cap_setuid`/`cap_setgid` for the workload drop). Host DAC on host files is physically impossible despite kuid 0, because the host root is absent from its mount namespace.
- The **workload is never uid 0**: `kennel-bin-init` forks it and drops gid → groups → uid to the operator, then `no_new_privs` + seccomp + Landlock make the drop irreversible.
- **`kennel-bin-init` stays uid 0** so PID 1 is a different uid from the operator-uid workload and facades, which therefore cannot signal or `ptrace` it.

### `kennel-bin-init`-path provenance

`kennel-bin-init` is the one trusted binary the privhelper hands the kennel to, so its identity is established by **provenance, not by the wire**: its path comes from the root-owned deployment config (`Deployment::kennel_bin_init()` → libexec), never from the operator-supplied `Plan`. The privhelper verifies it is **root-owned and not group/other-writable**, `open`s it **before the `clone`** (the host path is gone after `pivot_root`), and `fexecve`s it by descriptor. The operator cannot substitute a uid-0 init, and `fexecve` keeps the binary out of the view entirely (the workload cannot even see it). The privhelper `execve`s it with **empty argv/envp** — the supervision-half Plan is pulled over binder (boundary 15), not pushed through arguments or the environment, so nothing leaks via `/proc/<pid>/cmdline` or `environ`.

**Validator.** `kennel-privhelper`'s `validate` module. For each per-operation request:

- `add-addr` / `del-addr`: the `addr` must fall within the caller's per-kennel loopback subnet — IPv4 laid out `127 | tag(12) | ctx(8) | host(4)` (a **/28**) or IPv6 `0xfd | gid(40) | ctx(16) | host(64)` (a **/64**), where `tag`/`gid` are the caller's per-user values (from `/etc/kennel/subkennel`) and `ctx` is the value in the request. The helper reconstructs the embedded `tag`/`ctx` from the address and refuses anything outside the caller's scope. The `interface` must be `lo` or a per-kennel dummy interface named `<namespace>-<id>`, where `<namespace>` is the caller's per-user resource namespace (default `kennel`, so the default install accepts `kennel-<id>`; the rule is namespace-parameterised, not a literal `kennel-` prefix). The `prefix` is fixed at 28 (IPv4) or 64 (IPv6); any other value is refused.
- `setup-egress`: the request carries the target cgroup `path`; the helper requires it to start with the kennel cgroup root, reject `..`/symlink components, and — the cross-user check — confirm the caller actually **owns** that cgroup before it loads and attaches the egress BPF to it. The map contents (the kennel's own egress allowlist) are not scope-validated: the caller already controls them; the cgroup path is the boundary.
- `set-gid-map`: the helper refuses any gid the caller is **not** a member of and any target pid the caller does **not** own, then writes the identity `gid_map` for that pid (it holds `CAP_SETGID` in the init userns; an unprivileged process cannot self-map a group it lacks). Mapping a group the user is not in would be an escalation, so this gating is the boundary.

There is **no** cgroup-create / cgroup-delete operation: the privhelper neither creates nor deletes cgroups. kenneld creates and removes the per-kennel cgroup itself, unprivileged, in its systemd-delegated subtree; the privhelper's only cgroup interaction is the egress-BPF attach (delegated to `kennel-privhelper-bpf`, which re-checks ownership) onto a cgroup kenneld already made.

The validator rejects out-of-scope requests with a stable numeric refusal code carried on the wire (`AddrOutOfScope = 2` for an address outside the reserved subnet, alongside `BadPrefix = 1`, `InterfaceNotAllowed = 3`, `InterfaceNameTooLong = 4`, `GidNotMember = 5`, `EmptyGidMap = 6`, and the scope/ownership codes `100`/`101`/`102`); the refusal is surfaced as a `priv.refuse` audit event and a non-zero exit. Nothing happens at the privileged syscall level.

**Failure mode.** A compromised kenneld asking the privhelper to add `169.254.169.254` to loopback would be refused. The privhelper logs the refusal to its own audit channel and exits non-zero. kenneld observes the refusal and surfaces it.

**Threat IDs addressed.** T1.6 (lateral movement: a hostile caller cannot direct the privhelper to do anything outside the reserved scope), T3.1 (privilege escalation via the helper: it is small and refuses out-of-scope requests; even on subversion of the calling process, the privileged syscall surface is bounded, and the rare host-context caps are not even on the factory — they live in the sub-helpers, each gated by its own ownership/scope re-check).

**Bounded duration of privilege.** The host-context operations are short-lived sub-helper execs: `kennel-privhelper-net` (the loopback add/del netlink op) and `kennel-privhelper-bpf` (the egress attach) exist only for the milliseconds of one validated syscall sequence, and `CAP_NET_ADMIN`/the BPF caps live *only* in those sub-helpers — never on the factory or a long-running daemon. The `ConstructKennel` factory invocation is longer — it lives across the whole construction (clone → maps → view → binderfs → pivot → `fexecve`) — but it relinquishes privilege at the hand-off: the factory child drops to the operator before the trusted init runs, and the privhelper parent stays only to reap the chain and relay the exit status (`07-2-kennel-bin-init.md` §7.2.1). See `01-process-model.md`.

---

## 2. Disk → policy parser

*Compile-time boundary: crossed by `kennel compile` when resolving a source policy, not on the spawn path. In attested deployments this is crossed centrally, not on the workstation.*

**What crosses.** TOML bytes from a policy file, a template, or a leaf delta.

**Trusted side.** The parser does not trust the file contents. The file may have been written by an attacker-influenced AI agent, may have been tampered with on disk, may have been sync'd from a compromised source.

**Validator.** `kennel-lib-policy::parse` and `kennel-lib-policy::resolve`. Per CODING-STANDARDS.md §10.2:

- `#[serde(deny_unknown_fields)]` on every config type. Unknown fields are categorical errors.
- Bounded reads at the call site (`take(N).read_to_string`); the policy file size cap is 256 KiB.
- Bounded template-chain recursion: depth limit 16, checked before descent.
- Duplicate keys rejected (the project's TOML parser is configured to reject; the default `toml` crate behaviour).
- Path-syntax validation: relative-path fields reject `..` and absolute paths; absolute-path fields reject `~/` and relative paths.
- Tilde expansion deferred until *after* signature verification (boundary 3).
- Numeric range checks at parse time.

**Failure mode.** Categorical reject. The parser returns a `PolicyError` variant naming the offending field; the policy is not loaded. No partial state is constructed.

**Threat IDs addressed.** T2.5 (template tampering), T2.6 (invariant weakening by user delta), T2.7 (template-chain depth-DoS).

---

## 3. Untrusted template/fragment → signature verifier and lockfile

*Compile-time boundary: crossed by `kennel compile`, not on the spawn path. The resolved artefacts' hashes are recorded in the settled policy's provenance block; the runtime does not re-verify source signatures.*

**What crosses.** A versioned reference (`<name>@<version>`) from a `template_base` or an `include`, resolving to a claimed-template or claimed-fragment artefact (already parsed, structurally valid TOML) and its signature envelope.

**Trusted side.** The **system** signing-key set is trusted: keys under `/etc/kennel/keys/` and the vendor `/usr/lib/kennel/keys/` (root-owned, mode 0644). Templates and fragments are the security baseline — the framework invariants and confinement floor — so they verify **only against system keys**; a template signed by the user's own `~/.config/kennel/keys` is **rejected** (the trust split, `07-paths.md` §Policy-signing trust split). This is asymmetric with the settled run policy (boundary 13), which a user *may* sign with their own key. The lockfile (`<name>.lock`, beside the leaf policy in its `policies/<name>/` folder, under the user's control) is trusted as the operator's recorded intent. Nothing else — not the artefact named by the reference, not its claimed version.

**Validator.** `kennel-lib-policy::signature` and `kennel-lib-policy::lock`. The procedure, for each resolved reference:

- Algorithm must be in the supported set (`ed25519`). Cryptographic minimums are enforced at validation; negotiation below the current floor is a categorical error.
- The `signed_fields` list must cover every top-level field of the artefact except `[signature]` itself — including `template_base` and `include`, so the artefact's own dependency declarations are signed. An artefact that signs only a subset of its fields is rejected; the rule is about the schema, not the instance.
- The canonical-form serialisation of `signed_fields` is computed deterministically (`kennel-lib-policy::canonical`); the signature is verified against it.
- The signing key must be in the configured key set, identified by `key_id`.
- The artefact's ed25519 signature is checked against the lockfile entry for this `(name, version)`. On first resolution the entry is recorded; on subsequent resolution a changed signature is rejected. This is the byte-pin: version pinning alone constrains *which* artefact is named, the lockfile constrains *what bytes* are composed (the signature is deterministic and bound to the exact canonical bytes, so it *is* the content commitment — the same reasoning as CODING-STANDARDS.md §5.5 for Rust crates).

An artefact that fails signature verification, or whose signature does not match a present lockfile entry, is rejected; its content is not composed, regardless of which fields the unverified portion contains.

**Failure mode.** `PolicyError::SignatureFailure` (with `key_id` if recognised) or `PolicyError::LockMismatch` (naming the reference). The artefact is not loaded; any policy that depends on it cannot be resolved. The only sanctioned way to change a locked entry is `kennel policy upgrade`, which surfaces the change for review.

**Threat IDs addressed.** T2.5 (template tampering: a re-signed or re-tagged artefact under the same version is caught by the lockfile byte-pin; an artefact signed by an untrusted key is refused), and the supply-chain class generally — a versioned reference is a pin to signed bytes, not a name lookup against whatever sits at that name today.

---

## 4. Workload → BPF programs

**What crosses.** The arguments of a syscall the workload invokes (connect, bind, setsockopt, sock_create, sendmsg).

**Trusted side.** Nothing on the workload's side. The kernel's BPF subsystem invokes our programs with the syscall arguments; our programs decide allow/deny.

**Validator.** BPF programs in `bpf/`. Per CODING-STANDARDS.md §4.1:

- Every pointer dereference is preceded by an explicit bounds check against the bearing structure's declared end.
- Loops are bounded with `#pragma unroll` and constant iteration counts, or use `bpf_loop`.
- Helper-function usage is restricted to the whitelist in `bpf/HELPERS.md`.
- The lookup order is deny-first: invariant-deny CIDRs are checked before allow-list match; an allow rule cannot accidentally cover an invariant-denied range.

Map data is populated by the loader at kennel start and marked read-only (`BPF_F_RDONLY_PROG`) where the kernel supports it. The workload cannot modify maps; the bpf() syscall is denied by seccomp.

**Failure mode.** Verdict is allow or deny. Deny returns 0 from the BPF program, which causes the kernel to fail the syscall with `EPERM` (or with `ECONNREFUSED` for connect). The deny event is emitted via the ringbuf for audit.

**Threat IDs addressed.** T1.1 (recon: workload cannot enumerate sockets we have not bound), T1.6 (lateral movement: workload cannot connect to host loopback services), T1.7 (DNS exfiltration: workload cannot issue DNS directly), T1.9 (supply-chain: unexpected destinations show up in audit).

---

## 5. BPF → userspace audit reader

**What crosses.** Packed structs from the BPF ringbuf, declared in `bpf/audit_events.h`.

**Trusted side.** The events come from our own BPF programs, attached to cgroups we created, populated by code we wrote. The trust is high — but the ringbuf reader still validates because the audit subsystem must never panic on a malformed event (the kennel must keep running even if a BPF event arrives that does not match the declared layout, which could happen across version skew).

**Validator.** `kennel-lib-bpf::ringbuf::parse`:

- Reads the fixed-size `audit_hdr` first, verifies `magic` is `0x4145564E`, verifies `version` is supported.
- Computes the expected payload size for the event kind from a static table; verifies it equals `header.length - sizeof(audit_hdr)`. A mismatch is reported as a structured error and the event is skipped.
- Reads the payload as a typed struct via `from_bytes` (safe; no `unsafe` cast).
- Resolves `ctx_byte` to a kennel name through kenneld's in-memory registry. An unknown `ctx_byte` is logged and the event is dropped (a stale BPF program attached to a defunct kennel, e.g., during the recovery procedure).

**Failure mode.** Malformed event → drop with a counter increment and a self-diagnostic via the other audit sinks. The reader does not panic.

**Threat IDs addressed.** Operational: the audit subsystem's availability under version skew.

---

## 6. CLI → kenneld

**What crosses.** Length-prefixed binary frames on the kenneld Unix socket: a `u32` body length, then a body that begins with an op byte and continues with primitively-encoded fields (lengths, strings, argv).

**Trusted side.** The wire format is internal. Both sides come from the same release. But kenneld still validates every field because protocol drift is a possibility (a CLI compiled against a different kenneld) and because the same socket handler is the path for any future external integration.

**Validator.** kenneld's `control` decoder. Per CODING-STANDARDS.md §10.2 and `02-6-ipc.md`:

- Frame length is bounded at `MAX_MESSAGE` (1 MiB); longer frames are a protocol violation, connection dropped.
- Each field is bounds-checked as it is read: string length is capped at `MAX_STRING` (64 KiB) and array/argv counts at `MAX_COUNT` (4096); a truncated or oversized field is rejected.
- String fields must be valid UTF-8 (`WireError::BadString`); an unknown op byte is `WireError::BadTag`.

The kennel name is format-validated at this boundary before it is used anywhere: `kenneld::server::validate_kennel_name` enforces the `[a-z0-9][a-z0-9-]{0,63}` grammar (§02-2) on both `Start` and `Stop` requests, rejecting an empty name, one over 64 characters, or any character outside `[a-z0-9-]`. This runs ahead of `reserve()` (which still rejects a duplicate name and an exhausted context pool), so a name carrying `/`, `..`, NUL, whitespace, or control bytes can never reach the synthetic-`/etc` staging path, the per-kennel audit directory, the synthetic `/etc/hostname`, or the registry key — closing the path-traversal and hostname/log-injection surface at the trust boundary.

**Failure mode.** Structured error response (with code from the catalogue in `02-6-ipc.md`); the connection remains open for the client to issue the next request or close. Protocol-framing violations close the connection.

---

## 7. Untrusted client → kenneld socket

**What crosses.** A `connect()` to `/run/user/<uid>/kennel/control.sock` from any process on the system.

**Trusted side.** The socket file's owner-and-mode (user-owned, mode 0600) limits who can connect at the filesystem layer. kenneld additionally checks `SO_PEERCRED` to verify the connecting process's UID matches kenneld's own.

**Validator.** kenneld's accept-loop handshake check:

- Accept the connection.
- `getsockopt(SO_PEERCRED)` to retrieve the peer UID, GID, PID.
- Reject (close connection without any wire-format exchange) if UID != kenneld's UID.
- Otherwise proceed with the protocol handshake (boundary 6).

The PID from `SO_PEERCRED` is recorded in audit events but not used for authorisation; PIDs can be reused, the UID is what matters.

**Failure mode.** Connection closed without any response; an audit event records the rejected attempt with the peer UID/PID. This is rare: only a misconfigured filesystem or a same-UID-but-distinct-program would trigger it.

**Threat IDs addressed.** T1.6 (lateral movement: another user on the same machine cannot ask kenneld to start a kennel as us, even if the socket file were inadvertently world-readable).

---

## 8. Workload → D-Bus facade

**What crosses.** D-Bus method-call wire format from the workload to the `IDBus` facade (§7.7).

**Trusted side.** Nothing on the workload side. The `IDBus` facade is the D-Bus mediation membrane: a binder-based method filter that parses the workload's D-Bus traffic and translates allowed calls onto the bus. Our scope is:

- *Whether* the workload reaches any bus at all. The workload has no path to the host's session or system bus; the only D-Bus carrier in its view is the `IDBus` facade.
- *Which* methods the facade allows. kenneld is the membrane and applies the policy `[dbus]` allow-rules; method calls not in the allow list are rejected.

**Validator.** The `IDBus` facade (the D-Bus method filter) and kenneld's `[dbus]` allow-rules.

**Failure mode.** Out-of-scope D-Bus calls are denied and surface as `dbus.call-deny` audit events.

**Threat IDs addressed.** T1.6 (lateral movement to D-Bus services: the host dbus is not reachable, only the mediated facade).

---

## 9. Workload → netproxy

**What crosses.** SOCKS5 request bytes on the kennel's loopback proxy address.

**Trusted side.** The proxy does not trust the SOCKS5 client's claims. Hostname resolution happens server-side (the proxy resolves; the workload cannot bypass DNS). Allow/deny is on the resolved destination, not on the client's claim.

**Validator.** `host-netproxy::server`. Per the SOCKS5 spec plus our additions:

- SOCKS5 method negotiation: only `NoAuth` accepted; other methods rejected.
- CONNECT request: destination must be hostname-with-port (resolved by proxy against allowlist) or IPv4/IPv6 numeric. Numeric addresses are checked directly against the allowlist; the cgroup BPF rules also deny the underlying connect() to addresses outside the allowlist (defence in depth).
- Bounded read on the request bytes (SOCKS5 messages are small; cap at 1 KiB).

**Failure mode.** Unallowed destination → SOCKS5 reply 0x02 (connection not allowed by ruleset). Audit event emitted.

**Threat IDs addressed.** T1.1 (exfiltration: arbitrary destinations refused), T1.7 (DNS exfiltration: workload cannot ask DNS for unallowed names, even via SOCKS5 — the proxy refuses), T1.9 (supply-chain).

---

## 10. Kernel-side string → audit log

**What crosses.** Strings originating from kernel structures (`task->comm`, resolved paths, dbus member names) flowing into audit-log strings that humans and SIEMs read.

**Trusted side.** Nothing. `task->comm` can be set by a workload via `prctl(PR_SET_NAME, ...)` to attacker-controlled bytes. Paths may contain control characters or non-UTF-8 bytes.

**Validator.** `kennel-lib-text::sanitise_for_audit`, called by the audit writer for every event-field that may carry kernel-side strings. Per CODING-STANDARDS.md §10.3 and §10.4:

- Control characters escaped (`\x1b`, `\b`, `\r`, ...).
- Non-UTF-8 replaced with U+FFFD; the event carries `sanitised: true` if any replacement occurred.
- Length cap (128 bytes for comm, 4096 for paths); truncation marked.

**Failure mode.** Sanitisation is total — every string passes through. There is no fallback to raw output. If sanitisation itself errors (rare, but a bug in the helper would be one), the event is emitted with `sanitisation_error: true` and the affected field absent. The other fields are still emitted; the event is not dropped.

**Threat IDs addressed.** Terminal injection (an attacker writes terminal escape sequences in their process's comm, hoping to manipulate the operator's terminal when reading the audit log).

---

## 11. Network bytes → DNS resolver

**What crosses.** DNS response bytes from the upstream resolver to the netproxy.

**Trusted side.** Not the response. DNS responses can be forged on-path (if the upstream resolver is not over DoT/DoH) or returned by a malicious recursor. The netproxy treats DNS responses as untrusted.

**Validator.** `host-netproxy::dns`:

- Standard DNS-format validation (well-formed RR types, lengths consistent with the message).
- The resolved name is checked against the allowlist. The set of returned A/AAAA records is what the netproxy uses for the actual `connect()`; if multiple records, the proxy tries them in order.
- `on_resolve_change = "warn"` (per the template) logs when a name resolves to a different IP than previously cached for the same kennel lifetime. Useful for detecting late-stage rebinding-style attacks.

**Failure mode.** A name not in the allowlist returns SOCKS5 `host unreachable` to the workload. A malformed DNS response is treated as resolution failure.

**Threat IDs addressed.** T1.7 (DNS exfiltration), T1.9 (supply-chain: unexpected resolver-rewrites are visible in audit).

---

## 12. Workload → audit log files

**What crosses.** A workload's attempts to read or write its own audit log directory.

**Trusted side.** Not the workload. The workload could try to read its own audit log to learn what kenneld has observed, or write to it to inject misleading events.

**Validator.** The shim. By default, `~/.local/state/kennel/<kennel>/` is *not* bind-mounted into the workload's view. The audit log path is invisible from inside the kennel.

If an operator's policy explicitly grants the workload read access to its audit log (rare; only useful for self-monitoring tools running inside the kennel), the grant is read-only and audit events from that read attempt are themselves recorded.

**Failure mode.** Attempted access from inside the kennel resolves to `ENOENT` (path not in view).

**Threat IDs addressed.** T1.1 (recon: workload cannot learn what is being audited), T2.2 (anti-forensics: workload cannot tamper with audit data).

---

## 13. Settled policy → runtime

**What crosses.** A signed settled policy (`02-2-config-schema.md` §The settled policy) into the spawn path that enforces it.

**Trusted side.** The daemon's trust store. Unlike templates (boundary 3, system-only), a settled run policy may be signed by a **system** key (`/etc/kennel/keys`, `/usr/lib/kennel/keys`) **or** the calling user's own `~/.config/kennel/keys` (the trust split, `07-paths.md` §Policy-signing trust split). The daemon loads system keys first, then the user's, so a user key can never *shadow* a system key of the same id. This is sound: a settled leaf only narrows *within* the template's invariants — re-asserted unconditionally at step 3 below — and a kennel runs with the user's own authority, so trusting the user's own run-policy signature grants no escalation. Nothing else is trusted — not the settled artefact's claim to be valid, not its provenance block, not the `framework_invariants_asserted` list it carries.

**Validator.** `kennel-lib-spawn`'s settled-policy verifier:

1. Verify the settled policy's `signature` against the trust store (system keys + the user's own; see above). One verification. In attested deployments this is the *only* signature check at runtime; the source-artefact signatures (boundary 3) were verified at compile time and are recorded in the provenance block, not re-verified here.
2. Check `settled_schema_version` is in the supported range.
3. **Re-assert framework invariants** against `effective_policy`, regardless of the signature and regardless of `framework_invariants_asserted`. Framework invariants are Project Kennel's structural guarantees, not the signer's; a validly-signed settled policy that violates one is refused. The checks (`kennel-lib-policy::invariant::validate`) are a handful of structural assertions and are cheap: `cap.no_new_privs`, `exec.deny_setuid`/`deny_setgid`/`deny_setcap`/`deny_writable`, the mandatory home shim (`fs.home.shadow`; `$HOME` is `/home/<user>`), the non-empty invariant deny CIDRs (cloud metadata, link-local — RFC1918 is intentionally *not* invariant, design §7.5), and `proc.visibility == self`. `net.mode` is matched exhaustively (the type admits only `constrained`/`open`) rather than asserted to a single value; there is no separate "PID namespace" assertion at this step.
4. Substitute the `deferred_substitutions` with per-instance values; refuse if any other unsubstituted placeholder remains in `effective_policy`.

**Trust reduction.** This boundary is deliberately narrow. The spawn path links none of the template machinery — no TOML template parsing, no chain-walking, no include resolution, no delta application, no source-signature verification. Those crossed boundary 3 at compile time. The runtime trusts one signature and re-checks the structural invariants. On a fleet workstation that holds only settled policies, this is the entire policy-trust surface.

**Failure mode.** The signature, schema-version, and invariant checks live in `kennel_lib_policy::verify_settled`; their failures surface as `SpawnError::Policy` wrapping the underlying `PolicyError` — `PolicyError::Signature(..)` for a bad signature, `PolicyError::UnsupportedSchemaVersion { .. }` for an out-of-range `settled_schema_version`, and `PolicyError::InvariantViolations(..)` (carrying the violated invariant names) for a framework-invariant failure. An unresolved placeholder is the distinct `SpawnError::UnsubstitutedPlaceholder { field, value }` (naming the field and value). The spawn is refused; no workload runs.

**Threat IDs addressed.** T2.5 and T2.6 at runtime (a tampered or invariant-weakening settled policy is refused by signature check and invariant re-assertion respectively); supports the attestation capability (the workstation enforces exactly the signed artefact, identified by its signature — the deterministic ed25519 commitment — with no live resolution that could diverge).

---

## 14. Workload/facade → kenneld over binder

**What crosses.** A binder transaction on **node 0** (the well-known servicemanager handle) of the kennel's per-instance binderfs bus: a service-registry verb (`addService`/`getService`/`listServices`/`isDeclared`/`getDeclaredInstances`) or a facade verb (`org.projectkennel.IAfUnix/default` `CONNECT`), encoded as a length-bounded `binder_transaction_data` and its flat payload (`02-4-binder.md`).

**Trusted side.** Nothing on the workload's side. The workload holds only an unforgeable node reference (no path to enumerate, no abstract name to probe); kenneld is the policy decision point for every call. The decisive trusted fact is **kernel-stamped caller identity**: the binder driver injects `sender_pid`/`sender_euid` into every transaction, and a process cannot forge them.

**Validator.** kenneld's `binder` looper (`kenneld::binder`), `#![forbid(unsafe_code)]`; the unsafe ioctl ABI is confined to `kennel-lib-binder` (boundary into the kernel, the third unsafe crate after `kennel-lib-syscall`/`kennel-lib-bpf`), whose `BC_*`/`BR_*` decoder consumes workload-controlled bytes and carries a fuzz target per CODING-STANDARDS §10.6.

- The `BC_*`/`BR_*` command stream and each transaction are length-bounded; service names are ≤ 255 bytes, validated UTF-8, `..`/control-character-free per CODING-STANDARDS §10.
- Registry verbs are checked against the kennel's settled policy before recording or resolving; `org.projectkennel.*` is a reserved namespace — `addService` under it from any caller but kenneld is rejected, and `getService` for it always resolves locally (the VINTF-declared analogue: a service the policy does not declare cannot register and reports `isDeclared = false`).
- The `org.projectkennel.IAfUnix/default` `CONNECT` facade validates the requested path against `[[unix.allow]]`, performs the `connect()` **host-side**, and returns the connected fd via `BINDER_TYPE_FD` — the path never enters the constructed view. `BINDER_TYPE_FD`/`BINDER_TYPE_PTR` are permitted only **intra-instance**; on any cross-instance path they are rejected.

**Failure mode.** A disallowed or out-of-namespace transaction gets `BR_FAILED_REPLY`; the looper never blocks (relay/facade I/O is handed to a delegate and the looper returns to `BINDER_WRITE_READ`). Every verb is audited (`binder.register` / `binder.lookup`, service name + outcome + requesting pid).

**Threat IDs addressed.** T1.1 (recon: no socket path or abstract name to enumerate — only opaque node references), T1.6 (lateral movement: a granted facade is a per-call decision in kenneld, not a connectable node in the view).

---

## 15. `kennel-bin-init` → kenneld (lifecycle / config)

**What crosses.** Binder transactions on node 0 in a **distinct high code range** (`0x100+`, disjoint from the registry verbs 1–5 and `CONNECT_AFUNIX` = 5): `GET_SANDBOX_PLAN` (the config pull) and the fire-and-forget `NOTIFY_BOOT_SYNC` / `NOTIFY_FACADE_CRASH` / `NOTIFY_WORKLOAD_EXEC` lifecycle verbs (`07-2-kennel-bin-init.md` §7.2.4). This makes `kennel-bin-init` (PID 1) a binder consumer on the same instance kenneld manages — the kennel's control plane *is* the binder bus.

**Trusted side.** Not the verb's claim to come from init. A workload *can address* node 0, so these verbs would be an escalation if any process could exercise them. The trusted fact is again the **kernel-stamped `sender_pid`** — but note the topology subtlety: kenneld is the context manager from the **host** PID namespace (it acquired node 0 via `/proc/<init>/root`), so the driver reports `sender_pid` as `kennel-bin-init`'s **host pid**, *not* the kennel-internal `1`. The naive `sender_pid == 1` gate would be wrong.

**Validator.** kenneld's lifecycle gate. It accepts `GET_SANDBOX_PLAN` and acts on a `NOTIFY_*` only when

```
sender_pid == init_host_pid  &&  sender_euid == 0
```

where `init_host_pid` is a **bootstrap fact from the privhelper** over the construction socketpair (`07-2-kennel-bin-init.md` §7.2.2), never wire-supplied. `sender_euid == 0` is defence-in-depth: `kennel-bin-init` is the only uid-0 process (facades and the workload run as the operator), so it cannot be impersonated; the host-pid match is the primary, exact gate. kenneld identifies *which* kennel a `GET_SANDBOX_PLAN` belongs to by the **binderfs instance** the transaction arrived on (per-instance fd + looper — no token), and replies with the supervision-half Plan as flat `kennel-lib-spawn::wire` bytes (binder *copies* the buffer — `BINDER_TYPE_PTR` rejected — so there is no host↔sandbox shared-memory hazard); the supervision-half decoder runs post-pivot inside `kennel-bin-init`, contained, and is bounded + fuzzed.

**Failure mode.** Any verb whose `sender_pid`/`sender_euid` does not match is a logged `Deny` (`binder.lifecycle-forged`) returning `BR_FAILED_REPLY`. The reliable kennel exit status rides the process chain (`kennel-bin-init` → privhelper → kenneld), not binder, which may already be torn down — binder carries in-life telemetry only.

**Threat IDs addressed.** T3.1 (privilege escalation: a workload addressing node 0 cannot drive construction/lifecycle verbs — the host-pid gate makes them inert for anyone but the trusted init).

---

## 16. Cross-kennel transaction → kenneld relay *(roadmap)*

*Roadmap: the cross-instance / inter-kennel relay is designed, not built (`02-4-binder.md` §Inter-kennel IPC). This boundary describes the intended contract.*

**What crosses.** A binder transaction routed from a consuming kennel's instance to a providing kennel's instance via kenneld's cross-instance registry — only when **both** sides declare it (`[[binder.consume]]` and `[[binder.provide]]` with matching `accept_from`); a unilateral declaration denies.

**Trusted side / TCB note.** This is the one place kenneld grows from control-plane supervisor to **synchronous data-path relay** — every relayed payload passes through it. The trade is bounded, not unbounded: only **flat scalar / `BINDER_TYPE_ARRAY`** payloads cross (fd and shared-memory objects are rejected cross-instance, kenneld inspecting the object-type field before relaying), and the per-instance pending-cookie table is bounded — overflow returns `BR_FAILED_REPLY`, never silent queueing, so a slow provider degrades to refusals on one instance rather than stalling the looper or growing kenneld without limit. Whether the relay stays in-kenneld or moves to a dedicated broker is an open question (`02-4-binder.md` §Open questions).

**Failure mode.** A provider crash fires the binder death notification automatically (`BR_DEAD_REPLY` to in-flight callers, not a hang); a consumer's exit destroys its nodes and `BR_DEAD_REPLY`s pending cross-instance transactions it owned. Each cross-instance transaction is audited (`binder.cross`: `from_ctx`, `to_ctx`, service, code, payload byte count, outcome — never content).

---

## 17. Kennel net-ns ↔ host net-ns

The per-kennel network namespace, the four network modes, and the loopback mirror are built: `kennel-lib-spawn::plan` unshares `Namespaces::NET` for every mode but `host` (`02-5-binder-net.md`). Only `mode = host` shares the host network namespace, reinstating the host-recon residual (T1.6) by design.

**What crosses.** The only controlled crossing of the kennel net-ns boundary is binder: the `org.projectkennel.INet/default` node carries egress `CONNECT_INET` (shim → kenneld → `host-netproxy` delegate) and the inbound `BIND_INET` ingress hand-off (`host-inetd` accept → kenneld → `facade-client`, §7.5.7). The two loopback stacks (the kennel's `/28` + `/64` inside its net-ns, the same addresses mirrored on the host `lo` alias) are otherwise **independent — no routing, no NAT** — so a `connect()` inside the kennel to its loopback stays inside it.

**Trusted side.** Not the shim's request. kenneld is the policy decision point; the delegates (`host-netproxy` for `CONNECT`, `host-inetd` for the `BIND` mirror) hold **no binder access** and do their blocking I/O off the binder path, returning fds to kenneld by `SCM_RIGHTS`. `BINDER_TYPE_FD` is permitted on the `INet` node because shim↔kenneld is intra-instance; the general cross-instance fd prohibition (boundary 16) is not implicated. The shim never `connect()`s or `bind()`s a received fd — it is already in the desired state.

**Host-side mirror.** A native `bind()` inside the kennel is gated by `[[net.bpf.bind]]` at the cgroup `bind` hook; an allowed bind is reported to kenneld, which raises the host-side leg's mirror of the same `ip:port` on the host alias — so every listener that exists is both intra-kennel-reachable and observable host-side at the kennel's own IP, and the allow/deny decision is policy's alone (no workload-initiated `BIND` transaction). `mode = host` kennels share the host stack directly, use no mirror, and reinstate the host-network recon threat (T1.6) by design.

**Failure mode.** A disallowed `CONNECT_INET` destination returns `BR_FAILED_REPLY` and is audited `net.connect-deny` (and `net.egress`); a denied `bind()` fails at the syscall (`EACCES`) and is audited `net.bind-deny` (an allowed bind, `net.bind-rewrite`). Egress resolution stays proxy-side (`socks5h://` semantics; the kennel has no DNS path of its own).

---

## Privilege transitions

Beyond the boundary inventory, two specific privilege transitions deserve naming because they are where most of the design's safety properties land:

### `PR_SET_NO_NEW_PRIVS`

Set unconditionally before `execve()` by `kennel-lib-spawn`. This is a framework invariant per CODING-STANDARDS.md §11.2 — the policy cannot disable it. It blocks setuid binaries from gaining privilege via execve, blocks file capabilities from being granted via execve, blocks AT_SECURE-clearing.

### Landlock sealing

The Landlock ruleset is constructed by `kennel-lib-spawn` from the resolved policy, then sealed via `landlock_restrict_self`. After sealing, the ruleset cannot be widened — by the kernel's design — for the lifetime of the process and its descendants. The seal happens after all setup operations (mount construction, BPF attach, capability drop) so the setup itself has the access it needs, and before execve so the workload starts under the restriction.

Both transitions are owned by `kennel-lib-spawn`; both are tested with positive (the setup works) and negative (a workload cannot bypass them) integration tests under `tests/`.

---

## What this chapter does not cover

- The mechanism details of each kernel feature (Landlock semantics, cgroup BPF attach types, seccomp filter format): design doc §7 and §8.
- The wire formats themselves: `02-6-ipc.md`.
- The audit event schema: `02-3-audit-schema.md`.
- The locking matrix that protects shared state inside kenneld: `05-state-and-supervision.md`.
- The recovery procedure when kenneld restarts: `05-state-and-supervision.md`.
- The CODING-STANDARDS rules these enforcers must follow: CODING-STANDARDS.md §4, §10.
