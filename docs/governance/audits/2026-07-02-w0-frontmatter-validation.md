# W0 — front-matter validation probes (0.6.0, 2026-07-02)

**Scope.** The five empirical unknowns the 0.6.0 structural bets rest on
([ROADMAP-0.6.0.md](../ROADMAP-0.6.0.md) W0). Each probe is measured, not reasoned; each names its
dependent workstream and the consequence a red result forces. The discipline is "the codebase
measures kernel behaviour rather than reasons about it" — so this note records the actual command
output and the byte that crossed, not an argument that it should.

**Host.** `Linux 7.0.0-27-generic aarch64`. Landlock ABI **8** active
(`lockdown,capability,landlock,yama,apparmor,ima,evm` in `/sys/kernel/security/lsm`). AppArmor
active, 234 profiles loaded, `apparmor_parser`/`aa-exec` present,
`kernel.apparmor_restrict_unprivileged_userns=1` (the restricting configuration W1/mesh depend on).
`/dev/net/tun` present; binder fs registered. Toolchain 1.95.0. This host carries every mechanism the
probes need, so none is deferred — P5 in particular is testable here, not only on a separate AppArmor
host.

Probe programs are in the session scratchpad (not committed — they are throwaway measurement tools,
not corpus). Each result below is reproduced from their output.

---

## P1 — Landlock across the `/proc/<pid>/root` magic symlink → **RED (path-grants); fd-passing is the fix**

**Question (gates the W1 fs manifest).** kenneld reaches each kennel's binder at
`/proc/<init>/root/dev/binderfs/binder` — a magic-symlink traversal into another mount namespace.
Once kenneld is under a Landlock fs ruleset, can that ruleset *grant* access to such a target, so the
binder reaches survive the seal as ordinary path rules?

**Method.** A holder process in its own mount namespace with a char device behind a fresh mount
(mimicking binderfs), reached from a second process via `/proc/<holder>/root/...`. Controlled cases,
each in its own forked process (restrict_self is irreversible), against a ruleset handling
`READ_FILE|WRITE_FILE`:

| Case | Result |
| --- | --- |
| same-mount-ns grant (sanity — proves the ruleset logic) | **OPEN OK** |
| cross-ns, grant an unrelated dir only | **DENIED (EACCES)** |
| cross-ns, grant the target device *file* via the magic symlink | **DENIED (EACCES)** |
| cross-ns, grant the target parent *dir* via the magic symlink | **DENIED (EACCES)** |
| pre-seal fd (open before restrict_self, use after) | **held fd usable; re-open denied** |
| held **dirfd** pre-seal, `openat(dirfd,"binder")` post-seal | **DENIED (EACCES)** |
| **fd received via SCM_RIGHTS** from the holder, used post-seal | **WORKS** (fstat → `S_IFCHR`) |

**Finding.** Landlock *does* govern the cross-ns target (it is denied when ungranted — it does not
escape the ruleset), but the target inode lives in a mount that is not in the sealed process's
mount-namespace tree, so it matches no `PATH_BENEATH` rule and falls to the handled-but-ungranted
default. **Access across the magic symlink cannot be granted by any path rule, nor by `openat`
beneath a pre-seal dirfd.** The only mechanism that works post-seal is operating on an
already-resolved fd — passed via `SCM_RIGHTS` or held from before the seal.

**Consequence for W1 (decided: reaches move to the parent leg).** The sealed monitor must **not** open
`/proc/<pid>/root/...` by path after the seal. The affected reaches are small and enumerable — the
binder device ([lib.rs:1556](../../../src/crates/kenneld/src/lib.rs#L1556)), the mesh-bus device dir
([mesh_bus.rs:112](../../../src/crates/kenneld/src/mesh_bus.rs#L112)), and a socket-path reach
([lib.rs:1234](../../../src/crates/kenneld/src/lib.rs#L1234)) — all reached via `/proc/<pid>/root`,
all opened *per kennel, post-seal*, so none can be pre-opened before the seal. These reaches move to
the **unsealed parent leg**: being unconfined, the parent follows the magic symlink freely, then hands
the resolved fd to the monitor **once** over the existing parent→child relay (the same `SCM_RIGHTS`
channel that carries the delegate fds). It is a one-time fd handoff, **not** a per-message forward —
the monitor does its binder I/O directly on the fd afterwards (Landlock does not govern an already-open
fd), so node-0 brokering stays in the monitor at full speed. This gives the clean two-leg split the
design wants — the parent owns every unsealable operation (inet, delegate exec, cross-ns fd
acquisition); the monitor is pure-AF_UNIX with no cross-namespace reach — and it reuses the existing
relay rather than adding a holder→monitor channel. The fs manifest grants **no** `/proc/<pid>/root`
path, so the class drops out of the path-grant surface entirely (rejected alternatives: a
holder→monitor fd path, which adds a channel; and mounting binderfs in the monitor's own namespace to
make it in-tree-grantable, which would rework the holder's node-ownership self-map and still relay
per-message).

---

## P2 — fork-point threading → **GREEN**

**Question (gates the W1 fork split).** The parent relay must fork before any thread exists. Is
kenneld's startup single-threaded through the intended fork point (before `serve()`)?

**Method.** Static: kenneld has **no async runtime** (`kenneld/Cargo.toml` pulls no tokio/rayon/async;
the resolver is deliberately synchronous — [inet/dns.rs:11](../../../src/crates/kenneld/src/inet/dns.rs#L11)),
and every `thread::spawn` is in `serve()`/supervisor/bpf_audit/tripwire — all after the listener.
Dynamic: `strace -f` of a fresh startup (private `XDG_RUNTIME_DIR`) traced `clone`/`clone3`/socket
calls. The startup sequence was:

```
socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 3
listen(3, -1)                                = 0
accept4(3, ...                               [blocks]
```

**Finding.** No `clone`/`clone3` anywhere before the `accept4` loop; the first thread spawns only
per-connection after `accept` ([server.rs:1051](../../../src/crates/kenneld/src/server.rs#L1051)). The
process is single-threaded through the serve point.

**Consequence for W1.** None — the fork point (early in `run()`, before `serve()`) is single-threaded
as the design assumes. The process half proceeds as sketched.

---

## P3 — inet inventory of the future sealed child → **GREEN (with a broader deny set)**

**Question (gates the W1 seccomp seal).** The seal assumes DNS (`getaddrinfo` via
`SystemResolver`) is the only inet-socket user in what becomes the sealed child. Is it — and are there
NSS/glibc surprises?

**Method.** Static: the only inet-socket path in the child's code is `inet::dns::SystemResolver`
(`to_socket_addrs` → glibc `getaddrinfo`); every other kenneld socket is `AF_UNIX` (control, mesh,
binder, delegate command sockets). Dynamic: `strace -f` of a `getaddrinfo` of an external name on this
host (`nsswitch` `hosts: files mdns4_minimal [NOTFOUND=return] dns`) opened:

- `socket(AF_INET, SOCK_DGRAM)` and `socket(AF_INET6, SOCK_DGRAM)` — the resolver's DNS sockets
  (`connect` to `127.0.0.53:53`, the systemd-resolved stub);
- **`socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)`** — glibc's RFC 6724 source-address selection;
- `socket(AF_UNIX)` — nscd / resolved stub.

**Finding.** `getaddrinfo` is the sole inet user, exactly as assumed — and it is the operation W1
moves to the parent relay. Post-move, the child's own code opens only `AF_UNIX`. The surprise the
roadmap flagged is real but benign: `getaddrinfo` also opens an `AF_NETLINK/NETLINK_ROUTE` socket, and
that leaves with DNS.

**Consequence for W1.** The seccomp seal should deny **`AF_INET`, `AF_INET6`, `AF_NETLINK`, and
`AF_PACKET`**, not just `AF_INET`/`AF_INET6` as the roadmap sketched. The child needs only `AF_UNIX`,
so the broader denylist costs nothing and closes the `NETLINK_ROUTE` interface-enumeration vector that
the roadmap's accepted "recon residual" otherwise leaves open at the syscall (full recon-denial also
needs the fs manifest to withhold `/proc/net` and `/sys/class/net` — a manifest note, not a seal one).

---

## P4 — `MSG_ERRQUEUE` port-unreachable recovery → **GREEN**

**Question (shapes W2 Part D).** The broker translates a flow's `ECONNREFUSED` into an ICMPv6
port-unreachable reconstructed from the error-queue read. Does the connected-UDP error queue deliver
what the reconstruction needs on this kernel?

**Method.** A connected UDP socket (`IPV6_RECVERR`/`IP_RECVERR` set) to a closed loopback port, then
`recvmsg(MSG_ERRQUEUE)` parsing `sock_extended_err` + `SO_EE_OFFENDER`.

```
IPv6 (::1:9):      origin=ICMP6 type=1 code=4 errno=111(ECONNREFUSED)  offender=::1        [recoverable]
IPv4 (127.0.0.1:9): origin=ICMP  type=3 code=3 errno=111(ECONNREFUSED)  offender=127.0.0.1 [recoverable]
```

**Finding.** The error queue delivers exactly what Part D reconstructs from: origin, ICMPv6
type 1 / code 4 (port unreachable), `ee_errno == ECONNREFUSED`, and a recoverable offender address.
The type/code even matches the facade ingress predicate's allowed set (`ICMPv6 error, type 1,
codes {1,4}`).

**Consequence for W2.** None — the broker's port-unreachable translation is buildable as specified;
refused ports need not degrade to idle-expiry. Part D proceeds.

---

## P5 — AppArmor `userns` grant across the fork split → **GREEN**

**Question (accompanies W1).** W1 forks an unsealed parent and a sealed child under the kenneld
profile, and the mesh holder (forked from the child) does an unprivileged userns self-map. Does the
profile's `userns` grant survive the fork split *and* the child's Landlock+seccomp seal?

**Method.** A test binary at a **fresh, never-reused path** under a `flags=(unconfined)` profile
granting `userns` (the real profile's idiom — [dist/apparmor/kenneld](../../../dist/apparmor/kenneld)),
replicating the holder's exact sequence (`unshare(USER)`, `setgroups=deny`, `uid_map "0 <uid> 1"`,
then `unshare(MOUNT)` to prove in-ns `CAP_SYS_ADMIN`):

```
forked plain holder   -> SELF-MAP+USERNS OK
forked+SEALED holder  -> SELF-MAP+USERNS OK   (Landlock+seccomp installed before the map)
```

**Finding.** The `userns` grant is inherited across `fork` and lets the unprivileged forked child
self-map — with **no seccomp required**, consistent with the shipped system (the live daemon runs
`Seccomp: 0`, and the holder self-map works). The full seal does **not** break the grant or the
self-map: AppArmor (unconfined), Landlock, and seccomp stack cleanly. Two constraints hold:
`flags=(unconfined)` is required — an *enforcing* profile yields a capability-stripped userns whose
map write fails even with `userns,` granted (which is why the real profile is name-only, per its own
comment); and the child's Landlock manifest must **grant `/proc` write** so the holder's
`/proc/self/uid_map`/`setgroups` writes are not Landlock-blocked (the P1 lesson applied to the seal —
verified: the sealed case passed only with `/proc` granted in the ruleset).

**Consequence for W1.** None blocking — the AppArmor profile stays `flags=(unconfined)`; the seal is
Landlock+seccomp only; the fs manifest grants `/proc` write for the holder's map writes. The profile
edit that lands with W1 keeps the unconfined idiom.

**Methodology note (recorded so it is not repeated).** An earlier version of this probe reported a
spurious "seccomp is required for the self-map." The cause was **AppArmor profile-attachment collision
on a reused binary path** — loading several profiles (enforce and unconfined) against the same binary
path over one session left the grant not reliably taking effect, so the process behaved as
capability-stripped regardless of the loaded profile. A clean, never-collided path per profile removed
the artifact. When probing AppArmor path-attached profiles, use a fresh binary path for each profile.

---

## Summary

| Probe | Verdict | Dependent | Consequence applied |
| --- | --- | --- | --- |
| P1 Landlock magic-symlink | **RED (path) / fd-passing OK** | W1 fs manifest | cross-ns binder reaches move to the unsealed parent leg; the fd rides the existing relay as a one-time handoff (not per-message); manifest grants no `/proc/<pid>/root` path |
| P2 fork-point threading | GREEN | W1 fork split | none — startup single-threaded through `serve()` |
| P3 child inet inventory | GREEN (broaden) | W1 seccomp seal | deny `AF_INET/AF_INET6/AF_NETLINK/AF_PACKET`; child needs only `AF_UNIX` |
| P4 MSG_ERRQUEUE recovery | GREEN | W2 Part D | none — port-unreachable translation buildable as specified |
| P5 AppArmor across fork | GREEN | W1 profile/seal | profile stays `flags=(unconfined)`; Landlock manifest grants `/proc` write |

No probe blocks its workstream. Two shape the design before its manifest is drawn: **P1** moves the
cross-ns binder reaches to the unsealed parent leg (the fd rides the existing relay as a one-time
handoff) and keeps `/proc/<pid>/root` out of the fs manifest, and **P3** broadens the seccomp seal's
socket-family denylist. Both land with W1 as first-class parts of its manifest and seal, per W0's
contract.
