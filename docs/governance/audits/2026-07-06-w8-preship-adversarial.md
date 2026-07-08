# W8 — pre-ship adversarial pass on the 0.6.0 boundaries

**Date:** 2026-07-06 · **Release:** 0.6.0 (ship gate) · **Verdict:** three ship-blockers found and
**fixed**; four residuals accepted and recorded. The tag is unblocked once the fixes land.

## Scope and method

0.6.0 creates three boundaries that did not exist before, each parsing or trusting something the
workload or the invocation controls. This pass drove each one adversarially, in parallel, then
**every candidate finding was re-verified against the code (and, where possible, reproduced live)
before it counted** — a red-team's "plausible" is not a confirmed hole.

- **The UDP-egress facade + broker** (W2) — hostile L3 frames and DNS wire parsed in operator context.
- **The `[fs.cwd]` invocation-cwd write grant** (W11) — a signed slot the untrusted invocation fills
  with a writable directory.
- **The W15 asymmetric-`source` fs redirect** — the confused-deputy floor decoupling view path from
  host origin.

## Confirmed and fixed

### F1 — W15 write-set floor bypassed by a trailing slash or `..` (HIGH) — FIXED

The confused-deputy floor (`kennel_lib_policy::invariant::paths_intersect`) compared **raw grant
strings** with `strip_prefix`. A trailing `/` on the writable grant defeated it: `write = "~/data/"`
with `source = "~/data/cred.json"` was accepted (`"~/data/cred.json".strip_prefix("~/data/")` =
`"cred.json"`, no leading `/` → "no intersection"), while the semantically identical `write =
"~/data"` was refused. **Reproduced live** against the installed compiler. A `..` in the source
(`~/.config/../data/cred.json`) evaded it the same way and collapsed into the write set at spawn
(`open_no_symlinks`/`open_no_magiclinks` set no `RESOLVE_BENEATH`). Either way the workload writes
the source through its own grant and reads it back at `path` as operator-provided content.

**Fix:** `paths_intersect` now compares **by path component** (splitting on `/`, dropping `""`/`.`,
collapsing `..`), so a trailing slash or dot-segment cannot slip a source past the floor; and
`translate_fs_redirects` **rejects a `..` component** in a redirect `source`/`path` at compile
(canonical paths only — the structural floor cannot vet a non-canonical source). Regression tests
cover both variants; the legit-redirect and sibling-path cases still pass.

### F2 — UDP rebinding to loopback/RFC1918/ULA not closed; the flow dial reaches host-local services (HIGH) — FIXED

The tun-broker runs `net.mode = host` and dials the **untrusted-name-resolved** address. Its only
CIDR floor was the cgroup `net.bpf` deny of cloud-metadata + link-local (the invariant floor
deliberately leaves RFC1918/loopback reachable, for the TCP proxy's local-dev case). But the TCP
CONNECT decision *also* runs a userspace special-use refusal (`is_special_use`, gated by
`accept_private_resolved`) on the resolved address — and the UDP flow dial had **no equivalent**. So
an allowed name whose DNS an attacker controls, rebound to `127.0.0.53`, would have the broker dial
the **host resolver** in the host netns — handing the workload arbitrary DNS resolution, the exfil
axis constrained mode exists to make unexpressible. `[net.udp]` is hostname-only (no IP/CIDR opt-in),
so a UDP name can *never* legitimately resolve to special-use.

**Fix — two gates in the dialer** (the cgroup floor cannot carry either: the broker's own
`getaddrinfo` shares that cgroup and legitimately reaches the host resolver, and the BPF is
**deny-first** — an allow can never override a deny, so a `/32` resolver carve-out cannot beat a
loopback deny without weakening the property that keeps the cloud-metadata deny un-defeatable):

1. **Non-routable rebinding gate** ([`is_nonroutable_egress`](../../../src/crates/kennel-lib-policy/src/netaddr.rs),
   in `kennel_lib_policy::netaddr`): `flow::dial` drops any resolved **loopback / link-local /
   unspecified / multicast / broadcast** address and refuses a flow that resolves only into that set
   (`FlowError::Rebound`). This is deliberately **narrower** than the TCP path's `is_special_use`:
   **RFC1918 / CGNAT / ULA are NOT dropped by default** — constrained UDP legitimately reaches
   private/internal endpoints (enterprise data-sync, QUIC to a private host); a deployment that wants
   them refused adds them to the tun-broker's `[net.bpf].connect.deny`. `is_special_use` (the full
   set, used by the TCP CONNECT decision with its `accept_private_resolved` opt-in) is unchanged.
2. **DNS/mDNS port deny**: the dial refuses destination ports **53** and **5353** regardless of
   grant. A UDP flow to a resolver at *any* address — including a **public** one (Azure's
   `168.63.129.16`, a bare `8.8.8.8`), and now any reachable private resolver — is the DNS-exfil
   axis, and name resolution is the shim's job, never a `[net.udp]` destination. This is what closes
   the resolver reach now that private space is dialable by default.

The wildcard-exfil channel (a minted `<data>.example.com` reaching the granted domain's own NS via
the broker's `getaddrinfo`) is bounded separately by the per-grant mint cap (F4). A kernel-enforced
policy-level loopback/link-local deny was considered and **rejected** for the reasons above (deny-first
BPF + the resolver living on loopback *or* link-local depending on host); the dialer gates are the
clean, host-independent close.

### F3 — cwd `$HOME` refusal fails OPEN (MEDIUM) — FIXED

`resolve_cwd_grant` refused a cwd equal to `$HOME` only when `HOME` was set **and** canonicalised
cleanly; an unset or unresolvable `HOME` skipped the check, so a non-overridable floor invariant
("never bind `$HOME`") silently permitted a whole-home writable bind. **Fix:** the check fails
**closed** — if the operator's `$HOME` cannot be resolved, the cwd grant is refused. Also added: a
**world-writable** cwd is refused (any host user could plant content and the required markers in the
tree the confined workload then writes — a cross-user vector); group-writable is deliberately still
allowed (private-usergroup systems use `0775` project dirs with the operator's own single-member
group — refusing it would be a false positive). Tests added.

### F4 — UDP synthetic pool grows unbounded (MEDIUM) — FIXED

`Pool::mint` had no ceiling, and its comment falsely claimed the flow cap bounds it — but a mint
costs only a zero-wire DNS AAAA query and opens no flow, so under a wildcard grant a workload could
grow the operator-context `name → synthetic` map without bound (sharpest as an O(n) per-packet
reverse scan too). **Fix:** a `MAX_POOL` ceiling (4096 distinct names/kennel, far above any real
workload); past it a new name is answered NODATA exactly like a denied one. Self-inflicted and
fate-shared regardless, but no longer unbounded, and the false comment is corrected.

## Accepted residuals (recorded, not fixed)

- **The TCP egress path cannot be DNS-closed by port.** The UDP tun-broker default-denies dest ports
  53/5353, but the TCP proxy path (`net.proxy`) cannot mirror that: **DoH runs on 443** (and DoQ on
  853), indistinguishable from ordinary HTTPS/QUIC egress, so a blanket port deny there would break
  the web. There is no port that both closes DNS-over-HTTPS and leaves normal egress working. The
  posture is therefore a **policy-authoring guidance, not a control**: a proxy grant should name
  **specific ports/services**, not a blanket name that also opens 443 to an arbitrary DoH resolver.
  The DNS-exfil-inside-an-approved-flow shape is the T1.8 residual, unchanged.
- **RFC1918 / CGNAT / ULA are reachable from constrained UDP by default.** The dialer's rebinding gate
  drops only loopback / link-local / unspecified / multicast / broadcast — *never*-a-real-remote
  addresses. Private/internal unicast space stays reachable because constrained UDP legitimately
  targets it (enterprise data-sync, QUIC to a private endpoint). A deployment that wants private space
  refused adds the ranges to the tun-broker's `[net.bpf].connect.deny`; the resolver-reach subset of
  this is already closed by the 53/5353 port deny. A rebound name pointing the *constrained* workload
  at a private LAN host is the T1.6 host-network-reach shape (the broker is `net.mode = host`),
  bounded to what a policy's deny list permits.
- **cwd sensitive-path exposure is a footgun, not a vuln.** The floor admits any operator-owned,
  non-`$HOME`, non-world-writable *marked* directory as a writable bind — including, in principle,
  the operator's own `~/.ssh` (with planted markers) or the runtime store. This is **not** an
  escalation under the threat model: the invocation is the **operator** (the workload — the adversary
  — is not yet running and has no control socket in its view to start a run with a chosen cwd, so it
  cannot influence `req.cwd`). Exposing one's own directory to one's own agent is a footgun the markers
  make deliberate, not a boundary the framework must hold against the operator. Adding a sensitive-path
  denylist would be [[no-security-theatre]] against a non-adversary.
- **cwd check-then-use (rename-into-place).** The floor check and the bind are two resolutions of the
  same path string. A symlink swap is closed (`RESOLVE_NO_SYMLINKS` at the bind), but a real-directory
  rename into `resolved` between check and bind is not — it requires **write on an ancestor** of an
  operator-owned cwd (a world-writable *ancestor*; the cwd itself is now refused if world-writable).
  Niche (operator's own misconfiguration) and the invocation is trusted; the tighter fix (bind via an
  `O_PATH` fd captured at check time) is recorded as future hardening.
- **cwd symlinked markers** are followed (`std::fs::metadata`), so a `.git`/`.claude` symlink satisfies
  a marker. This does **not** redirect the bind (the cwd itself is bound, never the marker target), so
  it is informational, not an escape.
- **UDP exfil under a wildcard grant** is the T1.8 shape — now **bounded**. With `[[net.udp.allow]]
  name = ".example.com"`, the broker's `getaddrinfo` on a minted `<data>.example.com` reaches
  `example.com`'s own authoritative NS — a DNS tunnel to the granted domain. It reaches only that
  domain's NS (the inherent cost of granting a wildcard), and is now capped: the synthetic pool mints
  at most `MAX_PER_GRANT` (32) distinct names **per grant**, so a single wildcard grant can carry at
  most 32 distinct tunnelled labels before further names are answered NODATA. An exact grant mints
  one. The remaining channel (≤ 32 labels to the granted domain's NS) is the accepted T1.8 residual.

## Proven defended (negative results — so a future pass need not re-derive them)

- **The facade L3 predicates never panic, over-read, or wrongly accept.** `parse_ipv6` bounds-checks
  every field and pins `header + payload_len == len`; `egress_ok` requires `next_header == UDP`
  **directly**, so an extension-header chain that shifts nexthdr is structurally rejected, not
  followed. v4, workload ICMPv6, spoofed src, off-`/64` dst, and dst == interface each have a named
  reject. The 20k-input `parsers_never_panic_on_adversarial_bytes` fuzz smoke passed clean.
- **Cloud-metadata SSRF is closed at connect** (both families, deny-first before the broad allow);
  the connected-UDP dial issues a real `connect()`, so it traverses the cgroup hook.
- **Denied names are zero-wire:** the shim mints only on `AAAA ∧ allowed`, answers NODATA (never
  NXDOMAIN) otherwise, and never resolves a denied name.
- **Literal-IP egress** dies `ENETUNREACH` (off-`/64` dst dropped at the facade regardless of the
  workload's routing table).
- **Flow ceilings** (concurrency cap, new-flow token bucket, idle reap) are wired and enforced; the
  pool's reserved `::1`/`::2` suffixes are compile-time-guarded.
- **W15:** the compile refusals (source on multi-path / remove / `fs.deny` / `exec.allow`, `/proc`
  redirect, cross-axis orphan/double-source) all fire; the `/etc` protected floor
  (`is_overlayable_etc_path`) rejects `..` and globs and matches the first component below `/etc`
  against the persona-mask + loader set; the RO-source `RESOLVE_NO_MAGICLINKS` vs RW-source
  `RESOLVE_NO_SYMLINKS` split is correct; audit records `source → path` on divergence.
- **cwd:** symlink floor escape is closed (`canonicalize` resolves the final component, ownership vets
  the target), `$HOME` normalisation games are defeated (canonicalise both sides), a file cannot
  satisfy a `dir/` marker, and a writable cwd covering a redirect source is refused at spawn.

## Disposition

The three ship-blockers (F1, F2, F3) and the two mediums (F3's world-writable leg, F4) are fixed with
tests. The residuals are accepted and recorded above. No finding survived verification unfixed.
