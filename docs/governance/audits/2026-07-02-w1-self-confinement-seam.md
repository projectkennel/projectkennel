# W1 kenneld self-confinement — seam reassessment (2026-07-02)

**Verdict.** W1 as scoped for 0.6.0 is **withdrawn**. Building the relay half surfaced that the
fork-split seam is drawn through code not factored for it, so the confinement boundary keeps hitting
host-facing effects ad hoc and the relay protocol grows without converging. The tidy prerequisite —
factoring all host effects behind one narrow seam — is larger than the seal itself and is the real
first step of any future attempt. This note records why, so a future W1 does not rediscover it by
the same ad-hoc path.

## What was attempted

Fork kenneld once at startup (before threads, W0 P2) into an **unsealed parent relay** and a **sealed
monitor**. The monitor installs a Landlock+seccomp seal before touching kennel input; the relay
performs, on the monitor's behalf, the operations the seal denies (inet, exec, cross-mount-namespace
opens). Built and verified: the relay wire codec (fuzzed), transport, serve loop, monitor client, the
fork (watched live — monitor forks the relay child, child blocks in `recvmsg`, fate-shares on monitor
death), DNS resolution routed through the relay (P3), and the binder-device open routed through it
(P1). That work is discarded with the branch; the primitive was not retained (dead weight in the TCB
if the seam moves).

## What W0 validated — still sound, reusable for any future attempt

The five front-matter probes ([2026-07-02-w0-frontmatter-validation.md](2026-07-02-w0-frontmatter-validation.md))
are kernel facts and remain true regardless of the seam:

- **P1** — Landlock cannot grant access to a target across a mount-namespace boundary reached via the
  `/proc/<pid>/root` magic symlink; an `SCM_RIGHTS`-passed fd is the only post-seal mechanism.
- **P2** — kenneld startup is single-threaded through the serve point (a fork there is safe).
- **P3** — `getaddrinfo` is the sole inet-socket user; it also opens `AF_NETLINK`.
- **P4** — connected-UDP `MSG_ERRQUEUE` delivers ICMPv6 port-unreachable (this is a **W2** input, not
  W1 — unaffected by this withdrawal).
- **P5** — the AppArmor `userns` grant survives fork and the Landlock+seccomp seal.

Their "consequence for W1" lines are moot while W1 is withdrawn; the measurements are not.

## What building revealed — the loose ends

The seal wants a clean line between reference-monitor *logic* (safe to confine) and host-facing
*effects* (must stay unconfined). In kenneld today those are interleaved, not separated. The effects
were found one at a time, each becoming its own relocation with its own shape:

1. **The exec surface is wide.** The monitor execs, on the construction path: `sha256sum` (workload
   digest-pinning, [server.rs:2406](../../../src/crates/kenneld/src/server.rs#L2406)),
   `host-netproxy` / `host-inetd` ([lib.rs:1259,1282](../../../src/crates/kenneld/src/lib.rs#L1259)),
   `host-dbus` ([lib.rs:1944](../../../src/crates/kenneld/src/lib.rs#L1944)), and the bastion's
   `kennel-sshd` / `ssh-keygen`. The roadmap's "execute = privhelper only (the relay launches
   host-netproxy and host-inetd)" undercounts by four binaries plus a run-to-completion tool.

2. **Seccomp inheritance forces all inet delegates onto the relay.** A seccomp filter is inherited
   across `execve`. A delegate the *sealed* monitor execs would inherit the monitor's
   `AF_INET`/`AF_INET6` deny — but `host-netproxy`/`host-inetd`/`host-dbus`/`kennel-sshd` exist to
   open inet sockets. So they **cannot** be exec'd by the sealed monitor under any Landlock-execute
   allowlist; they must descend from the unsealed relay. A bounded-allowlist seal is therefore
   unsound for exactly the delegates that matter.

3. **`sha256sum` cannot be replaced in-process.** It is exec'd precisely to keep a hash implementation
   (`sha2` and its chain) out of the daemon's curated vendored closure. Replacing the exec with a
   crate is refused on dependency-discipline grounds, so digest-pinning must become a relay
   run-to-completion op — a message shape beyond the "held to three."

4. **Delegate lifecycle must move too.** Delegates are not cgroup-reaped today: the monitor holds each
   `Child` and `kill()`s it on teardown ([lib.rs:636](../../../src/crates/kenneld/src/lib.rs#L636)),
   and they are not placed in the kennel cgroup. Once the relay execs them, the monitor can neither
   `waitpid` nor `kill` a non-child, so lifecycle management (a relay-side supervisor, or a move into
   the kennel cgroup with its resource-limit tradeoff) has to be designed — a restructuring, not a
   relocation.

## Diagnosis

These are not five surprises; they are one structural fact. **Host-facing effects (exec, inet,
cross-namespace opens) are interleaved through kenneld's construction and runtime brokering rather
than routed through a single seam.** Drawing the confinement boundary through unfactored code means
discovering each effect where the seal trips over it, and the relay protocol grows once per effect
with no convergence point.

Two ways to make the split tidy, and the attempt was on neither:

1. **Factor host-effects behind one narrow interface first** (a `HostEffects` seam: resolve,
   exec-delegate + lifecycle, open-cross-ns, run-to-completion). Route *all* of construction and
   brokering through it. The seal then becomes mechanical: sealed side = logic + an effects-client;
   unsealed side = the single effects-impl. Clean, but a larger prerequisite than the seal.
2. **Ad hoc** (the attempt): find each effect as the seal hits it. Never converges tidily.

## The security caveat, stated honestly

Even completed, the sealed monitor retains the authority to *drive* the relay — exec delegates,
resolve+pin+dial, open binder fds, construct kennels. A compromised monitor can push a great deal
through that channel (the roadmap already conceded mis-brokering). "Bounded compromise" is real but
the bound is wide, which is a further reason not to pay the restructuring cost until the effects
factoring makes the boundary — and the residual — sharp.

## Disposition

- PR #154 closed; the branch and the relay primitive removed.
- W1 leaves the 0.6.0 roadmap and moves to the backlog, gated on the host-effects factoring as its
  named first step.
- 0.6.0's structural bet is **W2 (UDP egress)**, which does not have this problem; the release stands
  on W2 plus the mediation and owed items.
