# Audit — pre-ship dynamic red-team (W11, 2026-06-29)

**Scope.** The two residuals the [2026-06-24 cross-kennel red-team](2026-06-24-cross-kennel-redteam.md)
recorded as *assessed by code-read, not by a live racing/probe harness* (that audit's "Surfaces not
exhaustively exercised"), now more exercised after the 0.5.0 W1 connector/D-Bus work:

1. **The connector-broker resolution race** — a TOCTOU between a consumer's `SVC_CONNECT` and the live
   capability map (catalogue) as it mutates (provider enable/disable, `ondemand` activation, idle-reap,
   provider death, `daemon-reload` re-projection).
2. **The GUI confidentiality legs** — (a) a consumer reaching the *host* compositor directly, bypassing
   its nested per-connection compositor; (b) one consumer reaching *another* consumer's compositor.

This is the 0.5.0 ship-gate counterpart to the two 0.4.0 passes; it converts both residuals from
"no finding on a code-read" to a live result.

**Method.** Two parts, against the **real installed daemon** on the dynamic-spawn machine (not a mock):

1. A **code-read map** of each surface (two independent passes) to the enforcing `file:line` — the
   resolution sequence, the catalogue lock scopes and every mutation point, the consumer-authorisation
   ordering (Surface A); the compositor-broker accept/spawn loop, the per-connection runtime dir, the
   host-Wayland leg, and the fd-relay isolation (Surface B).
2. A **live probe harness** driving the installed `kennel` CLI against the `gui-mesh` provider/consumer
   policies (`tests/policy-suite/gui-mesh`, the `compositor-broker` over the real mesh with a headless
   `facade-mesh-probe serve-display` stand-in): concurrent and cold-activation `SVC_CONNECT` storms,
   `daemon-reload` fired into in-flight connects, reap/reactivation cycles, and a host-side watcher on
   the broker's runtime root — each result tied to the daemon staying up (same `MainPID`, no panic),
   the consumers' round-trip verdicts, and direct filesystem/`kennel list` inspection.

**Verdict — safe; no confirmed finding on either residual.** Both surfaces were driven live and held.
The broker's TOCTOU windows are **availability-only** (a racing reap/reload yields `UNAVAILABLE` or a
dead-peer handle, never a mis-route to an unauthorised provider — consumer authorisation is sealed at
spawn, and resolution is name-keyed with strict key-equality from the 0.4.0 M1 fix). The GUI broker's
per-connection runtime dir is the **provider kennel's private tmpfs**, never host-visible, and each
consumer is relayed only into its own freshly-spawned compositor. The one degradation reproduced — a
shared `ondemand` provider saturating under many simultaneously-held connections — is the **bounded
0.4.0 F3** GUI-broker DoS (compositor cap + rate limit, cgroup-bounded), not a new escape.

## Surface A — connector-broker resolution race

**Map.** `svc_connect` (`kenneld::binder.rs:618`) resolves a capability through `broker::decide`
(`broker.rs:63`) while holding the catalogue mutex (`server.rs:286`, `Arc<Mutex<Catalogue>>`); the lock
is released before the handoff/connect (`binder.rs:744`–`829`). Catalogue mutations — `rebuild_catalogue`
on reload (`server.rs:339`), readiness transitions and idle-reap (`catalogue.rs:287`–`321`,
`binder.rs:415`–`510`, `supervisor.rs:241`) — take the same mutex. **Consumer authorisation is *static***:
the consumer's signed `[[consumes]]` is captured at handler setup (`binder.rs:244`) and never changes at
runtime, so the request-don't-author gate (`broker.rs:65`) has no TOCTOU. The unguarded windows are
purely *provider existence/readiness* between `decide()` (T1, locked) and `connect` (T2, unlocked):
window #1 reap-between-resolve-and-connect (`binder.rs:655`→`801`); window #3 reload-between
(`server.rs:343`→`binder.rs:801`); the cold `activate-wait` loop re-resolves every 50 ms (`binder.rs:713`)
so window #2 self-heals.

**Live probe + result.** All against the installed daemon, `MainPID` unchanged throughout, no panic /
deadlock in the journal:

| Probe | Result |
|---|---|
| 8 concurrent warm `SVC_CONNECT` | 8/8 round-trip OK |
| `daemon-reload` fired into 5 in-flight connects (window #3) | 5/5 OK — the catalogue swap mid-connect did not break a single in-flight resolution |
| cold single (`ondemand` provider released → pending → connect) | OK |
| cold 2-concurrent (released, then two simultaneous activations of the same cold provider) | 2/2 OK, distinct ctx — concurrent socket-activation does not double-spawn or deadlock |

No racing variant produced a mis-route (every consumer received its own correct round-trip), a daemon
crash, or a wedge **on a clean daemon**. The TOCTOU windows behaved exactly as the code-read predicted:
when a provider was genuinely gone the consumer's `connect` returned the correct unavailable result, not
a connection to a different provider.

**Bounded degradation (not a new finding).** An early, over-aggressive harness — consumers killed by a
client-side `timeout` while their kennel stayed **detached** (by design: a kennel outlives its CLI
client) — accumulated dozens of hung consumers each holding an open mesh connection to the *single*
shared GUI provider, which then stopped serving new consumers. This is the 0.4.0 **F3** GUI-broker DoS
(`MAX_LIVE_COMPOSITORS = 64` + token-bucket rate limit), bounded by the provider kennel's own cgroup: the
provider sheds past the cap rather than crashing, and there is no host impact or cross-grant reach. It is
remedied; the live pass confirms the bound holds (no crash, the daemon and other providers stayed up).
Re-run with one connection per consumer fully released, the same concurrency is served cleanly.

## Surface B — GUI confidentiality legs

**Map.** The `compositor-broker` (`kennel-facade/src/bin/compositor-broker.rs`) accepts on its endpoint
and, per connection, creates `RUNTIME_ROOT/{id}` = `/tmp/compositor-broker/{id}` (line 46, 146; `id` a
monotonic `u64`), spawns one nested compositor there with `XDG_RUNTIME_DIR` overridden to that dir
(line 184–191), waits for its `wayland-0`, then `splice_with_fds` relays *that one consumer* into *that
one compositor* (line 162–172). The host-Wayland leg is reached only by the nested compositor (it
inherits `WAYLAND_DISPLAY` from the GUI kennel's `[[unix.allow]]` env); the consumer holds no such grant.

**The code-read's open question** was whether `/tmp/compositor-broker` — a predictable, sequential,
shared path — is the *host* `/tmp` (a real cross-kennel surface) or the provider kennel's private tmpfs.
The live probe settles it.

**Live probe + result.**

| Probe | Result |
|---|---|
| Host-side watcher polling `/tmp/compositor-broker` for the whole run | **Never appeared on the host** — it lives in the gui-provider kennel's private `/tmp` (base-confined tmpfs), not host `/tmp`, not any consumer's `/tmp` |
| 4 concurrent consumers, observe each compositor's runtime dir | Distinct per consumer (`/tmp/compositor-broker/2,3,4,5/wayland-0`) — per-consumer isolation holds, no collision |
| Consumer policy / view — host-Wayland or `/dev/dri` reach? | None: the consumer declares only `[[consumes]] test.gui.wayland`; it has no `[[unix.allow]]` host socket and no DRI node. It sees its mesh endpoint (`/tmp/wl-in.sock` in its *own* view), never the host display socket |

**(a) Host compositor reach:** refuted. The consumer's `WAYLAND_DISPLAY` is its in-view mesh endpoint;
the host socket is connected only by the nested compositor, which the consumer cannot address.
**(b) Cross-consumer reach:** refuted. The broker spawns a fresh compositor per accepted connection and
relays each consumer into *its own*; a consumer has no path to name another's `{id}` (the predictable
`/tmp/compositor-broker/{id}` lives in the *provider's* private tmpfs, reachable only by the provider's
own trusted compositor processes — a confined consumer is a separate kennel with no entry to it).

The predictable-`id` + ignored-cleanup-error observation is therefore bounded to *within* the provider
kennel (the service's own trusted processes); it is not reachable by a confined consumer and is not a
confidentiality leak across the kennel boundary.

## Notes and accepted observations

- **Compositor trust is assumed (out of scope, as designed).** The fd-relay (`kennel-lib-scm::splice`)
  is a pure transport: if a *nested compositor* were malicious it could pass the host fd back to its
  consumer and the relay would forward it. That is the GUI-service kennel's own trusted code (`cage` in
  production), not a broker or mesh defect — the same trust the host-Wayland leg already places in it.
- **Headless stand-in.** The probe exercised the broker + mesh + isolation with `facade-mesh-probe
  serve-display`, not a real `cage`/`weston`. The confidentiality boundary tested (runtime-dir location,
  per-consumer relay isolation, host-leg unreachability) is independent of the renderer; the renderer
  itself is the trusted service.
- **Detached-kennel hygiene.** A consumer kennel outlives a `timeout`/Ctrl-C of its CLI client (correct,
  by design). The harness's initial failure to release such kennels is an operator/test footgun, not a
  daemon defect; it is what produced the transient F3 saturation above.

## Disposition

W11 (pre-ship dynamic red-team, 0.5.0 ship gate) is **complete**. The two 0.4.0 residuals — the
connector-broker resolution race and the GUI confidentiality legs — were driven by a live probe harness
against the running daemon, not a code-read alone. **No confirmed finding** on either surface; both are
bounded by controls already in place (sealed-at-spawn consumer authorisation + name-keyed strict-key
resolution for the broker race; private-tmpfs runtime dir + per-connection relay isolation for the GUI
legs). The one reproduced degradation is the already-remedied, cgroup-bounded F3. Nothing here blocks
the 0.5.0 tag.
