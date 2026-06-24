# Audit — cross-kennel surface red-team (W15, 2026-06-24)

**Scope.** The four cross-kennel surfaces the 0.4.0 mesh introduces: the connector broker (mesh
service resolution, W5), the provide-name namespace gate (reserved `org.projectkennel.*`, W1/W4),
the ungrantable host-control-socket rule (W10), and the GUI legs (nested inner compositor +
fd-brokered host leg, W7). This is the standing-service counterpart to the
[2026-06-22 dynamic-spawn red-team](2026-06-22-spawn-surface-redteam.md), which covered the
ephemeral spawn surface, not the mesh.

**Method.** Two complementary passes against the source, both externally driven (Gemini 3.1 Pro) and
then **independently re-verified here against the enforcing code** — external findings are confirmed,
not trusted: each was traced to the control it claimed to defeat (or the gap it claimed) at
`file:line` before it drove any change.

1. An adversarial **red-team** (one attacker per surface, each finding facing a refute-or-survive
   skeptic pass). The first round over-reached — it asserted an escape that verification refuted, and
   missed the runtime gate that refutes it because it had not been shown `catalogue.rs`. After a
   scoping correction it produced the tighter set recorded below.
2. An architectural **assessment** of the mesh as built, which surfaced two robustness defects (a
   routing footgun and a head-of-line stall) the adversarial pass had not — neither a breakout, both
   worth fixing.

Five confirmed findings (F1–F3 security, M1–M2 mesh-robustness), one refuted (F2), plus accepted
observations. Disposition: F1/F3 in **#120** (merged); M1/M2 in **#121**.

**Verdict — safe-with-fixes.** The strong claim — *no kennel can reach another kennel's services or
the host control surface beyond its signed grant* — **holds, with the F1 fix.** The headline
provider-spoofing concern (**F2**) is **refuted**: the maintainer-signature gate is backstopped at
runtime and holds. The one real escape was **F1** — the host control socket, ungrantable by rule on
the `[[unix.allow]]` path, was reachable on the *filesystem-grant* path; now closed at two layers.
The remaining confirmed findings are a bounded DoS (**F3**) and two mesh-robustness defects (**M1**
routing correctness, **M2** liveness), all remedied.

## Confirmed findings and remedies

| # | Sev | Finding | Remedy |
|---|---|---|---|
| F1 | HIGH | **Host control socket reachable via an `fs` grant.** The control socket (`/run/user/<uid>/kennel/control.sock`, the CLI→daemon trust boundary) is refused on the `[[unix.allow]]` path at both compile (`unix.rs:107`, `is_control_socket`) and construction (`binder.rs:825`, canonicalised). But that refusal was **absent from `fs.read`/`fs.write`**: `translate_fs` (`translate.rs:1240`) applied no such check, and the `binder.rs` backstop only guards the brokered `af_unix_connect` path — an `fs` grant is bind-mounted straight into the view by the spawn factory, never touching it. A signed policy naming the parent dir `fs.write = ["/run/user/<uid>/kennel"]` thus drags `control.sock` into the view, violating the design's stated invariant that the socket is "grantable by no policy" (`unix.rs:111`). `is_control_socket` checks the socket *leaf*; the grant names a *directory* ancestor it does not catch. (ESCAPE — invariant break; takeover contingency in Notes) | **Fixed, two layers (#120).** (1) *Primary, compile-time:* new `kennel_lib_control::socket::grant_exposes_control_socket` — an ancestor-aware form of `is_control_socket`; `translate_fs` sweeps every `fs` path through it (one pass: `read` folds in `write`, `exclusive ⊆ write`), so the policy is **refused at install** — parity with `unix.rs`. (2) *Structural backstop, at the privileged factory:* the lexical compile guard cannot see a grant written with the deferred `<uid>` placeholder, which resolves only at `substitute`, *after* the check. So the **unprivileged** daemon adds its own `socket_path()` to the view's blind-mask list (`policy.rs:loaded_from_settled`) and the **privhelper — a dumb applier, no tree-searching** — over-mounts an empty file there (`materialize_masks`, the T2.8-manifest primitive). However the tree was bound, `connect(2)` hits a plain file (`ENOTSOCK`); a no-op on the common path. |
| F3 | LOW–MED | **GUI broker unbounded DoS.** `compositor-broker.rs` spawns a thread + a nested-compositor `Child` for *every* accepted connection, with no concurrency bound *and* no rate limit. A consumer brokered to the GUI service can (a) hold many compositors open at once, or (b) spam connect/disconnect to thrash spawn/teardown — degrading the shared GUI service for co-consumers. Bounded by the GUI kennel's own cgroup (no host impact, no escape) — an in-budget availability gap. (CONTRACT-GAP) | **Fixed, both axes (#120).** A soft **concurrency cap** (`MAX_LIVE_COMPOSITORS = 64`, atomic-counter slot reservation; over the ceiling the connection is dropped, not queued) bounds simultaneous compositors; a **token-bucket rate limit** (burst 32, 8/sec sustained) on the accept loop bounds connect *churn* the cap alone would let through. Generous for real bursts; a flood is throttled, not served. |
| M1 | MED | **Key-matching asymmetry (routing footgun).** The private `key` discriminator was matched permissively — `match (c, p) { (Some(a), Some(b)) => a == b, _ => true }` — so a **keyed consumer silently matched a keyless provider**. A generic keyless provider could then swallow traffic a key was set specifically to bind (e.g. a keyed build-cache consumer routed to a generic cache left running). Not an attacker escalation — injecting an enablement symlink is out-of-scope for a confined agent (see Notes) — a routing-correctness defect that makes mesh topology unpredictable. | **Fixed (#121).** `key_compatible` is now strict equality (`consume_key == provider_key`): if either side sets a key, both must hold the identical one; keyed↔keyless is a **mismatch, not a fallback**. A *keyless* consumer still binds a keyless provider when one exists (and gets nothing from a keyed-only catalogue). The design wording "the optional key to match, if both sides set one" was the ambiguity that produced the over-permissive code; `07-13-service-catalog.md` §7.13.4 step 3 is de-ambiguated to the intended strict semantics. This is a **code-to-design fix**, not a design change. |
| M2 | LOW (liveness) | **Head-of-line blocking in `ondemand` activation.** `facade-afunix`'s accept loop called `broker()` on the **accept thread** before dispatching to a worker. When the target is an `ondemand` provider still booting, the broker transaction blocks (consume-with-wait, §7.13.4a) — stalling **every other pending connection** on that facade behind one slow boot. | **Fixed (#121).** `broker()` now runs **inside the per-connection worker**, so a slow boot delays only its own client; kenneld serves the now-concurrent `SVC_CONNECT`s on its looper pool. No new DoS surface — the worker thread was already spawned per connection for the splice. |

## Refuted findings

| # | Claimed | Why it does not hold (cited) |
|---|---|---|
| F2 | **Provider spoofing via a self-signed reserved name.** The first red-team round held that the `org.projectkennel.*` gate is compile-time only (`mesh.rs:77`) and that runtime enablement (`enablement.rs`) merely verifies a signature without asserting maintainer provenance, so a user-key-signed `org.projectkennel.wayland` symlinked into an enablement dir would load and be brokered to. | **Refuted — the runtime gate exists and is wired.** `enablement.rs:load_provider` only *loads* and captures the `signing_key_id`; the authorisation gate is downstream. (a) `Catalogue::project` (`policy.rs:256`) gates each `[[provides]]` via `catalogue.rs:provide_authorized` — a `RESERVED_PREFIX` name requires `vendor_key_ids.contains(signing_key_id)` (`catalogue.rs:48`) — and **drops** an unauthorised reserved claim. (b) Policy `load` (`policy.rs:281–298`) re-runs `first_unauthorized_provide` after `verify_settled_signed` and **rejects the whole policy** ("closing the provider-name-spoofing channel"). (c) `vendor_key_ids` is loaded from the vendor key dir and is **not host-redefinable** (`catalogue.rs:18`). A self-signed reserved provide is dropped *and* its policy refused; no consumer is ever brokered to it. Precisely the W15-scoped maintainer-gate question — it holds. |

## What held (verified controls)

Confirmed by code citation:

- **The control-socket refusal is double-gated on the `[[unix.allow]]` path** — compile-time, lexically
  normalised so a `..` disguise is caught (`unix.rs:107`), *and* construction-time against the real,
  `canonicalize`-resolved endpoint (`binder.rs:824–829`). F1 was the *missing third door* (the `fs`
  path), not a hole in this one.
- **The reserved-namespace gate is enforced twice at runtime** (drop-and-audit in `project`, hard
  refuse in `load`) over a non-host-redefinable maintainer keyset — see F2.
- **Request-don't-author floor.** A consumer reaches a capability only if its own signed `[[consumes]]`
  declares the name (`broker.rs:decide`, `NoGrant`); the workload cannot widen it at runtime. This
  bounds a prompt-injected agent: it cannot route to a local service it was not granted, even knowing
  a vulnerability in it.
- **Control/data-plane separation.** The broker routes the `SVC_CONNECT` handshake and then steps out:
  it passes connected fds and `splice_with_fds` relays bytes, so kenneld parses no Wayland/D-Bus/JSON
  payload — a malformed payload cannot reach the central daemon.
- **A consumer workload cannot inject raw binder commands via `SCM_RIGHTS`.** It connects to a plain
  `AF_UNIX` stream owned by `facade-afunix`, which relays bytes/fds to the broker-returned stream; raw
  workload bytes never reach `/dev/binderfs/binder` (`facade-afunix.rs`, `kennel-lib-scm::splice`).
- **Declaration/enablement separation** (`autorun`/`ondemand`, `enablement.rs`). A template declaring a
  `[[provides]]` sits inert until the operator links it; an AI agent's declaration does not auto-start
  a background service.

## Notes and accepted observations

- **F1 takeover contingency (now moot).** The *invariant break* was certain. End-to-end control-plane
  *takeover* additionally required the in-view `connect()` to succeed — dependent on the socket mode
  (`bind()` sets none, relying on the `0700` `/run/user/<uid>` parent, bypassed when the `kennel`
  subdir is bound directly) and the in-userns uid map vs. the dropped masked identity — and was **not
  independently reproduced**. The backstop makes it moot: the socket is a plain file in the view, with
  nothing to connect to. Fixed at the refusal, not left to the perimeter.
- **F1 residual: source-symlink aliasing.** The backstop masks the socket's canonical in-view path. A
  bind *source* that symlink-resolves the socket to a *different* in-view path would sidestep both the
  lexical compile guard and the canonical-path mask. That is the separately-tracked anchored
  bind-source `RESOLVE_NO_SYMLINKS` guard (BACKLOG); it needs an operator-placed host symlink at a
  granted path and is the general writable-bind-source concern, not specific to the control socket.
- **Accepted: tier shadowing (`Tier::User` > `Tier::Host`).** The catalogue intentionally prefers a
  per-user provider over a per-host one (`catalogue.rs`, §7.13.6) so a developer can override a
  system service with their own. A forgotten user-level enablement symlink can therefore intercept
  traffic meant for a host provider — a standard UNIX-override footgun, **not a privilege escalation**
  (a confined agent cannot create enablement symlinks; that is an operator act). Kept as designed; no
  change.
- **Surfaces not exhaustively exercised (residual).** The connector-broker *resolution race* (TOCTOU
  between `SVC_CONNECT` and the live capability map) and the GUI *confidentiality* legs (host-global
  leak through the inner compositor; one kennel reaching another's compositor) produced **no confirmed
  finding**, but were assessed by code-read, not by a live racing/probe harness. "No finding from a
  focused pass" is not "proven safe"; a dynamic pass against a running daemon + compositor remains a
  follow-up option, recorded here rather than silently closed.

## Disposition

W15 (cross-kennel red-team, 0.4.0 ship gate) is **complete**: the mesh and host-control surfaces were
red-teamed and architecturally assessed, every finding independently verified, and all five confirmed
findings remedied (F1/F3 in #120, M1/M2 in #121; F2 refuted). Two residuals are recorded above for a
later dynamic pass — neither blocks the tag.
