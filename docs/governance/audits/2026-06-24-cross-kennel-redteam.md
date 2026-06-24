# Audit — cross-kennel surface red-team (W15, 2026-06-24)

**Scope.** The four cross-kennel surfaces the 0.4.0 mesh introduces: the connector broker (mesh
service resolution, W5), the provide-name namespace gate (reserved `org.projectkennel.*`, W1/W4),
the ungrantable host-control-socket rule (W10), and the GUI legs (nested inner compositor +
fd-brokered host leg, W7). This is the standing-service counterpart to the
[2026-06-22 dynamic-spawn red-team](2026-06-22-spawn-surface-redteam.md), which covered the
ephemeral spawn surface, not the mesh.

**Method.** An external red-team (Gemini 3.1 Pro) ran one attacker per surface dimension against the
source, each finding facing a skeptic pass that could refute it only by citing a specific control
with `file:line`. Its output was then **independently re-verified here against the enforcing code** —
external findings are confirmed, not trusted: each was traced to the control it claimed to defeat (or
the gap it claimed), and two of the three were corrected on verification. 3 candidate findings →
2 confirmed (one escalation gap, one bounded DoS), 1 refuted.

**Verdict — safe-with-fixes.** The strong claim — *no kennel can reach another kennel's services or
the host control surface beyond its signed grant* — **held, with one fix.** The headline
provider-spoofing concern (F2) is **refuted**: the maintainer-signature gate the external pass
reported as "compile-time only" is in fact backstopped at runtime and holds (the external model
disclosed it had not been given `catalogue.rs`, which is where the gate lives). The one real gap was
**F1** — the host control socket, ungrantable by rule on the `[[unix.allow]]` path, was reachable on
the *filesystem-grant* path, which carried neither the compile refusal nor the construction backstop.
That is now closed. F3 (the compositor-broker's unbounded per-connection spawn) is a real but
cgroup-bounded DoS, now capped. All actionable findings are remedied in this change.

## Confirmed findings and remedies

| # | Sev | Finding | Remedy |
|---|---|---|---|
| 1 | HIGH | **Host control socket reachable via an `fs` grant.** The control socket (`/run/user/<uid>/kennel/control.sock`, the CLI→daemon trust boundary) is refused on the `[[unix.allow]]` path at both compile (`unix.rs:107`, `is_control_socket`) and construction (`binder.rs:825`, canonicalised). But that refusal is **absent from `fs.read`/`fs.write`**: `translate_fs` (`translate.rs:1240`) applies no such check, and the construction backstop in `binder.rs` only guards the brokered `af_unix_connect` path — an `fs` grant is bind-mounted straight into the view by the spawn factory, never touching it. A signed policy naming the parent dir `fs.write = ["/run/user/<uid>/kennel"]` thus drags `control.sock` into the view, violating the design's stated invariant that the socket is "grantable by no policy" (`unix.rs:111`). `is_control_socket` checks the socket *leaf*; the grant names a *directory* ancestor, which it does not catch. (ESCAPE — invariant break; see Notes on takeover contingency) | **Fixed.** New `kennel_lib_control::socket::grant_exposes_control_socket` — an ancestor-aware form of `is_control_socket` (refuses the socket or any directory that contains it, this-uid and structural-any-uid). `translate_fs` now sweeps every `fs` path through it (one pass: `read` folds in `write`, and `exclusive ⊆ write`), refusing the grant at compile — the loud primary guard, parity with `unix.rs`. |
| 3 | LOW–MED | **compositor-broker unbounded per-connection spawn.** The GUI broker's accept loop (`compositor-broker.rs`) spawns a thread + a nested-compositor `Child` for *every* accepted connection with no concurrency bound. A consumer brokered to the GUI service can spam connect/disconnect, churning thread/process creation and degrading the GUI service for co-consumers. Bounded by the GUI kennel's own cgroup (no host impact, no escape) — an in-budget availability gap, not a breakout. (CONTRACT-GAP) | **Fixed.** A soft concurrency cap (`MAX_LIVE_COMPOSITORS = 64`): the accept loop reserves a slot via an atomic counter and drops connections over the ceiling (the consumer retries) rather than spawning unboundedly; the slot is released when the window folds. |

## Refuted findings

| # | Claimed | Why it does not hold (cited) |
|---|---|---|
| 2 | **Provider spoofing via a self-signed reserved name.** The external pass held that the `org.projectkennel.*` gate is compile-time only (`mesh.rs:77`) and that runtime enablement (`enablement.rs`) merely verifies a signature without asserting maintainer provenance, so a user-key-signed `org.projectkennel.wayland` symlinked into an enablement dir would load and be brokered to. | **Refuted — the runtime gate exists and is wired.** `enablement.rs:load_provider` only *loads* and captures the `signing_key_id`; the authorisation gate is downstream, exactly where the policy-lib comment (`lib.rs:87`) says the key-id is carried *for*. (a) `Catalogue::project` (`policy.rs:256`) gates each `[[provides]]` via `catalogue.rs:provide_authorized` — a `RESERVED_PREFIX` name requires `vendor_key_ids.contains(signing_key_id)` (`catalogue.rs:48`) — and **drops** an unauthorised reserved claim. (b) Policy `load` (`policy.rs:281–298`) re-runs `first_unauthorized_provide` after `verify_settled_signed` and **rejects the whole policy** ("the runtime backstop … closing the provider-name-spoofing channel"). (c) `vendor_key_ids` is loaded from the vendor key dir and is **not host-redefinable** (`catalogue.rs:18`), so a user cannot enrol their own key as a maintainer. A self-signed reserved provide is dropped *and* its policy refused; no consumer is ever brokered to it. This is precisely the W15-scoped "does the maintainer-signature gate hold against a user-signed reserved provide" question — it does. |

## What held (verified controls)

The verification confirmed, by code citation, that these hold:

- **The control-socket refusal is double-gated on the `[[unix.allow]]` path** — compile-time, lexically
  normalised so a `..` disguise is caught (`unix.rs:107`), *and* construction-time against the real,
  `canonicalize`-resolved endpoint (`binder.rs:824–829`). F1 was the *missing third door* (the `fs`
  path), not a hole in this one.
- **The reserved-namespace gate is enforced twice at runtime** (drop-and-audit in `project`, hard
  refuse in `load`) over a non-host-redefinable maintainer keyset — see F2 above.
- **A consumer workload cannot inject raw binder commands via `SCM_RIGHTS`.** The workload connects to
  a plain `AF_UNIX` stream owned by `facade-afunix`, which relays bytes/fds to the broker-returned
  stream; raw workload bytes never reach `/dev/binderfs/binder` (`facade-afunix.rs`,
  `kennel-lib-scm::splice`). (Confirmed by the external skeptic pass; re-checked here.)

## Notes

- **F1 takeover contingency (stated honestly).** The *invariant break* is certain: a signed policy can
  bind the control-socket directory into a view, which the design says no policy may express. Whether
  that reaches end-to-end control-plane *takeover* additionally requires the in-view `connect()` to
  succeed, which depends on the socket mode (`bind()` sets none explicitly, relying on the `0700`
  `/run/user/<uid>` parent — bypassed when the `kennel` subdir is bound directly) and the kennel's
  in-userns uid mapping vs. the dropped masked identity. That end-to-end step was **not independently
  reproduced** in this pass. The fix restores the structural invariant regardless, so the question is
  moot — which is why it is fixed at the refusal, not left to the perimeter.
- **F1 symlink-source residual.** The compile guard is lexical; a bind *source* that symlink-resolves
  to the control dir at construction is the separately-tracked deferred work (the anchored
  bind-source `RESOLVE_NO_SYMLINKS` guard, BACKLOG) — which, when landed, covers the control socket
  for free. No new half-measure was added here to avoid a `kennel-lib-control` dependency in the
  spawn crate (which deliberately carries none).
- **Surfaces not exhaustively exercised.** The connector-broker *resolution race* (TOCTOU between
  `SVC_CONNECT` and the live capability map) and the GUI *confidentiality* legs (host-global leak
  through the inner compositor; one kennel reaching another's compositor) produced **no confirmed
  finding**, but were assessed by code-read, not by a live racing/probe harness. "No finding from a
  focused pass" is not "proven safe"; a dynamic pass against a running daemon + compositor remains an
  option before or shortly after the tag.
