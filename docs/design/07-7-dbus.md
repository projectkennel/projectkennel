# §7.7 Policy surface: D-Bus (mediated via the IDBus facade)

> **D-Bus is mediated through the binder gateway, never granted as a direct socket.** The
> mechanism is the `org.projectkennel.IDBus/default` facade (§7.1.5),
> built to the same convert/act spine as the SOCKS5 egress path (§7.5): an in-kennel facade
> parses the adversarial D-Bus wire and emits a *typed* method-call message; an
> operator-context delegate filters it through the table kenneld compiled from `[dbus]`,
> reconstructs a well-formed call, and sends it to the real bus. kenneld builds the two
> processes and the conduit between them at construction and is out of the per-message path
> (§7.7.2a). There is no external dependency, no bus-socket artefact in the kennel's view, and
> call-level audit. The structured `[dbus]` policy in §7.7.6 is the rule source.

D-Bus is the largest single capability surface on a typical Linux desktop. This chapter is
why a direct grant is categorically wrong (§7.7.1), the mediation architecture that replaces
it (§7.7.2–§7.7.5), and the policy surface that drives it (§7.7.6 onward).

## 7.7.1 Why direct D-Bus access is categorically wrong

A bare socket grant for `$XDG_RUNTIME_DIR/bus` gives the kennel every service the user's
session offers. A default session bus has dozens connected — the notification daemon, network
manager, the shell (gnome-shell/kwin), the file manager, screen lock, login manager, systemd
user, the secret service, packagekit, polkit. Through them a kennel can:

- Read or write files via file-manager method calls.
- **Spawn processes** via `org.freedesktop.systemd1.Manager.StartTransientUnit` — an
  unconfined process in the user's session, escaping the kennel entirely.
- Inhibit screen lock, trigger logout, or reconfigure the session.
- Send notifications that appear to come from any application (phishing the operator).
- **Read stored credentials** via `org.freedesktop.secrets` (gnome-keyring / KWallet).
- Mount filesystems via `org.freedesktop.UDisks2`, or reconfigure DNS/wifi via NetworkManager.

A kennel with the bus socket has essentially the capability of the unconfined session, by
asking the session to act on its behalf. Direct grants are never offered.

## 7.7.2 The mediation architecture: facade · filter · delegate

D-Bus rides the kennel's single auditable inter-namespace chokepoint — the binder gateway
(§7.1) — and it rides it **per message**. This is the defining difference from the INet egress
(§7.5), and it dictates the transport. INet makes one *connect-time* decision and then hands the
kennel an already-established socket to stream over: a single fd, no further mediation, because
the security decision was the connect. D-Bus has a security decision on **every message**, so the
channel never becomes a post-decision stream — it stays security-relevant for its whole life.
A raw conduit fd is therefore exactly wrong here: handing the kennel a direct fd to the trusted,
operator-context delegate would expose the entire `host-dbus` process to whatever holds the other
end — the facade, or malware in the kennel pretending to be it.

So every D-Bus message is transacted across the binder gateway to node 0, and **kenneld relays it
to the delegate doing as little as possible**. kenneld neither parses the frame (so the D-Bus
engine never enters the daemon TCB) nor filters it (that is the delegate's mechanical job,
§7.7.2a) — but it *is* the membrane: the kennel reaches `host-dbus` only through kenneld, over the
enforced binder hop, with kenneld binding each connection to the in-kennel consumer that opened it
(§7.7.2a, per-connection ownership). The adversarial-wire parser runs in the kennel; the bus
connection and the mechanical filter run in the operator-context delegate; kenneld is the cheap,
owner-checked relay between them.

```
  kennel (own user+net ns)          │  kenneld (the membrane)   │  operator context (host)
                                    │                           │
  workload ─D-Bus wire─▶ facade-dbus ─binder txn (node 0)─▶ relay ─owner-only pipe─▶ host-dbus ─▶ real
    (libdbus/sd-bus)       ▲    parse→typed frame │  · no parse, no filter   │  · filter (table)   bus
                           │                      │  · binds each conn to    │  · reconstruct+send
  workload ◀─reply/signal◀─┘◀─binder reply / DBUS_RECV◀─  its in-kennel opener◀─┴──◀ reply (by serial) /
                                    │              · shovels frame bytes      │     match-rule'd signal
                                    │                by connection id         │
   kenneld: spawns facade-dbus + host-dbus, compiles [dbus] → the filter table it hands the
            delegate, and per message is the minimal-work relay — NOT cut out of the path.
```

- **`facade-dbus` (in-kennel, untrusted side).** The **sole parser of adversarial D-Bus
  wire.** It terminates the workload's bus connection (the kennel's `DBUS_SESSION_BUS_ADDRESS`
  points at it), parses each method call, and emits a **typed** `IDBus` transaction carrying
  the vetted-able fields: `{bus, destination, object_path, interface, member, signature,
  serial, body}`. It holds no authority and speaks only for the workload, so its compromise
  buys the workload nothing it could not already attempt — the §4.8 quarantine: the
  hostile-protocol parser sits on the untrusted side of the boundary.
- **The mechanical filter — the compiled `[dbus]` match table + the refuse-to-broker set
  (§7.7.5).** A typed transaction is matched against the table at destination/path/interface/
  member granularity; never against D-Bus wire. **kenneld compiles the policy; the delegate
  applies it.** The single policy *source* is the settled artefact (the compiler turns
  `[dbus]` into the match table at construction, as it already turns every other section into
  runtime form); the delegate is a mechanical enforcer of that table, not a second author of
  policy — the same way `host-netproxy` dials a kenneld-pinned address rather than deciding the
  address itself. This is why the filter runs in the delegate and not kenneld (§7.7.2a).
- **`host-dbus` delegate (operator context).** Joins `host-netproxy`/`host-inetd` as a third
  host-side delegate, run unprivileged in the operator's own context (it reaches exactly the
  operator's own buses, no more). It is reachable **only from kenneld**, over an owner-only pipe —
  never directly from the kennel. It holds the connections to the real session and system buses,
  **filters** each typed transaction kenneld relays to it through the compiled table kenneld
  handed it at spawn, and on a pass **reconstructs** a well-formed D-Bus message from the vetted
  typed fields and sends it. It never re-parses the kennel's adversarial bytes — it reads only the
  typed fields the facade produced. Its concurrency model is §7.7.2b.

### 7.7.2a kenneld relays per message but neither parses nor filters

Two separable questions — *what mediates the transport* and *what applies the filter* — and the
answer to the first is **kenneld**, to the second the **delegate**. Conflating them is what
produced the earlier (wrong) idea that kenneld could be cut out of the per-message path with a
raw socketpair.

**kenneld is the membrane (transport).** The kennel reaches the trusted `host-dbus` process only
by transacting node 0; kenneld relays each message to the delegate over an owner-only pipe and
the reply back. Because it is the only path, the binder gateway enforces the one hop the kennel
controls — bounded transaction size, the fuzzed decoder, no fd injection, and **per-connection
ownership** kenneld enforces. There is no daemon-wide "the facade" identity to check: a binder pid
cannot prove a caller *is* the wire-terminating facade, and `facade-dbus` is restartable (a crash
re-forks it under a fresh pid), so a fixed pid gate would be both unprovable and brittle. What
kenneld *can* enforce, and does, is narrower and real: `DBUS_OPEN` records the kernel-attested
opener pid as the connection's owner, and a later `DBUS_SEND`/`DBUS_RECV`/`DBUS_CLOSE` from a
different pid is refused — so one in-kennel consumer cannot hijack, drain, or tear down another's
bus connection by guessing its `conn_id`. (Any in-kennel process may still open its *own*
connection; the delegate's allowlist, not caller identity, bounds what a connection can do.) A raw
conduit fd would throw all of that away and expose the delegate to whatever in the kennel holds the
fd — the exposure a per-message security boundary cannot accept.

**kenneld does as little as possible.** Per message it routes opaque frame bytes by connection id
and shovels the reply back. It does **not** parse the frame — so `kennel-lib-dbus`/the D-Bus
marshaller never enter the daemon TCB ([[tcb-only-shrinks]]); `cargo tree -p kenneld` stays clean
of them — and it does **not** apply the allowlist. That is why it can sit in the path cheaply:
the expensive, chatty work (parsing adversarial wire, matching the per-method table, the bus
round-trip) is exactly what is kept *off* kenneld's synchronous loop. This is the sense in which
kenneld was "designed to do as little as possible passing on the messages" — minimal-work relay,
not absentee.

**The filter runs in the delegate.** The per-method check is a mechanical match-table application
(not policy authorship), it scales on the delegate's own threads (§7.7.2b), and it runs at
operator authority outside the daemon TCB — the same division as every host delegate, which acts
on a kenneld-pinned decision rather than re-deciding. *(This refines the `07-1-binder.md`
framing, which put the check in kenneld; the filter locus is the delegate, the transport locus is
kenneld.)*

### 7.7.2b The delegate's concurrency model

`host-dbus` is sized for per-message mediation without a single serial bottleneck — no async
runtime, real threads, the same sync bar as kenneld and `host-netproxy`:

- **Outbound — the typed messages kenneld relays in.** Each is run through the compiled filter
  (§7.7.2a). A message that passes is reconstructed and sent to the bus; a message that fails is
  refused — an `AccessDenied` frame returned to kenneld (and on to the facade) without ever
  touching the bus. Mediation never blocks on the bus, so a slow or hung host service cannot
  stall mediation of other calls. *(The as-built delegate realises this on a single-threaded
  `poll(2)` event loop over the kenneld pipe and the bus fd; the thread-pool sketch here is the
  throughput target for a very chatty bus, not a correctness requirement.)*
- **Per-request worker (ephemeral).** Owns one host-bus round-trip: it reconstructs the
  well-formed message, assigns it a delegate-side serial (the kennel's serials and the bus's
  serials are different namespaces — the worker records `kennel_serial ↔ bus_serial` so the
  reply can be matched back), sends it on the shared bus connection, and parks awaiting its
  reply. The worker count is bounded by the kennel cgroup (`pids.max`); a flood of calls
  applies back-pressure on the outbound pool rather than unbounded thread growth.
- **Inbound — reading the host bus connection and demultiplexing.** A **reply** is matched by
  `reply_serial` to its recorded `kennel_serial` and returned to kenneld, which routes it to the
  facade (as the reply to the originating `DBUS_SEND`); a **signal/broadcast** is run through the
  compiled match-rule filter (§7.7.4) and, on a pass, pushed to kenneld, which delivers it to the
  facade's outstanding `DBUS_RECV`. A message matching no live request and no rule is dropped.

Two consequences worth stating: independent calls fan out to separate workers, so the bus may
see a single client's distinct calls **out of order** — acceptable because D-Bus gives no
cross-call ordering guarantee for distinct method calls, but noted; and the serial-mapping
table is the one piece of per-connection state the delegate keeps, torn down with the kennel.

The rest of this chapter is written to the delegate locus.

Routing D-Bus through the binder gateway gives the kennel no bus-socket artefact in its view
(a misconfigured grant cannot leave a live socket behind), no external dependency, and per-call
audit on the same path as every other binder transaction.

**The cost (§4.8).** D-Bus mediation is **per message** — the security property *is* the
per-method allowlist, so something trusted must see every call (unlike `INet`, which mediates the
connection once and then hands off an fd to stream over). Two trusted things see each call, by
design: kenneld **relays** it (cheaply — route bytes, owner-check the connection, no parse, no
filter) and the operator-context `host-dbus` **filters** it (§7.7.2a). No raw bus fd, and no raw
conduit fd, is ever vended to the kennel — the kennel's only D-Bus channel is binder transactions
to node 0. The expensive per-message work (parse, allowlist, bus round-trip) lands on the facade
and the delegate, bounded by the kennel cgroup (`pids.max`/`memory.max`) and the rate limiter
(§7.7.2c); kenneld's added cost is the minimal relay, which is why it can be on the path. D-Bus is
chatty; this is the price of method-level mediation, paid mostly outside the TCB.

### 7.7.2c Bounding the conduit: framing and rate

Riding binder rather than a raw fd is what *lets* the gateway bound the per-message channel; the
bounds themselves are explicit, because the conduit carries security-relevant message units, not
an opaque stream:

- **Size.** The typed transaction is a flat, length-prefixed TLV (tag · length · fields), each
  field bounded; an over-long length is a decode error, never an allocation. The decoder is
  fuzzed (CODING-STANDARDS §10.6) — and because kenneld frames and relays these, the TLV codec
  lives in a crate kenneld already links (`kennel-lib-binder`, the node-0 service wire), **not**
  in the D-Bus engine crate that pulls the marshaller. kenneld gets framing without mini-sansio
  entering the TCB.
- **Rate.** A token-bucket filter caps the message rate a kennel can push. It is enforced at the
  membrane — kenneld sheds a flood at the gateway before it reaches `host-dbus` at all — and
  again at the delegate (defence in depth). The bucket (sustained rate + burst) lives beside the
  TLV codec in `kennel-lib-binder`, so kenneld owns the cap without the engine. A kennel over its
  rate gets `org.freedesktop.DBus.Error.LimitsExceeded` back, a clean failure rather than a hang.

These replace, explicitly, the implicit bounds binder transactions would have given a direct
node-to-node path (kernel transaction size limit, buffer back-pressure) — here re-derived in our
own wire because the relay hop to the host delegate is a pipe, not a binder node.

## 7.7.3 Message-level mediation, not byte filtering

The decision is made on **parsed protocol fields**, never by stripping bytes from a stream.
This is the opposite of the PTY escape filter (§7.9.5), which pattern-strips a byte stream
without understanding a protocol — that model is wrong for D-Bus and is not used here. The
facade fully parses the D-Bus message into typed fields; the decision point matches
`destination`/`object_path`/`interface`/`member` against the allowlist; the delegate emits a
fresh, well-formed message. At no point does trusted code interpret adversarial bytes: the
facade that parses the hostile wire is on the untrusted side, and the delegate that builds the
outbound message reads only the vetted typed fields. "TCB growth is a decision point, not a
parser" holds because the adversarial-wire parser is quarantined in the facade — and under the
delegate locus the decision point is not in the TCB at all.

## 7.7.4 Outbound and inbound are different paths

Outbound (kennel → bus) and inbound (bus → kennel) are **not symmetric**, and conflating them
into one "bidirectional filter" would smuggle an adversarial-wire parser into the trusted host
delegate. They are designed separately:

- **Outbound — method calls.** Adversarial. Parsed by `facade-dbus` in the kennel, typed
  across the conduit, decided and reconstructed by `host-dbus`. This is the path §7.7.2
  describes.
- **Inbound — replies.** A reply to an approved call is **trusted-origin** (it comes from the
  operator's own bus / a host service the call was allowed to reach). The delegate reads it and
  returns it over the conduit as the call's reply; the facade hands the body to the workload as
  data. The workload must treat a reply body as untrusted *input* (as it must any input), but
  no Project Kennel trusted component is parsing kennel-controlled bytes to produce it.
- **Inbound — signals.** Signals are broadcast by host services and delivered only under a
  **match-rule allowlist**: the kennel receives a signal only if its sending service is on the
  `talk` list (or explicitly `broadcast`-listed) *and* the kennel has registered a matching
  subscription. The delegate holds the kennel's match rules and filters the host bus's signal
  stream down to that set before forwarding; the facade re-emits them to the workload. A signal from a service the kennel may not talk to is never delivered — this is
  what stops a kennel from passively monitoring the session (e.g. watching `NameOwnerChanged`
  to fingerprint what the operator runs).
- **Inbound — calls to an owned name.** A kennel that `own`s a name (rare; almost always
  empty) is addressable on the bus, so other session peers can call it. Such an inbound call's
  body is trusted-origin (a host session peer), delivered through the facade to the workload as
  input. Name ownership is `RequestName`'d by the delegate on the kennel's behalf only for
  names in the `own` list.

The asymmetry is the airtight statement of "no parser of kennel-controlled bytes in a trusted
component": the only adversarial-input parser is the outbound in-kennel facade.

## 7.7.5 The refuse-to-broker set

Some bus services cannot be safely brokered to untrusted code at all — not "default-deny but
grantable as a footgun," but **refused by the facade regardless of policy**, named explicitly,
the way the SSH bastion refuses to be a signing oracle (§7.10) and §11.2 refuses to let the
workload attest as the operator. A policy that names one of these in an `allow` list is a
**compile error**, not a warning: brokering them is not a footgun the operator chooses for
their own workload *within* the threat model — it defeats the monitor's reason to exist.

The set:

- **`org.freedesktop.secrets`** (Secret Service: gnome-keyring / KWallet). A
  read-the-operator's-stored-credentials oracle. Brokering it re-introduces exactly the
  ambient-credential surface the constructed `$HOME` (T1.1) removes — handing the workload the
  operator's saved passwords and tokens. This is the read-side analogue of the §11.2 signing
  axiom: a capability that cannot be delegated to code the kennel exists to contain.
- **Session / process control** — `org.freedesktop.systemd1` (`Manager.StartTransientUnit`
  and friends: spawn an **unconfined** process in the user's session, the cleanest possible
  kennel escape), `org.freedesktop.login1` (logout / reboot / lock / power), and the desktop
  session managers (`org.gnome.SessionManager`, `org.kde.*` equivalents). Brokering any of
  these lets the workload ask the session to run code or control the session — a model-defeat,
  not an in-model footgun.

**Refuse-to-broker vs default-deny — and the footgun principle.** Everything not on an
`allow` list is already *default-denied*; that baseline is overridable in a user delta with a
loud warning + threat tag ([[footgun-warn-dont-forbid]]) for services that are dangerous but
conceivably legitimate (a `NetworkManager` connectivity query, a `UDisks2` mount for a media
kennel). The refuse-to-broker set is the **narrow axiom carve-out above that**: like the
signing oracle, allowing it would be security theatre — claiming confinement while handing
over the credentials or a spawn escape — so the framework refuses rather than warns. The set
is deliberately small and named; it is not a denylist to be grown casually.

## 7.7.6 Policy primitives

The `[dbus]` section is re-introduced to the policy schema (it was removed in 0.1) as the
rule source. The operator writes structured policy; kenneld compiles it to the per-method
match table the `host-dbus` filter enforces (§7.7.2b) — the operator never writes proxy flags
or match-rule strings.

```toml
[dbus]
session.enabled = true              # default false: no session bus, no facade node
system.enabled  = false             # default false: system bus rarely needed

[dbus.session.allow]
# Destinations the kennel may TALK to (call methods on, receive replies + their signals).
talk = [
    "org.freedesktop.Notifications",
    "org.freedesktop.portal.*",     # the portal family (file picker, screenshot, …)
]
# Finer than `talk`: specific destination=interface.member calls (when `talk` is too broad).
call = []
# Signals the kennel may receive (subset of senders it may `talk` to; match-rule allowlist).
broadcast = []
# Names the kennel may OWN (be addressable as). Almost always empty for a kennel.
own = []

[dbus.session.deny]
# Belt-and-braces explicit denies (the lists above are already allowlists; this guards
# against an accidental widening in a user delta). The refuse-to-broker set (§7.7.5) is
# enforced regardless and need not be listed.
talk = ["org.freedesktop.UDisks2", "org.freedesktop.NetworkManager"]

[dbus.system.allow]
talk = []                           # default: nothing on the system bus

[dbus.audit]
level = "summary"                   # "off" | "summary" | "full"; path is the §8.6 audit sink
```

Resolution and folding follow the other list-valued sections (§5): `talk`/`call`/`broadcast`/
`own`/`deny` take `[[dbus.session.allow.talk.add]]`-style leaf deltas, each requiring a
`reason`. Naming a refuse-to-broker destination (§7.7.5) anywhere in an `allow` list fails
compilation with the named reason. A kennel with no `[dbus]` section gets no
`org.projectkennel.IDBus/default` node at all — `getService` for it returns
`BR_FAILED_REPLY`, and a client's bus connection fails at the facade (the standard "cannot
connect to bus" error), so absence is the secure default by construction.

## 7.7.7 The portal pattern

`org.freedesktop.portal.*` deserves special attention: it is the *intended* path for sandboxed
applications to reach user resources (files, screenshots, camera) through **user-mediated**
dialogs. A portal call pops a dialog the operator sees and approves, and returns only the
chosen result — meaningfully different from granting the underlying resource. A kennel that
needs a file-open dialog should `talk` to the portal family rather than be granted the
filesystem. Caveats: portal coverage varies by desktop (GNOME/KDE/others); portal access from
non-Flatpak kennels is supported but less battle-tested; and the portal lives on the session
bus, so `session.enabled = true` is the prerequisite — this is the smallest legitimate D-Bus
grant. A portal-only kennel is approximately the Flatpak default and a reasonable starting
point.

## 7.7.8 Notifications: a worked case

Showing desktop notifications (build complete, agent finished) is one of the simplest
legitimate grants:

```toml
[dbus]
session.enabled = true
[dbus.session.allow]
talk = ["org.freedesktop.Notifications"]
```

The facade forwards `Notify()` calls and their replies, and delivers `NotificationClosed` /
`ActionInvoked` signals **only for this kennel's own notifications** (the match-rule allowlist,
§7.7.4); other services and other applications' signals are not delivered. The capability
granted is "pop a notification"; nothing else on the bus.

**The action footgun.** A notification may declare *actions* the daemon runs on the operator's
click ("open file", "reply"). The click triggers them in the operator's session, not the
kennel — a path by which a kennel could phish the operator into running something (an action
labelled "Click to fix" that opens a hostile URL). This is inherent to a user-facing
notification capability, not a flaw in the mediation; templates granting Notifications carry
the threat tag and the operator-facing caution.

## 7.7.9 Template defaults

Most confined templates set `session.enabled = false` — no bus, no facade node, connection
attempts fail at the facade. Templates that need notifications enable the session bus and
allow only `org.freedesktop.Notifications`; templates that need file dialogs or screenshots
allow only `org.freedesktop.portal.*`. A template that wants broad desktop integration (rare
for a kennel) must document loudly that it approximates the unconfined session capability and
that the threat model is correspondingly weakened. No template grants the refuse-to-broker set
(§7.7.5) — it cannot.

## 7.7.10 Operational concerns and failure modes

The facade and delegate share the kennel's lifecycle: kenneld spawns `facade-dbus` (in the
view) and `host-dbus` (operator context) before the workload starts and tears them down when
it exits — no accumulating daemons, no per-kennel resident process beyond the kennel's own.

| Situation | Behaviour |
|---|---|
| `facade-dbus` crashes | The kennel's bus connection drops; clients see connection errors. kenneld restarts it (best-effort) or the kennel's bus stays down — the kennel never gains *unmediated* access as a result. |
| Host bus restarts | `host-dbus` reconnects with backoff; the kennel's connection (terminated at the facade) survives the host bus restart. |
| Policy denies a call | the delegate's filter refuses it before it reaches the bus; the facade returns `org.freedesktop.DBus.Error.AccessDenied` to the client; the deny is audited. |
| A refuse-to-broker destination is reached at runtime | Cannot occur via policy (compile error, §7.7.5); a hard-coded facade refusal is the backstop. |
| Kennel `RequestName`s a name not in `own` | The delegate refuses; `RequestName` returns `NOT_ALLOWED`. |
| `session.enabled = false`, client connects | No facade node; connection fails with the standard "cannot connect to bus". |
| Activation service in an allowed `talk` set | the filter permits `org.freedesktop.DBus.StartServiceByName` for allowed destinations, so on-demand services autolaunch through the delegate. |

Audit volume: D-Bus is chatty (dozens of calls/minute even idle). `summary` logs
first-and-last-of-kind per `destination.member`; `full` logs every call; default `summary`.

## 7.7.11 Test plan

A `tests/policy-suite/dbus-*` case proves each invariant against the real `kennel run` path
(the policy-suite is the e2e, [[policy-test-suite-is-the-e2e]]); the facade's wire parser
carries a fuzz target (CODING-STANDARDS §10.6, untrusted-input parser):

1. `session.enabled = false`: a bus connection fails ("cannot connect to bus").
2. Notifications allowed: `notify-send` succeeds; a call to `org.gnome.SessionManager` is a
   **compile error** (refuse-to-broker), and a call to `org.freedesktop.UDisks2` (default-deny)
   returns `AccessDenied` at runtime.
3. `org.freedesktop.secrets` named in `allow`: **compile error**, naming the credential-oracle
   reason.
4. Portal allowed: a portal call returns via the delegate; a `secrets` call is refused.
5. A signal from a non-`talk` service is **not** delivered to the kennel; a signal for the
   kennel's own notification **is**.
6. Audit records denied calls with full `destination.member` + timestamp.
7. `host-dbus` survives a host dbus-daemon restart (kennel's bus stalls then recovers).
8. `RequestName` for a name not in `own` returns `NOT_ALLOWED`.
9. The facade fuzz target survives the no-panic corpus over malformed D-Bus messages.
