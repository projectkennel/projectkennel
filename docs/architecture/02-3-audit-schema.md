# API surfaces — audit schema

> **Scope.** The audit *event schema* below is the durable contract. The
> multi-sink delivery layer is **built**: the `kennel-lib-audit` writer fans one
> sanitised event out to the `file`, `stdout`, `syslog`, and (feature
> `audit-journald`) `journald` sinks, applying the per-class levels; the `[audit]`
> policy section is parsed, validated, and carried in the signed settled policy as
> `AuditRuntime`; kenneld builds the writer from it and emits the `lifecycle.*`
> events; a bounded per-sink worker queue caps a stuck sink's effect on the writer;
> and the journald sink stamps `MESSAGE_ID`. The installation-wide `audit.toml`
> remains roadmap (`08-as-built-notes.md` §8.1).
>
> **Scope: the writer unifies every source kenneld can reach in userspace —
> including the BPF ring buffer.** Two cases differ:
>
> - The cgroup **BPF programs** emit to **our own** `audit_ringbuf` (a
>   `BPF_MAP_TYPE_RINGBUF`, `bpf/audit_events.h`/`bpf/kennel.bpf.h`) — **not** to
>   `dmesg` or the kernel audit subsystem. **kenneld drains the ring buffer**
>   (`kenneld::bpf_audit`), attributes each event to its kennel by `ctx_byte`,
>   carries `comm` as untrusted (writer-sanitised), and emits canonical events
>   **through this writer** with `source: bpf` (so a `net.bind-deny` lands in the
>   same JSONL/syslog/journald sinks as a userspace event). The privhelper pins the
>   per-kennel ring buffer in the owner's `/run/user/<uid>/kennel/bpf/<id>/`; the unprivileged kenneld
>   reopens it with `BPF_OBJ_GET`, so the drain adds no privilege.
> - **LSM denials** (Landlock/AppArmor) *are* the kernel's to log — they surface
>   through the kernel's own channels (`dmesg`/auditd), not our ring buffer, so they
>   are genuinely out of this writer's scope.
>
> The userspace sources that route through the writer today: kenneld's lifecycle
> events, the egress proxy's per-request `net.egress` events
> (`host-netproxy::audit::Record::to_event`, written to
> `~/.local/state/kennel/<kennel>/network.jsonl` plus any other configured sink), and
> the privhelper's `priv.*` events (kenneld records them on the helper's behalf).
> kenneld shares one `kennel_uuid` with the proxy per run, so their events correlate.

## Stability commitment

**Stable** per `02-0-overview.md`. The audit *event schema* is versioned by an explicit `schema_version` field present on every event regardless of which sink emits it. Consumers read the field and decide how to handle it.

The project's commitments:

- A `schema_version` value is stable for the lifetime of the major version that introduced it. New fields may be added; existing fields do not change name or type within a `schema_version`.
- When `schema_version` is bumped, the project emits both the old and the new version in parallel for at least one full minor release.
- Within a `schema_version`, the *set* of event types may grow additively.

`schema_version` is a small integer, currently `1`.

The schema is independent of how the events are transported. The same event landing in a JSONL file, in systemd-journald, in syslog, and on a kennel daemon's stdout carries the same `schema_version` and the same logical fields. Sink mappings are documented per sink below.

---

## Audit events as an abstract stream

The Project Kennel audit log is conceptually a *stream* of structured events. Each event is the canonical structure described in §Common envelope and §Event types below. The stream has several *sinks* — concrete transports that carry events to a consumer. Sink choice is an operator decision; the event schema is invariant across sinks.

Sources of events (where they originate before being passed to the sinks):

- **Kernel** via Landlock and AppArmor LSM hooks (filesystem denials, ptrace denials).
- **cgroup BPF programs.** Network connect/bind/sock-create denials, allow events under summary or full level. Programs write to *our* `audit_ringbuf`; the audit reader in kenneld (`kenneld::bpf_audit`) drains it and translates each event to a canonical `net.*` event through the unified writer with `source: bpf` (`02-7-bpf-abi.md` §The audit ring buffer).
- **The netproxy.** SOCKS5-level allow/deny, DNS resolution, byte counters.
- **xdg-dbus-proxy.** D-Bus method allow/deny.
- **kennel-privhelper.** Privileged-operation invocations and refusals.
- **The spawn wrapper (kennel-lib-spawn).** Lifecycle events for the workload (start, exit, signal).
- **kenneld.** Daemon lifecycle, policy load, kennel registration, and — as binder node 0 — every binder registry verb (`binder.register`/`lookup`) and the `kennel-bin-init`↔node-0 lifecycle verbs (`lifecycle.plan-pull`/`boot-sync`/`facade-crash`/`workload-exec`).

In the roadmap delivery model, a centralised audit-event writer (`kennel-lib-audit`) is the seam between these sources and the sinks: sources emit `AuditEvent` values and the writer fans them out to every configured sink. Today each source owns its own sink directly — the netproxy formats its JSONL records and kenneld owns the per-kennel file.

---

## Sinks

A *sink* is an output target for the canonical event stream. The configured sink set is per-installation, set in `/etc/kennel/audit.toml`; an operator may override on a per-kennel basis via the policy's `[audit].sinks` field.

The supported sinks:

| Sink | Default | Use when |
|---|---|---|
| `file` (JSONL) | Yes | The system has no systemd-journald, or the operator wants file-based shipping (logrotate, Fluentd tailing, etc.). The default; works everywhere. |
| `journald` | No | The system runs systemd-journald (either system or user journal). Native query via `journalctl`. The recommended sink for SIEM integration on systemd hosts. |
| `syslog` | No | The system runs an RFC 5424 syslog daemon (rsyslog, syslog-ng) and journald is not in use. |
| `stdout` | No | Container deployments where logs are captured from the kenneld process's stdout by an orchestrator. |

Multiple sinks may be active concurrently — for example, `file` + `journald` during a migration period — and the same event is emitted to each. The sink fan-out keeps a slow sink from stalling the writer: each sink is wrapped in a bounded per-sink worker queue (`TimeoutSink`, default capacity 1024 events) whose worker thread performs the possibly-blocking I/O. The writer's hand-off to a sink is a non-blocking channel send; if a sink's worker falls behind and its queue fills, further events for that sink are dropped (the back-pressure equivalent of a per-emit timeout) and the writer reports the drop to the other sinks.

A sink that fails to emit an event raises an internal error which is itself recorded — in the other sinks. A configuration where the only sink fails is a hard error: events are dropped and kenneld logs a self-diagnostic via stderr; the operator is expected to notice.

The configuration schema for sinks lives in the policy's `[audit]` section; see `02-2-config-schema.md` for the schema and §Sink configuration below for the details.

---

## Common envelope

Every event, regardless of sink, carries the following fields. Field names below are the *canonical* names; sink-specific representations rename or restructure but preserve semantics.

| Field | Type | Notes |
|---|---|---|
| `schema_version` | integer | `1` currently. |
| `ts` | timestamp | RFC 3339, UTC, microsecond precision. |
| `kennel` | string | Kennel name. Stable across kennel restarts. |
| `kennel_uuid` | UUID v7 | Kennel-instance UUID; changes per kennel start; groups events from one lifetime. |
| `event` | string | Event-type identifier (e.g. `net.connect-deny`). |
| `resource` | string | Event class: `net`, `fs`, `exec`, `unix`, `dbus`, `binder`, `priv`, `lifecycle`. |
| `outcome` | string | `allow`, `deny`, `info`, `error`. |
| `source` | string | Originator: `kernel`, `bpf`, `proxy`, `dbus-proxy`, `kennel-lib-spawn`, `kenneld`, `privhelper`. |
| `host` | string | Hostname at event time. |
| `pid` | integer | Workload PID at event time (absent for events not tied to a workload PID, e.g., daemon-lifecycle). |
| `comm` | string | `task->comm`, up to 16 bytes; sanitised. |

Event-specific fields extend the envelope; see §Event types.

---

## Event types

The catalogue below names every event in the schema. Field lists are non-exhaustive — each sink representation in the sink sections describes the full field mapping for that sink.

As-built: the events emitted through the writer today are the **lifecycle** events (kenneld, including the binder lifecycle verbs `lifecycle.plan-pull`/`boot-sync`/`facade-crash`/`workload-exec`), the **`net.connect-*`**/**`net.bind-*`** events (the cgroup BPF programs, drained from the `audit_ringbuf` by `kenneld::bpf_audit` with `source: bpf`), the per-request **`net.egress`** events (the per-kennel netproxy), the **`binder.register`**/**`binder.lookup`** registry events (kenneld as node 0), and the **`priv.*`** events (the privhelper). The **`exec.*`**, **`unix.*`**, **`dbus.*`**, and **`fs.scrub-hit`** events are defined here but only emitted once their subsystems are built (exec-allowlist auditing, the AF_UNIX shim's connect log, the D-Bus proxy, and `fs.scrub` respectively). The bare **`net.bind`**/**`net.bpf.deny`** (the *extended* `[net.bpf]` socket-shaping + dynamic mirror-report, `02-7`), the **`binder.cross`** cross-instance relay, and **`kennel.spawn`** events are roadmap (the extended socket-shaping, the inter-kennel relay, and `SpawnKennel` are unbuilt). All are part of the stable schema so sinks and tooling can be written against them ahead of the producers.

### Network (`resource: "net"`)

The connect/bind events below are *BPF-sourced*: the cgroup programs emit them into
**our** `audit_ringbuf` (not `dmesg`; see §Scope), and kenneld **drains the ring buffer**
(`kenneld::bpf_audit`) — attributing each event to its kennel by `ctx_byte`, carrying
`comm` as untrusted (writer-sanitised), and emitting the canonical event with
`source: bpf`. The mapping from the BPF `audit_kind` to these event names is in
`02-7-bpf-abi.md`.

- **`net.connect-allow`** / **`net.connect-deny`** — connect() attempt, sourced from the BPF connect programs. Allow under audit-level rules; deny always. Adds `addr_family`, `addr`, `port`.
- **`net.bind-allow`** / **`net.bind-deny`** / **`net.bind-rewrite`** — bind() attempt, sourced from the BPF bind programs. Adds `addr_requested`, `addr_rewritten` (for rewrites), `port`.

The `net.connect-*` and `net.bind-*` events above are **built**: the per-kennel network
namespace, the four network modes, and the loopback mirror are all in place, and these events
are emitted today (`kenneld::bpf_audit` drains them from the `audit_ringbuf` with `source: bpf`,
proven by `kenneld/tests/bpf_drain.rs`).

**Status: roadmap (extended `[net.bpf]` socket-shaping).** The two events below are part of the
stable schema but are emitted only once the *extended* socket-shaping (`02-7`) lands — the bare
`net.bind` with its `mirrored` field needs the dynamic bind-hook mirror report (the built mirror
is eager-from-policy, not a per-bind report), and `net.bpf.deny` needs the families/types/protocols
+ `[[net.bpf.*]]` shaping layered over the as-built egress gate. They are also BPF-sourced — kenneld
drains them from the `audit_ringbuf` and emits them with `source: bpf`.

- **`net.bind`** — a `bind()` at the cgroup `bind` hook (`[[net.bpf.bind]]` gate). Adds
  `addr`, `port`, and — on an **allowed** bind — `mirrored` (boolean, `true` once the
  host-side mirror has raised the same `ip:port` on the host alias; see
  `02-5-binder-net.md` §The host-side mirror). The `outcome` carries the allow/deny.
- **`net.bpf.deny`** — a `[net.bpf]`-denied `bind()` / `connect()` / `socket()` at the
  socket-shaping hooks. Adds `family`, `type`, `protocol`, `addr`, `port`, and `rule`
  (the policy clause that denied it). Always `outcome: deny`.

The `org.projectkennel.INet` network crossing (`02-5-binder-net.md`) is
audited as part of the per-request `net.egress` record below: the `INet` `CONNECT_INET`
transaction is the binder front of the netproxy CONNECT delegate, so an allowed or
denied dial surfaces through `net.egress` exactly as a SOCKS5 request does — the binder
transport is invisible to the audit layer. The `INet` `BIND_INET` inbound half (the §7.5.7
host-side mirror handing an accepted connection to the kennel) carries `outcome: info`
for a delivered inbound and `outcome: error` for a delivery the shim could not splice;
it adds no new event type — it rides the existing `net.egress` stream with `wire:
inet-inbound`.

The one network event the userspace writer *does* emit is the netproxy's
per-request `net.egress` record, described next.

The per-kennel proxy emits one `net.egress` record per request (`host-netproxy::audit`), carrying `wire` (`socks5` or `http-connect`), `host`, `port`, `resolved` (the IP the name resolved to via the OS resolver, or null), `egress_outcome` (`allowed` / `denied` / `failed`), `reason` (for denies and failures), and `bytes_up` / `bytes_down`. The canonical envelope `outcome` (`allow` / `deny` / `error`) is set in parallel from the same disposition; `egress_outcome` is the event-specific, proxy-flavoured token. Name-to-address resolution goes through the OS resolver and is recorded in the `resolved` field of this single record — there is no separate DNS-lookup event and no DNS-protocol telemetry, because the proxy does not implement a resolver of its own.

### Filesystem (`resource: "fs"`)

- **`fs.access-deny`** — Landlock-denied access. Adds `path` (canonicalised), `access` (`read`/`write`/`exec`), `syscall`.
- **`fs.scrub-hit`** — a scrub-pattern match returned an empty file. Adds `path`, `pattern`.

### Exec (`resource: "exec"`)

- **`exec`** (`exec.allow` / `exec.deny` outcome) — execve() attempt. `exec.deny` is the *event* for a deny-by-default refusal (there is no `exec.deny` policy list, §7.3.4). Adds `binary` (resolved path), `argv_first` (truncated, sanitised), `reason` (for denies). Full argv only with `log_full_argv = true`.

### AF_UNIX (`resource: "unix"`)

- **`unix.connect-allow`** / **`unix.connect-deny`** — Adds `path`, `namespace` (`filesystem` or `abstract`), `reason`.

### D-Bus (`resource: "dbus"`)

- **`dbus.call-allow`** / **`dbus.call-deny`** — Adds `bus` (`session`/`system`), `destination`, `interface`, `member`, `reason`.

### Binder (`resource: "binder"`)

Every binder decision is audited through the unified writer with `source: kenneld` —
kenneld is node 0 and so witnesses every verb directly (`02-4-binder.md` §Audit
events). Payload *content* is never logged: byte counts and outcomes only, per
CODING-STANDARDS §9.3.

The registry verbs are **built** (kenneld serves node 0 today); the cross-instance
relay and `SpawnKennel` are **roadmap** (`02-4-binder.md`).

- **`binder.register`** — an `addService` (`IServiceManager` register). Adds `service`
  (the `org.projectkennel.*`-form name), `reason` (for denies). The `outcome` carries
  the allow/deny against the kennel's settled policy.
- **`binder.lookup`** — a `getService`. Adds `service`, `scope` (`local` or `cross`),
  `reason` (for denies).
- **`binder.cross`** *(roadmap)* — a cross-instance transaction (inter-kennel relay).
  Adds `from_ctx`, `to_ctx`, `service`, `code` (the transaction code), `bytes` (payload
  byte count, content never logged). The `outcome` carries the relay disposition.
- **`binder.service-crash`** — a facade/service process crash and restart. Adds
  `service`; `outcome: error`.

The `binder.cross` and `kennel.spawn` records, correlated by transaction `code` and the
calling kennel ctx, are what let a security team reconstruct *which agent request caused
which file access in which kennel* from the JSONL log alone (design §7.1.9).

### Kennel spawning (`resource: "lifecycle"`)

- **`kennel.spawn`** *(roadmap)* — a `SpawnKennel` request (`02-4-binder.md` §Kennel
  spawning). Adds `template`, `scoped_name`, `policy_hash` (the effective policy hash).
  `source: kenneld`.

### Privileged (`resource: "priv"`)

The `source` is `privhelper`, but kenneld writes these on the helper's behalf: the helper is root and transient and holds no writer, so kenneld records each call at the IPC boundary (an `AuditedPrivileged` wrapper around its helper client), exactly as it records kernel/BPF-sourced events. `operation` is the wire op (`add-addr`, `del-addr`, `setup-egress`, `set-gid-map`); a refusal maps the wire refusal `code` to a human `message`. The `outcome` is `allow` for an invocation, `deny` for a policy refusal, and `error` for a protocol/syscall/IPC failure.

- **`priv.invoke`** — privhelper invocation. Adds `operation`, `params` (object), `duration_ms`.
- **`priv.refuse`** — privhelper refusal. Adds `operation`, `params`, `code`, `message`.

### Lifecycle (`resource: "lifecycle"`)

- **`lifecycle.kennel-start`** — Schema adds `policy_path`, `template_chain` (array), `policy_hash`, `workload_argv0`, `started_pid`. Today kenneld emits `ctx` and `started_pid`; the remaining provenance fields are reserved and filled as their sources are wired.
- **`lifecycle.kennel-exit`** — Schema adds `uptime_seconds`, `workloads_run`, `reason`. Today kenneld emits `reason`.
- **`lifecycle.workload-exit`** — Schema adds `pid`, `exit_code`, `signal`, `uptime_seconds`, `rss_max_bytes`. Today kenneld emits `pid` and `exit_code`.

The binder bus carries the construction/lifecycle control plane between `kennel-bin-init`
(PID 1) and kenneld as node 0 (`02-4-binder.md` §Lifecycle, `07-2-kennel-bin-init.md`).
These verbs are witnessed by kenneld directly (`source: kenneld`, `resource:
lifecycle`) and are audited **as lifecycle events, not as `binder.cross`** — the
binder transport is the channel, not the subject. kenneld stamps the kernel-supplied
`sender_pid` (the init's unforgeable **host** pid) and `sender_euid`; a verb from any
other sender is a logged deny. All four are **built**:

- **`lifecycle.plan-pull`** — `kennel-bin-init` pulled its supervision-half Plan via
  `GET_SANDBOX_PLAN` to node 0. Adds `init_host_pid`. `outcome: info` on a served reply,
  `outcome: deny` on the identity-gate reject.
- **`lifecycle.boot-sync`** — `NOTIFY_BOOT_SYNC`: `kennel-bin-init` finished constructing the
  view and reached its supervision loop. Adds `init_host_pid`; `outcome: info`.
- **`lifecycle.facade-crash`** — `NOTIFY_FACADE_CRASH`: an operator-uid protocol facade
  (e.g. `org.projectkennel.IAfUnix/default`) crashed. Adds `service`; `outcome: error`.
- **`lifecycle.workload-exec`** — `NOTIFY_WORKLOAD_EXEC`: `kennel-bin-init` is about to
  `execve` the workload (after the irreversible identity drop + seccomp + Landlock). Adds
  `started_pid`; `outcome: info`.

**Status: reserved (roadmap).** The daemon and state-dump lifecycle events below are part of the stable schema and hold registered `MESSAGE_ID`s, but kenneld does not yet construct or emit them; they are wired as the per-daemon supervisor and the `SIGUSR1` handler land (`05-state-and-supervision.md`).

- **`lifecycle.daemon-spawn`** / **`lifecycle.daemon-exit`** — Adds `daemon` (name), `pid`, daemon-specific listening addresses.
- **`lifecycle.daemon-giveup`** — A daemon exceeded the crash-loop restart limit and is no longer being respawned (`05-state-and-supervision.md`). Adds `daemon` (name), `restarts`, `window_seconds`.
- **`lifecycle.kenneld-state-dump`** — Emitted on `SIGUSR1`: one event per registered kennel with its state, reference count, drain-timer remaining, and daemon PIDs. A debugging aid.

---

## Audit levels

The `[audit].<class>.level` policy field controls which events of each resource class are emitted:

- `off` — emit nothing.
- `denies-only` — emit only `outcome: "deny"` events.
- `summary` — emit denies plus the first `allow` per `(resource, target)` pair per kennel lifetime. Default.
- `full` — emit every event regardless of outcome.

Lifecycle and privileged-operation events are always emitted regardless of class level. Levels apply per resource class independently; an operator may set `network = "summary"` and `filesystem = "denies-only"` in the same kennel.

The level controls *whether* an event is emitted, not *which sinks* it goes to. If an event is emitted, it goes to every configured sink.

---

## Sanitisation

All string fields that may carry attacker-controlled bytes (paths, hostnames, dbus member names, command names) are sanitised on the writer side per CODING-STANDARDS.md §10.3 and §10.4 *before* being passed to sinks. Sinks receive already-sanitised content. Control characters are escaped (`\x1b`, `\b`, …); non-UTF-8 bytes are replaced with U+FFFD and a `sanitised: true` field is added to the event.

This is centralised in `kennel-lib-audit` so that:

- Every sink benefits from one sanitisation pass.
- Sink-specific encoding (JSON for file, journald field encoding) cannot bypass sanitisation by escaping differently.
- The fuzz target on `kennel-lib-audit`'s writer covers every sink output.

---

## Sink: JSONL file

The default sink. Each event is a single JSON object on its own line, UTF-8 encoded, newline-terminated. Files live under the per-kennel state directory (`07-paths.md`):

- `~/.local/state/kennel/<kennel>/network.jsonl`
- `~/.local/state/kennel/<kennel>/filesystem.jsonl`
- `~/.local/state/kennel/<kennel>/exec.jsonl`
- `~/.local/state/kennel/<kennel>/unix.jsonl`
- `~/.local/state/kennel/<kennel>/dbus.jsonl`
- `~/.local/state/kennel/<kennel>/binder.jsonl`
- `~/.local/state/kennel/<kennel>/priv.jsonl`
- `~/.local/state/kennel/<kennel>/lifecycle.jsonl`

One file per resource class per kennel. The class-level granularity makes `kennel audit --resource net` a single file open.

**Concurrent writers.** Per-kennel daemons that emit network events (the netproxy in particular) write directly to `network.jsonl` via `O_APPEND`-opened handles. `write()` calls under `PIPE_BUF` (4 KiB on Linux) are atomic. The writer rejects events that would exceed 4 KiB; longer events are a bug, not a runtime case.

**Rotation.** Kenneld rotates files at 64 MB by default (configurable per kennel via `[audit].file.rotate_at_bytes`). Rotated files are renamed `<class>.<unix-timestamp>.jsonl`. When `[audit].file.compress_after_seconds` is set, the file sink gzips a rotated file once it is at least that old — lazily, swept at the next rotation, by shelling out to the system `gzip(1)` on the already-closed file (producing `<class>.<unix-timestamp>.jsonl.gz`). There is no in-process compression codec: a file at rest is exactly `gzip(1)`'s job, so no DEFLATE library enters the TCB. Compression is best-effort — if `gzip` is missing, denied, or fails, the rotated file is left uncompressed and the failure is reported to stderr; the live append path is never touched. Retention is operator policy via external rotation tooling (logrotate, similar) or via `[audit].file.retain_count` (which counts compressed and uncompressed rotations alike) if the operator wants kenneld to handle it.

**Querying.** `kennel audit <kennel>` (`02-1-cli.md`) reads these files directly. The CLI does not depend on any external log-shipping infrastructure; the file sink is queryable from a fresh shell on the host.

**Field encoding.** Canonical envelope fields and event-specific fields go directly into the JSON object. Field ordering is deterministic for diff-friendliness (the canonical order is the order in the §Common envelope table above, then event-specific fields in declared order). Consumers must not depend on field order.

A representative line:

```json
{"schema_version":1,"ts":"2026-05-25T12:34:56.789012Z","kennel":"ai-coding","kennel_uuid":"01HZX...","event":"net.connect-deny","resource":"net","outcome":"deny","source":"bpf","host":"workstation","pid":12345,"comm":"curl","addr_family":"ipv4","addr":"169.254.169.254","port":80,"reason":"in net.deny.invariant (cloud metadata)"}
```

---

## Sink: systemd-journald

The recommended sink on systemd-using systems. Events are emitted via `sd_journal_send` (called from `kennel-lib-audit` through a vetted Rust binding; see `02-8-internal-api.md`).

The destination journal is determined by where kenneld runs:

- kenneld started by `systemd --user` → user journal (queryable as the user: `journalctl --user _SYSTEMD_USER_UNIT=kenneld.service`).
- kenneld started by system systemd → system journal (queryable as root or via journal-reader group membership: `journalctl _SYSTEMD_UNIT=kenneld.service`).

**Field mapping.** Each canonical event field maps to one journald field, with the field name uppercased and prefixed `KENNEL_`. journald field names must match `[A-Z0-9_]+`; the writer enforces this and rejects (with a self-diagnostic) any event field whose canonical name does not satisfy the constraint. The current event-type schema is designed to satisfy it.

| Canonical field | journald field | Notes |
|---|---|---|
| `schema_version` | `KENNEL_SCHEMA_VERSION` | Integer rendered as string. |
| `ts` | (journald owns the timestamp) | The canonical `ts` is set automatically by journald as `__REALTIME_TIMESTAMP`; the canonical value is also emitted as `KENNEL_TS` for sub-microsecond precision and consumer round-tripping. |
| `kennel` | `KENNEL_NAME` | |
| `kennel_uuid` | `KENNEL_UUID` | |
| `event` | `KENNEL_EVENT` | |
| `resource` | `KENNEL_RESOURCE` | |
| `outcome` | `KENNEL_OUTCOME` | |
| `source` | `KENNEL_SOURCE` | |
| `host` | (journald owns the host) | Set automatically as `_HOSTNAME`; `KENNEL_HOST` is also emitted for symmetry. |
| `pid` | `KENNEL_PID` | journald's own `_PID` is the *kenneld* pid; `KENNEL_PID` is the *workload* pid. |
| `comm` | `KENNEL_COMM` | |
| event-specific fields | `KENNEL_<UPPER>` | Each event-specific field; e.g., `addr` → `KENNEL_ADDR`, `port` → `KENNEL_PORT`. |
| array values | repeated `KENNEL_<FIELD>` | journald allows multi-valued keys; e.g., `template_chain` becomes three `KENNEL_TEMPLATE_CHAIN` entries. |
| nested objects | `KENNEL_<FIELD>_JSON` | Serialised as JSON in a single field; rare. |

Additional fields journald requires or expects:

| journald field | Value |
|---|---|
| `MESSAGE` | Human-readable one-line summary synthesised by the writer; e.g., `"deny connect to 169.254.169.254:80 (cloud metadata)"`. Never the only place where structured information lives; consumers read `KENNEL_*` fields, not `MESSAGE`. |
| `MESSAGE_ID` | A UUID per event type, registered in the hard-coded `MESSAGE_IDS` table in `kennel-lib-audit::message_ids` (the source of truth; emitted in journald's dash-free 32-hex form). Allows journald filtering by event kind: `journalctl MESSAGE_ID=<uuid>`. |
| `SYSLOG_IDENTIFIER` | `kennel-lib-audit`. |
| `PRIORITY` | Syslog level mapped from `outcome`: `info`/`allow` → 6 (info), `deny` → 4 (warning), `error` → 3 (err). |

**Querying.** `journalctl` directly: `journalctl --user _SYSTEMD_USER_UNIT=kenneld.service KENNEL_NAME=ai-coding KENNEL_EVENT=net.connect-deny --since "1h ago"`. The `kennel audit` CLI subcommand reads from the file sink by default; for journald-only deployments, `kennel audit --print-journalctl-command <kennel>` emits the equivalent `journalctl` invocation with the requested filters.

**Back-pressure.** `sd_journal_send` is non-blocking under normal conditions but may block briefly under heavy log pressure. The journald sink, like every sink, runs behind a bounded per-sink worker queue (`TimeoutSink`, default capacity 1024): the writer's hand-off is a non-blocking channel send, and the worker thread performs the blocking `sd_journal_send`. When the worker falls behind and the queue fills, the event is dropped (the writer's send returns an error) rather than blocking the writer. Drops are emitted as `lifecycle.audit-drop` events to the other sinks (or, if journald is the only sink, surfaced via kenneld's stderr).

---

## Sink: syslog (RFC 5424)

A minimal sink for systems without journald. Events are emitted as RFC 5424 messages to `/dev/log` (or `/run/systemd/journal/dev-log` on systemd systems, which redirects to journald — in which case using the journald sink directly is preferred).

Mapping:

- APP-NAME: `kennel-lib-audit`.
- PROCID: kenneld PID.
- MSGID: the event type, in dot-form (`net.connect-deny`).
- STRUCTURED-DATA: one SD-ELEMENT with SD-ID `kennel@<PEN>`. The live value is `kennel@32473`, where `32473` is the RFC 5612 PEN reserved for documentation/examples — a placeholder the project's own IANA Private Enterprise Number replaces at the first release that commits to syslog support. Each canonical event field becomes one SD-PARAM. Field-name casing follows the canonical schema; SD-PARAM names allow lowercase and dots.
- MSG: a human-readable one-line summary, the same string as journald's `MESSAGE`.

Syslog message length is capped at 2 KiB (`SYSLOG_MAX_BYTES`) on most receivers. When a formatted message exceeds the cap, the writer truncates on a UTF-8 char boundary and appends a literal `...[truncated]` marker to the message. There is no separate truncation event: the `lifecycle.audit-truncate` `MESSAGE_ID` is reserved in the registry but the writer does not emit it.

---

## Sink: stdout

For container deployments. Each event is written as a single JSONL line to kenneld's stdout (not the workload's stdout). The container orchestrator captures stdout and ships it to the operator's log system.

When this sink is active, the file sink is typically disabled, and the per-kennel JSONL files are not written. The schema in the stdout stream is identical to the file sink's JSONL: one event per line, same field ordering, same sanitisation guarantees.

Consumers downstream of the orchestrator (e.g., a logstash receiver) parse the stdout stream the same way they would parse the file sink.

---

## Sink configuration

The policy's `[audit]` section configures sinks and per-class levels. Sketch (full schema in `02-2-config-schema.md`):

```toml
[audit]
sinks = ["file", "journald"]   # default ["file"]

[audit.file]
dir = "~/.local/state/kennel/<kennel>/"   # default; <kennel> is substituted
rotate_at_bytes = "64M"
compress_after_seconds = 3600
retain_count = 8

[audit.journald]
# journald is auto-detected (user vs system) from kenneld's invocation context;
# no required fields.

[audit.syslog]
facility = "user"               # default; one of: user, daemon, auth, authpriv, ...

[audit.stdout]
# no required fields.

[audit.network]
level = "summary"
[audit.filesystem]
level = "denies-only"
[audit.exec]
level = "summary"
[audit.unix]
level = "summary"
[audit.dbus]
level = "summary"
[audit.binder]
level = "summary"
```

Defaults: sinks = `["file"]`, all classes at `summary` except `filesystem` which is `denies-only` (filesystem traffic is high-volume; full or summary is opt-in).

An installation-wide default lives in `/etc/kennel/audit.toml` and is inherited by every kennel unless overridden in the leaf policy. The installation default is the right place to choose `["journald"]` once; per-kennel overrides are reserved for the exceptional case.

kenneld reads two defaults files at spawn — `/etc/kennel/audit.toml` (root-owned, installation-wide) and `~/.config/kennel/audit.toml` (the user's override) — each holding the `[audit]` section body at top level (`sinks`, `[network]`/`[filesystem]`/…, `[file]`, `[syslog]`), validated by exactly the policy's `[audit]` validator. They merge per-field, lowest to highest precedence: **built-in default < `/etc/kennel/audit.toml` < `~/.config/kennel/audit.toml` < the leaf policy's `[audit]`**. A missing file is skipped and a malformed one is logged and skipped, so a bad defaults file never blocks a spawn.

---

## Consumer guidance

Consumers should:

- **Pick a sink.** Choose `file` for portability, `journald` for systemd integration, `stdout` for container-orchestrator pipelines. Do not mix consumer logic across sinks for the same deployment.
- **Filter on `schema_version`.** Refuse to interpret events with a version the consumer does not understand.
- **Filter on `event` or `resource` before parsing event-specific fields.** Unknown event types are not errors; they are events from a newer minor schema.
- **Treat missing optional fields as "not applicable".**
- **Do not depend on field ordering** within a JSON object (file sink) or on `KENNEL_*` field ordering (journald). The canonical writer ordering is for diff-friendliness, not for parsing.
- **Cope with line lengths up to 4 KiB** (file/stdout sinks); the writer rejects longer events so consumers do not need to handle truncation. For syslog, expect truncation flagged by `truncated: true`.

For journald specifically: filter on `MESSAGE_ID` when targeting a specific event type rather than matching `MESSAGE` substrings. `MESSAGE` is for humans; `KENNEL_*` and `MESSAGE_ID` are for tooling.

---

## What this chapter does not cover

- The audit log philosophy (always-deny, sampled-allow, per-kennel correlation): design doc §8.6.
- Where each daemon emits events from in its codepath: `02-8-internal-api.md` (`kennel-lib-audit` crate).
- Rotation and retention as runtime concerns: `05-state-and-supervision.md`.
- The on-disk path layout for audit files: `07-paths.md`.
- How `kennel audit` queries the file sink: `02-1-cli.md`.
- The PEN registration for the syslog SD-ID: project administrative, not architectural.
