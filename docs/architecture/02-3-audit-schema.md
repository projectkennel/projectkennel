# API surfaces — audit schema

> **Scope.** The audit *event schema* below is the durable contract. The
> multi-sink delivery layer is **built**: the `kennel-audit` writer fans one
> sanitised event out to the `file`, `stdout`, `syslog`, and (feature
> `audit-journald`) `journald` sinks, applying the per-class levels; the `[audit]`
> policy section is parsed, validated, and carried in the signed settled policy as
> `AuditRuntime`; kenneld builds the writer from it and emits the `lifecycle.*`
> events; a bounded per-sink worker queue caps a stuck sink's effect on the writer;
> and the journald sink stamps `MESSAGE_ID`. The installation-wide `audit.toml`
> remains roadmap (`08-as-built-notes.md` §8.1).
>
> **Scope: the writer unifies *userspace* sources.** Kernel-side events report
> through the kernel's own channels, deliberately *not* through this writer:
>
> - The cgroup **BPF programs** report via the kernel — the audit ring buffer
>   (`bpf/audit_events.h`, `bpf/kennel.bpf.h`) and `dmesg`. Funnelling them through
>   an unprivileged userspace writer would add privilege and TCB for no gain.
> - **LSM denials** (Landlock/AppArmor) are the kernel's to log.
>
> Both userspace sources route through the writer: kenneld's lifecycle events,
> and the egress proxy's per-request `net.egress` events
> (`kennel-netproxy::audit::Record::to_event`, written to
> `~/.local/state/kennel/<kennel>/network.jsonl` plus any other configured sink).
> kenneld shares one `kennel_uuid` with the proxy per run, so their events
> correlate.

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
- **cgroup BPF programs.** Network connect/bind/sock-create denials, allow events under summary or full level. Programs write to a kernel ringbuf; the audit reader in kenneld translates to canonical events.
- **The netproxy.** SOCKS5-level allow/deny, DNS resolution, byte counters.
- **xdg-dbus-proxy.** D-Bus method allow/deny.
- **kennel-privhelper.** Privileged-operation invocations and refusals.
- **The spawn wrapper (kennel-spawn).** Lifecycle events for the workload (start, exit, signal).
- **kenneld.** Daemon lifecycle, policy load, kennel registration.

In the roadmap delivery model, a centralised audit-event writer (`kennel-audit`) is the seam between these sources and the sinks: sources emit `AuditEvent` values and the writer fans them out to every configured sink. Today each source owns its own sink directly — the netproxy formats its JSONL records and kenneld owns the per-kennel file.

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

Multiple sinks may be active concurrently — for example, `file` + `journald` during a migration period — and the same event is emitted to each. The sink fan-out is synchronous from the writer's perspective; each sink is responsible for its own back-pressure handling and for not blocking the writer past a configured timeout (default 50 ms; configurable per sink).

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
| `resource` | string | Event class: `net`, `fs`, `exec`, `unix`, `dbus`, `priv`, `lifecycle`. |
| `outcome` | string | `allow`, `deny`, `info`, `error`. |
| `source` | string | Originator: `kernel`, `bpf`, `proxy`, `dbus-proxy`, `kennel-spawn`, `kenneld`, `privhelper`. |
| `host` | string | Hostname at event time. |
| `pid` | integer | Workload PID at event time (absent for events not tied to a workload PID, e.g., daemon-lifecycle). |
| `comm` | string | `task->comm`, up to 16 bytes; sanitised. |

Event-specific fields extend the envelope; see §Event types.

---

## Event types

The catalogue below names every event the project currently emits. Field lists are non-exhaustive — each sink representation in the sink sections describes the full field mapping for that sink.

### Network (`resource: "net"`)

- **`net.connect-allow`** / **`net.connect-deny`** — connect() attempt, sourced from the BPF connect programs. Allow under audit-level rules; deny always. Adds `addr_family`, `addr`, `port`.
- **`net.bind-allow`** / **`net.bind-deny`** / **`net.bind-rewrite`** — bind() attempt, sourced from the BPF bind programs. Adds `addr_requested`, `addr_rewritten` (for rewrites), `port`.

The per-kennel proxy emits one `egress` record per request (`kennel-netproxy::audit`), carrying `wire` (`socks5` or `http-connect`), `host`, `port`, `resolved` (the IP the name resolved to via the OS resolver, or null), `outcome` (`allowed` / `denied` / `failed`), `reason` (for denies and failures), and `bytes_up` / `bytes_down`. Name-to-address resolution goes through the OS resolver and is recorded in the `resolved` field of this single record — there is no separate DNS-lookup event and no DNS-protocol telemetry, because the proxy does not implement a resolver of its own.

### Filesystem (`resource: "fs"`)

- **`fs.access-deny`** — Landlock-denied access. Adds `path` (canonicalised), `access` (`read`/`write`/`exec`), `syscall`.
- **`fs.scrub-hit`** — a scrub-pattern match returned an empty file. Adds `path`, `pattern`.

### Exec (`resource: "exec"`)

- **`exec.allow`** / **`exec.deny`** — execve() attempt. Adds `binary` (resolved path), `argv_first` (truncated, sanitised), `reason` (for denies). Full argv only with `log_full_argv = true`.

### AF_UNIX (`resource: "unix"`)

- **`unix.connect-allow`** / **`unix.connect-deny`** — Adds `path`, `namespace` (`filesystem` or `abstract`), `reason`.

### D-Bus (`resource: "dbus"`)

- **`dbus.call-allow`** / **`dbus.call-deny`** — Adds `bus` (`session`/`system`), `destination`, `interface`, `member`, `reason`.

### Privileged (`resource: "priv"`)

The `source` is `privhelper`, but kenneld writes these on the helper's behalf: the helper is root and transient and holds no writer, so kenneld records each call at the IPC boundary (an `AuditedPrivileged` wrapper around its helper client), exactly as it records kernel/BPF-sourced events. `operation` is the wire op (`add-addr`, `del-addr`, `setup-egress`, `set-gid-map`); a refusal maps the wire refusal `code` to a human `message`. The `outcome` is `allow` for an invocation, `deny` for a policy refusal, and `error` for a protocol/syscall/IPC failure.

- **`priv.invoke`** — privhelper invocation. Adds `operation`, `params` (object), `duration_ms`.
- **`priv.refuse`** — privhelper refusal. Adds `operation`, `params`, `code`, `message`.

### Lifecycle (`resource: "lifecycle"`)

- **`lifecycle.kennel-start`** — Adds `policy_path`, `template_chain` (array), `policy_hash`, `workload_argv0`, `started_pid`.
- **`lifecycle.kennel-exit`** — Adds `uptime_seconds`, `workloads_run`, `reason`.
- **`lifecycle.daemon-spawn`** / **`lifecycle.daemon-exit`** — Adds `daemon` (name), `pid`, daemon-specific listening addresses.
- **`lifecycle.daemon-giveup`** — A daemon exceeded the crash-loop restart limit and is no longer being respawned (`05-state-and-supervision.md`). Adds `daemon` (name), `restarts`, `window_seconds`.
- **`lifecycle.workload-exit`** — Adds `pid`, `exit_code`, `signal`, `uptime_seconds`, `rss_max_bytes`.
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

This is centralised in `kennel-audit` so that:

- Every sink benefits from one sanitisation pass.
- Sink-specific encoding (JSON for file, journald field encoding) cannot bypass sanitisation by escaping differently.
- The fuzz target on `kennel-audit`'s writer covers every sink output.

---

## Sink: JSONL file

The default sink. Each event is a single JSON object on its own line, UTF-8 encoded, newline-terminated. Files live under the per-kennel state directory (`07-paths.md`):

- `~/.local/state/kennel/<kennel>/network.jsonl`
- `~/.local/state/kennel/<kennel>/filesystem.jsonl`
- `~/.local/state/kennel/<kennel>/exec.jsonl`
- `~/.local/state/kennel/<kennel>/unix.jsonl`
- `~/.local/state/kennel/<kennel>/dbus.jsonl`
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

The recommended sink on systemd-using systems. Events are emitted via `sd_journal_send` (called from `kennel-audit` through a vetted Rust binding; see `02-6-internal-api.md`).

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
| `MESSAGE_ID` | A UUID per event type, registered in `audit/message-ids.toml` in the repo. Allows journald filtering by event kind: `journalctl MESSAGE_ID=<uuid>`. |
| `SYSLOG_IDENTIFIER` | `kennel-audit`. |
| `PRIORITY` | Syslog level mapped from `outcome`: `info`/`allow` → 6 (info), `deny` → 4 (warning), `error` → 3 (err). |

**Querying.** `journalctl` directly: `journalctl --user _SYSTEMD_USER_UNIT=kenneld.service KENNEL_NAME=ai-coding KENNEL_EVENT=net.connect-deny --since "1h ago"`. The `kennel audit` CLI subcommand reads from the file sink by default; for journald-only deployments, `kennel audit --print-journalctl-command <kennel>` emits the equivalent `journalctl` invocation with the requested filters.

**Back-pressure.** `sd_journal_send` is non-blocking under normal conditions but may block briefly under heavy log pressure. The writer applies a 50 ms timeout per emit; on timeout, the event is recorded as dropped (incrementing a counter) and the writer continues. Drops are themselves emitted as `lifecycle.audit-drop` events to the other sinks (or, if journald is the only sink, surfaced via kenneld's stderr).

---

## Sink: syslog (RFC 5424)

A minimal sink for systems without journald. Events are emitted as RFC 5424 messages to `/dev/log` (or `/run/systemd/journal/dev-log` on systemd systems, which redirects to journald — in which case using the journald sink directly is preferred).

Mapping:

- APP-NAME: `kennel-audit`.
- PROCID: kenneld PID.
- MSGID: the event type, in dot-form (`net.connect-deny`).
- STRUCTURED-DATA: one SD-ELEMENT with SD-ID `kennel@<PEN>` (where `<PEN>` is the IANA Private Enterprise Number for Project Kennel; reserved at the first release that ships syslog support). Each canonical event field becomes one SD-PARAM. Field-name casing follows the canonical schema; SD-PARAM names allow lowercase and dots.
- MSG: a human-readable one-line summary, the same string as journald's `MESSAGE`.

Syslog message length is capped at 2 KiB on most receivers. The writer truncates after sanitisation if needed, adding a `truncated: true` SD-PARAM. Truncation is logged as a `lifecycle.audit-truncate` event to other sinks if any.

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
- Where each daemon emits events from in its codepath: `02-6-internal-api.md` (`kennel-audit` crate).
- Rotation and retention as runtime concerns: `05-state-and-supervision.md`.
- The on-disk path layout for audit files: `07-paths.md`.
- How `kennel audit` queries the file sink: `02-1-cli.md`.
- The PEN registration for the syslog SD-ID: project administrative, not architectural.
