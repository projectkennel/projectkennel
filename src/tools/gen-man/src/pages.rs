//! The page data: the single editable source for every manpage.
//!
//! Plain Rust `const` data rather than a parsed sidecar, so there is no TOML
//! parser to vendor (the project bans third-party deps) and the content is
//! type-checked at compile time. The emitter in `main.rs` turns each [`Page`]
//! into groff `man(7)` source.
//!
//! The `kennel` and `kennel-policy` command synopses are kept verbatim from the
//! `CommandSpec` tables in `kenneld/src/bin/kennel.rs`; a test in that crate
//! asserts the two stay in sync (`SYNC_COMMANDS` / `SYNC_POLICY` below are the
//! checked-against copies).

// Constant-index reads into the `SYNC_*` tables (`SYNC_COMMANDS[0].2`) are
// in-bounds by construction and verified by the sync-test in `kennel.rs`; the
// workspace `indexing_slicing` deny targets runtime input, not literal indexing of
// a local const, so it is allowed here in this build-only tool.
#![allow(clippy::indexing_slicing)]

/// One command/sub-verb entry on a `.1` page (a row under SYNOPSIS + OPTIONS).
pub struct Command {
    /// The usage line, verbatim from `CommandSpec.usage` (without the leading `kennel`).
    /// Begins with the verb, so no separate name field is needed.
    pub usage: &'static str,
    /// One-line summary, verbatim from `CommandSpec.summary`.
    pub summary: &'static str,
    /// Per-option `(flag, description)` rows for the OPTIONS section. May be empty.
    pub options: &'static [(&'static str, &'static str)],
}

/// One field row on a `.5` config page.
pub struct Field {
    /// The field or key name.
    pub name: &'static str,
    /// Its type / value shape.
    pub kind: &'static str,
    /// What it does (one line; kept terse for roff).
    pub desc: &'static str,
}

/// A field group on a `.5` page (a sub-table, e.g. `[fs.home]`).
pub struct FieldGroup {
    /// The group heading (e.g. "[fs.home]"), or "" for the top-level fields.
    pub heading: &'static str,
    /// Optional one-line intro under the heading.
    pub intro: &'static str,
    /// The fields in this group.
    pub fields: &'static [Field],
}

/// One manpage.
pub struct Page {
    /// The page name without section suffix (`kennel`, `policy.toml`, `host-inetd`).
    pub name: &'static str,
    /// The man section (1 command, 5 file format, 8 system binary).
    pub section: u8,
    /// The one-line NAME-section description (after the `name \- `).
    pub summary: &'static str,
    /// The SYNOPSIS line(s). For a `.1` with commands, the per-command synopsis is
    /// rendered from `commands` instead; this is the bare one-liner for the rest.
    pub synopsis: &'static str,
    /// The DESCRIPTION body (free roff-safe prose; blank lines separate paragraphs).
    pub description: &'static str,
    /// Commands for a `.1` page (empty for `.5`/`.8`).
    pub commands: &'static [Command],
    /// Field groups for a `.5` page (empty otherwise).
    pub fields: &'static [FieldGroup],
    /// EXIT STATUS rows `(code, meaning)` (empty to omit the section).
    pub exit_status: &'static [(&'static str, &'static str)],
    /// FILES rows `(path, meaning)` (empty to omit).
    pub files: &'static [(&'static str, &'static str)],
    /// EXAMPLES `(command, what-it-does)` (empty to omit).
    pub examples: &'static [(&'static str, &'static str)],
    /// SEE ALSO references (e.g. "kenneld(8)").
    pub see_also: &'static [&'static str],
}

// ---------------------------------------------------------------------------
// Sync copies of the CommandSpec tables (kenneld/src/bin/kennel.rs). The test
// `man_meta_in_sync` in that crate asserts these match the live tables, so a CLI
// change that is not reflected here fails CI. Kept as (name, summary, usage).
// ---------------------------------------------------------------------------

/// Top-level `kennel` commands, mirrored from `COMMANDS`.
pub const SYNC_COMMANDS: &[(&str, &str, &str)] = &[
    (
        "run",
        "run a workload confined by a policy, in the foreground",
        "run <policy> [<name>] [--key K] [--force] [--template-dir D]... [--trust-dir D]... [-- <cmd...>]",
    ),
    (
        "attach",
        "reattach a terminal to a running kennel (Ctrl-\\ d to detach)",
        "attach <name>",
    ),
    ("stop", "stop a running kennel", "stop <name>"),
    ("list", "list running kennels", "list"),
    (
        "policy",
        "author, inspect, sign, and check policies",
        "policy <list|show|edit|generate|compile|validate|sign|lint|risks|upgrade> [...]",
    ),
    (
        "keygen",
        "generate a policy-signing key",
        "keygen <key-id> [--dir DIR] [--force]",
    ),
    (
        "subkennel",
        "manage /etc/kennel/subkennel allocations",
        "subkennel <add|check> [--uid N] [--namespace NS] [--tag N] [--file PATH]",
    ),
    (
        "audit",
        "show a kennel's audit log",
        "audit <name> [--resource CLASS] [--since DUR] [--novel-only] [--follow] [--print-journalctl-command]",
    ),
];

/// `kennel policy` sub-verbs, mirrored from `POLICY_VERBS`.
pub const SYNC_POLICY: &[(&str, &str, &str)] = &[
    (
        "list",
        "list policies and templates in the search path",
        "policy list",
    ),
    (
        "show",
        "show what a policy resolves to (the effective policy)",
        "policy show <policy> [--template-dir D]... [--trust-dir D]...",
    ),
    ("edit", "edit a policy's source in $EDITOR", "policy edit <name>"),
    (
        "generate",
        "scaffold a new leaf policy",
        "policy generate <name> [--from <template>]",
    ),
    (
        "compile",
        "compile a source policy into a signed settled artefact",
        "policy compile <policy> [--output P] [--key K | --unsigned] [--require-signed] [--no-lock] [--template-dir D]... [--trust-dir D]...",
    ),
    (
        "validate",
        "resolve and check a policy without writing an artefact",
        "policy validate <policy> [--require-signed] [--template-dir D]... [--trust-dir D]...",
    ),
    (
        "sign",
        "sign a source template/fragment with a key",
        "policy sign <template> --key <key> [--output <path>]",
    ),
    (
        "lint",
        "check the shipped template corpus for incoherences",
        "policy lint [--template-dir D]... [--trust-dir D]...",
    ),
    (
        "risks",
        "evaluate a policy against the threat catalogue (exposures, residuals)",
        "policy risks <policy> [--template-dir D]... [--trust-dir D]... [--json]",
    ),
    (
        "upgrade",
        "re-pin a policy's template to a newer version (with review)",
        "policy upgrade <name> [--yes] [--template-dir D]... [--trust-dir D]...",
    ),
];

// ---------------------------------------------------------------------------
// Shared bits.
// ---------------------------------------------------------------------------

const COMMON_OPTS: &[(&str, &str)] = &[
    (
        "--template-dir D",
        "Add a directory to the template/fragment search path (repeatable). Overrides the config.toml default cascade.",
    ),
    (
        "--trust-dir D",
        "Add a directory to the signing-key trust store used while authoring (repeatable).",
    ),
];

const EXIT_CODES: &[(&str, &str)] = &[
    (
        "0",
        "Success. For kennel run, the workload's own exit code is passed through (clamped to a byte).",
    ),
    (
        "1",
        "Generic failure: the CLI could not reach kenneld, a file could not be read, or kenneld returned an error.",
    ),
    (
        "3",
        "Policy validation or resolution failure: schema, invariants, template inheritance, or include conflict.",
    ),
    ("6", "Signature or lockfile-pin failure during resolution."),
    (
        "7",
        "kennel policy lint found at least one coherence finding across the template corpus.",
    ),
];

// ---------------------------------------------------------------------------
// The pages.
// ---------------------------------------------------------------------------

/// Every manpage Project Kennel ships.
pub const PAGES: &[Page] = &[
    // -- kennel(1) ----------------------------------------------------------
    Page {
        name: "kennel",
        section: 1,
        summary: "run and manage confined workloads (kennels)",
        synopsis: "\\fBkennel\\fR \\fIcommand\\fR [\\fIargs\\fR...]",
        description: "\
kennel is the command-line front-end to Project Kennel, a security sandbox that \
runs a workload (an AI coding agent, a build, a service) under a signed policy. \
Each invocation of \\fBkennel run\\fR is one kennel: its own context, cgroup, \
constructed filesystem view, masked identity, per-kennel network namespace, and \
egress proxy, all torn down when the workload exits.

The CLI talks to the per-user \\fBkenneld\\fR(8) daemon over a control socket; \
kenneld constructs and supervises the kennel. Policy authoring (compile, sign, \
validate, lint) is done locally by the CLI and needs no daemon.

Run \\fBkennel \\fIcommand\\fB --help\\fR for a command's usage. The policy \
sub-verbs have their own page, \\fBkennel-policy\\fR(1).",
        commands: &[
            Command {
                usage: SYNC_COMMANDS[0].2,
                summary: SYNC_COMMANDS[0].1,
                options: &[
                    ("--key K", "Sign the in-memory compiled policy with key K for the local-dev run loop (auto-compile)."),
                    ("--force", "Override a [workload] pinned argv with a CLI -- command."),
                    ("-- <cmd...>", "The command to run inside the kennel (overrides [workload].argv unless pinned)."),
                    (COMMON_OPTS[0].0, COMMON_OPTS[0].1),
                    (COMMON_OPTS[1].0, COMMON_OPTS[1].1),
                ],
            },
            Command { usage: SYNC_COMMANDS[1].2, summary: SYNC_COMMANDS[1].1, options: &[] },
            Command { usage: SYNC_COMMANDS[2].2, summary: SYNC_COMMANDS[2].1, options: &[] },
            Command {
                usage: SYNC_COMMANDS[3].2,
                summary: SYNC_COMMANDS[3].1,
                options: &[("(sub-verbs)", "See kennel-policy(1) for list, show, edit, generate, compile, validate, sign, lint.")],
            },
            Command {
                usage: SYNC_COMMANDS[4].2,
                summary: SYNC_COMMANDS[4].1,
                options: &[
                    ("--dir DIR", "Write the key pair to DIR instead of the default key store."),
                    ("--force", "Overwrite an existing key of the same id."),
                ],
            },
            Command {
                usage: SYNC_COMMANDS[5].2,
                summary: SYNC_COMMANDS[5].1,
                options: &[
                    ("add", "Append a provably-valid allocation line for a uid (collision-free tag/gid)."),
                    ("check", "Validate the allocation file and report malformed lines."),
                    ("--uid N", "The target uid (defaults to the caller)."),
                    ("--namespace NS", "The allocation namespace."),
                    ("--tag N", "A specific 12-bit tag (otherwise allocated)."),
                    ("--file PATH", "Operate on PATH instead of /etc/kennel/subkennel."),
                ],
            },
            Command {
                usage: SYNC_COMMANDS[6].2,
                summary: SYNC_COMMANDS[6].1,
                options: &[
                    ("--resource CLASS", "Filter to one class (network, filesystem, exec, ...)."),
                    ("--since DUR", "Only events newer than DUR (e.g. 1h, 30m)."),
                    ("--novel-only", "Suppress events seen in a prior run (new events only)."),
                    ("--follow", "Stream new events as they arrive."),
                    ("--print-journalctl-command", "Print the equivalent journalctl invocation and exit."),
                ],
            },
        ],
        fields: &[],
        exit_status: EXIT_CODES,
        files: &[
            ("/usr/libexec/kennel/", "The helper binaries kenneld resolves (see kennel-helpers via the .8 pages)."),
            ("~/.config/kennel/config.toml", "User CLI conveniences (search paths). See config.toml(5)."),
            ("/etc/kennel/subkennel", "Per-user kennel allocations. See subkennel(5)."),
        ],
        examples: &[
            ("kennel run ai-coding-strict -- claude", "Run Claude Code confined by the ai-coding-strict template."),
            ("kennel run ./policy.toml myjob", "Auto-compile and run a local source policy as kennel 'myjob'."),
            ("kennel list", "Show running kennels."),
            ("kennel audit myjob --follow", "Stream myjob's audit log."),
        ],
        see_also: &["kennel-policy(1)", "kenneld(8)", "policy.toml(5)", "config.toml(5)", "system.toml(5)", "subkennel(5)"],
    },
    // -- kennel-policy(1) ---------------------------------------------------
    Page {
        name: "kennel-policy",
        section: 1,
        summary: "author, inspect, compile, and sign Project Kennel policies",
        synopsis: "\\fBkennel policy\\fR \\fIsub-verb\\fR [\\fIargs\\fR...]",
        description: "\
\\fBkennel policy\\fR is the policy-authoring noun group of \\fBkennel\\fR(1). \
A policy is a TOML file (see \\fBpolicy.toml\\fR(5)) that inherits from a signed \
template chain and may compose signed fragments. These sub-verbs resolve, check, \
compile, and sign policies; none of them need the \\fBkenneld\\fR(8) daemon.

Compilation resolves the inheritance chain and includes, verifies every \
referenced artefact's signature and lockfile pin, and emits a signed settled \
artefact that the daemon enforces at \\fBkennel run\\fR time.",
        commands: &[
            Command {
                usage: SYNC_POLICY[0].2, summary: SYNC_POLICY[0].1, options: &[],
            },
            Command {
                usage: SYNC_POLICY[1].2, summary: SYNC_POLICY[1].1,
                options: &[(COMMON_OPTS[0].0, COMMON_OPTS[0].1), (COMMON_OPTS[1].0, COMMON_OPTS[1].1)],
            },
            Command { usage: SYNC_POLICY[2].2, summary: SYNC_POLICY[2].1, options: &[] },
            Command {
                usage: SYNC_POLICY[3].2, summary: SYNC_POLICY[3].1,
                options: &[("--from <template>", "Scaffold the leaf from this template (default base-confined).")],
            },
            Command {
                usage: SYNC_POLICY[4].2, summary: SYNC_POLICY[4].1,
                options: &[
                    ("--output P", "Write the settled artefact to P."),
                    ("--key K", "Sign the settled artefact with key K."),
                    ("--unsigned", "Emit an unsigned artefact (mutually exclusive with --key)."),
                    ("--require-signed", "Fail unless every referenced artefact is signed."),
                    ("--no-lock", "Do not read or write the kennel.lock pin file."),
                    (COMMON_OPTS[0].0, COMMON_OPTS[0].1),
                    (COMMON_OPTS[1].0, COMMON_OPTS[1].1),
                ],
            },
            Command {
                usage: SYNC_POLICY[5].2, summary: SYNC_POLICY[5].1,
                options: &[
                    ("--require-signed", "Fail unless every referenced artefact is signed."),
                    (COMMON_OPTS[0].0, COMMON_OPTS[0].1),
                    (COMMON_OPTS[1].0, COMMON_OPTS[1].1),
                ],
            },
            Command {
                usage: SYNC_POLICY[6].2, summary: SYNC_POLICY[6].1,
                options: &[
                    ("--key <key>", "The signing key id (required)."),
                    ("--output <path>", "Write the signed artefact to path."),
                ],
            },
            Command {
                usage: SYNC_POLICY[7].2, summary: SYNC_POLICY[7].1,
                options: &[(COMMON_OPTS[0].0, COMMON_OPTS[0].1), (COMMON_OPTS[1].0, COMMON_OPTS[1].1)],
            },
            Command {
                usage: SYNC_POLICY[8].2, summary: SYNC_POLICY[8].1,
                options: &[
                    ("--json", "Emit the structured report (for CI/tooling) instead of the human view."),
                    (COMMON_OPTS[0].0, COMMON_OPTS[0].1),
                    (COMMON_OPTS[1].0, COMMON_OPTS[1].1),
                ],
            },
            Command {
                usage: SYNC_POLICY[9].2, summary: SYNC_POLICY[9].1,
                options: &[
                    ("--yes", "Migrate without the interactive confirmation (for scripts/CI)."),
                    ("--template-dir D", "Add a directory to the template search path (repeatable)."),
                    ("--trust-dir D", "Trust store the new version's signature verifies against (forwarded to the recompile)."),
                ],
            },
        ],
        fields: &[],
        exit_status: EXIT_CODES,
        files: &[
            ("kennel.lock", "The lockfile beside a leaf policy: pins the SHA-256 of every resolved reference."),
            ("~/.config/kennel/keys/", "User signing-key store (run policies; not templates). See config.toml(5)."),
        ],
        examples: &[
            ("kennel policy generate myjob --from ai-coding-strict", "Scaffold a new leaf policy from a template."),
            ("kennel policy validate myjob", "Resolve and check it without writing an artefact."),
            ("kennel policy compile myjob --key my-key-2026", "Compile and sign a settled artefact."),
            ("kennel policy lint", "Check the shipped template corpus for incoherences."),
        ],
        see_also: &["kennel(1)", "policy.toml(5)", "kenneld(8)"],
    },
    // -- kenneld(8) ---------------------------------------------------------
    Page {
        name: "kenneld",
        section: 8,
        summary: "the per-user Project Kennel supervisor daemon",
        synopsis: "\\fBkenneld\\fR",
        description: "\
kenneld is the per-user, socket-activated supervisor for Project Kennel. It is \
not invoked directly: it is started on demand by its systemd socket unit when the \
\\fBkennel\\fR(1) CLI connects, and it persists for the user session.

For each \\fBkennel run\\fR, kenneld verifies the settled policy, invokes the \
\\fBkennel-privhelper\\fR(8) factory to construct the kennel (namespaces, identity \
maps, the constructed view, the per-kennel binderfs bus), acquires binder node 0, \
and supervises the facades and the workload until exit, then tears the kennel down. \
kenneld is unprivileged; the one privilege boundary is the privhelper.

kenneld resolves its helper binaries and trust store through a config cascade; see \
\\fBsystem.toml\\fR(5). Spawn diagnostics are controlled by the \\fIlog_level\\fR key \
there and split across the user and system journals.",
        commands: &[],
        fields: &[],
        exit_status: &[],
        files: &[
            ("/usr/libexec/kennel/", "The helper binaries kenneld forks (see the host-*, facade-*, kennel-* .8 pages)."),
            ("/etc/kennel/system.toml", "Integrity-sensitive deployment config (binary paths, trust store). See system.toml(5)."),
            ("/etc/kennel/keys/", "The daemon's signing-key trust store."),
            ("/etc/kennel/subkennel", "Per-user allocations kenneld requires to start a kennel. See subkennel(5)."),
            ("~/.local/state/kennel/<kennel>/", "Per-kennel audit log (append-only)."),
        ],
        examples: &[],
        see_also: &["kennel(1)", "kennel-privhelper(8)", "system.toml(5)", "subkennel(5)"],
    },
    // -- policy.toml(5) -----------------------------------------------------
    Page {
        name: "policy.toml",
        section: 5,
        summary: "Project Kennel policy file format",
        synopsis: "\\fIpolicy\\fR.toml, \\fItemplate\\fR.toml, \\fIfragment\\fR.toml",
        description: "\
A Project Kennel policy is a TOML file: a leaf policy, a template it inherits from, \
or a fragment it includes. The parser rejects unknown keys, duplicate keys, type \
mismatches, and out-of-range path forms. This page is a field summary; the full \
schema reference, inheritance and signing model, and the [net.*] / [binder] tables \
are in docs/architecture/02-2-config-schema.md.

Paths use \\fB~/\\fR for the kennel persona home (\\fI/home/<user>\\fR, never a host \
path), \\fB/abs\\fR for host-absolute, \\fB<kennel>\\fR for the runtime id, and \
\\fB*\\fR/\\fB**\\fR globs. Execution is deny-by-default.",
        commands: &[],
        fields: &[
            FieldGroup {
                heading: "top-level",
                intro: "Identity and inheritance.",
                fields: &[
                    Field { name: "template_base", kind: "name@vN", desc: "Parent template reference; absent only for the root (base-confined)." },
                    Field { name: "template_name / template_version", kind: "string", desc: "A template's own name and version (templates only)." },
                    Field { name: "name", kind: "string", desc: "The kennel name (leaf policies; matches the filename)." },
                    Field { name: "include", kind: "array of name@vN", desc: "Signed fragments composed additively." },
                    Field { name: "signature", kind: "table", desc: "Signature envelope; required for templates/fragments, optional for leaves." },
                ],
            },
            FieldGroup {
                heading: "[exec]",
                intro: "What may be execve()'d. Deny-by-default.",
                fields: &[
                    Field { name: "allow", kind: "array of path globs", desc: "The execve allowlist; empty denies all. A bare ** is the warned permissive opt-out." },
                    Field { name: "deny", kind: "array of path globs", desc: "Carves exceptions out of allow." },
                    Field { name: "deny_setuid / deny_setgid / deny_setcap / deny_writable", kind: "bool", desc: "Framework invariants (true): refuse setuid/setgid/fcap/writable-path binaries." },
                    Field { name: "path", kind: "array", desc: "$PATH search roots recorded for the workload." },
                    Field { name: "shell", kind: "string", desc: "The login shell (default /bin/sh); must be in allow when an allowlist is enforced." },
                ],
            },
            FieldGroup {
                heading: "[fs]",
                intro: "Filesystem access; write covers create/modify/delete.",
                fields: &[
                    Field { name: "read / write / deny", kind: "array of path globs", desc: "Read (and traverse/execute), write, and categorical denies (deny evaluated first)." },
                ],
            },
            FieldGroup {
                heading: "[fs.home] / [fs.tmp] / [fs.proc] / [fs.dev]",
                intro: "The constructed view sub-tables.",
                fields: &[
                    Field { name: "fs.home.persist", kind: "array", desc: "Home-relative paths that persist writably across runs (else reconstructed each spawn)." },
                    Field { name: "fs.home.readonly", kind: "bool", desc: "Make the constructed $HOME read-only." },
                    Field { name: "fs.tmp.private / .size / .mode", kind: "bool / string / string", desc: "Private /tmp tmpfs, its size cap (\"512M\"), and mode (\"0700\")." },
                    Field { name: "fs.proc.visibility / .hidepid", kind: "string / bool", desc: "Procfs visibility (\"self\") and hidepid=2." },
                    Field { name: "fs.dev.allow", kind: "array of paths", desc: "Trivial pseudo-device baseline (/dev/null, /dev/urandom, ...)." },
                    Field { name: "[[fs.dev.passthrough]]", kind: "array of tables", desc: "Real host devices: path, group, reason (required), threats (exposed tag required)." },
                ],
            },
            FieldGroup {
                heading: "[identity]",
                intro: "The masked persona and supplementary groups.",
                fields: &[
                    Field { name: "user / group", kind: "string", desc: "Masked user and primary group names (default kennel)." },
                    Field { name: "groups", kind: "array", desc: "Supplementary groups to retain; the operator must be a member of each." },
                ],
            },
            FieldGroup {
                heading: "[env]",
                intro: "Environment is synthesised, not inherited.",
                fields: &[
                    Field { name: "set", kind: "table", desc: "Variables forced to a value (the recommended path)." },
                    Field { name: "pass / deny", kind: "array of globs", desc: "Pass-through from the caller (discouraged) and denies over it." },
                ],
            },
            FieldGroup {
                heading: "[net], [net.proxy], [net.bpf], [net.bind], [net.audit]",
                intro: "Egress; see policy.toml's full reference for the complete tables.",
                fields: &[
                    Field { name: "net.mode", kind: "string", desc: "none / constrained (default) / unconstrained / host." },
                    Field { name: "net.reason", kind: "string", desc: "Required when mode = host (reinstates the T1.6 host-recon residual)." },
                    Field { name: "[[net.proxy.allow]]", kind: "array of tables", desc: "By-name/CIDR egress allow (proxied modes): name, cidr, ports, protocol, reason, tls, threats." },
                    Field { name: "[net.bpf]", kind: "tables", desc: "Kernel CIDR+port connect/bind ACL (every mode); author may only narrow." },
                ],
            },
            FieldGroup {
                heading: "[unix]",
                intro: "AF_UNIX socket shim.",
                fields: &[
                    Field { name: "default / abstract", kind: "string", desc: "Default floor and abstract-namespace toggle (both default deny)." },
                    Field { name: "[[unix.allow]]", kind: "array of tables", desc: "name, real, shim, env, reason, threats." },
                ],
            },
            FieldGroup {
                heading: "[ssh]",
                intro: "Per-kennel SSH egress via the bastion (no real key in the kennel).",
                fields: &[
                    Field { name: "allow_headless", kind: "bool", desc: "Allow a non-interactive kennel to drive a key with no touch (loud; threat-tagged)." },
                    Field { name: "[[ssh.destinations]]", kind: "array of tables", desc: "dest, options (host-side ssh argv), reason (required), threats." },
                ],
            },
            FieldGroup {
                heading: "[lifecycle], [cap], [seccomp], [unsafe], [ulimits], [workload], [audit]",
                intro: "The remaining controls.",
                fields: &[
                    Field { name: "lifecycle.ttl / .ttl_action", kind: "string", desc: "TTL (\"8h\") and action: exit (alias stop, default) / warn / renew." },
                    Field { name: "cap.no_new_privs / .bounding_set", kind: "bool / array", desc: "no_new_privs (true) and the capability bounding set (empty drops all)." },
                    Field { name: "seccomp.profile / .deny / .allow", kind: "string / array / array", desc: "Baseline profile plus syscall deny/allow." },
                    Field { name: "[unsafe.ptrace] / [unsafe.signal]", kind: "tables", desc: "Advisory cross-boundary allowlists (allow_targets/allow_from); scoping is from PID-ns/seccomp \\(em these warn, they do not impose the control." },
                    Field { name: "[ulimits]", kind: "table", desc: "setrlimit pairs (nofile, nproc, as, cpu, ...)." },
                    Field { name: "[workload] argv / cwd / pinned / sha256", kind: "mixed", desc: "The command, working dir, pin against CLI override, and binary digest pin." },
                    Field { name: "[audit] sinks + [audit.*]", kind: "tables", desc: "Sink selection and per-class levels; see system.toml(5) and 02-3-audit-schema.md." },
                ],
            },
        ],
        exit_status: &[],
        files: &[
            ("kennel.lock", "Lockfile beside the leaf policy: pins each resolved reference by SHA-256."),
        ],
        examples: &[],
        see_also: &["kennel-policy(1)", "kennel(1)", "system.toml(5)"],
    },
    // -- system.toml(5) -----------------------------------------------------
    Page {
        name: "system.toml",
        section: 5,
        summary: "Project Kennel deployment configuration (integrity-sensitive)",
        synopsis: "/etc/kennel/system.toml, /usr/lib/kennel/system.toml",
        description: "\
system.toml holds the integrity-sensitive paths kenneld resolves at startup: the \
helper-binary directory, the signing-key trust store, and the host sshd. It is \
\\fBnot\\fR user-overridable \\(em kenneld never reads ~/.config for these, because \
letting a user redirect the trust store would defeat policy signing.

Resolution is a cascade, lowest priority first: the vendor copy \
(/usr/lib/kennel/system.toml), then /etc/kennel/system.toml, each key overriding \
the layer below. Compiled-in defaults apply where a key is unset, so a host with no \
file still runs.",
        commands: &[],
        fields: &[
            FieldGroup {
                heading: "",
                intro: "",
                fields: &[
                    Field { name: "libexec_dir", kind: "path", desc: "Directory of kenneld's helper binaries (default /usr/libexec/kennel)." },
                    Field { name: "trust_dir", kind: "path", desc: "The daemon's signing-key trust store (default /etc/kennel/keys)." },
                    Field { name: "sshd", kind: "path", desc: "The host sshd the per-user SSH bastion launches (default /usr/sbin/sshd)." },
                    Field { name: "log_level", kind: "string", desc: "Spawn-path diagnostic verbosity: info (default), debug, trace. Splits across the user and system journals." },
                ],
            },
            FieldGroup {
                heading: "per-binary overrides",
                intro: "Absolute paths; each defaults to <libexec_dir>/<name>. Override one binary's location:",
                fields: &[
                    Field { name: "privhelper", kind: "path", desc: "kennel-privhelper \\(em the suid privilege boundary." },
                    Field { name: "netproxy", kind: "path", desc: "host-netproxy \\(em egress CONNECT delegate." },
                    Field { name: "socks5", kind: "path", desc: "facade-socks5 \\(em in-kennel SOCKS5/HTTP front-end." },
                    Field { name: "inetd", kind: "path", desc: "host-inetd \\(em inbound BIND mirror delegate." },
                    Field { name: "facade_client", kind: "path", desc: "facade-client \\(em in-kennel inbound BIND pull end." },
                    Field { name: "afunix", kind: "path", desc: "facade-afunix \\(em AF_UNIX socket-shim facade." },
                    Field { name: "ssh", kind: "path", desc: "facade-ssh \\(em in-kennel SSH egress connector." },
                    Field { name: "akc", kind: "path", desc: "kennel-akc \\(em sshd AuthorizedKeysCommand helper." },
                    Field { name: "init", kind: "path", desc: "kennel-bin-init \\(em trusted uid-0 PID 1." },
                ],
            },
        ],
        exit_status: &[],
        files: &[
            ("/usr/lib/kennel/system.toml", "Vendor (lowest-priority) copy installed by the package."),
            ("/etc/kennel/system.toml", "Administrator overrides (highest priority)."),
        ],
        examples: &[],
        see_also: &["kenneld(8)", "config.toml(5)", "kennel(1)"],
    },
    // -- config.toml(5) -----------------------------------------------------
    Page {
        name: "config.toml",
        section: 5,
        summary: "Project Kennel user CLI configuration",
        synopsis: "~/.config/kennel/config.toml, /etc/kennel/config.toml, /usr/lib/kennel/config.toml",
        description: "\
config.toml holds conveniences for the \\fBkennel\\fR(1) CLI: where it searches for \
templates, signing keys, and run policies while authoring. It is safe to edit as a \
user \\(em it only steers the CLI's search, never enforcement. The daemon enforces \
against its own locked trust store (system.toml's trust_dir) regardless of anything \
here.

Search order, highest priority first: ~/.config/kennel/config.toml (or \
$XDG_CONFIG_HOME), /etc/kennel/config.toml, then the vendor copy. A set list \
\\fBreplaces\\fR the built-in three-layer default for that key.",
        commands: &[],
        fields: &[
            FieldGroup {
                heading: "",
                intro: "Each is a list of absolute paths (no ~ expansion).",
                fields: &[
                    Field { name: "template_dirs", kind: "array of paths", desc: "Where compile/validate resolve <name>@<version>." },
                    Field { name: "key_dirs", kind: "array of paths", desc: "The authoring trust store. Note the trust split: templates verify only against the SYSTEM stores, never ~/.config/kennel/keys." },
                    Field { name: "policy_dirs", kind: "array of paths", desc: "Where kennel run <name> resolves a policy by name." },
                ],
            },
        ],
        exit_status: &[],
        files: &[
            ("~/.config/kennel/keys/", "User signing keys (valid for run policies, not templates)."),
        ],
        examples: &[],
        see_also: &["kennel(1)", "kennel-policy(1)", "system.toml(5)"],
    },
    // -- subkennel(5) -------------------------------------------------------
    Page {
        name: "subkennel",
        section: 5,
        summary: "Project Kennel per-user allocation file",
        synopsis: "/etc/kennel/subkennel",
        description: "\
/etc/kennel/subkennel records, one line per user, the per-user resources a kennel \
draws on \\(em analogous to /etc/subuid and /etc/subgid. A user with no valid line \
cannot start \\fBkenneld\\fR(8). Use \\fBkennel subkennel add\\fR to append a \
provably-valid line and \\fBkennel subkennel check\\fR to validate the file.

Each line is colon-separated: \\fIuid\\fB:\\fItag\\fB:\\fIgid\\fB:\\fInamespace\\fR. \
Fields after the fourth are ignored. Blank lines and lines beginning with # are \
comments.",
        commands: &[],
        fields: &[
            FieldGroup {
                heading: "fields",
                intro: "uid:tag:gid:namespace",
                fields: &[
                    Field { name: "uid", kind: "decimal", desc: "The owning user's uid." },
                    Field { name: "tag", kind: "decimal", desc: "A per-user 12-bit tag (0..4095), unique per uid; partitions the kennel's reserved ranges." },
                    Field { name: "gid", kind: "10 hex digits", desc: "The reserved gid base, exactly ten lowercase hex digits." },
                    Field { name: "namespace", kind: "string", desc: "The allocation namespace (non-empty)." },
                ],
            },
        ],
        exit_status: &[],
        files: &[("/etc/kennel/subkennel", "The allocation file itself.")],
        examples: &[
            ("kennel subkennel add --uid 1000", "Append a collision-free allocation for uid 1000."),
            ("kennel subkennel check", "Validate every line and report malformed ones."),
        ],
        see_also: &["kennel(1)", "kenneld(8)"],
    },
    // -- helper .8 pages (terse) -------------------------------------------
    helper("host-netproxy", "egress CONNECT delegate (the dumb dialer)",
        "host-netproxy is kenneld's host-network-namespace egress delegate. kenneld \
resolves and pins a destination, then hands this process the pinned address and a \
conduit; it dials and splices. It holds no policy and no binder access."),
    helper("host-inetd", "inbound BIND mirror delegate",
        "host-inetd is kenneld's host-side inbound-BIND delegate (the reverse of \
host-netproxy). For each policy-mirrored port it binds the kennel's loopback alias \
on the host, accepts, splices locally, and pushes the conduit's kennel end back to \
kenneld. It holds no policy. See the §7.5.7 mirror."),
    helper("facade-socks5", "in-kennel SOCKS5/HTTP egress front-end",
        "facade-socks5 runs inside the kennel network namespace as the workload-facing \
egress endpoint. It speaks SOCKS5 and HTTP-proxy on one port, forwards each request \
across the binder gateway (CONNECT_INET) to kenneld, and splices. It carries no \
policy."),
    helper("facade-client", "in-kennel inbound BIND pull end",
        "facade-client runs inside the kennel as the in-kennel end of the inbound BIND \
mirror (the reverse of facade-socks5). For each mirrored port it pulls inbound \
connections from kenneld over binder (BIND_INET), connects the workload's native \
listener, and splices. It carries no policy."),
    helper("facade-afunix", "AF_UNIX socket-shim facade",
        "facade-afunix is the in-kennel end of the brokered AF_UNIX socket shim. A \
granted [[unix.allow]] socket is reached by a binder CONNECT to kenneld, which \
performs the host-side connect and returns the connected fd; the real path never \
enters the kennel view."),
    helper("facade-ssh", "in-kennel SSH egress connector",
        "facade-ssh is the in-kennel connector for per-kennel SSH egress. The kennel \
never holds a real key; this process reaches the re-origination bastion, which runs \
the host-side ssh as the operator against a destination fixed by which synthetic \
key authenticated."),
    helper("kennel-akc", "sshd AuthorizedKeysCommand helper",
        "kennel-akc is the root-owned AuthorizedKeysCommand helper for the per-kennel \
SSH egress bastion. sshd invokes it to fetch the synthetic public key for a \
connecting kennel; it queries the running kenneld. Bindings live only in kenneld \\(em \
there is no authorized_keys file."),
    helper("kennel-bin-init", "trusted uid-0 PID 1 inside a kennel",
        "kennel-bin-init is the kennel's PID 1: a trusted, root-owned binary the \
privhelper factory fexecves after pivot_root. It makes no policy decisions \\(em it \
pulls a supervision plan from kenneld over binder and executes it verbatim, forking \
the facades and the workload and reaping them."),
    helper("kennel-privhelper", "the suid privilege boundary and kennel factory",
        "kennel-privhelper is the one privileged component: a setuid-root helper (file \
caps, never sudo) that performs the address add/delete, egress setup, and the \
ConstructKennel factory operation (namespaces, identity maps, the constructed view, \
binderfs). It validates every request and drops privilege; everything else runs as \
the user."),
];

/// Build a terse section-8 helper page: SYNOPSIS, a one-paragraph role, the
/// not-user-invoked note, and SEE ALSO kenneld(8). These binaries are forked by
/// kenneld, never run by hand, but each gets a real page so `man <name>` resolves.
const fn helper(name: &'static str, summary: &'static str, role: &'static str) -> Page {
    Page {
        name,
        section: 8,
        summary,
        synopsis: "(internal \\(em forked by kenneld(8), not invoked directly)",
        description: role,
        commands: &[],
        fields: &[],
        exit_status: &[],
        files: &[],
        examples: &[],
        see_also: &["kenneld(8)", "kennel(1)"],
    }
}
