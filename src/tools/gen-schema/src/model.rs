//! The policy-schema data model — every authored `[table]` and field, as plain Rust.
//!
//! This mirrors the `kennel-lib-compile` source structs (`source.rs`, plus the `[audit]`
//! and `[signature]` shapes from `kennel-lib-policy`). It is the **single source for the
//! emitted JSON Schema**, and it is kept honest by the schema↔parser cross-check test in
//! `kennel-lib-compile` (a dev-dependency on this crate): the test builds a TOML document
//! that exercises every field here and asserts the real parser accepts it, and that the
//! parser rejects a field this model does not declare. So a field added to the parser
//! without a matching entry here — or vice versa — fails CI, exactly as `gen-man`'s
//! command tables are pinned to the CLI dispatch tables.
//!
//! Tables are referenced by name (`Ty::Obj`/`Ty::ObjArray`) and collected into JSON
//! Schema `$defs` by the emitter; [`root()`] is the document's top-level object.

/// The shape of one field's value.
pub enum Ty {
    /// A free string.
    Str,
    /// A string constrained to an explicit set of values (JSON Schema `enum`).
    Enum(&'static [&'static str]),
    /// A boolean.
    Bool,
    /// A non-negative integer.
    Int,
    /// A TCP/UDP port (`u16`: 0–65535).
    Port,
    /// An array of strings.
    StrArray,
    /// An array of ports.
    PortArray,
    /// A table of `string = string` pairs (`[ulimits]`, `[env].set`).
    Map,
    /// A single nested table, referenced by its [`Table::name`].
    Obj(&'static str),
    /// An array-of-tables (`[[…]]`), referenced by its [`Table::name`].
    ObjArray(&'static str),
}

/// One field of a table.
pub struct Field {
    /// The TOML key.
    pub key: &'static str,
    /// Its value shape.
    pub ty: Ty,
    /// Whether the field is required (JSON Schema `required`). Almost everything in an
    /// authored policy is optional (sections compose by delta); only a couple of
    /// array-entry keys are mandatory (e.g. a deny rule's `cidr`).
    pub required: bool,
    /// One-line description, surfaced as hover documentation in an editor.
    pub desc: &'static str,
}

/// A named object definition — the root policy or one `[table]`.
pub struct Table {
    /// The def name (the `$defs` key; also the `Ty::Obj`/`ObjArray` reference target).
    pub name: &'static str,
    /// One-line description of the table.
    pub title: &'static str,
    /// Its fields, in emission order.
    pub fields: &'static [Field],
}

const fn f(key: &'static str, ty: Ty, desc: &'static str) -> Field {
    Field {
        key,
        ty,
        required: false,
        desc,
    }
}

const fn req(key: &'static str, ty: Ty, desc: &'static str) -> Field {
    Field {
        key,
        ty,
        required: true,
        desc,
    }
}

/// The set of threat IDs an entry exposes / mitigates — reused on every grant.
const THREATS: &[Field] = &[
    f(
        "exposed",
        Ty::StrArray,
        "Threat IDs this entry weakens defence against.",
    ),
    f(
        "mitigated",
        Ty::StrArray,
        "Threat IDs this entry actively mitigates.",
    ),
];

/// The root document and every `[table]`/`[[table]]`. The first entry, `policy`, is the
/// top-level object; the rest are `$defs`.
pub static TABLES: &[Table] = &[
    Table {
        name: "policy",
        title: "A Project Kennel source policy — a template, fragment, or leaf, as authored in TOML (`docs/architecture/02-2-config-schema.md`). Every key is optional unless noted; unknown keys are rejected by the compiler.",
        fields: &[
            f("template_base", Ty::Str, "Versioned reference to the parent template (`<name>@v<ver>`). Absent only for the root template."),
            f("template_version", Ty::Str, "This artefact's own version."),
            f("template_name", Ty::Str, "The template's own name (present on templates, absent on leaves)."),
            f("name", Ty::Str, "The kennel name (present on leaf policies, absent on templates)."),
            f("include", Ty::StrArray, "Additional signed fragments composed additively (versioned references)."),
            f("threat_catalogue_version", Ty::Str, "The THREATS.md catalogue version this artefact was authored against."),
            f("signature", Ty::Obj("signature"), "Detached signature envelope over the artefact's canonical content (required for templates/fragments, optional for leaves)."),
            f("cap", Ty::Obj("cap"), "Capabilities and no_new_privs."),
            f("exec", Ty::Obj("exec"), "What may be execve()'d."),
            f("fs", Ty::Obj("fs"), "Filesystem grants and the constructed view."),
            f("net", Ty::Obj("net"), "Network egress/bind policy."),
            f("unix", Ty::Obj("unix"), "AF_UNIX socket policy."),
            f("ssh", Ty::Obj("ssh"), "Per-kennel SSH egress (the re-origination bastion)."),
            f("identity", Ty::Obj("identity"), "The workload's masked identity and supplementary groups."),
            f("binder", Ty::Obj("binder"), "User-defined binder IPC services this kennel may register/look up."),
            f("unsafe", Ty::Obj("unsafe"), "Advisory footgun sub-sections (scoping enforced by the PID namespace + seccomp)."),
            f("env", Ty::Obj("env"), "Environment curation."),
            f("seccomp", Ty::Obj("seccomp"), "The seccomp filter."),
            f("lifecycle", Ty::Obj("lifecycle"), "TTL and TTL action."),
            f("audit", Ty::Obj("audit"), "Audit sinks and per-class levels."),
            f("ulimits", Ty::Map, "setrlimit(2) resource limits as `name = \"soft\"` or `name = \"soft:hard\"`."),
            f("workload", Ty::Obj("workload"), "The command the kennel runs, optionally pinned."),
            f("tty", Ty::Obj("tty"), "Terminal hardening for an interactive (PTY) workload."),
            f("trust", Ty::Obj("trust"), "The masked workspace trust manifest (T2.8)."),
            f("dbus", Ty::Obj("dbus"), "D-Bus mediation via the IDBus facade (§7.7)."),
            f("rootfs", Ty::Obj("rootfs"), "`[rootfs]` — boot an unpacked OCI image as the kennel root (OCI run model only; §7.11). A loud substrate-trust grant: rejected by `kennel run`, required by `kennel oci run`."),
        ],
    },
    Table {
        name: "signature",
        title: "Detached signature envelope over the artefact's canonical content.",
        fields: &[
            req("algorithm", Ty::Str, "The signature algorithm (e.g. `ed25519`)."),
            req("key_id", Ty::Str, "Identifier of the signing key."),
            req("signature", Ty::Str, "The signature value (base64/hex)."),
            f("signed_fields", Ty::StrArray, "The canonical field list the signature covers."),
        ],
    },
    Table {
        name: "cap",
        title: "`[cap]` — capabilities and no_new_privs.",
        fields: &[
            f("no_new_privs", Ty::Bool, "PR_SET_NO_NEW_PRIVS (a framework invariant once resolved: must be true)."),
            f("bounding_set", Ty::StrArray, "The capability bounding set to retain (empty drops them all)."),
        ],
    },
    Table {
        name: "exec",
        title: "`[exec]` — the execve allowlist (deny-by-default).",
        fields: &[
            f("allow", Ty::StrArray, "Allowlisted binary paths. Empty/absent denies all execve; a bare `**` is the permissive opt-out (warned)."),
            f("deny", Ty::StrArray, "Denylisted absolute paths or globs."),
            f("deny_setuid", Ty::Bool, "Refuse setuid binaries at execve (framework invariant)."),
            f("deny_setgid", Ty::Bool, "Refuse setgid binaries (framework invariant)."),
            f("deny_setcap", Ty::Bool, "Refuse file-capability binaries (framework invariant)."),
            f("deny_writable", Ty::Bool, "Refuse execution of files in writable paths (framework invariant)."),
            f("path", Ty::StrArray, "PATH search roots recorded for the workload's environment."),
            f("shell", Ty::Str, "The kennel's login shell (default `/bin/sh`; must be in `allow` when an allowlist is enforced)."),
        ],
    },
    Table {
        name: "fs",
        title: "`[fs]` and its sub-tables.",
        fields: &[
            f("read", Ty::StrArray, "Paths granted read (and directory traversal / execute)."),
            f("write", Ty::StrArray, "Paths granted write."),
            f("exclusive", Ty::StrArray, "Writable paths bound exclusively: kenneld over-mounts an opaque sentinel on the host path during the run (T2.8). Each must also appear in `write`."),
            f("deny", Ty::StrArray, "Categorical denies (belt-and-braces over the constructed view)."),
            f("home", Ty::Obj("fs_home"), "The constructed $HOME view."),
            f("tmp", Ty::Obj("fs_tmp"), "The private /tmp tmpfs."),
            f("proc", Ty::Obj("fs_proc"), "procfs visibility."),
            f("dev", Ty::Obj("fs_dev"), "The minimal /dev."),
        ],
    },
    Table {
        name: "fs_home",
        title: "`[fs.home]` — the constructed-$HOME shim.",
        fields: &[
            f("shadow", Ty::Bool, "Whether $HOME is shadowed by a constructed view (must be true once resolved)."),
            f("persist", Ty::StrArray, "Home-relative paths that persist across runs (opt-in, per path; visible in the diff)."),
            f("readonly", Ty::Bool, "Make the constructed $HOME read-only (default: writable but ephemeral tmpfs)."),
        ],
    },
    Table {
        name: "fs_tmp",
        title: "`[fs.tmp]` — private /tmp.",
        fields: &[
            f("private", Ty::Bool, "Whether /tmp is a private tmpfs."),
            f("size", Ty::Str, "Size cap in human form (`512M`, `1G`)."),
            f("mode", Ty::Str, "Mount mode (octal digits, e.g. `0700`)."),
        ],
    },
    Table {
        name: "fs_proc",
        title: "`[fs.proc]` — procfs visibility and hidepid.",
        fields: &[
            f("visibility", Ty::Enum(&["self"]), "Visibility (`self` is the only permitted value once resolved)."),
            f("hidepid", Ty::Bool, "Mount /proc with hidepid=2."),
        ],
    },
    Table {
        name: "fs_dev",
        title: "`[fs.dev]` — the constructed /dev allowlist.",
        fields: &[
            f("allow", Ty::StrArray, "Pseudo-device baseline bound into the kennel's /dev (`/dev/null`, `/dev/urandom`, …)."),
            f("passthrough", Ty::ObjArray("dev_passthrough"), "`[[fs.dev.passthrough]]` — specific real host devices exposed to the kennel (each loud: reason + threat tag required)."),
        ],
    },
    Table {
        name: "dev_passthrough",
        title: "One `[[fs.dev.passthrough]]` entry — a host device made available in the kennel's /dev.",
        fields: &[
            f("path", Ty::Str, "The device node, an absolute path under /dev (e.g. `/dev/ttyUSB0`)."),
            f("group", Ty::Str, "The owning group that gates access (DAC; the user must already be a member)."),
            f("reason", Ty::Str, "Why this device is exposed (required)."),
            f("threats", Ty::Obj("threats"), "Threat tags — must carry an `exposed` tag."),
        ],
    },
    Table {
        name: "rootfs",
        title: "`[rootfs]` — an OCI image unpacked as the kennel's root filesystem (OCI run model; design §7.11). Substrate-trust waiver T3.8. **Mutually exclusive with `[workload]`**: an OCI policy has a mandatory `[rootfs]` and never a `[workload]` (the compiler refuses both). There is no per-binary pin in the OCI model — `[workload].sha256` does not apply; execution integrity rests on the image **digest** (the runner checks `[rootfs].image` against the recorded digest) plus the operator's unconfined `kennel oci run … -- <cmd>` invocation, not a daemon-enforced cryptographic pin of the entrypoint binary.",
        fields: &[
            req("path", Ty::Str, "The unpacked image rootfs (the store entry's `rootfs/`). Its presence marks the policy OCI-model."),
            req("image", Ty::Str, "The `image@sha256:…` the build pulled from; the runner refuses unless it equals the store entry's recorded digest."),
            req("reason", Ty::Str, "Why this substrate is trusted (required; the substrate-trust waiver is loud)."),
            f("persistence", Ty::Enum(&["discard", "persist"]), "Rootfs persistence (§7.11.4a): `discard` (default; ephemeral upper, gone at teardown) | `persist` (managed upper under the store entry — a loud value the risk engine derives an exposure from)."),
            f("readonly", Ty::StrArray, "Closure-lock (§7.11.4c): rootfs paths Landlock denies writes to (the executable-closure boundary the DAC-flatten erased; the FHS closure is build-derived for a non-root image). `[\"/\"]` is whole-tree-immutable. Longest-prefix wins with `writable`."),
            f("writable", Ty::StrArray, "Closure-lock holes (§7.11.4c): rootfs paths to keep writable, carved back out of `readonly` (longest-prefix wins). Loud — each carve-out derives its own risk line."),
        ],
    },
    Table {
        name: "net",
        title: "`[net]` and its sub-tables.",
        fields: &[
            f("mode", Ty::Enum(&["none", "constrained", "unconstrained", "host"]), "Egress mode (default `constrained`). `host` shares the host network stack and reinstates the host-recon residual."),
            f("reason", Ty::Str, "Required only when `mode = host`: the documented justification for sharing the host network stack."),
            f("proxy_listen_v4_address", Ty::Str, "IPv4 proxy listen address as `offset:port` within the kennel's subnet (presence enables the family)."),
            f("proxy_listen_v6_address", Ty::Str, "IPv6 proxy listen address as `offset:port`."),
            f("proxy", Ty::Obj("net_proxy"), "The user-space egress policy the per-kennel proxy enforces (constrained/unconstrained)."),
            f("bpf", Ty::Obj("net_bpf"), "The kernel/syscall ACL (cgroup connect/bind BPF + Landlock): CIDR + ports, no names."),
            f("bind", Ty::Obj("net_bind"), "Bind-address rewriting policy."),
            f("ipv6", Ty::Obj("net_ipv6"), "IPv6-specific options."),
            f("audit", Ty::Obj("net_audit"), "Per-kennel egress audit log."),
        ],
    },
    Table {
        name: "net_proxy",
        title: "`[net.proxy]` — the user-space egress policy (proxied modes only; a rule under `mode=host` is a compile error).",
        fields: &[
            f("allow", Ty::ObjArray("net_allow"), "`[[net.proxy.allow]]` — by-name (or by-CIDR) egress allow entries."),
            f("deny", Ty::Obj("net_proxy_deny"), "The deny table: the non-removable invariant floor and the optional author policy denylist."),
        ],
    },
    Table {
        name: "net_proxy_deny",
        title: "`[net.proxy.deny]` — the framework floor plus the optional author denylist.",
        fields: &[
            f("invariant", Ty::ObjArray("net_deny_rule"), "`[[net.proxy.deny.invariant]]` — cloud-metadata / link-local, non-removable (T1.6)."),
            f("policy", Ty::ObjArray("net_deny_rule"), "`[[net.proxy.deny.policy]]` — the author's optional denylist."),
        ],
    },
    Table {
        name: "net_bpf",
        title: "`[net.bpf]` — the kernel/syscall ACL (socket-family shaping + directional connect/bind gates).",
        fields: &[
            f("families", Ty::StrArray, "Permitted socket families (e.g. `AF_INET`, `AF_INET6`, `AF_UNIX`)."),
            f("deny_families", Ty::StrArray, "Denied socket families (`AF_NETLINK`, `AF_PACKET`, …)."),
            f("connect", Ty::Obj("net_bpf_acl"), "`[net.bpf.connect]` — the outbound CONNECT ACL (deny-first)."),
            f("bind", Ty::Obj("net_bpf_acl"), "`[net.bpf.bind]` — the inbound BIND ACL (deny-first)."),
        ],
    },
    Table {
        name: "net_bpf_acl",
        title: "One direction of the `[net.bpf]` kernel ACL: CIDR+port allow/deny, deny-first.",
        fields: &[
            f("allow", Ty::ObjArray("bpf_rule"), "CIDR+port allow rules."),
            f("deny", Ty::ObjArray("bpf_rule"), "CIDR+port deny rules (deny-first)."),
        ],
    },
    Table {
        name: "bpf_rule",
        title: "One `[net.bpf]` rule: a CIDR (or `*`) + ports + protocol. No name field — the kernel ACL cannot resolve names.",
        fields: &[
            f("cidr", Ty::Str, "The CIDR (`10.0.0.0/8`, a bare address, or `*` = any host)."),
            f("ports", Ty::PortArray, "Permitted ports (empty = any port)."),
            f("protocol", Ty::Enum(&["tcp", "udp", "any"]), "Transport protocol."),
            f("reason", Ty::Str, "Why this rule exists (required)."),
            f("threats", Ty::Obj("threats"), "Threat tags."),
        ],
    },
    Table {
        name: "net_allow",
        title: "One `[[net.proxy.allow]]` entry.",
        fields: &[
            f("name", Ty::Str, "The destination host (or dot-prefixed suffix)."),
            f("cidr", Ty::Str, "A CIDR destination, when the rule is by-address rather than by-name."),
            f("ports", Ty::PortArray, "Permitted ports."),
            f("protocol", Ty::Enum(&["tcp", "udp", "any"]), "Transport protocol."),
            f("reason", Ty::Str, "Why this destination is permitted (required)."),
            f("tls", Ty::Obj("net_tls"), "TLS requirements for the destination."),
            f("threats", Ty::Obj("threats"), "Threat tags."),
        ],
    },
    Table {
        name: "net_tls",
        title: "`tls.*` on a `[[net.proxy.allow]]` entry.",
        fields: &[f("required", Ty::Bool, "Whether TLS is required to the destination.")],
    },
    Table {
        name: "net_deny_rule",
        title: "One `[[net.proxy.deny.invariant]]` / `[[net.proxy.deny.policy]]` entry.",
        fields: &[
            req("cidr", Ty::Str, "The denied CIDR (e.g. `169.254.169.254/32`)."),
            f("reason", Ty::Str, "Why the deny exists (required)."),
            f("threats", Ty::Obj("threats"), "Threat tags."),
        ],
    },
    Table {
        name: "net_bind",
        title: "`[net.bind]` — bind-address handling (the wildcard-rewrite knobs; the allow/deny gate is `[net.bpf.bind]`).",
        fields: &[
            f("inaddr_any_policy", Ty::Enum(&["rewrite", "deny"]), "What to do with a wildcard IPv4 bind."),
            f("in6addr_any_policy", Ty::Enum(&["rewrite", "deny"]), "What to do with a wildcard IPv6 bind."),
            f("allow_host_loopback_v4", Ty::Bool, "Whether binding the host IPv4 loopback is permitted."),
            f("allow_host_loopback_v6", Ty::Bool, "Whether binding the host IPv6 loopback is permitted."),
            f("min_port", Ty::Port, "Lowest bindable port."),
            f("allowed_ports", Ty::PortArray, "Explicit allowlist of bindable ports (empty = any at or above min_port)."),
        ],
    },
    Table {
        name: "net_ipv6",
        title: "`[net.ipv6]`.",
        fields: &[f("force_v6only", Ty::Bool, "Force IPV6_V6ONLY=1 so a dual-stack socket cannot escape the v4 rewrite.")],
    },
    Table {
        name: "net_audit",
        title: "`[net.audit]` — per-kennel egress audit log.",
        fields: &[
            f("log_path", Ty::Str, "Where the per-kennel egress JSONL log is written."),
            f("level", Ty::Enum(&["summary", "full"]), "Audit verbosity."),
        ],
    },
    Table {
        name: "unix",
        title: "`[unix]` — AF_UNIX policy.",
        fields: &[
            f("default", Ty::Enum(&["deny", "allow"]), "Default disposition (`allow` is forbidden once resolved)."),
            f("abstract", Ty::Enum(&["deny", "allow"]), "Abstract-namespace socket disposition."),
            f("allow", Ty::ObjArray("unix_allow"), "`[[unix.allow]]` — granted sockets, including per-kennel service instances."),
        ],
    },
    Table {
        name: "unix_allow",
        title: "One `[[unix.allow]]` entry.",
        fields: &[
            f("name", Ty::Str, "A logical name (e.g. `ssh-agent`) for a per-kennel service instance."),
            f("real", Ty::Str, "The real host socket path."),
            f("shim", Ty::Str, "The shim path the socket is bound at inside the kennel."),
            f("env", Ty::Str, "An environment variable to set to the shim path (e.g. `SSH_AUTH_SOCK`)."),
            f("reason", Ty::Str, "Why this socket is granted (required)."),
            f("threats", Ty::Obj("threats"), "Threat tags."),
        ],
    },
    Table {
        name: "binder",
        title: "`[binder]` — user-defined binder IPC services (the reserved `org.projectkennel.*` facades are never declared here).",
        fields: &[
            f("provide", Ty::ObjArray("binder_provide"), "`[[binder.provide]]` — services a process in this kennel may register."),
            f("consume", Ty::ObjArray("binder_consume"), "`[[binder.consume]]` — services this kennel may look up (cross-instance)."),
        ],
    },
    Table {
        name: "binder_provide",
        title: "One `[[binder.provide]]` entry.",
        fields: &[
            f("name", Ty::Str, "The service name (must not begin with the reserved `org.projectkennel.`)."),
            f("accept_from", Ty::StrArray, "Peer kennels permitted to look this service up (cross-instance)."),
            f("reason", Ty::Str, "Why this service is provided (required)."),
            f("threats", Ty::Obj("threats"), "Threat tags."),
        ],
    },
    Table {
        name: "binder_consume",
        title: "One `[[binder.consume]]` entry.",
        fields: &[
            f("name", Ty::Str, "The service name (must not begin with the reserved `org.projectkennel.`)."),
            f("from", Ty::Str, "The providing kennel (cross-instance); absent for a local service."),
            f("reason", Ty::Str, "Why this service is consumed (required)."),
            f("threats", Ty::Obj("threats"), "Threat tags."),
        ],
    },
    Table {
        name: "identity",
        title: "`[identity]` — the workload's masked identity and supplementary groups.",
        fields: &[
            f("user", Ty::Str, "The masked user name ($USER/$LOGNAME and synthetic passwd account). Default `kennel`."),
            f("group", Ty::Str, "The masked primary group name. Default `kennel`."),
            f("groups", Ty::StrArray, "Supplementary group names to retain (the user must be a member of each)."),
        ],
    },
    Table {
        name: "ssh",
        title: "`[ssh]` — per-kennel SSH egress (the re-origination bastion; a kennel never holds a real key).",
        fields: &[
            f("allow_headless", Ty::Bool, "Whether a granted key may be driven by a non-interactive (CI) kennel with no per-use touch. Loud; default false."),
            f("threats", Ty::Obj("threats"), "Threat tags for the section — must carry an `exposed` tag when `allow_headless = true`."),
            f("destinations", Ty::ObjArray("ssh_destination"), "`[[ssh.destinations]]` — the SSH egress allowlist."),
        ],
    },
    Table {
        name: "ssh_destination",
        title: "One `[[ssh.destinations]]` entry — a destination the kennel may reach over the bastion.",
        fields: &[
            f("dest", Ty::Str, "The SSH destination as the host-side `ssh` is invoked with it (`git@github.com`, a config alias)."),
            f("options", Ty::StrArray, "Host-side `ssh` invocation options, passed verbatim as argv tokens before `<dest>` (run as the operator)."),
            f("reason", Ty::Str, "Why this destination is granted (required)."),
            f("threats", Ty::Obj("threats"), "Threat tags."),
        ],
    },
    Table {
        name: "workload",
        title: "`[workload]` — the command the kennel runs, optionally pinned.",
        fields: &[
            f("argv", Ty::StrArray, "The command + args (argv[0] is the program). Absent ⇒ supplied at `kennel run`."),
            f("cwd", Ty::Str, "Working directory inside the view (may carry a `~`/`<home>` placeholder)."),
            f("pinned", Ty::Bool, "Refuse a CLI `--` override of argv unless `--force`."),
            f("sha256", Ty::StrArray, "Accepted lowercase-hex SHA-256 digests of the workload binary, verified before exec."),
        ],
    },
    Table {
        name: "unsafe",
        title: "`[unsafe]` — advisory footgun umbrella (scoping enforced by the PID namespace + seccomp, not by these tables).",
        fields: &[
            f("ptrace", Ty::Obj("boundary_acl"), "`[unsafe.ptrace]` — ptrace across the kennel boundary."),
            f("signal", Ty::Obj("boundary_acl"), "`[unsafe.signal]` — signalling across the kennel boundary."),
        ],
    },
    Table {
        name: "boundary_acl",
        title: "A cross-boundary allowlist, shared by `[unsafe.ptrace]` and `[unsafe.signal]`.",
        fields: &[
            f("allow_targets", Ty::StrArray, "Permitted targets (`self`, …)."),
            f("allow_from", Ty::StrArray, "Permitted sources."),
        ],
    },
    Table {
        name: "env",
        title: "`[env]` — environment curation (the environment is synthesised, not inherited).",
        fields: &[
            f("pass", Ty::StrArray, "Variables passed through from the caller's environment (globs allowed; discouraged, per-variable)."),
            f("deny", Ty::StrArray, "Variables denied even if passed (globs allowed)."),
            f("set", Ty::Map, "Variables forced to a specific value (`KEY = \"value\"`)."),
        ],
    },
    Table {
        name: "seccomp",
        title: "`[seccomp]` — the seccomp filter.",
        fields: &[
            f("profile", Ty::Str, "The baseline profile name (`default`)."),
            f("deny", Ty::StrArray, "Syscalls denied on top of the profile."),
            f("allow", Ty::StrArray, "Syscalls explicitly allowed."),
        ],
    },
    Table {
        name: "lifecycle",
        title: "`[lifecycle]` — TTL and TTL action.",
        fields: &[
            f("ttl", Ty::Str, "Time-to-live in human form (`8h`, `30m`)."),
            f("ttl_action", Ty::Enum(&["exit", "stop", "warn", "renew"]), "What to do at TTL expiry (default `exit`; `stop` is an alias)."),
        ],
    },
    Table {
        name: "tty",
        title: "`[tty]` — terminal hardening for an interactive (PTY) workload.",
        fields: &[f(
            "filter_terminal_escapes",
            Ty::Bool,
            "Filter dangerous escape sequences (OSC 52 clipboard, notifications, opaque bands) from the workload's PTY output. Default true.",
        )],
    },
    Table {
        name: "trust",
        title: "`[trust]` — the masked workspace manifest (T2.8).",
        fields: &[
            f("manifest", Ty::Bool, "Maintain a masked `.trust-manifest.json` at every writable workspace root. Default true."),
            f("on_change", Ty::Enum(&["warn", "freeze", "kill"]), "What kenneld does when a watched trigger is mutated during the run (default `warn`)."),
        ],
    },
    Table {
        name: "dbus",
        title: "`[dbus]` — D-Bus mediation (§7.7). Absent ⇒ no bus access (no facade node).",
        fields: &[
            f("session", Ty::Obj("dbus_bus"), "`[dbus.session]` — the user session bus (notifications, portals)."),
            f("system", Ty::Obj("dbus_bus"), "`[dbus.system]` — the system bus (rarely needed)."),
            f("audit", Ty::Obj("dbus_audit"), "`[dbus.audit]` — per-kennel D-Bus call audit verbosity."),
        ],
    },
    Table {
        name: "dbus_bus",
        title: "One bus's enable flag and rule set (`[dbus.session]` / `[dbus.system]`).",
        fields: &[
            f("enabled", Ty::Bool, "Whether this bus is reachable at all (default false ⇒ no facade node)."),
            f("allow", Ty::Obj("dbus_rules"), "`[dbus.<bus>.allow]` — what the kennel may reach (allowlist; default-deny)."),
            f("deny", Ty::Obj("dbus_rules"), "`[dbus.<bus>.deny]` — belt-and-braces explicit denies."),
        ],
    },
    Table {
        name: "dbus_rules",
        title: "The four D-Bus rule classes at destination/interface/member granularity.",
        fields: &[
            f("talk", Ty::StrArray, "Destinations the kennel may call methods on and receive replies/signals from."),
            f("call", Ty::StrArray, "Finer than `talk`: specific `destination=interface.member` calls."),
            f("broadcast", Ty::StrArray, "Signals the kennel may receive (a subset of `talk` senders)."),
            f("own", Ty::StrArray, "Names the kennel may own (be addressable as). Almost always empty."),
        ],
    },
    Table {
        name: "dbus_audit",
        title: "`[dbus.audit]` — D-Bus call audit verbosity.",
        fields: &[f("level", Ty::Enum(&["off", "summary", "full"]), "Audit verbosity (default `summary`).")],
    },
    Table {
        name: "audit",
        title: "`[audit]` — audit sinks and per-class levels.",
        fields: &[
            f("sinks", Ty::StrArray, "Enabled sinks (`file`, `stdout`, `syslog`, `journald`)."),
            f("file", Ty::Obj("audit_file"), "`[audit.file]` — the rotating file sink."),
            f("syslog", Ty::Obj("audit_syslog"), "`[audit.syslog]` — the syslog sink."),
            f("journald", Ty::Obj("audit_empty"), "`[audit.journald]` — the journald sink (no fields)."),
            f("stdout", Ty::Obj("audit_empty"), "`[audit.stdout]` — the stdout sink (no fields)."),
            f("network", Ty::Obj("audit_class"), "`[audit.network]` — level override for the network class."),
            f("filesystem", Ty::Obj("audit_class"), "`[audit.filesystem]` — level override for the filesystem class."),
            f("exec", Ty::Obj("audit_class"), "`[audit.exec]` — level override for the exec class."),
            f("unix", Ty::Obj("audit_class"), "`[audit.unix]` — level override for the unix class."),
            f("dbus", Ty::Obj("audit_class"), "`[audit.dbus]` — level override for the dbus class."),
        ],
    },
    Table {
        name: "audit_file",
        title: "`[audit.file]` — the rotating file sink.",
        fields: &[
            f("dir", Ty::Str, "Directory the JSONL log is written to."),
            f("rotate_at_bytes", Ty::Str, "Rotate the log once it reaches this size (human form, `10M`)."),
            f("compress_after_seconds", Ty::Int, "Compress a rotated segment after this many seconds."),
            f("retain_count", Ty::Int, "How many rotated segments to retain."),
        ],
    },
    Table {
        name: "audit_syslog",
        title: "`[audit.syslog]` — the syslog sink.",
        fields: &[f("facility", Ty::Str, "The syslog facility.")],
    },
    Table {
        name: "audit_empty",
        title: "An empty audit sink table (journald, stdout: no fields).",
        fields: &[],
    },
    Table {
        name: "audit_class",
        title: "A per-class audit level override.",
        fields: &[f("level", Ty::Enum(&["off", "denies-only", "summary", "full"]), "The class level.")],
    },
    Table {
        name: "threats",
        title: "Threat-tag metadata attached to a grant.",
        fields: THREATS,
    },
];

/// The root table (the top-level document object).
///
/// # Panics
/// Never in practice: [`TABLES`] is a non-empty static whose first entry is the root
/// `policy` table. The `expect` documents that invariant rather than guarding a
/// reachable failure.
#[must_use]
pub fn root() -> &'static Table {
    TABLES
        .first()
        .expect("TABLES always contains the root `policy` table")
}

/// Look a table up by its def name.
#[must_use]
pub fn table(name: &str) -> Option<&'static Table> {
    TABLES.iter().find(|t| t.name == name)
}
