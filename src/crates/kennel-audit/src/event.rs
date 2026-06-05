//! The canonical audit event: the producer-facing envelope and the typed value
//! model the writer renders into every sink.
//!
//! A source (the netproxy, the privhelper, kenneld, …) constructs an [`Event`]
//! describing one thing that happened. The [`crate::Writer`] stamps the
//! envelope fields it owns (`schema_version`, `ts`, `kennel`, `kennel_uuid`,
//! `host`), runs the single sanitisation pass over the untrusted strings,
//! applies the audit-level filter, and fans the result out to the sinks. The
//! event schema is the durable contract (`docs/architecture/02-3-audit-schema.md`).

/// A value carried by one audit field.
///
/// The distinction the writer cares about is [`Value::Untrusted`] versus
/// everything else: untrusted strings pass through
/// [`kennel_text::sanitise_for_audit`] exactly once before any sink sees them
/// (the centralised content pass of `02-3-audit-schema.md` §Sanitisation), so a
/// sink's own structural encoding cannot reintroduce a live control sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// A trusted string — an internal token or a value the project formatted
    /// itself (a rendered IP address, a policy hash). Structurally escaped by
    /// each sink, but not content-sanitised (it carries no attacker bytes).
    Str(String),
    /// An untrusted string — a path, a hostname, `comm`, an `argv` element. The
    /// writer content-sanitises it once before rendering.
    Untrusted(String),
    /// A signed integer.
    Int(i64),
    /// An unsigned integer.
    Uint(u64),
    /// A boolean.
    Bool(bool),
    /// JSON `null` / "not applicable".
    Null,
    /// An ordered array of values (e.g. a template chain).
    Array(Vec<Self>),
    /// An ordered object of named sub-values (e.g. a privileged op's `params`).
    /// Keys are internal literals; values are rendered (and sanitised if
    /// untrusted) recursively.
    Object(Vec<(&'static str, Self)>),
}

impl Value {
    /// A trusted string value.
    #[must_use]
    pub fn str(s: impl Into<String>) -> Self {
        Self::Str(s.into())
    }

    /// An untrusted string value (sanitised once by the writer).
    #[must_use]
    pub fn untrusted(s: impl Into<String>) -> Self {
        Self::Untrusted(s.into())
    }

    /// An object value from ordered named fields.
    #[must_use]
    pub const fn object(fields: Vec<(&'static str, Self)>) -> Self {
        Self::Object(fields)
    }
}

/// The resource class of an event. Drives the `resource` envelope field, the
/// per-class file the JSONL sink routes to, and whether the audit level applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    /// Network: connect/bind decisions and proxy egress records.
    Net,
    /// Filesystem: Landlock denials, scrub hits.
    Fs,
    /// Binary execution.
    Exec,
    /// `AF_UNIX` socket connections.
    Unix,
    /// D-Bus method calls.
    Dbus,
    /// Privileged-helper invocations and refusals.
    Priv,
    /// Kennel and daemon lifecycle.
    Lifecycle,
}

impl Resource {
    /// The stable `resource` token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Net => "net",
            Self::Fs => "fs",
            Self::Exec => "exec",
            Self::Unix => "unix",
            Self::Dbus => "dbus",
            Self::Priv => "priv",
            Self::Lifecycle => "lifecycle",
        }
    }

    /// The file-name stem for the JSONL file sink (`<stem>.jsonl`).
    #[must_use]
    pub const fn file_stem(self) -> &'static str {
        match self {
            Self::Net => "network",
            Self::Fs => "filesystem",
            Self::Exec => "exec",
            Self::Unix => "unix",
            Self::Dbus => "dbus",
            Self::Priv => "priv",
            Self::Lifecycle => "lifecycle",
        }
    }

    /// Whether events of this class are emitted regardless of the audit level.
    /// Lifecycle and privileged-operation events always are (`02-3` §Audit
    /// levels).
    #[must_use]
    pub const fn always_emitted(self) -> bool {
        matches!(self, Self::Priv | Self::Lifecycle)
    }
}

/// The outcome of the audited action; the `outcome` envelope field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The action was permitted.
    Allow,
    /// The action was refused.
    Deny,
    /// Informational; no allow/deny decision (e.g. a lifecycle event).
    Info,
    /// An error occurred handling the action.
    Error,
}

impl Outcome {
    /// The stable `outcome` token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Info => "info",
            Self::Error => "error",
        }
    }

    /// The RFC 5424 / journald severity for this outcome (`02-3`: info/allow →
    /// 6, deny → 4, error → 3).
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::Allow | Self::Info => 6,
            Self::Deny => 4,
            Self::Error => 3,
        }
    }
}

/// The originating component; the `source` envelope field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// A kernel LSM hook (Landlock, `AppArmor`).
    Kernel,
    /// A cgroup BPF program.
    Bpf,
    /// The per-kennel egress proxy.
    Proxy,
    /// The xdg-dbus-proxy.
    DbusProxy,
    /// The spawn wrapper.
    KennelSpawn,
    /// The daemon itself.
    Kenneld,
    /// The privileged helper.
    Privhelper,
}

impl Source {
    /// The stable `source` token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Bpf => "bpf",
            Self::Proxy => "proxy",
            Self::DbusProxy => "dbus-proxy",
            Self::KennelSpawn => "kennel-spawn",
            Self::Kenneld => "kenneld",
            Self::Privhelper => "privhelper",
        }
    }
}

/// One audit event, as constructed by a source before the writer stamps the
/// envelope and renders it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// The event-type identifier, e.g. `net.connect-deny`. An internal literal.
    pub event: &'static str,
    /// The resource class.
    pub resource: Resource,
    /// The outcome.
    pub outcome: Outcome,
    /// The originating component.
    pub source: Source,
    /// The workload PID, if the event is tied to one.
    pub pid: Option<u32>,
    /// The workload `comm`, if known (untrusted; sanitised by the writer).
    pub comm: Option<String>,
    /// The summary-dedup key: under the `summary` level, the first `allow` per
    /// `(resource, target)` per kennel lifetime is emitted. Not itself emitted.
    pub target: Option<String>,
    /// Event-specific fields, in the order they should render after the
    /// envelope.
    pub fields: Vec<(&'static str, Value)>,
}

impl Event {
    /// Start an event with the four always-present envelope discriminators.
    #[must_use]
    pub const fn new(
        event: &'static str,
        resource: Resource,
        outcome: Outcome,
        source: Source,
    ) -> Self {
        Self {
            event,
            resource,
            outcome,
            source,
            pid: None,
            comm: None,
            target: None,
            fields: Vec::new(),
        }
    }

    /// Set the workload PID.
    #[must_use]
    pub const fn pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    /// Set the workload `comm` (untrusted).
    #[must_use]
    pub fn comm(mut self, comm: impl Into<String>) -> Self {
        self.comm = Some(comm.into());
        self
    }

    /// Set the summary-dedup target key.
    #[must_use]
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Append an event-specific field.
    #[must_use]
    pub fn field(mut self, key: &'static str, value: Value) -> Self {
        self.fields.push((key, value));
        self
    }
}

/// The per-class audit level (`02-3` §Audit levels): which events of a class are
/// emitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Level {
    /// Emit nothing.
    Off,
    /// Emit only `deny` outcomes.
    DeniesOnly,
    /// Emit denies plus the first `allow` per `(resource, target)` per kennel
    /// lifetime. The default.
    #[default]
    Summary,
    /// Emit every event.
    Full,
}

impl Level {
    /// Parse a level token. Returns `None` for an unknown token (the caller
    /// turns that into a policy validation error).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "off" => Some(Self::Off),
            "denies-only" => Some(Self::DeniesOnly),
            "summary" => Some(Self::Summary),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    /// The stable token for this level.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::DeniesOnly => "denies-only",
            Self::Summary => "summary",
            Self::Full => "full",
        }
    }
}
