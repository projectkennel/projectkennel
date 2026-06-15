//! Translate a resolved, folded source policy into the settled `EffectivePolicy`.
//!
//! # Purpose
//!
//! The compiler stage after [`crate::resolve`](mod@crate::resolve): take the effective [`SourcePolicy`]
//! (rich, human-facing, every section) and produce the flat
//! [`crate::settled::EffectivePolicy`] the runtime enforces, plus the list of
//! per-instance placeholders the runtime must still fill
//! (`deferred_substitutions`). This is where the human forms become machine forms:
//! `"169.254.169.254/32"` → `NetRule { cidr, prefix_len }`, `"512M"` → `size_mib`,
//! `"8h"` → `ttl_seconds`, `"constrained"`/`"none"`/`"open"` → [`NetMode`].
//!
//! # The runtime-relevant subset (02-2 §The settled policy, 08 §8.2)
//!
//! The settled `EffectivePolicy` carries only `net`, `fs`, `exec`, `proc`, `cap`,
//! `seccomp`, `lifecycle`. The source-only sections (`unix`, `ssh`, `dbus`, `x11`,
//! `env`, `ptrace`, `signal`, and the informational `fs.deny`/`fs.scrub`/`exec.deny`)
//! are compile-time or shim-construction concerns and are intentionally dropped here —
//! their effects are realised by other mechanisms (Landlock grant-absence, the
//! shim builder, the env curator, the SSH bastion), not by the settled artefact.
//!
//! # Substitution
//!
//! Nothing is substituted at compile time. Every placeholder — `<kennel>`, `<ctx>`,
//! `<uid>`, `<home>`, `<user>`, and the per-user `<tag>`/`<gid>` — is left in place
//! and recorded in `deferred_substitutions`; the daemon fills them all at spawn from
//! the user's scope and identity (it loads the scope from `/etc/kennel/subkennel`),
//! and refuses to spawn if any *other* placeholder survives (02-2 §Variable
//! substitution). The compiler never needs to know the installation's tag/gid.
//!
//! # Non-goals
//!
//! - Provenance, signing, and the lockfile: a separate increment.
//!
//! Seccomp is carried as a **denylist by name**, matching the source: the syscall
//! names pass through verbatim and the spawn layer resolves them to numbers via
//! `kennel_lib_syscall::seccomp::syscall_number` (`libc::SYS_*`) — so the signed policy
//! stays architecture-independent and no syscall-number table lives in this pure crate.

use crate::settled::{
    AuditFileConfig, AuditRuntime, AuditSinkKind, BinderConsumeRuntime, BinderProvideRuntime,
    BinderRuntime, CapPolicy, DevPolicy, EffectivePolicy, EnvRuntime, ExecPolicy, FsPolicy,
    IdentityRuntime, LifecyclePolicy, NameRule, NetMode, NetPolicy, NetRule, ProcPolicy,
    ProcVisibility, Protocol, ProxyListen, SeccompAction, SeccompPolicy, SshGrant, SshKnownHostPin,
    SshRuntime, TmpPolicy, TtlAction, UlimitsRuntime, UnixRuntime, UnixSocket, WorkloadRuntime,
};
use crate::source::{AuditSection, SourcePolicy};
use crate::PolicyError;
use std::collections::BTreeSet;

/// The product of translation: the settled effective policy plus the per-instance
/// placeholders the runtime must substitute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Translated {
    /// The flat, runtime-enforced policy.
    pub effective_policy: EffectivePolicy,
    /// The per-kennel SSH runtime (§7.10) — a service input, not enforcement.
    pub ssh: SshRuntime,
    /// The per-kennel `AF_UNIX` socket shims (§7.6) — a service input, not enforcement.
    pub unix: UnixRuntime,
    /// The workload's in-kennel identity (§7.4) — the supplementary groups it retains.
    pub identity: IdentityRuntime,
    /// The per-kennel binder IPC runtime (§7.1.4) — user-defined provide/consume grants.
    pub binder: BinderRuntime,
    /// The per-kennel audit runtime (§02-3) — sinks and per-class level deviations.
    pub audit: AuditRuntime,
    /// The synthesised environment (§7.9.2) — the fixed `[env].set` vars.
    pub env: EnvRuntime,
    /// The per-kennel resource limits (§7.4) — applied via `setrlimit` in the seal.
    pub ulimits: UlimitsRuntime,
    /// The workload to run (§7.4) — argv, cwd, pin, and optional sha256.
    pub workload: WorkloadRuntime,
    /// Per-instance placeholders (`<kennel>`, `<ctx>`, …) still to be filled at spawn.
    pub deferred_substitutions: Vec<String>,
}

/// Translate an effective (resolved, folded) source policy into the settled form.
///
/// `effective` must be the output of [`crate::resolve::resolve`] (nothing left to
/// inherit). All placeholders are deferred to spawn (see the module §Substitution).
///
/// # Errors
///
/// Returns [`PolicyError::Translation`] if a required field is missing or a human
/// form (CIDR, size, duration, port spec, net mode) is malformed.
pub fn translate(effective: &SourcePolicy) -> Result<Translated, PolicyError> {
    let mut deferred = BTreeSet::new();
    let net = translate_net(effective, &mut deferred)?;
    let fs = translate_fs(effective, &mut deferred)?;
    let exec = translate_exec(effective, &mut deferred)?;
    let proc = translate_proc(effective)?;
    let cap = CapPolicy {
        no_new_privs: effective
            .cap
            .as_ref()
            .and_then(|c| c.no_new_privs)
            .unwrap_or(false),
    };
    // Seccomp is a denylist by name: carry the source's denied syscalls through
    // verbatim (the spawn layer resolves names→numbers via libc). An empty deny list
    // means no filter is installed.
    let seccomp = SeccompPolicy {
        deny_action: SeccompAction::Errno,
        deny: effective
            .seccomp
            .as_ref()
            .and_then(|s| s.deny.clone())
            .unwrap_or_default(),
    };
    let lifecycle = translate_lifecycle(effective)?;
    let ssh = translate_ssh(effective);
    let unix = translate_unix(effective, &mut deferred);
    let identity = translate_identity(effective)?;
    let binder = translate_binder(effective);
    let audit = translate_audit(effective, &mut deferred)?;
    let env = translate_env(effective, &mut deferred);
    let ulimits = translate_ulimits(effective)?;
    let workload = translate_workload(effective, &mut deferred)?;

    Ok(Translated {
        effective_policy: EffectivePolicy {
            net,
            fs,
            exec,
            proc,
            cap,
            seccomp,
            lifecycle,
        },
        ssh,
        unix,
        identity,
        binder,
        audit,
        env,
        ulimits,
        workload,
        deferred_substitutions: deferred.into_iter().collect(),
    })
}

/// Translate `[workload]` into the settled [`WorkloadRuntime`] (§7.4). `argv` carries
/// through verbatim (a bare `argv[0]` is resolved against the kennel `PATH` at spawn,
/// not here); `cwd` is `subst`-ed for `~`/`<home>` like other in-view paths; `sha256`,
/// when set, is validated as 64 lowercase hex (the spawn verifies the binary against it
/// before exec). An absent or argv-less `[workload]` yields an empty runtime (omitted
/// from the canonical form), so a no-`[workload]` policy signs exactly as before.
///
/// # Errors
///
/// [`PolicyError::Translation`] if `sha256` is not 64 lowercase-hex characters.
fn translate_workload(
    src: &SourcePolicy,
    deferred: &mut BTreeSet<String>,
) -> Result<WorkloadRuntime, PolicyError> {
    let Some(w) = src.workload.as_ref() else {
        return Ok(WorkloadRuntime::default());
    };
    let argv = w.argv.clone().unwrap_or_default();
    let cwd = w.cwd.as_deref().map(|c| subst(c, deferred));
    let pinned = w.pinned.unwrap_or(false);
    let mut sha256 = Vec::new();
    for h in w.sha256.iter().flatten() {
        if !is_sha256_hex(h) {
            return Err(translation(format!(
                "workload.sha256 `{h}` is not 64 lowercase-hex characters"
            )));
        }
        sha256.push(h.clone());
    }
    Ok(WorkloadRuntime {
        argv,
        cwd,
        pinned,
        sha256,
    })
}

/// Whether `s` is a 64-character lowercase-hex SHA-256 digest.
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() && b <= b'f')
}

/// Flatten the resolved `[binder]` section into the settled [`BinderRuntime`]: one
/// runtime entry per `[[binder.provide]]`/`[[binder.consume]]`. Already
/// compile-time-validated (`crate::binder`), so each entry has a non-reserved `name`.
/// An absent or empty `[binder]` yields an empty runtime (omitted from the canonical
/// form), so a no-`[binder]` policy signs exactly as before.
fn translate_binder(src: &SourcePolicy) -> BinderRuntime {
    let Some(binder) = &src.binder else {
        return BinderRuntime::default();
    };
    let provide = binder
        .provide
        .iter()
        .filter_map(|p| {
            p.name.as_ref().map(|name| BinderProvideRuntime {
                name: name.clone(),
                accept_from: p.accept_from.clone(),
            })
        })
        .collect();
    let consume = binder
        .consume
        .iter()
        .filter_map(|c| {
            c.name.as_ref().map(|name| BinderConsumeRuntime {
                name: name.clone(),
                from: c.from.clone(),
            })
        })
        .collect();
    BinderRuntime { provide, consume }
}

/// Translate `[ulimits]` into the settled [`UlimitsRuntime`] (§7.4). Each entry is a
/// `setrlimit` resource name (validated against [`ULIMIT_RESOURCES`]) and a value of
/// the form `soft` or `soft:hard`, every token a number (optional `K`/`M`/`G`, 1024-
/// based) or `unlimited`. The value is normalised to the settled form `soft` (when
/// `soft == hard`) or `"soft hard"`, each token a decimal or the literal `unlimited`.
/// Nothing is set by default — an absent or empty `[ulimits]` yields an empty runtime.
///
/// # Errors
///
/// [`PolicyError::Translation`] on an unknown resource name or an unparseable value.
fn translate_ulimits(src: &SourcePolicy) -> Result<UlimitsRuntime, PolicyError> {
    let mut limits = std::collections::BTreeMap::new();
    let Some(src_limits) = src.ulimits.as_ref() else {
        return Ok(UlimitsRuntime::default());
    };
    for (name, value) in src_limits {
        if !crate::settled::ULIMIT_RESOURCES.contains(&name.as_str()) {
            return Err(translation(format!(
                "unknown ulimit resource `{name}` (expected one of {})",
                crate::settled::ULIMIT_RESOURCES.join(", ")
            )));
        }
        let (soft, hard) = if let Some((s, h)) = value.split_once(':') {
            (parse_rlim_token(name, s)?, parse_rlim_token(name, h)?)
        } else {
            let t = parse_rlim_token(name, value)?;
            (t.clone(), t)
        };
        let normalised = if soft == hard {
            soft
        } else {
            format!("{soft} {hard}")
        };
        limits.insert(name.clone(), normalised);
    }
    Ok(UlimitsRuntime { limits })
}

/// Parse one ulimit token — `unlimited`/`infinity`, or a number with an optional
/// `K`/`M`/`G` (1024-based) suffix — into its normalised settled string (`"unlimited"`
/// or a decimal). `field` names the resource for the error message.
fn parse_rlim_token(field: &str, tok: &str) -> Result<String, PolicyError> {
    let t = tok.trim();
    if t.eq_ignore_ascii_case("unlimited") || t.eq_ignore_ascii_case("infinity") {
        return Ok("unlimited".to_owned());
    }
    // Strip an optional 1024-based suffix; each is a distinct single char, so the
    // first match wins. `find_map` over a table avoids an if-let/else chain.
    let (num, mult): (&str, u64) = [('K', 1u64 << 10), ('M', 1u64 << 20), ('G', 1u64 << 30)]
        .into_iter()
        .find_map(|(c, m)| {
            t.strip_suffix([c, c.to_ascii_lowercase()])
                .map(|stripped| (stripped, m))
        })
        .unwrap_or((t, 1));
    let base = num.trim().parse::<u64>().map_err(|_| {
        translation(format!(
            "ulimit `{field}` value `{tok}` is not a number (optional K/M/G) or `unlimited`"
        ))
    })?;
    let scaled = base.checked_mul(mult).ok_or_else(|| {
        translation(format!(
            "ulimit `{field}` value `{tok}` overflows a 64-bit limit"
        ))
    })?;
    Ok(scaled.to_string())
}

/// Flatten the source `[env].set` into the settled [`EnvRuntime`] (§7.9.2). The
/// environment is *synthesised* from policy, not curated from the parent: only the
/// explicit `set` map is carried (the legacy `pass`/`deny` curation fields are
/// ignored — there is no inheritance to filter). Placeholders in the values are
/// recorded as deferred (filled by the daemon at spawn), like every other policy
/// string. An empty result is omitted from the canonical form.
fn translate_env(src: &SourcePolicy, deferred: &mut BTreeSet<String>) -> EnvRuntime {
    let mut vars = std::collections::BTreeMap::new();
    if let Some(set) = src.env.as_ref().and_then(|e| e.set.as_ref()) {
        for (key, value) in set {
            vars.insert(key.clone(), subst(value, deferred));
        }
    }
    EnvRuntime { vars }
}

/// The valid per-class audit levels and the valid syslog facilities.
const AUDIT_LEVELS: [&str; 4] = ["off", "denies-only", "summary", "full"];
const SYSLOG_FACILITIES: [&str; 20] = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
];

/// Flatten the source `[audit]` section into the settled [`AuditRuntime`],
/// validating sink names, per-class levels, sizes, and the syslog facility.
/// Only deviations from the `02-3` defaults are carried; an absent or all-default
/// section yields the empty runtime (omitted from the canonical form).
fn translate_audit(
    src: &SourcePolicy,
    deferred: &mut BTreeSet<String>,
) -> Result<AuditRuntime, PolicyError> {
    src.audit.as_ref().map_or_else(
        || Ok(AuditRuntime::default()),
        |audit| translate_audit_section(audit, deferred),
    )
}

/// Translate one `[audit]` section — a policy's, or a standalone `audit.toml`
/// defaults file — into the settled [`AuditRuntime`].
fn translate_audit_section(
    audit: &AuditSection,
    deferred: &mut BTreeSet<String>,
) -> Result<AuditRuntime, PolicyError> {
    let mut sinks = Vec::new();
    for name in &audit.sinks {
        let kind = match name.as_str() {
            "file" => AuditSinkKind::File,
            "journald" => AuditSinkKind::Journald,
            "syslog" => AuditSinkKind::Syslog,
            "stdout" => AuditSinkKind::Stdout,
            other => {
                return Err(translation(format!(
                    "unknown audit sink `{other}` (expected file/journald/syslog/stdout)"
                )))
            }
        };
        if !sinks.contains(&kind) {
            sinks.push(kind);
        }
    }

    let level =
        |class: &Option<crate::source::AuditClassSection>| -> Result<Option<String>, PolicyError> {
            match class.as_ref().and_then(|c| c.level.as_ref()) {
                None => Ok(None),
                Some(l) if AUDIT_LEVELS.contains(&l.as_str()) => Ok(Some(l.clone())),
                Some(l) => Err(translation(format!(
                    "unknown audit level `{l}` (expected off/denies-only/summary/full)"
                ))),
            }
        };

    let syslog_facility = match audit.syslog.as_ref().and_then(|s| s.facility.as_ref()) {
        None => None,
        Some(f) if SYSLOG_FACILITIES.contains(&f.as_str()) => Some(f.clone()),
        Some(f) => {
            return Err(translation(format!(
                "unknown syslog facility `{f}` (expected user/daemon/auth/local0-7/…)"
            )))
        }
    };

    let file = match &audit.file {
        None => AuditFileConfig::default(),
        Some(f) => AuditFileConfig {
            dir: f.dir.as_ref().map(|d| subst(d, deferred)),
            rotate_at_bytes: match &f.rotate_at_bytes {
                None => None,
                Some(s) => Some(parse_size_bytes(s)?),
            },
            compress_after_seconds: f.compress_after_seconds,
            retain_count: f.retain_count,
        },
    };

    Ok(AuditRuntime {
        sinks,
        network_level: level(&audit.network)?,
        filesystem_level: level(&audit.filesystem)?,
        exec_level: level(&audit.exec)?,
        unix_level: level(&audit.unix)?,
        dbus_level: level(&audit.dbus)?,
        syslog_facility,
        file,
    })
}

/// Parse a standalone `audit.toml` defaults file into an [`AuditRuntime`].
///
/// The file body is the `[audit]` section content at top level (`sinks`,
/// `[file]`, `[network]`/`[filesystem]`/…), validated exactly as a policy's
/// `[audit]` section is. For the installation-wide `/etc/kennel/audit.toml` and
/// the per-user override (`08` §8.1). `dir` placeholders are left literal —
/// kenneld roots the file sink at the per-kennel state dir regardless.
///
/// # Errors
/// [`PolicyError::Parse`] if the TOML is malformed, or a translation error for an
/// unknown sink/level/facility or a malformed size.
pub fn parse_audit_defaults(toml: &str) -> Result<AuditRuntime, PolicyError> {
    let section: AuditSection =
        basic_toml::from_str(toml).map_err(|e| PolicyError::Parse(e.to_string()))?;
    let mut deferred = BTreeSet::new();
    translate_audit_section(&section, &mut deferred)
}

/// Parse a human byte size (`"64M"`, `"1G"`, `"512K"`, bare = bytes) into bytes.
fn parse_size_bytes(s: &str) -> Result<u64, PolicyError> {
    let bad = || {
        translation(format!(
            "size `{s}` is not a number with an optional K/M/G suffix"
        ))
    };
    let trimmed = s.trim();
    // (suffix-pair, multiplier), largest first; bare number is bytes.
    let units: [([char; 2], u64); 3] = [
        (['G', 'g'], 1024 * 1024 * 1024),
        (['M', 'm'], 1024 * 1024),
        (['K', 'k'], 1024),
    ];
    let mut num = trimmed;
    let mut mult = 1_u64;
    for (suffix, factor) in units {
        if let Some(stripped) = trimmed.strip_suffix(suffix) {
            num = stripped;
            mult = factor;
            break;
        }
    }
    let value = num.trim().parse::<u64>().map_err(|_| bad())?;
    value.checked_mul(mult).ok_or_else(bad)
}

/// Gather the workload's retained supplementary groups (§7.4): the explicit
/// `[identity].groups` plus every group named by a `[[fs.dev.passthrough]]` (a device
/// is unusable without its DAC group), de-duplicated in first-seen order. `kenneld`
/// resolves these names to GIDs and membership-checks them at spawn.
fn translate_identity(src: &SourcePolicy) -> Result<IdentityRuntime, PolicyError> {
    let mut groups: Vec<String> = Vec::new();
    let mut push = |g: &str| {
        if !g.is_empty() && !groups.iter().any(|e| e == g) {
            groups.push(g.to_owned());
        }
    };
    if let Some(identity) = &src.identity {
        for g in &identity.groups {
            push(g);
        }
    }
    if let Some(dev) = src.fs.as_ref().and_then(|fs| fs.dev.as_ref()) {
        for pt in &dev.passthrough {
            if let Some(g) = &pt.group {
                push(g);
            }
        }
    }
    let id = src.identity.as_ref();
    let user = id
        .and_then(|i| i.user.clone())
        .unwrap_or_else(|| crate::settled::DEFAULT_USER.to_owned());
    validate_name("identity.user", &user)?;
    let group = id
        .and_then(|i| i.group.clone())
        .unwrap_or_else(|| crate::settled::DEFAULT_GROUP.to_owned());
    validate_name("identity.group", &group)?;
    Ok(IdentityRuntime {
        user,
        group,
        groups,
    })
}

/// Reject anything that is not a portable, non-system Unix user/group name. The
/// `identity.user` becomes the synthetic `/etc/passwd` account, `$USER`/`$LOGNAME`,
/// and the *path component* of `$HOME` (`/home/<user>`); `identity.group` becomes the
/// synthetic primary-group name. A `/`, `:`, NUL, or whitespace would corrupt the
/// passwd/group file or escape the home path — refuse, never sanitise.
fn validate_name(field: &str, name: &str) -> Result<(), PolicyError> {
    let invalid =
        |why: &str| PolicyError::Translation(format!("{field} `{name}` is invalid: {why}"));
    if name.is_empty() {
        return Err(invalid("must not be empty"));
    }
    if name.len() > 32 {
        return Err(invalid("must be at most 32 characters"));
    }
    // Portable name: lowercase letter or underscore first, then lowercase letters,
    // digits, underscore, or hyphen (the `useradd(8)` NAME_REGEX default).
    let first_ok = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_');
    if !first_ok {
        return Err(invalid("must start with a lowercase letter or `_`"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        return Err(invalid("may only contain `[a-z0-9_-]`"));
    }
    Ok(())
}

/// Flatten the source `[unix]` section into the settled [`UnixRuntime`]: one
/// [`UnixSocket`] per `[[unix.allow]]` grant. Already compile-time-validated
/// (`crate::unix`), so each entry has `real`/`shim` and no SSH agent slips through.
/// Install constants are substituted now; per-instance placeholders (`<kennel>`,
/// `<uid>`, `<home>`) survive into [`Translated::deferred_substitutions`] for the
/// runtime to fill.
fn translate_unix(src: &SourcePolicy, deferred: &mut BTreeSet<String>) -> UnixRuntime {
    let Some(unix) = &src.unix else {
        return UnixRuntime::default();
    };
    let sockets = unix
        .allow
        .iter()
        .filter_map(|a| match (&a.real, &a.shim) {
            (Some(real), Some(shim)) => Some(UnixSocket {
                name: a.name.clone().unwrap_or_default(),
                real: subst(real, deferred),
                shim: subst(shim, deferred),
                env: a.env.clone(),
            }),
            _ => None,
        })
        .collect();
    UnixRuntime { sockets }
}

/// Flatten the source `[ssh]` section into the settled [`SshRuntime`]: one
/// [`SshGrant`] per `(host, fingerprint)` edge. Already compile-time-validated
/// (`crate::ssh`), so the fingerprints and `hosts ⊆ net.allow:22` hold here.
fn translate_ssh(src: &SourcePolicy) -> SshRuntime {
    let Some(ssh) = &src.ssh else {
        return SshRuntime::default();
    };
    let mut grants = Vec::new();
    for key in &ssh.keys {
        let Some(fp) = &key.fingerprint else { continue };
        for host in &key.hosts {
            grants.push(SshGrant {
                host: host.clone(),
                fingerprint: fp.clone(),
            });
        }
    }
    let known_hosts = ssh
        .known_hosts
        .iter()
        .filter_map(|kh| match (&kh.host, &kh.key) {
            (Some(host), Some(key)) => Some(SshKnownHostPin {
                host: host.clone(),
                key: key.clone(),
            }),
            _ => None,
        })
        .collect();
    SshRuntime {
        allow_headless: ssh.allow_headless.unwrap_or(false),
        grants,
        known_hosts,
    }
}

// ---- net -----------------------------------------------------------------------

fn translate_net(
    src: &SourcePolicy,
    deferred: &mut BTreeSet<String>,
) -> Result<NetPolicy, PolicyError> {
    let net = src.net.as_ref().ok_or_else(|| missing("net"))?;
    let mode = match net.mode.as_deref() {
        // `none` is "constrained with an empty allowlist" — the proxy denies all.
        Some("constrained" | "none") | None => NetMode::Constrained,
        Some("open") => NetMode::Open,
        Some(other) => {
            return Err(translation(format!(
                "net.mode `{other}` is not representable"
            )))
        }
    };
    let proxy = match net.proxy_listen_v4_address.as_deref() {
        Some(addr) => parse_proxy(addr)?,
        None => ProxyListen::default(),
    };

    let mut allow: Vec<NetRule> = Vec::new();
    let mut allow_names: Vec<NameRule> = Vec::new();
    for entry in &net.allow {
        let protocol = parse_protocol(entry.protocol.as_deref())?;
        if let Some(cidr) = &entry.cidr {
            let (addr, prefix_len) = parse_cidr(cidr)?;
            let addr = subst(&addr, deferred);
            if entry.ports.is_empty() {
                allow.push(NetRule {
                    cidr: addr,
                    prefix_len,
                    port_min: 0,
                    port_max: u16::MAX,
                    protocol,
                });
            } else {
                for &p in &entry.ports {
                    allow.push(NetRule {
                        cidr: addr.clone(),
                        prefix_len,
                        port_min: p,
                        port_max: p,
                        protocol,
                    });
                }
            }
        } else if let Some(name) = &entry.name {
            allow_names.push(NameRule {
                name: name.clone(),
                ports: entry.ports.clone(),
                protocol,
            });
        } else {
            return Err(translation(
                "net.allow entry has neither `name` nor `cidr`".to_owned(),
            ));
        }
    }

    // Implied rule: an `[[ssh.keys]]` host grant implies egress to that host on port 22. SSH leaves
    // the kennel only over the egress gateway, so a granted host must be in the allowlist on :22 —
    // deriving it here means the author writes the ssh grant once, not also a parallel [[net.allow]].
    // Skipped if the author already named the host (their entry, possibly with extra ports, wins).
    if let Some(ssh) = &src.ssh {
        for key in &ssh.keys {
            for host in &key.hosts {
                if !allow_names.iter().any(|r| &r.name == host) {
                    allow_names.push(NameRule {
                        name: host.clone(),
                        ports: vec![22],
                        protocol: Protocol::Tcp,
                    });
                }
            }
        }
    }

    let mut deny_invariant: Vec<NetRule> = Vec::new();
    if let Some(deny) = &net.deny {
        for d in &deny.invariant {
            let (addr, prefix_len) = parse_cidr(&d.cidr)?;
            deny_invariant.push(NetRule {
                cidr: addr,
                prefix_len,
                port_min: 0,
                port_max: u16::MAX,
                protocol: Protocol::Any,
            });
        }
    }

    // The bind floor (§7.5.7): a workload bind below `min_port` is denied by the
    // bind4/bind6 BPF. Carried into the kennel_meta map; `0` (or absent) = no floor.
    let bind_port_min = net.bind.as_ref().and_then(|b| b.min_port).unwrap_or(0);
    // The bind-port allowlist (§7.5.7): when non-empty, only these ports may be bound.
    // Capped at the bind_subnet array size; an over-long list is a translation error
    // (a hard map limit, not a footgun), so the author learns it rather than having
    // ports silently dropped.
    let bind_allowed_ports = net
        .bind
        .as_ref()
        .and_then(|b| b.allowed_ports.clone())
        .unwrap_or_default();
    if bind_allowed_ports.len() > crate::settled::MAX_BIND_PORTS {
        return Err(translation(format!(
            "[net.bind].allowed_ports has {} entries; the maximum is {}",
            bind_allowed_ports.len(),
            crate::settled::MAX_BIND_PORTS
        )));
    }

    Ok(NetPolicy {
        mode,
        bind_port_min,
        bind_allowed_ports,
        proxy,
        allow,
        allow_names,
        deny_invariant,
    })
}

/// Parse a `"offset:port"` proxy-listen address.
fn parse_proxy(addr: &str) -> Result<ProxyListen, PolicyError> {
    let (off, port) = addr
        .split_once(':')
        .ok_or_else(|| translation(format!("proxy address `{addr}` is not `offset:port`")))?;
    let offset = off
        .trim()
        .parse::<u8>()
        .map_err(|_| translation(format!("proxy offset `{off}` is not a byte")))?;
    let port = port
        .trim()
        .parse::<u16>()
        .map_err(|_| translation(format!("proxy port `{port}` is not a u16")))?;
    Ok(ProxyListen { offset, port })
}

fn parse_protocol(p: Option<&str>) -> Result<Protocol, PolicyError> {
    match p {
        Some("tcp") | None => Ok(Protocol::Tcp),
        Some("udp") => Ok(Protocol::Udp),
        Some("any") => Ok(Protocol::Any),
        Some(other) => Err(translation(format!(
            "protocol `{other}` is not tcp/udp/any"
        ))),
    }
}

/// Split `"<addr>/<prefix>"`; a bare address takes the host prefix (32 v4 / 128 v6).
fn parse_cidr(cidr: &str) -> Result<(String, u8), PolicyError> {
    if let Some((addr, plen)) = cidr.split_once('/') {
        let prefix = plen
            .parse::<u8>()
            .map_err(|_| translation(format!("CIDR `{cidr}` has a bad prefix length")))?;
        Ok((addr.to_owned(), prefix))
    } else {
        let prefix = if cidr.contains(':') { 128 } else { 32 };
        Ok((cidr.to_owned(), prefix))
    }
}

// ---- fs ------------------------------------------------------------------------

fn translate_fs(
    src: &SourcePolicy,
    deferred: &mut BTreeSet<String>,
) -> Result<FsPolicy, PolicyError> {
    let fs = src.fs.as_ref().ok_or_else(|| missing("fs"))?;
    let home = fs.home.as_ref().ok_or_else(|| missing("fs.home"))?;

    let mut read = subst_each(fs.read.as_deref().unwrap_or_default(), deferred);
    let write = subst_each(fs.write.as_deref().unwrap_or_default(), deferred);
    // Implied rule: a writable path is readable. A policy author granting `fs.write` on a tree
    // means it to be usable, which requires read; restating it as `fs.read` is noise. Fold each
    // write path into read if not already present (order-preserving, deduped).
    for w in &write {
        if !read.contains(w) {
            read.push(w.clone());
        }
    }

    let tmp = match &fs.tmp {
        Some(t) => TmpPolicy {
            private: t.private.unwrap_or(false),
            size_mib: match &t.size {
                Some(s) => parse_size_mib(s)?,
                None => DEFAULT_TMP_MIB,
            },
            mode: t.mode.clone().unwrap_or_else(|| "0700".to_owned()),
        },
        None => TmpPolicy {
            private: false,
            size_mib: DEFAULT_TMP_MIB,
            mode: "0700".to_owned(),
        },
    };

    // The constructed-/dev bind set: the pseudo-device baseline (`fs.dev.allow`) plus
    // every `[[fs.dev.passthrough]]` device path (§7.4.8). Both bind identically at
    // spawn; the passthrough's reason/threats/group are compile-time-only (validated
    // by `crate::dev`, then dropped — like the other informational source fields).
    let mut dev_allow = subst_each(
        fs.dev
            .as_ref()
            .and_then(|d| d.allow.as_deref())
            .unwrap_or_default(),
        deferred,
    );
    if let Some(d) = &fs.dev {
        for pt in &d.passthrough {
            if let Some(path) = &pt.path {
                dev_allow.push(subst(path, deferred));
            }
        }
    }
    let dev = DevPolicy { allow: dev_allow };

    let home_persist = subst_each(&home.persist, deferred);

    Ok(FsPolicy {
        home_shadow: home.shadow.unwrap_or(false),
        read,
        write,
        home_persist,
        home_readonly: home.readonly.unwrap_or(false),
        tmp,
        dev,
    })
}

/// Default private-`/tmp` size when a policy omits one.
const DEFAULT_TMP_MIB: u32 = 512;

/// Split a human size into its numeric part and a mebibyte multiplier.
fn size_unit(t: &str) -> (&str, u32) {
    if let Some(n) = t.strip_suffix(['G', 'g']) {
        return (n, 1024);
    }
    if let Some(n) = t.strip_suffix(['M', 'm']) {
        return (n, 1);
    }
    (t, 1)
}

/// Parse a human size (`"512M"`, `"1G"`, bare = MiB) into mebibytes.
fn parse_size_mib(s: &str) -> Result<u32, PolicyError> {
    let bad = || {
        translation(format!(
            "size `{s}` is not a number with an optional M/G suffix"
        ))
    };
    let (num, mult) = size_unit(s.trim());
    let value = num.trim().parse::<u32>().map_err(|_| bad())?;
    value.checked_mul(mult).ok_or_else(bad)
}

// ---- exec ----------------------------------------------------------------------

fn translate_exec(
    src: &SourcePolicy,
    deferred: &mut BTreeSet<String>,
) -> Result<ExecPolicy, PolicyError> {
    let exec = src.exec.as_ref();
    let flag =
        |f: fn(&crate::source::ExecSection) -> Option<bool>| exec.and_then(f).unwrap_or(false);
    let mut allow = subst_each(
        exec.and_then(|e| e.allow.as_deref()).unwrap_or_default(),
        deferred,
    );
    // exec.deny (§7.3.4) is composed up the chain (folded in resolve) and carried into
    // the settled policy for audit and runtime warning. "deny evaluated before allow":
    // a deny that exactly matches an allow entry is *subtracted* here, so Landlock never
    // grants EXECUTE on it (the only deny the allow-only LSM can actually enforce). A
    // deny that falls inside an allowed directory, or that is set without any allow, is
    // advisory — `ExecPolicy::deny_warnings` flags it at compile and spawn.
    let deny = subst_each(
        exec.and_then(|e| e.deny.as_deref()).unwrap_or_default(),
        deferred,
    );
    allow.retain(|a| !deny.contains(a));
    let path = subst_each(
        exec.and_then(|e| e.path.as_deref()).unwrap_or_default(),
        deferred,
    );
    // The login shell (§7.9.2a): default /bin/sh. Execution is deny-by-default, so the
    // shell must itself be allowed or the kennel would set a shell it then refuses to
    // run. The exceptions: an empty allowlist (a no-exec floor like `base-confined` —
    // there is no shell to run, by design), and the explicit `**` permissive opt-in
    // (everything runs). Caught here at compile time (after the deny subtraction, so
    // denying your own shell is caught as the same contradiction).
    let shell = exec
        .and_then(|e| e.shell.clone())
        .map_or_else(crate::settled::default_shell, |s| subst(&s, deferred));
    let permits_everything = allow.iter().any(|e| matches!(e.trim(), "**" | "/**"));
    if !allow.is_empty() && !permits_everything && !allow.contains(&shell) {
        return Err(translation(format!(
            "[exec].shell `{shell}` is not in exec.allow (the kennel would refuse to run its own shell)"
        )));
    }
    // The resolved `loaders` set (each allowlisted dynamic binary's PT_INTERP) is filled at
    // compile time by `kennel_lib_policy::libresolve` (it reads the binaries from disk), so it is
    // empty here. There is no `[lib]` section: libraries are not execute-gated (`07-3-exec`).
    Ok(ExecPolicy {
        deny_setuid: flag(|e| e.deny_setuid),
        deny_setgid: flag(|e| e.deny_setgid),
        deny_setcap: flag(|e| e.deny_setcap),
        deny_writable: flag(|e| e.deny_writable),
        allow,
        deny,
        path,
        shell,
        loaders: Vec::new(),
    })
}

// ---- proc / lifecycle ----------------------------------------------------------

fn translate_proc(src: &SourcePolicy) -> Result<ProcPolicy, PolicyError> {
    // Visibility comes from [proc] or, failing that, [fs.proc]; only "self" is valid.
    let visibility = src
        .proc
        .as_ref()
        .and_then(|p| p.visibility.as_deref())
        .or_else(|| {
            src.fs
                .as_ref()
                .and_then(|f| f.proc.as_ref())
                .and_then(|p| p.visibility.as_deref())
        });
    match visibility {
        Some("self") | None => {}
        Some(other) => {
            return Err(translation(format!(
                "proc.visibility `{other}` is not `self`"
            )))
        }
    }
    let hidepid = src.proc.as_ref().and_then(|p| p.hidepid).or_else(|| {
        src.fs
            .as_ref()
            .and_then(|f| f.proc.as_ref())
            .and_then(|p| p.hidepid)
    });
    Ok(ProcPolicy {
        visibility: ProcVisibility::SelfOnly,
        hidepid: hidepid.unwrap_or(false),
    })
}

fn translate_lifecycle(src: &SourcePolicy) -> Result<LifecyclePolicy, PolicyError> {
    let lc = src.lifecycle.as_ref();
    let ttl_seconds = match lc.and_then(|l| l.ttl.as_deref()) {
        Some(s) => Some(parse_duration_secs(s)?),
        None => None,
    };
    // §9.7: exit | warn | renew, defaulting to exit. "stop" is accepted as a
    // backward-compatible alias for "exit" (the token earlier builds shipped).
    let ttl_action = match lc.and_then(|l| l.ttl_action.as_deref()) {
        Some("exit" | "stop") | None => TtlAction::Exit,
        Some("warn") => TtlAction::Warn,
        Some("renew") => TtlAction::Renew,
        Some(other) => {
            return Err(translation(format!(
                "ttl_action `{other}` is not exit/warn/renew"
            )))
        }
    };
    Ok(LifecyclePolicy {
        ttl_seconds,
        ttl_action,
    })
}

/// Split a human duration into its numeric part and a seconds multiplier.
fn duration_unit(t: &str) -> (&str, u64) {
    if let Some(n) = t.strip_suffix(['s', 'S']) {
        return (n, 1);
    }
    if let Some(n) = t.strip_suffix(['m', 'M']) {
        return (n, 60);
    }
    if let Some(n) = t.strip_suffix(['h', 'H']) {
        return (n, 3600);
    }
    if let Some(n) = t.strip_suffix(['d', 'D']) {
        return (n, 86_400);
    }
    (t, 1)
}

/// Parse a human duration (`"8h"`, `"30m"`, `"5s"`, `"2d"`, bare = seconds) into seconds.
fn parse_duration_secs(s: &str) -> Result<u64, PolicyError> {
    let bad = || {
        translation(format!(
            "duration `{s}` is not a number with an optional s/m/h/d suffix"
        ))
    };
    let (num, mult) = duration_unit(s.trim());
    let value = num.trim().parse::<u64>().map_err(|_| bad())?;
    value.checked_mul(mult).ok_or_else(bad)
}

// ---- substitution --------------------------------------------------------------

/// Substitute install constants in `s` and record any remaining `<…>` placeholders.
fn subst(s: &str, deferred: &mut BTreeSet<String>) -> String {
    // `<tag>`/`<gid>` are NOT substituted here. They are per-user values the daemon
    // already holds (the reserved scope it loads from `/etc/kennel/subkennel`), so
    // they are deferred to spawn like `<ctx>`/`<uid>` — the compiler only records
    // them. This keeps one source of truth (the daemon) and means the CLI never has
    // to know or find out the installation's tag/gid.
    let s = canonicalize_home(s);
    collect_placeholders(&s, deferred);
    s
}

/// Canonicalise the home prefix to `~`, so the settled policy carries exactly ONE way to name the
/// kennel's home and **zero host-context home references**. `$HOME`/`$HOME/` rewrite to `~`/`~/`.
/// A literal absolute host-home path cannot be recognised here (the compiler is host- and
/// user-independent — it does not know the operator's home), so that form is normalised at spawn,
/// where the home is known; here we canonicalise the symbolic forms an author writes.
fn canonicalize_home(s: &str) -> String {
    if s == "$HOME" {
        return "~".to_owned();
    }
    if let Some(rest) = s.strip_prefix("$HOME/") {
        return format!("~/{rest}");
    }
    s.to_owned()
}

/// Apply [`subst`] to each element of a slice.
fn subst_each(items: &[String], deferred: &mut BTreeSet<String>) -> Vec<String> {
    items.iter().map(|s| subst(s, deferred)).collect()
}

/// Record every `<lowercase-token>` occurrence in `s` into `deferred`.
fn collect_placeholders(s: &str, deferred: &mut BTreeSet<String>) {
    let mut rest = s;
    while let Some((_, after)) = rest.split_once('<') {
        match after.split_once('>') {
            Some((tok, tail)) => {
                if !tok.is_empty() && tok.chars().all(|c| c.is_ascii_lowercase()) {
                    deferred.insert(format!("<{tok}>"));
                }
                rest = tail;
            }
            None => break,
        }
    }
}

// ---- error helpers -------------------------------------------------------------

fn missing(field: &str) -> PolicyError {
    PolicyError::Translation(format!(
        "required section/field `{field}` is absent from the effective policy"
    ))
}

const fn translation(msg: String) -> PolicyError {
    PolicyError::Translation(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::{resolve, TemplateSource};
    use crate::settled::{Provenance, ResolvedArtifact, SettledPolicy};
    use crate::source::parse;

    const BASE_CONFINED: &str = include_str!("../../../../templates/base-confined/policy.toml");
    const AI_CODING_STRICT: &str =
        include_str!("../../../../templates/ai-coding-strict/policy.toml");
    const UNTRUSTED_BUILD: &str = include_str!("../../../../templates/untrusted-build/policy.toml");

    struct MapSource(Vec<(String, String, Vec<u8>)>);
    impl TemplateSource for MapSource {
        fn fetch(&self, name: &str, version: &str) -> Option<Vec<u8>> {
            self.0
                .iter()
                .find(|(n, v, _)| n == name && v == version)
                .map(|(_, _, b)| b.clone())
        }
    }
    fn base_src() -> MapSource {
        MapSource(vec![(
            "base-confined".to_owned(),
            "v1".to_owned(),
            BASE_CONFINED.as_bytes().to_vec(),
        )])
    }
    fn ulimits_src(pairs: &[(&str, &str)]) -> SourcePolicy {
        let mut m = std::collections::BTreeMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_owned(), (*v).to_owned());
        }
        SourcePolicy {
            ulimits: Some(m),
            ..SourcePolicy::default()
        }
    }

    #[test]
    fn ulimits_normalise_soft_hard_suffixes_and_unlimited() {
        let src = ulimits_src(&[
            ("nofile", "8192"),
            ("as", "2G"),
            ("cpu", "unlimited"),
            ("nproc", "512:1024"),
            ("memlock", "64K"),
        ]);
        let r = translate_ulimits(&src).expect("translate ulimits");
        assert_eq!(r.limits.get("nofile").map(String::as_str), Some("8192"));
        assert_eq!(r.limits.get("as").map(String::as_str), Some("2147483648"));
        assert_eq!(r.limits.get("cpu").map(String::as_str), Some("unlimited"));
        assert_eq!(r.limits.get("nproc").map(String::as_str), Some("512 1024"));
        assert_eq!(r.limits.get("memlock").map(String::as_str), Some("65536"));
    }

    #[test]
    fn ulimits_unknown_resource_is_rejected() {
        let err = translate_ulimits(&ulimits_src(&[("bogus", "1")])).expect_err("must reject");
        assert!(format!("{err:?}").contains("bogus"), "got {err:?}");
    }

    #[test]
    fn ulimits_non_numeric_value_is_rejected() {
        assert!(translate_ulimits(&ulimits_src(&[("nofile", "lots")])).is_err());
    }

    #[test]
    fn workload_translates_argv_cwd_pin_and_valid_sha256() {
        use crate::source::WorkloadSection;
        let src = SourcePolicy {
            workload: Some(WorkloadSection {
                argv: Some(vec!["run-tests.sh".to_owned(), "--all".to_owned()]),
                cwd: Some("~/suite".to_owned()),
                pinned: Some(true),
                sha256: Some(vec!["a".repeat(64), "b".repeat(64)]),
            }),
            ..SourcePolicy::default()
        };
        let mut deferred = BTreeSet::new();
        let w = translate_workload(&src, &mut deferred).expect("translate workload");
        assert_eq!(w.argv, vec!["run-tests.sh", "--all"]);
        assert!(w.pinned);
        // A SET of accepted digests (multiple versions valid under one policy).
        assert_eq!(w.sha256, vec!["a".repeat(64), "b".repeat(64)]);
        // `~` is the canonical home form in the settled policy; the spawn resolves it to
        // the persona home (home-persona-path-model), so it stays `~/suite` here.
        assert_eq!(w.cwd.as_deref(), Some("~/suite"));
    }

    #[test]
    fn workload_absent_yields_empty_runtime_omitted_from_canonical_form() {
        let mut deferred = BTreeSet::new();
        let w = translate_workload(&SourcePolicy::default(), &mut deferred).expect("translate");
        assert!(w.is_empty());
    }

    #[test]
    fn workload_rejects_malformed_sha256() {
        use crate::source::WorkloadSection;
        for bad in [
            "tooshort",
            &"A".repeat(64),
            &"g".repeat(64),
            &"a".repeat(63),
        ] {
            let src = SourcePolicy {
                workload: Some(WorkloadSection {
                    argv: Some(vec!["x".to_owned()]),
                    sha256: Some(vec![bad.to_owned()]),
                    ..WorkloadSection::default()
                }),
                ..SourcePolicy::default()
            };
            let mut deferred = BTreeSet::new();
            assert!(
                translate_workload(&src, &mut deferred).is_err(),
                "sha256 `{bad}` should be rejected"
            );
        }
    }

    fn translate_template(src: &str) -> Translated {
        let entry = parse(src.as_bytes()).expect("parse");
        let resolved = resolve(&entry, &base_src()).expect("resolve");
        translate(&resolved.effective).expect("translate")
    }

    #[test]
    fn ssh_section_flattens_into_the_settled_runtime() {
        use crate::source::{NetAllow, NetSection, SourcePolicy, SshKey, SshKnownHost, SshSection};
        let src = SourcePolicy {
            net: Some(NetSection {
                allow: vec![NetAllow {
                    name: Some("github.com".to_owned()),
                    ports: vec![22],
                    reason: Some("r".to_owned()),
                    ..NetAllow::default()
                }],
                ..NetSection::default()
            }),
            ssh: Some(SshSection {
                allow_headless: Some(true),
                keys: vec![SshKey {
                    fingerprint: Some(
                        "SHA256:n0Vd5Bn8j3p2q1rStUvWxYzAbCdEfGhIjKlMnOpQrSt".to_owned(),
                    ),
                    hosts: vec!["github.com".to_owned()],
                    reason: Some("push".to_owned()),
                    threats: None,
                }],
                known_hosts: vec![SshKnownHost {
                    host: Some("git.internal".to_owned()),
                    key: Some("ssh-ed25519 AAAA".to_owned()),
                }],
                ..SshSection::default()
            }),
            ..SourcePolicy::default()
        };
        let ssh = translate_ssh(&src);
        assert!(ssh.allow_headless);
        assert_eq!(ssh.grants.len(), 1);
        assert_eq!(
            ssh.grants.first().map(|g| g.host.as_str()),
            Some("github.com")
        );
        assert_eq!(
            ssh.known_hosts.first().map(|k| k.host.as_str()),
            Some("git.internal")
        );
        assert!(!ssh.is_empty());
        // No [ssh] ⇒ empty runtime, omitted from the canonical form (back-compat).
        assert!(translate_ssh(&SourcePolicy::default()).is_empty());
    }

    fn translate_audit_str(src: &str) -> Result<AuditRuntime, PolicyError> {
        let mut deferred = BTreeSet::new();
        let parsed = parse(src.as_bytes()).expect("parse");
        translate_audit(&parsed, &mut deferred)
    }

    #[test]
    fn audit_section_flattens_sinks_levels_and_file() {
        let rt = translate_audit_str(
            r#"
            name = "k"
            [audit]
            sinks = ["file", "journald", "file"]
            [audit.network]
            level = "full"
            [audit.filesystem]
            level = "off"
            [audit.syslog]
            facility = "local3"
            [audit.file]
            rotate_at_bytes = "64M"
            retain_count = 4
            "#,
        )
        .expect("translate");
        assert_eq!(
            rt.sinks,
            vec![AuditSinkKind::File, AuditSinkKind::Journald],
            "dedup preserves first-seen order"
        );
        assert_eq!(rt.network_level.as_deref(), Some("full"));
        assert_eq!(rt.filesystem_level.as_deref(), Some("off"));
        assert_eq!(rt.syslog_facility.as_deref(), Some("local3"));
        assert_eq!(rt.file.rotate_at_bytes, Some(64 * 1024 * 1024));
        assert_eq!(rt.file.retain_count, Some(4));
        assert!(!rt.is_empty());
    }

    #[test]
    fn no_audit_section_is_empty_and_back_compatible() {
        let rt = translate_audit_str("name = \"k\"").expect("translate");
        assert!(
            rt.is_empty(),
            "absent [audit] omits from the canonical form"
        );
    }

    #[test]
    fn unknown_sink_level_facility_and_size_are_rejected() {
        assert!(translate_audit_str("name=\"k\"\n[audit]\nsinks=[\"smtp\"]").is_err());
        assert!(
            translate_audit_str("name=\"k\"\n[audit.network]\nlevel=\"loud\"").is_err(),
            "bad level rejected"
        );
        assert!(
            translate_audit_str("name=\"k\"\n[audit.syslog]\nfacility=\"nope\"").is_err(),
            "bad facility rejected"
        );
        assert!(
            translate_audit_str("name=\"k\"\n[audit.file]\nrotate_at_bytes=\"big\"").is_err(),
            "bad size rejected"
        );
    }

    #[test]
    fn audit_defaults_file_parses_the_section_body_at_top_level() {
        // A standalone audit.toml: the [audit] body without the [audit] wrapper.
        let rt = parse_audit_defaults(
            r#"
            sinks = ["journald"]
            [network]
            level = "full"
            [file]
            rotate_at_bytes = "128M"
            compress_after_seconds = 3600
            "#,
        )
        .expect("parse defaults");
        assert_eq!(rt.sinks, vec![AuditSinkKind::Journald]);
        assert_eq!(rt.network_level.as_deref(), Some("full"));
        assert_eq!(rt.file.rotate_at_bytes, Some(128 * 1024 * 1024));
        assert_eq!(rt.file.compress_after_seconds, Some(3600));
    }

    #[test]
    fn audit_defaults_file_rejects_bad_values() {
        assert!(parse_audit_defaults("sinks = [\"smtp\"]").is_err());
        assert!(parse_audit_defaults("[file]\nrotate_at_bytes = \"big\"").is_err());
        assert!(parse_audit_defaults("not = valid = toml").is_err());
    }

    #[test]
    fn overlay_lets_the_higher_layer_win_per_field() {
        // The defaults file uses the source `[audit]`-section shape: the facility
        // is `[syslog] facility`, not the settled flat `syslog_facility`.
        let base = parse_audit_defaults(
            "sinks = [\"journald\"]\n[syslog]\nfacility = \"local0\"\n[file]\nretain_count = 8",
        )
        .expect("base");
        let over = AuditRuntime {
            network_level: Some("full".to_owned()),
            file: AuditFileConfig {
                retain_count: Some(2),
                ..AuditFileConfig::default()
            },
            ..AuditRuntime::default()
        };
        let merged = base.overlay(&over);
        // over wins where set:
        assert_eq!(merged.network_level.as_deref(), Some("full"));
        assert_eq!(merged.file.retain_count, Some(2));
        // base survives where over is unset:
        assert_eq!(merged.sinks, vec![AuditSinkKind::Journald]);
        assert_eq!(merged.syslog_facility.as_deref(), Some("local0"));
        // an empty `over.sinks` does not clobber the base sinks:
        assert!(!merged.sinks.is_empty());
    }

    #[test]
    fn exec_shell_and_path_translate_with_allowlist_check() {
        let src = parse(
            b"name = \"k\"\n[exec]\nallow = [\"/bin/bash\", \"/usr/bin/git\"]\npath = [\"/usr/bin\", \"/bin\"]\nshell = \"/bin/bash\"\n",
        )
        .expect("parse");
        let ep = translate_exec(&src, &mut BTreeSet::new()).expect("translate");
        assert_eq!(ep.shell, "/bin/bash");
        assert_eq!(ep.path, vec!["/usr/bin".to_owned(), "/bin".to_owned()]);

        // A shell not in a non-empty allowlist is a compile error.
        let bad =
            parse(b"name = \"k\"\n[exec]\nallow = [\"/usr/bin/git\"]\nshell = \"/bin/bash\"\n")
                .expect("parse");
        assert!(translate_exec(&bad, &mut BTreeSet::new()).is_err());

        // Default shell /bin/sh; no allowlist ⇒ no constraint.
        let dfl = parse(b"name = \"k\"\n").expect("parse");
        let ep2 = translate_exec(&dfl, &mut BTreeSet::new()).expect("translate");
        assert_eq!(ep2.shell, "/bin/sh");
        assert!(ep2.path.is_empty());
    }

    #[test]
    fn exec_deny_is_carried_and_exact_matches_subtracted_from_allow() {
        // "deny evaluated before allow": an exact-match deny is removed from allow
        // (Landlock never grants EXECUTE on it); the full deny list is carried for
        // audit and runtime warning.
        let src = parse(
            b"name = \"k\"\n[exec]\nallow = [\"/usr/bin/git\", \"/usr/bin/sudo\"]\ndeny = [\"/usr/bin/sudo\", \"/usr/bin/mount\"]\nshell = \"/usr/bin/git\"\n",
        )
        .expect("parse");
        let ep = translate_exec(&src, &mut BTreeSet::new()).expect("translate");
        assert_eq!(ep.allow, vec!["/usr/bin/git".to_owned()], "sudo subtracted");
        assert_eq!(
            ep.deny,
            vec!["/usr/bin/sudo".to_owned(), "/usr/bin/mount".to_owned()],
            "full deny list carried"
        );
        // /usr/bin/sudo was an exact allow entry now removed, and there is no glob
        // dir grant re-exposing it ⇒ enforced by omission, no warning. /usr/bin/mount
        // is simply never granted ⇒ also enforced, no warning.
        assert!(ep.deny_warnings().is_empty(), "{:?}", ep.deny_warnings());
    }

    #[test]
    fn exec_deny_inside_an_allowed_glob_dir_warns() {
        let src = parse(
            b"name = \"k\"\n[exec]\nallow = [\"/usr/bin/**\", \"/bin/sh\"]\ndeny = [\"/usr/bin/sudo\"]\n",
        )
        .expect("parse");
        let ep = translate_exec(&src, &mut BTreeSet::new()).expect("translate");
        // The glob dir grant re-exposes sudo; Landlock cannot subtract ⇒ advisory warn.
        let w = ep.deny_warnings();
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w
            .first()
            .is_some_and(|s| s.contains("falls inside allowed directory")));
    }

    #[test]
    fn exec_deny_without_any_allow_is_redundant_not_warned() {
        // Deny-by-default: an empty allowlist denies ALL execution, so a deny names
        // paths that are already denied — redundant and harmless, no warning.
        let src = parse(b"name = \"k\"\n[exec]\ndeny = [\"/usr/bin/sudo\"]\n").expect("parse");
        let ep = translate_exec(&src, &mut BTreeSet::new()).expect("translate");
        assert!(ep.deny_warnings().is_empty(), "{:?}", ep.deny_warnings());
    }

    #[test]
    fn exec_deny_under_permissive_wildcard_warns() {
        // The only "deny enforces nothing" case now: explicit `permissive-exec` (`**`)
        // grants all execution, so Landlock cannot subtract a single denied path.
        let src = parse(b"name = \"k\"\n[exec]\nallow = [\"**\"]\ndeny = [\"/usr/bin/sudo\"]\n")
            .expect("parse");
        let ep = translate_exec(&src, &mut BTreeSet::new()).expect("translate");
        let w = ep.deny_warnings();
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w.first().is_some_and(|s| s.contains("permissive-exec")));
    }

    #[test]
    fn env_set_is_synthesised_ignoring_pass_and_deny() {
        let src = parse(
            b"name = \"k\"\n[env]\npass = [\"FOO\"]\ndeny = [\"BAR\"]\nset = { LANG = \"C.UTF-8\", TZ = \"UTC\" }\n",
        )
        .expect("parse");
        let env = translate_env(&src, &mut BTreeSet::new());
        assert_eq!(env.vars.get("LANG").map(String::as_str), Some("C.UTF-8"));
        assert_eq!(env.vars.get("TZ").map(String::as_str), Some("UTC"));
        // Synthesis carries only `set` — the legacy pass/deny curation is ignored.
        assert_eq!(env.vars.len(), 2);
    }

    #[test]
    fn fs_home_persist_carries_to_settled() {
        let src = parse(b"name = \"k\"\n[fs.home]\nshadow = true\npersist = [\".bashrc\"]\n")
            .expect("parse");
        let fs = translate_fs(&src, &mut BTreeSet::new()).expect("translate_fs");
        assert_eq!(fs.home_persist, vec![".bashrc".to_owned()]);
    }

    #[test]
    fn fs_home_readonly_defaults_false_and_carries_when_set() {
        let dflt = parse(b"name = \"k\"\n[fs.home]\nshadow = true\n").expect("parse");
        let fs = translate_fs(&dflt, &mut BTreeSet::new()).expect("translate_fs");
        assert!(!fs.home_readonly, "home is writable by default");
        let ro =
            parse(b"name = \"k\"\n[fs.home]\nshadow = true\nreadonly = true\n").expect("parse");
        let fs = translate_fs(&ro, &mut BTreeSet::new()).expect("translate_fs");
        assert!(fs.home_readonly, "readonly carries to the settled policy");
    }

    #[test]
    fn unix_section_flattens_into_the_settled_runtime() {
        use crate::source::{SourcePolicy, UnixAllow, UnixSection};
        let src = SourcePolicy {
            unix: Some(UnixSection {
                default: Some("deny".to_owned()),
                abstract_ns: Some("deny".to_owned()),
                allow: vec![UnixAllow {
                    name: Some("gpg-agent".to_owned()),
                    real: Some("~/.gnupg/kennels/<kennel>/S.gpg-agent".to_owned()),
                    shim: Some("~/.gnupg/S.gpg-agent".to_owned()),
                    reason: Some("sign commits".to_owned()),
                    ..UnixAllow::default()
                }],
            }),
            ..SourcePolicy::default()
        };
        let mut deferred = BTreeSet::new();
        let unix = translate_unix(&src, &mut deferred);
        assert_eq!(unix.sockets.len(), 1);
        let s = unix.sockets.first().expect("socket");
        assert_eq!(s.name, "gpg-agent");
        assert_eq!(s.shim, "~/.gnupg/S.gpg-agent");
        assert!(s.env.is_none());
        // The per-instance placeholder in `real` is recorded for runtime substitution.
        assert!(
            deferred.contains("<kennel>"),
            "the <kennel> placeholder is deferred"
        );
        assert!(!unix.is_empty());
        // No [unix] ⇒ empty runtime, omitted from the canonical form.
        assert!(translate_unix(&SourcePolicy::default(), &mut deferred).is_empty());
    }

    #[test]
    fn identity_unions_explicit_groups_with_device_passthrough_groups() {
        use crate::source::{
            DevPassthrough, FsDev, FsSection, IdentitySection, SourcePolicy, Threats,
        };
        let src = SourcePolicy {
            identity: Some(IdentitySection {
                groups: vec!["plugdev".to_owned(), "dialout".to_owned()],
                ..IdentitySection::default()
            }),
            fs: Some(FsSection {
                dev: Some(FsDev {
                    allow: None,
                    passthrough: vec![
                        DevPassthrough {
                            path: Some("/dev/ttyUSB0".to_owned()),
                            group: Some("dialout".to_owned()), // already listed — de-duped
                            reason: Some("serial".to_owned()),
                            threats: Some(Threats {
                                exposed: vec!["T2.1".to_owned()],
                                mitigated: vec![],
                            }),
                        },
                        DevPassthrough {
                            path: Some("/dev/net/tun".to_owned()),
                            group: Some("netdev".to_owned()), // contributed by the device
                            reason: Some("vpn".to_owned()),
                            threats: Some(Threats {
                                exposed: vec!["T2.1".to_owned()],
                                mitigated: vec![],
                            }),
                        },
                    ],
                }),
                ..FsSection::default()
            }),
            ..SourcePolicy::default()
        };
        let id = translate_identity(&src).expect("translate identity");
        assert_eq!(
            id.groups,
            vec!["plugdev", "dialout", "netdev"],
            "explicit first, device groups added, de-duped"
        );
        // No [identity] and no device groups ⇒ empty (dropped from the canonical form).
        assert!(translate_identity(&SourcePolicy::default())
            .expect("translate identity")
            .is_empty());
    }

    #[test]
    fn identity_user_and_group_default_to_kennel_and_can_be_overridden() {
        use crate::source::IdentitySection;
        // Default: both `kennel`, so the runtime is empty (omitted from canonical form).
        let dflt = translate_identity(&SourcePolicy::default()).expect("default");
        assert_eq!(dflt.user, "kennel");
        assert_eq!(dflt.group, "kennel");
        assert!(dflt.is_empty());

        // Overridden: carried through, and no longer empty.
        let src = SourcePolicy {
            identity: Some(IdentitySection {
                user: Some("dev".to_owned()),
                group: Some("staff".to_owned()),
                groups: Vec::new(),
            }),
            ..SourcePolicy::default()
        };
        let id = translate_identity(&src).expect("override");
        assert_eq!(id.user, "dev");
        assert_eq!(id.group, "staff");
        assert!(!id.is_empty());
    }

    #[test]
    fn an_invalid_identity_name_is_refused() {
        use crate::source::IdentitySection;
        for (field, bad) in [
            ("user", "../escape"),
            ("user", "has space"),
            ("user", "Root"),     // uppercase
            ("user", "1leading"), // leading digit
            ("user", ""),
            ("group", "a:b"),
        ] {
            let mut sec = IdentitySection::default();
            if field == "user" {
                sec.user = Some(bad.to_owned());
            } else {
                sec.group = Some(bad.to_owned());
            }
            let src = SourcePolicy {
                identity: Some(sec),
                ..SourcePolicy::default()
            };
            assert!(
                translate_identity(&src).is_err(),
                "identity.{field} `{bad}` must be refused"
            );
        }
    }

    #[test]
    fn dev_passthrough_paths_merge_into_the_settled_dev_allowlist() {
        use crate::source::{
            DevPassthrough, FsDev, FsHome, FsSection, NetSection, SourcePolicy, Threats,
        };
        let src = SourcePolicy {
            net: Some(NetSection {
                mode: Some("none".to_owned()),
                ..NetSection::default()
            }),
            fs: Some(FsSection {
                home: Some(FsHome::default()),
                dev: Some(FsDev {
                    allow: Some(vec!["/dev/null".to_owned()]),
                    passthrough: vec![DevPassthrough {
                        path: Some("/dev/net/tun".to_owned()),
                        group: Some("netdev".to_owned()),
                        reason: Some("vpn".to_owned()),
                        threats: Some(Threats {
                            exposed: vec!["T2.1".to_owned()],
                            mitigated: vec![],
                        }),
                    }],
                }),
                ..FsSection::default()
            }),
            ..SourcePolicy::default()
        };
        let dev = translate(&src).expect("translate").effective_policy.fs.dev;
        // The pseudo-device baseline and the passthrough device both land in `allow`,
        // which is what the spawn binds. The reason/threats/group do not survive.
        assert!(dev.allow.iter().any(|d| d == "/dev/null"), "baseline kept");
        assert!(
            dev.allow.iter().any(|d| d == "/dev/net/tun"),
            "passthrough device bound in"
        );
    }

    #[test]
    fn ai_coding_strict_translates_its_unix_shim() {
        let t = translate_template(AI_CODING_STRICT);
        assert!(!t.unix.is_empty(), "the template grants a gpg-agent shim");
        let gpg = t
            .unix
            .sockets
            .iter()
            .find(|s| s.name == "gpg-agent")
            .expect("gpg-agent socket");
        assert_eq!(gpg.shim, "~/.gnupg/S.gpg-agent");
        // <kennel> in the real path is deferred to the runtime.
        assert!(gpg.real.contains("<kennel>"));
        assert!(t.deferred_substitutions.iter().any(|p| p == "<kennel>"));
        // SSH is never a unix shim.
        assert!(!t
            .unix
            .sockets
            .iter()
            .any(|s| s.env.as_deref() == Some("SSH_AUTH_SOCK")));
    }

    #[test]
    fn an_empty_ssh_runtime_does_not_change_the_canonical_bytes() {
        // A no-SSH policy must serialise byte-for-byte as before the field existed,
        // so existing signatures stay valid.
        let t = translate_template(AI_CODING_STRICT);
        assert!(t.ssh.is_empty(), "the in-tree template has no [ssh] grant");
    }

    #[test]
    fn ai_coding_strict_translates_to_a_runtime_policy() {
        let t = translate_template(AI_CODING_STRICT);
        let ep = &t.effective_policy;

        assert_eq!(ep.net.mode, NetMode::Constrained);
        assert!(ep
            .net
            .allow_names
            .iter()
            .any(|n| n.name == "github.com" && n.ports == vec![22, 443]));
        assert!(ep
            .net
            .deny_invariant
            .iter()
            .any(|r| r.cidr == "169.254.169.254" && r.prefix_len == 32));
        assert!(ep
            .net
            .deny_invariant
            .iter()
            .any(|r| r.cidr == "fd00:ec2::254" && r.prefix_len == 128));

        assert!(ep.fs.home_shadow);
        assert_eq!(ep.fs.tmp.size_mib, 512);
        assert_eq!(ep.fs.tmp.mode, "0700");
        assert!(ep.fs.dev.allow.iter().any(|d| d == "/dev/null"));

        assert!(ep.exec.deny_setuid && ep.exec.deny_writable);
        assert!(ep.exec.allow.iter().any(|a| a.contains("git")));

        assert!(ep.cap.no_new_privs);
        assert_eq!(ep.proc.visibility, ProcVisibility::SelfOnly);
        assert!(ep.proc.hidepid);

        // 8h TTL, warn.
        assert_eq!(ep.lifecycle.ttl_seconds, Some(28_800));
        assert_eq!(ep.lifecycle.ttl_action, TtlAction::Warn);

        // Per-instance placeholders are deferred to spawn (the daemon fills them).
        assert!(t.deferred_substitutions.iter().any(|p| p == "<kennel>"));
    }

    #[test]
    fn translated_policy_passes_framework_invariant_reassertion() {
        // The runtime re-asserts invariants on the settled policy; the compiler's
        // output must clear that bar.
        let t = translate_template(AI_CODING_STRICT);
        let policy = SettledPolicy {
            settled_schema_version: 1,
            name: "myproj".to_owned(),
            deferred_substitutions: t.deferred_substitutions,
            framework_invariants_asserted: Vec::new(),
            effective_policy: t.effective_policy,
            provenance: Provenance {
                compiler_version: "0.0.0".to_owned(),
                schema_version: 1,
                threat_catalogue_version: "0.1".to_owned(),
                leaf_policy_sha256: "00".to_owned(),
                invariant_set_sha256: "00".to_owned(),
                resolved_artifacts: Vec::<ResolvedArtifact>::new(),
            },
            ssh: t.ssh,
            unix: t.unix,
            identity: t.identity,
            binder: t.binder,
            audit: t.audit,
            env: t.env,
            ulimits: t.ulimits,
            workload: t.workload,
        };
        crate::invariant::validate(&policy).expect("framework invariants must hold");
    }

    #[test]
    fn untrusted_build_net_none_becomes_constrained_with_empty_allow() {
        let t = translate_template(UNTRUSTED_BUILD);
        let net = &t.effective_policy.net;
        assert_eq!(net.mode, NetMode::Constrained, "none => constrained");
        assert!(
            net.allow.is_empty() && net.allow_names.is_empty(),
            "no egress permitted"
        );
        // The mandatory cloud-metadata invariant deny still propagates (RFC1918 is
        // no longer an invariant — see base-confined [net]).
        assert!(net
            .deny_invariant
            .iter()
            .any(|r| r.cidr == "169.254.169.254" && r.prefix_len == 32));
        // 2h TTL, "stop" (the backward-compat alias for exit).
        assert_eq!(t.effective_policy.lifecycle.ttl_seconds, Some(7_200));
        assert_eq!(t.effective_policy.lifecycle.ttl_action, TtlAction::Exit);
    }

    #[test]
    fn net_bind_min_port_carries_into_the_settled_policy() {
        // `[net.bind].min_port` → `NetPolicy.bind_port_min` (the BPF bind floor, §7.5.7);
        // absent ⇒ 0 (no floor).
        let with =
            parse(b"name = \"k\"\n[net]\nmode = \"constrained\"\n[net.bind]\nmin_port = 8080\n")
                .expect("parse");
        assert_eq!(
            translate_net(&with, &mut BTreeSet::new())
                .expect("translate")
                .bind_port_min,
            8080
        );
        let without = parse(b"name = \"k\"\n[net]\nmode = \"constrained\"\n").expect("parse");
        assert_eq!(
            translate_net(&without, &mut BTreeSet::new())
                .expect("translate")
                .bind_port_min,
            0
        );
        // The shipped base-confined template sets the conventional 1024 floor.
        assert_eq!(
            translate_template(BASE_CONFINED)
                .effective_policy
                .net
                .bind_port_min,
            1024
        );
    }

    #[test]
    fn net_bind_allowed_ports_carries_and_is_capped() {
        let p = parse(
            b"name = \"k\"\n[net]\nmode = \"constrained\"\n[net.bind]\nallowed_ports = [8080, 9090]\n",
        )
        .expect("parse");
        assert_eq!(
            translate_net(&p, &mut BTreeSet::new())
                .expect("translate")
                .bind_allowed_ports,
            vec![8080, 9090]
        );
        // More than MAX_BIND_PORTS entries is a hard translation error.
        let many = (1..=9)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let src = format!(
            "name = \"k\"\n[net]\nmode = \"constrained\"\n[net.bind]\nallowed_ports = [{many}]\n"
        );
        let over = parse(src.as_bytes()).expect("parse");
        assert!(translate_net(&over, &mut BTreeSet::new()).is_err());
    }

    #[test]
    fn home_prefix_canonicalises_to_tilde_in_settled() {
        // $HOME/foo → ~/foo in the settled policy: one canonical home form, zero host-context refs.
        let src = parse(
            b"name = \"k\"\n[fs]\nread = [\"$HOME/foo\", \"~/bar\", \"/usr\"]\n[fs.home]\n[exec]\nallow = [\"$HOME/bin/tool\", \"/bin/sh\"]\n",
        )
        .expect("parse");
        let fs = translate_fs(&src, &mut BTreeSet::new()).expect("translate fs");
        assert!(
            fs.read.contains(&"~/foo".to_owned()),
            "$HOME/ → ~/ ; got {:?}",
            fs.read
        );
        assert!(fs.read.contains(&"~/bar".to_owned()), "~/ stays ~/");
        assert!(
            fs.read.contains(&"/usr".to_owned()),
            "non-home paths untouched"
        );
        assert!(
            !fs.read.iter().any(|p| p.contains("$HOME")),
            "no $HOME survives into settled"
        );
        let exec = translate_exec(&src, &mut BTreeSet::new()).expect("translate exec");
        assert!(
            exec.allow.contains(&"~/bin/tool".to_owned()),
            "exec.allow $HOME/ → ~/ ; got {:?}",
            exec.allow
        );
    }

    #[test]
    fn fs_write_implies_fs_read() {
        // A writable path is readable without restating it: fs.write folds into fs.read.
        // (Source `fs.write` is a `Vec<String>` scalar list — the template form.)
        let src =
            parse(b"name = \"k\"\n[fs]\nwrite = [\"~/proj/**\"]\n[fs.home]\n").expect("parse");
        let fs = translate_fs(&src, &mut BTreeSet::new()).expect("translate");
        assert!(
            fs.read.contains(&"~/proj/**".to_owned()),
            "a writable path is implied-readable; got read = {:?}",
            fs.read
        );
        assert!(fs.write.contains(&"~/proj/**".to_owned()));
    }

    #[test]
    fn ssh_host_implies_egress_allow_on_22() {
        // An [[ssh.keys]] host grant derives a by-name :22 egress allow; the author writes no
        // parallel [[net.allow]] (the implied-rule pass).
        let src = parse(
            b"name = \"k\"\n[net]\nmode = \"constrained\"\n[[ssh.keys]]\nfingerprint = \"SHA256:n0Vd5Bn8j3p2q1rStUvWxYzAbCdEfGhIjKlMnOpQrSt\"\nhosts = [\"git.internal\"]\n",
        )
        .expect("parse");
        let net = translate_net(&src, &mut BTreeSet::new()).expect("translate");
        let rule = net
            .allow_names
            .iter()
            .find(|r| r.name == "git.internal")
            .expect("ssh host derived into the egress allowlist");
        assert_eq!(rule.ports, vec![22], "derived on port 22");
    }

    #[test]
    fn an_authored_net_allow_for_an_ssh_host_is_not_duplicated() {
        // If the author already named the host, their entry (with its own ports) wins — no dup.
        let src = parse(
            b"name = \"k\"\n[net]\nmode = \"constrained\"\n[[net.allow]]\nname = \"git.internal\"\nports = [22, 443]\nreason = \"git over ssh + https\"\n[[ssh.keys]]\nfingerprint = \"SHA256:n0Vd5Bn8j3p2q1rStUvWxYzAbCdEfGhIjKlMnOpQrSt\"\nhosts = [\"git.internal\"]\n",
        )
        .expect("parse");
        let net = translate_net(&src, &mut BTreeSet::new()).expect("translate");
        let matches: Vec<&NameRule> = net
            .allow_names
            .iter()
            .filter(|r| r.name == "git.internal")
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "the author's entry is not duplicated by the implied rule"
        );
        assert_eq!(
            matches.first().expect("one match").ports,
            vec![22, 443],
            "the author's ports are preserved"
        );
    }

    #[test]
    fn seccomp_carries_the_deny_names() {
        let t = translate_template(AI_CODING_STRICT);
        let sc = &t.effective_policy.seccomp;
        assert_eq!(sc.deny_action, SeccompAction::Errno);
        // base-confined's denylist is inherited.
        assert!(sc.deny.iter().any(|s| s == "bpf"));
        assert!(sc.deny.iter().any(|s| s == "userfaultfd"));
    }

    #[test]
    fn size_and_duration_units_parse() {
        assert_eq!(parse_size_mib("512M").expect("M"), 512);
        assert_eq!(parse_size_mib("1G").expect("G"), 1024);
        assert_eq!(parse_size_mib("64").expect("bare"), 64);
        assert!(parse_size_mib("lots").is_err());
        assert_eq!(parse_duration_secs("8h").expect("h"), 28_800);
        assert_eq!(parse_duration_secs("30m").expect("m"), 1_800);
        assert_eq!(parse_duration_secs("5s").expect("s"), 5);
        assert_eq!(parse_duration_secs("2d").expect("d"), 172_800);
        assert!(parse_duration_secs("soon").is_err());
    }

    #[test]
    fn cidr_split_handles_prefix_and_bare_forms() {
        assert_eq!(
            parse_cidr("10.0.0.0/8").expect("v4"),
            ("10.0.0.0".to_owned(), 8)
        );
        assert_eq!(
            parse_cidr("169.254.169.254").expect("bare v4"),
            ("169.254.169.254".to_owned(), 32)
        );
        assert_eq!(
            parse_cidr("fd00:ec2::254").expect("bare v6"),
            ("fd00:ec2::254".to_owned(), 128)
        );
        assert!(parse_cidr("10.0.0.0/999").is_err());
    }

    #[test]
    fn tag_and_gid_are_deferred_to_spawn_not_substituted() {
        // The compiler no longer knows the installation's tag/gid; <tag>/<gid> are
        // left in place and recorded as deferred, for the daemon to fill from the
        // user's scope (it loads it from /etc/kennel/subkennel).
        let mut deferred = BTreeSet::new();
        let out = subst("addr-<tag>-<gid>-<kennel>", &mut deferred);
        assert_eq!(out, "addr-<tag>-<gid>-<kennel>");
        assert!(deferred.contains("<tag>"));
        assert!(deferred.contains("<gid>"));
        assert!(deferred.contains("<kennel>"));
    }
}
