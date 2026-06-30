//! Translate a resolved, folded source policy into the settled `EffectivePolicy`.
//!
//! # Purpose
//!
//! The compiler stage after [`crate::resolve`](mod@crate::resolve): take the effective [`SourcePolicy`]
//! (rich, human-facing, every section) and produce the flat
//! [`kennel_lib_policy::settled::EffectivePolicy`] the runtime enforces, plus the list of
//! per-instance placeholders the runtime must still fill
//! (`deferred_substitutions`). This is where the human forms become machine forms:
//! `"169.254.169.254/32"` → `NetRule { cidr, prefix_len }`, `"512M"` → `size_mib`,
//! `"8h"` → `ttl_seconds`, `"constrained"`/`"none"`/`"unconstrained"`/`"host"` → [`NetMode`].
//!
//! # The runtime-relevant subset (02-2, 08)
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
//! and refuses to spawn if any *other* placeholder survives (02-2
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

use crate::source::{PathField, SourcePolicy};
use kennel_lib_policy::settled::{
    AuditRuntime, BinderConsumeRuntime, BinderProvideRuntime, BinderRuntime, CapPolicy,
    ConsumeRuntime, DbusBusRuntime, DbusRuntime, DevPolicy, EffectivePolicy, EnvRuntime,
    ExecPolicy, FsPolicy, IdentityRuntime, LifecyclePolicy, MeshRuntime, NameRule, NetMode,
    NetPolicy, NetRule, ProcPolicy, ProcVisibility, Protocol, ProvideRuntime, ProxyListen,
    RestartPolicy, RootfsRuntime, SeccompAction, SeccompPolicy, ServiceRuntime, SshGrant,
    SshRuntime, TmpPolicy, TtlAction, UlimitsRuntime, UnixRuntime, UnixSocket, WorkloadRuntime,
};
use kennel_lib_policy::variant::{Manifest, Variant};
use kennel_lib_policy::PolicyError;
use std::collections::BTreeSet;

/// The product of translation: the settled effective policy plus the per-instance
/// placeholders the runtime must substitute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Translated {
    /// The flat, runtime-enforced policy.
    pub effective_policy: EffectivePolicy,
    /// The per-kennel SSH runtime — a service input, not enforcement.
    pub ssh: SshRuntime,
    /// The per-kennel `AF_UNIX` socket shims — a service input, not enforcement.
    pub unix: UnixRuntime,
    /// The workload's in-kennel identity — the supplementary groups it retains.
    pub identity: IdentityRuntime,
    /// The per-kennel binder IPC runtime — user-defined provide/consume grants.
    pub binder: BinderRuntime,
    /// The cross-kennel capability mesh runtime — `[[provides]]`/`[[consumes]]`.
    pub mesh: MeshRuntime,
    /// The `[service]` supervision discipline — the restart policy, present only when
    /// the policy declares `[service]`.
    pub service: Option<ServiceRuntime>,
    /// The per-kennel D-Bus runtime — the `IDBus` facade's rule set.
    pub dbus: DbusRuntime,
    /// The per-kennel audit runtime (-3) — sinks and per-class level deviations.
    pub audit: AuditRuntime,
    /// The synthesised environment — the fixed `[env].set` vars.
    pub env: EnvRuntime,
    /// The per-kennel resource limits — applied via `setrlimit` in the seal.
    pub ulimits: UlimitsRuntime,
    /// The workload to run — argv, cwd, pin, and optional sha256.
    pub workload: WorkloadRuntime,
    /// The per-kennel OCI substrate — the image root the daemon boots, when OCI-model.
    pub rootfs: RootfsRuntime,
    /// The mutable-field manifest — the signed variant constraints, present only on a
    /// spawn-target template. Empty otherwise.
    pub manifest: Manifest,
    /// Per-instance placeholders (`<kennel>`, `<ctx>`, …) still to be filled at spawn.
    pub deferred_substitutions: Vec<String>,
}

/// Translate an effective (resolved, folded) source policy into the settled form.
///
/// `effective` must be the output of [`crate::resolve::resolve`] (nothing left to
/// inherit). All placeholders are deferred to spawn (see the module).
///
/// # Errors
///
/// Returns [`PolicyError::Translation`] if a required field is missing or a human
/// form (CIDR, size, duration, port spec, net mode) is malformed.
pub fn translate(effective: &SourcePolicy) -> Result<Translated, PolicyError> {
    let mut deferred = BTreeSet::new();
    validate_rootfs(effective)?;
    validate_spawn(effective)?;
    validate_mutable_manifest(effective)?;
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
    // [tty]: the PTY escape filter, default on. Folds scalar-wins; absent ⇒ default.
    let tty = kennel_lib_policy::settled::TtyPolicy {
        filter_terminal_escapes: effective
            .tty
            .as_ref()
            .and_then(|t| t.filter_terminal_escapes)
            .unwrap_or(true),
    };
    // [trust]: the masked workspace manifest, default on. Absent ⇒ default.
    let trust = kennel_lib_policy::settled::TrustPolicy {
        manifest: effective
            .trust
            .as_ref()
            .and_then(|t| t.manifest)
            .unwrap_or(true),
        on_change: effective
            .trust
            .as_ref()
            .and_then(|t| t.on_change)
            .unwrap_or_default(),
    };
    let ssh = translate_ssh(effective);
    let unix = translate_unix(effective, &mut deferred);
    let identity = translate_identity(effective)?;
    let binder = translate_binder(effective);
    let mesh = translate_mesh(effective);
    let service = translate_service(effective)?;
    let dbus = translate_dbus(effective);
    let audit = translate_audit(effective, &mut deferred)?;
    let env = translate_env(effective, &mut deferred);
    let ulimits = translate_ulimits(effective)?;
    let workload = translate_workload(effective, &mut deferred)?;
    let rootfs = translate_rootfs_runtime(effective, &mut deferred);

    Ok(Translated {
        effective_policy: EffectivePolicy {
            net,
            fs,
            exec,
            proc,
            cap,
            seccomp,
            lifecycle,
            tty,
            trust,
        },
        ssh,
        unix,
        identity,
        binder,
        mesh,
        service,
        dbus,
        audit,
        env,
        ulimits,
        workload,
        rootfs,
        manifest: translate_manifest(effective),
        deferred_substitutions: deferred.into_iter().collect(),
    })
}

/// Map the source `[[mutable]]` manifest into the settled [`Variant`] form carried on the
/// signed template. The source well-formedness (exactly one constraint kind, etc.) is enforced by
/// [`validate_mutable_manifest`]; here we shape each entry into its settled variant. The settled
/// `Variant` is flat (the constraint kind is which fields are set), mirroring the source.
fn translate_manifest(src: &SourcePolicy) -> Manifest {
    src.mutable
        .iter()
        .map(|m| Variant {
            field: m.field.clone().unwrap_or_default(),
            one_of: m.oneof.clone().unwrap_or_default(),
            pool: m.from.clone().unwrap_or_default(),
            pool_max: m.max.unwrap_or(0),
            pattern: m.match_.clone().unwrap_or_default(),
            relpath_under: m.under.clone().unwrap_or_default(),
            freeform: m.freeform.unwrap_or(false),
            reason: m.reason.clone().unwrap_or_default(),
        })
        .collect()
}

/// Translate `[rootfs]` into the settled [`RootfsRuntime`]. Carries the substrate `path`
/// (`subst`-resolved for `~`/`<home>` like other in-view paths) and the provenance `image`. The
/// loud-grant well-formedness (path/image/reason all present) is already enforced by
/// [`validate_rootfs`] at the top of [`translate`], so this only shapes the runtime; `reason`
/// stays in source (the risk surface), never the settled artefact. Absent ⇒ an empty runtime,
/// omitted from the canonical form, so a non-OCI policy signs exactly as before.
fn translate_rootfs_runtime(src: &SourcePolicy, deferred: &mut BTreeSet<String>) -> RootfsRuntime {
    let Some(r) = src.rootfs.as_ref() else {
        return RootfsRuntime::default();
    };
    RootfsRuntime {
        path: r
            .path
            .as_deref()
            .map(|p| subst(p, deferred))
            .unwrap_or_default(),
        image: r.image.clone().unwrap_or_default(),
        // Empty (unset) stays empty in the settled form — the spawn path reads it as `discard`
        // — so an OCI policy that does not set persistence signs unchanged. `validate_rootfs`
        // has already rejected any value outside the two.
        persistence: r.persistence.clone().unwrap_or_default(),
        // Closure-lock lists pass through verbatim (rootfs paths, not subst-resolved — they are
        // in-image absolute paths the spawn keys Landlock rules on post-pivot).
        readonly: r.readonly.clone().unwrap_or_default(),
        writable: r.writable.clone().unwrap_or_default(),
    }
}

/// Translate `[workload]` into the settled [`WorkloadRuntime`]. `argv` carries
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

/// Flatten the resolved `[[provides]]`/`[[consumes]]` into the settled [`MeshRuntime`]: one runtime entry each. Already compile-time-validated (`crate::mesh`), so the
/// required fields are present — `filter_map` skips a malformed entry defensively. An empty
/// mesh yields an empty runtime (omitted from the canonical form), so a policy with no mesh
/// declarations signs exactly as before.
fn translate_mesh(src: &SourcePolicy) -> MeshRuntime {
    let provides = src
        .provides
        .iter()
        .filter_map(|p| {
            use kennel_lib_policy::settled::Shape;
            let name = p.name.clone()?;
            let shape = p.shape?;
            let key = p.key.clone();
            // An omitted `af-unix` endpoint defaults to `/run/<name>[.key]/sock`; other
            // shapes author a required endpoint, so a missing one drops the provide (caught at compile).
            let endpoint = match p.endpoint.clone() {
                Some(e) => e,
                None if shape == Shape::AfUnix => {
                    crate::mesh::default_af_unix_endpoint(&name, key.as_deref())
                }
                None => return None,
            };
            Some(ProvideRuntime {
                name,
                shape,
                endpoint,
                key,
            })
        })
        .collect();
    let consumes = src
        .consumes
        .iter()
        .filter_map(|c| {
            Some(ConsumeRuntime {
                name: c.name.clone()?,
                shape: c.shape?,
                at: c.at.clone(),
                env: c.env.clone(),
                key: c.key.clone(),
                required: c.required,
            })
        })
        .collect();
    MeshRuntime { provides, consumes }
}

/// Translate `[dbus]` into the settled [`DbusRuntime`]: one resolved rule set per
/// *enabled* bus. A bus with `enabled` unset/false yields no entry (no connection), so a
/// no-`[dbus]` (or all-disabled) policy signs exactly as before. The refuse-to-broker set
/// was already rejected at validation (`SourcePolicy::check_dbus`).
fn translate_dbus(src: &SourcePolicy) -> DbusRuntime {
    use crate::source::DbusBus;
    let Some(dbus) = &src.dbus else {
        return DbusRuntime::default();
    };
    let bus = |b: &Option<DbusBus>| -> Option<DbusBusRuntime> {
        let b = b.as_ref()?;
        if b.enabled != Some(true) {
            return None;
        }
        let allow = b.allow.clone().unwrap_or_default();
        let deny = b.deny.clone().unwrap_or_default();
        Some(DbusBusRuntime {
            talk: allow.talk,
            call: allow.call,
            broadcast: allow.broadcast,
            own: allow.own,
            deny_talk: deny.talk,
        })
    };
    DbusRuntime {
        session: bus(&dbus.session),
        system: bus(&dbus.system),
        audit_level: dbus.audit.as_ref().and_then(|a| a.level.clone()),
    }
}

/// Translate `[ulimits]` into the settled [`UlimitsRuntime`]. Each entry is a
/// `setrlimit` resource name (validated against [`kennel_lib_policy::settled::ULIMIT_RESOURCES`]) and a value of
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
        if !kennel_lib_policy::settled::ULIMIT_RESOURCES.contains(&name.as_str()) {
            return Err(translation(format!(
                "unknown ulimit resource `{name}` (expected one of {})",
                kennel_lib_policy::settled::ULIMIT_RESOURCES.join(", ")
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

/// Flatten the source `[env].set` into the settled [`EnvRuntime`]. The
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

/// Flatten the source `[audit]` section into the settled [`AuditRuntime`],
/// validating sink names, per-class levels, sizes, and the syslog facility.
/// Only deviations from the defaults are carried; an absent or all-default
/// section yields the empty runtime (omitted from the canonical form).
///
/// The translation itself lives in [`kennel_lib_policy::audit`] (the single source of truth
/// shared with the runtime `audit.toml` defaults parser); here we supply the
/// deferred-placeholder substitution for a file-sink `dir`.
fn translate_audit(
    src: &SourcePolicy,
    deferred: &mut BTreeSet<String>,
) -> Result<AuditRuntime, PolicyError> {
    src.audit.as_ref().map_or_else(
        || Ok(AuditRuntime::default()),
        |audit| kennel_lib_policy::audit::translate_audit_section(audit, |d| subst(d, deferred)),
    )
}

/// Gather the workload's retained supplementary groups: the explicit
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
        .unwrap_or_else(|| kennel_lib_policy::settled::DEFAULT_USER.to_owned());
    validate_name("identity.user", &user)?;
    let group = id
        .and_then(|i| i.group.clone())
        .unwrap_or_else(|| kennel_lib_policy::settled::DEFAULT_GROUP.to_owned());
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
/// Validate `[rootfs]`: the OCI substrate grant is loud and self-contained. When present
/// it must carry `path`, `image`, and a non-empty `reason` — the substrate-trust waiver (T3.8) is
/// loud the way `mode = host` requires `net.reason`. Absent ⇒ not an OCI-model policy, nothing to
/// check here; the `kennel run` vs `kennel oci run` consumer split is enforced at the verb.
fn validate_rootfs(src: &SourcePolicy) -> Result<(), PolicyError> {
    let Some(rootfs) = &src.rootfs else {
        return Ok(());
    };
    let need = |field: &str, val: &Option<String>| -> Result<(), PolicyError> {
        if val.as_deref().unwrap_or("").trim().is_empty() {
            return Err(translation(format!(
                "[rootfs] is an OCI substrate grant and requires a non-empty `{field}`"
            )));
        }
        Ok(())
    };
    need("path", &rootfs.path)?;
    need("image", &rootfs.image)?;
    need("reason", &rootfs.reason)?;
    // Grammar partition: `[rootfs]` and `[workload]` are mutually exclusive — an OCI
    // policy runs the image entrypoint via the launcher and has no per-binary pin, so a
    // `[workload]` block is a category error, not a silently-ignored field.
    if src.workload.is_some() {
        return Err(translation(
            "[rootfs] and [workload] are mutually exclusive: an OCI-model policy runs the image \
             entrypoint via the launcher (use `kennel oci run … -- <cmd>` for a Cmd override)"
                .to_owned(),
        ));
    }
    // Persistence is binary; empty (unset) means the default `discard`.
    let persistence = rootfs.persistence.as_deref().unwrap_or("discard");
    if !matches!(persistence, "discard" | "persist") {
        return Err(translation(format!(
            "[rootfs].persistence must be `discard` or `persist`, got `{persistence}`"
        )));
    }
    // `persist` + whole-tree-immutable is a contradiction (an upper that can never be written).
    let whole_tree_ro = rootfs
        .readonly
        .as_deref()
        .is_some_and(|r| r.iter().any(|p| p == "/"));
    if persistence == "persist" && whole_tree_ro {
        return Err(translation(
            "[rootfs] persistence = \"persist\" with readonly = [\"/\"] is a contradiction: the \
             managed upper could never be written — drop one"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Install-time ceiling on a spawn's mutable-field patch (; 02-10 "the patch is bounded by
/// the binder transaction buffer"). The patch rides one binder transaction (a ~1 MiB shared buffer
/// that also carries the template ref, the spawn uuid, and framing); a field-selection patch
/// approaching this is already pathological. Bounding the manifest's *worst case* here turns an
/// opaque runtime transport failure into a fail-fast install error on the spawn-target template.
const SPAWN_PATCH_MAX_BYTES: usize = 64 * 1024;

/// Worst-case encoded length of a single predicate value — a traversal-free `RESOLVE_IN_ROOT`
/// relpath, bounded by `PATH_MAX`.
const SPAWN_PRED_VALUE_MAX: usize = 4096;

/// A length-prefixed wire field costs a 4-byte count plus its bytes.
const WIRE_LEN_PREFIX: usize = 4;

/// Validate `[spawn]` local well-formedness: the delegated-instantiation grant is loud and
/// bounded. Cross-template eligibility of each named target (depth-1, ceilings, manifest) is the
/// *spawner's* compile-time gate in [`crate::compile`], which can resolve the targets; here we check
/// only what the grant's own bytes settle.
fn validate_spawn(src: &SourcePolicy) -> Result<(), PolicyError> {
    let Some(spawn) = &src.spawn else {
        return Ok(());
    };
    if spawn.reason.as_deref().unwrap_or("").trim().is_empty() {
        return Err(translation(
            "[spawn] is a delegated-instantiation grant and requires a non-empty `reason`"
                .to_owned(),
        ));
    }
    match spawn.max_instances {
        None => {
            return Err(translation(
                "[spawn] requires `max_instances` (the concurrent fork-bomb ceiling)".to_owned(),
            ));
        }
        Some(0) => {
            return Err(translation(
                "[spawn].max_instances must be at least 1 (0 grants nothing — drop [spawn] instead)"
                    .to_owned(),
            ));
        }
        Some(_) => {}
    }
    if spawn.allow.is_empty() {
        return Err(translation(
            "[spawn] grants nothing without at least one [[spawn.allow]] template".to_owned(),
        ));
    }
    for entry in &spawn.allow {
        let Some(template) = entry.template.as_deref() else {
            return Err(translation(
                "[[spawn.allow]] requires a `template` (an exact `name@version` trust-store ref)"
                    .to_owned(),
            ));
        };
        crate::source::validate_reference(template)
            .map_err(|d| translation(format!("[[spawn.allow]] template = \"{template}\": {d}")))?;
        if let Some(narrow) = &entry.mutable {
            if narrow.iter().any(|f| f.trim().is_empty()) {
                return Err(translation(format!(
                    "[[spawn.allow]] template = \"{template}\": `mutable` narrowing names an empty \
                     field"
                )));
            }
        }
    }
    Ok(())
}

/// Validate a `[[mutable]]` manifest on a spawn-target template: each entry names a
/// `field` and carries exactly one well-formed bound — pool (`from` + `max`), `oneof`, or predicate
/// (`type` + `under`) — and the manifest's worst-case patch fits the spawn transaction bound (so an
/// oversized manifest fails here, not as a runtime transport error). "Mutable" is writable *within*
/// the bound, never free; the bound is part of the signed declaration.
fn validate_mutable_manifest(src: &SourcePolicy) -> Result<(), PolicyError> {
    if src.mutable.is_empty() {
        return Ok(());
    }
    let mut worst_case = WIRE_LEN_PREFIX; // the patch's overall count prefix
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for m in &src.mutable {
        let field = m
            .field
            .as_deref()
            .map(str::trim)
            .filter(|f| !f.is_empty())
            .ok_or_else(|| {
                translation(
                    "[[mutable]] requires a non-empty `field` (the leaf-field path it opens)"
                        .to_owned(),
                )
            })?;
        if !seen.insert(field) {
            return Err(translation(format!(
                "[[mutable]] field = \"{field}\" is declared twice; each field opens once"
            )));
        }
        // A variant opens an EXISTING, registered policy leaf — never a coined field. The applicator's
        // registry (the verify half) is the authority; an unknown field cannot be applied at spawn, so
        // reject it here at the spawner's compile.
        if !kennel_lib_policy::patch::is_mutable_field(field) {
            return Err(translation(format!(
                "[[mutable]] field = \"{field}\" is not a mutable policy leaf (must be one the schema \
                 defines and the spawn applicator supports, e.g. `net.proxy.allow`, `fs.read`, \
                 `fs.write`, `rootfs.writable`)"
            )));
        }
        worst_case = worst_case.saturating_add(variant_worst_case(m, field)?);
    }
    if worst_case > SPAWN_PATCH_MAX_BYTES {
        return Err(translation(format!(
            "[[mutable]] manifest worst-case patch is {worst_case} bytes, over the \
             {SPAWN_PATCH_MAX_BYTES}-byte spawn transaction bound; reduce a pool `max` \
             or shorten the pools"
        )));
    }
    Ok(())
}

/// Validate one `[[mutable]]` variant carries exactly one well-formed constraint, returning its
/// worst-case contribution to the patch size. A `(field, value)` pair costs a length-prefix + the
/// field path plus a length-prefix + the value (saturating; a pathological manifest is rejected,
/// never overflows). The *open* constraints (pattern/predicate/freeform) have no sign-time count
/// bound, so each contributes one capped value as a floor; the runtime applicator enforces the true
/// `SPAWN_PATCH_MAX_BYTES` total over the actual patch.
fn variant_worst_case(m: &crate::source::MutableField, field: &str) -> Result<usize, PolicyError> {
    let is_pool = m.from.is_some() || m.max.is_some();
    let is_oneof = m.oneof.is_some();
    let is_pattern = m.match_.is_some();
    let is_pred = m.type_.is_some() || m.under.is_some();
    let is_freeform = m.freeform == Some(true);
    let kinds = [is_pool, is_oneof, is_pattern, is_pred, is_freeform]
        .into_iter()
        .filter(|b| *b)
        .count();
    if kinds != 1 {
        return Err(translation(format!(
            "[[mutable]] field = \"{field}\" must carry exactly one constraint — pool \
             (`from`+`max`), `oneof`, `match` (pattern), predicate (`type`+`under`), or \
             `freeform`; found {kinds}"
        )));
    }
    let field_cost = WIRE_LEN_PREFIX.saturating_add(field.len());
    let open_value = || {
        field_cost
            .saturating_add(WIRE_LEN_PREFIX)
            .saturating_add(SPAWN_PRED_VALUE_MAX)
    };
    let value_cost = |longest: usize| {
        field_cost
            .saturating_add(WIRE_LEN_PREFIX)
            .saturating_add(longest)
    };
    if is_pool {
        let from = m.from.as_deref().unwrap_or_default();
        if from.is_empty() {
            return Err(translation(format!(
                "[[mutable]] field = \"{field}\" is a pool bound and requires a non-empty `from`"
            )));
        }
        let max = m.max.ok_or_else(|| {
            translation(format!(
                "[[mutable]] field = \"{field}\" is a pool bound and requires `max`"
            ))
        })?;
        if max == 0 {
            return Err(translation(format!(
                "[[mutable]] field = \"{field}\": pool `max` must be at least 1"
            )));
        }
        let longest = from.iter().map(String::len).max().unwrap_or(0);
        Ok(usize::try_from(max)
            .unwrap_or(usize::MAX)
            .saturating_mul(value_cost(longest)))
    } else if is_oneof {
        let oneof = m.oneof.as_deref().unwrap_or_default();
        if oneof.is_empty() {
            return Err(translation(format!(
                "[[mutable]] field = \"{field}\" is a oneof bound and requires a non-empty `oneof` list"
            )));
        }
        Ok(value_cost(oneof.iter().map(String::len).max().unwrap_or(0)))
    } else if is_pattern {
        let pats = m.match_.as_deref().unwrap_or_default();
        if pats.is_empty() {
            return Err(translation(format!(
                "[[mutable]] field = \"{field}\" is a pattern bound and requires a non-empty `match` list"
            )));
        }
        // Each pattern must be a well-formed net-destination shape — validated by the verify half's
        // matcher so the compiler and the daemon agree on the grammar.
        for p in pats {
            kennel_lib_policy::variant::DestPattern::parse(p)
                .map_err(|e| translation(format!("[[mutable]] field = \"{field}\": {e}")))?;
        }
        Ok(open_value())
    } else if is_freeform {
        if m.reason.as_deref().unwrap_or("").trim().is_empty() {
            return Err(translation(format!(
                "[[mutable]] field = \"{field}\" is `freeform` and requires a non-empty `reason` \
                 (the loud rule)"
            )));
        }
        Ok(open_value())
    } else {
        let ty = m.type_.as_deref().unwrap_or("");
        if ty != "relpath" {
            return Err(translation(format!(
                "[[mutable]] field = \"{field}\": predicate `type` must be `relpath` (got `{ty}`)"
            )));
        }
        if m.under.as_deref().unwrap_or("").trim().is_empty() {
            return Err(translation(format!(
                "[[mutable]] field = \"{field}\": predicate requires a non-empty `under` root"
            )));
        }
        Ok(open_value())
    }
}

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
/// [`SshGrant`] per granted destination (`dest` + host-side `options`). Already
/// compile-time-validated (`crate::ssh`), so every `dest` is non-empty here.
fn translate_ssh(src: &SourcePolicy) -> SshRuntime {
    let Some(ssh) = &src.ssh else {
        return SshRuntime::default();
    };
    let grants = ssh
        .destinations
        .iter()
        .filter_map(|d| {
            d.dest.as_ref().map(|dest| SshGrant {
                dest: dest.clone(),
                options: d.options.clone(),
                // The synthetic keypair is minted by the compiler's I/O step (the CLI),
                // post-translate and pre-sign; translation leaves these empty.
                public_key: String::new(),
                key_file: String::new(),
            })
        })
        .collect();
    SshRuntime {
        allow_headless: ssh.allow_headless.unwrap_or(false),
        grants,
    }
}

// ---- net -----------------------------------------------------------------------

/// Parse the `net.mode` string into a [`NetMode`]; absent defaults to `constrained`.
fn parse_net_mode(mode: Option<&str>) -> Result<NetMode, PolicyError> {
    match mode {
        Some("constrained") | None => Ok(NetMode::Constrained),
        Some("none") => Ok(NetMode::None),
        Some("unconstrained") => Ok(NetMode::Unconstrained),
        Some("host") => Ok(NetMode::Host),
        Some(other) => Err(translation(format!(
            "net.mode `{other}` is not one of none/constrained/unconstrained/host"
        ))),
    }
}

/// Resolve the proxy listener for `mode`. Only the own-netns SOCKS modes
/// (constrained/unconstrained) carry one — `host` (direct, no proxy) and `none` (no
/// network) get the disabled marker regardless of any inherited `proxy_listen_*`. This is
/// the engine-level fix for the "mode=host but still proxied" composition bug.
fn resolve_proxy(mode: NetMode, addr: Option<&str>) -> Result<ProxyListen, PolicyError> {
    if !matches!(mode, NetMode::Constrained | NetMode::Unconstrained) {
        return Ok(ProxyListen::disabled());
    }
    addr.map_or_else(|| Ok(ProxyListen::default()), parse_proxy)
}

fn translate_net(
    src: &SourcePolicy,
    deferred: &mut BTreeSet<String>,
) -> Result<NetPolicy, PolicyError> {
    let net = src.net.as_ref().ok_or_else(|| missing("net"))?;
    let mode = parse_net_mode(net.mode.as_deref())?;
    // `host` shares the host net-ns and reinstates the host-recon residual (T1.6), so it is
    // gated on a non-empty `net.reason` — the operator must justify the tradeoff. Refuse it otherwise.
    if mode == NetMode::Host && net.reason.as_deref().unwrap_or("").trim().is_empty() {
        return Err(translation(
            "net.mode = host shares the host network stack (reinstates T1.6 host-recon) and \
             requires a non-empty net.reason"
                .to_owned(),
        ));
    }
    // `host` runs no egress proxy (it shares the host net-ns and egresses directly), so any
    // `[net.proxy]` rule under it can never be enforced. CIDR rules belong in
    // `[net.bpf]` (the kernel ACL); by-name rules cannot be enforced in host mode at all.
    if mode == NetMode::Host {
        // Only AUTHOR proxy rules (`allow`, `deny.policy`) are rejected: the framework
        // `deny.invariant` floor propagates into every policy (defence in depth) and is not
        // removable, so its presence under `host` is structural, not an author choice.
        let proxy_has_author_rules = net.proxy.as_ref().is_some_and(|p| {
            !p.allow.is_empty() || p.deny.as_ref().is_some_and(|d| !d.policy.is_empty())
        });
        if proxy_has_author_rules {
            return Err(translation(
                "net.mode = host has no egress proxy; move CIDR rules to [net.bpf]; by-name \
                 rules cannot be enforced in host mode"
                    .to_owned(),
            ));
        }
    }
    let proxy = resolve_proxy(mode, net.proxy_listen_v4_address.as_deref())?;

    let (allow, allow_names, deny_invariant, deny_author) =
        translate_proxy(net.proxy.as_ref(), deferred)?;

    // No implied egress is derived from `[ssh]`: the SSH destination is reached by the
    // host-side `ssh` the bastion runs as the operator, entirely outside the
    // kennel's egress. The only egress the kennel needs is the bastion's own loopback
    // endpoint, which `kenneld` grants as a host-service literal at spawn — not a policy
    // `net.proxy.allow` rule. So a destination never appears in the kennel's allowlist.

    // The kernel ACL (`[net.bpf]`): CIDR+port connect/bind allow/deny, no names.
    let (bpf_connect_allow, bpf_connect_deny) =
        translate_bpf_acl(net.bpf.as_ref().and_then(|b| b.connect.as_ref()), deferred)?;
    let (bpf_bind_allow, bpf_bind_deny) =
        translate_bpf_acl(net.bpf.as_ref().and_then(|b| b.bind.as_ref()), deferred)?;

    // The bind floor: a workload bind below `min_port` is denied by the
    // bind4/bind6 BPF. Carried into the kennel_meta map; `0` (or absent) = no floor.
    let bind_port_min = net.bind.as_ref().and_then(|b| b.min_port).unwrap_or(0);
    // The bind-port allowlist: when non-empty, only these ports may be bound.
    // Capped at the bind_subnet array size; an over-long list is a translation error
    // (a hard map limit, not a footgun), so the author learns it rather than having
    // ports silently dropped.
    let bind_allowed_ports = net
        .bind
        .as_ref()
        .and_then(|b| b.allowed_ports.clone())
        .unwrap_or_default();
    if bind_allowed_ports.len() > kennel_lib_policy::settled::MAX_BIND_PORTS {
        return Err(translation(format!(
            "[net.bind].allowed_ports has {} entries; the maximum is {}",
            bind_allowed_ports.len(),
            kennel_lib_policy::settled::MAX_BIND_PORTS
        )));
    }

    // The cgroup-BPF LPM tries are fixed-capacity (src/bpf/maps.h): allow 1024, deny 256, PER
    // FAMILY. The deny set is the invariant floor + the author's [net.bpf].*.deny +
    // [net.proxy].deny.policy; the connect-allow set is the author's [net.bpf].connect.allow.
    // Reject an over-capacity set at compile time, naming the limit — otherwise the (N+1)th
    // map update fails opaquely at spawn (ENOSPC) far from the policy that caused it.
    check_bpf_map_cap(
        "deny",
        deny_invariant
            .iter()
            .chain(&bpf_connect_deny)
            .chain(&deny_author),
        kennel_lib_policy::settled::MAX_BPF_DENY_PER_FAMILY,
    )?;
    check_bpf_map_cap(
        "allow",
        bpf_connect_allow.iter(),
        kennel_lib_policy::settled::MAX_BPF_ALLOW_PER_FAMILY,
    )?;
    check_bpf_map_cap(
        "bind allow",
        bpf_bind_allow.iter(),
        kennel_lib_policy::settled::MAX_BPF_ALLOW_PER_FAMILY,
    )?;
    check_bpf_map_cap(
        "bind deny",
        bpf_bind_deny.iter(),
        kennel_lib_policy::settled::MAX_BPF_DENY_PER_FAMILY,
    )?;

    Ok(NetPolicy {
        mode,
        bind_port_min,
        bind_allowed_ports,
        proxy,
        allow,
        allow_names,
        deny_invariant,
        deny_author,
        bpf_connect_allow,
        bpf_connect_deny,
        bpf_bind_allow,
        bpf_bind_deny,
    })
}

/// Translate `[net.proxy]` into the settled proxy lists: `(allow, allow_names,
/// deny_invariant, deny_author)`. CIDR allows become [`NetRule`]s (one per port, or a single
/// all-ports rule); by-name allows become [`NameRule`]s; the deny `invariant`/`policy` arrays
/// become `Protocol::Any` all-ports [`NetRule`]s. An allow with neither `name` nor `cidr` is
/// an error.
type ProxyLists = (Vec<NetRule>, Vec<NameRule>, Vec<NetRule>, Vec<NetRule>);
fn translate_proxy(
    proxy: Option<&crate::source::NetProxy>,
    deferred: &mut BTreeSet<String>,
) -> Result<ProxyLists, PolicyError> {
    let mut allow: Vec<NetRule> = Vec::new();
    let mut allow_names: Vec<NameRule> = Vec::new();
    let mut deny_invariant: Vec<NetRule> = Vec::new();
    let mut deny_author: Vec<NetRule> = Vec::new();
    let Some(p) = proxy else {
        return Ok((allow, allow_names, deny_invariant, deny_author));
    };
    for entry in &p.allow {
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
                for &port in &entry.ports {
                    allow.push(NetRule {
                        cidr: addr.clone(),
                        prefix_len,
                        port_min: port,
                        port_max: port,
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
                "net.proxy.allow entry has neither `name` nor `cidr`".to_owned(),
            ));
        }
    }
    if let Some(deny) = &p.deny {
        let any_rule = |d: &crate::source::NetDenyRule| -> Result<NetRule, PolicyError> {
            let (addr, prefix_len) = parse_cidr(&d.cidr)?;
            Ok(NetRule {
                cidr: addr,
                prefix_len,
                port_min: 0,
                port_max: u16::MAX,
                protocol: Protocol::Any,
            })
        };
        for d in &deny.invariant {
            deny_invariant.push(any_rule(d)?);
        }
        for d in &deny.policy {
            deny_author.push(any_rule(d)?);
        }
    }
    Ok((allow, allow_names, deny_invariant, deny_author))
}

/// Translate one `[net.bpf.connect]`/`[net.bpf.bind]` ACL into `(allow, deny)` settled
/// [`NetRule`] lists. Each [`BpfRule`](crate::source::BpfRule) carries a CIDR (or `"*"` =
/// `0.0.0.0/0` + `::/0`) plus ports + protocol — no names (the kernel cannot resolve them).
/// A rule with no cidr is an error.
fn translate_bpf_acl(
    acl: Option<&crate::source::NetBpfAcl>,
    deferred: &mut BTreeSet<String>,
) -> Result<(Vec<NetRule>, Vec<NetRule>), PolicyError> {
    let Some(acl) = acl else {
        return Ok((Vec::new(), Vec::new()));
    };
    let allow = translate_bpf_rules(acl.allow.resolved(), deferred)?;
    let deny = translate_bpf_rules(acl.deny.resolved(), deferred)?;
    Ok((allow, deny))
}

/// Expand a list of [`BpfRule`](crate::source::BpfRule)s into settled [`NetRule`]s: one rule
/// per (cidr, port) pair (or per cidr when `ports` is empty), with `"*"` expanding to both
/// `0.0.0.0/0` and `::/0`. A rule with no cidr is an error.
fn translate_bpf_rules(
    rules: &[crate::source::BpfRule],
    deferred: &mut BTreeSet<String>,
) -> Result<Vec<NetRule>, PolicyError> {
    let mut out: Vec<NetRule> = Vec::new();
    for rule in rules {
        let protocol = parse_protocol(rule.protocol.as_deref())?;
        let Some(cidr) = &rule.cidr else {
            return Err(translation("net.bpf rule needs a cidr".to_owned()));
        };
        // `"*"` is any host: expand to the v4 and v6 default routes so the kernel ACL
        // covers both families with one author rule.
        let cidrs: Vec<(String, u8)> = if cidr.trim() == "*" {
            vec![("0.0.0.0".to_owned(), 0), ("::".to_owned(), 0)]
        } else {
            vec![parse_cidr(cidr)?]
        };
        for (addr, prefix_len) in cidrs {
            let addr = subst(&addr, deferred);
            if rule.ports.is_empty() {
                out.push(NetRule {
                    cidr: addr,
                    prefix_len,
                    port_min: 0,
                    port_max: u16::MAX,
                    protocol,
                });
            } else {
                for &port in &rule.ports {
                    out.push(NetRule {
                        cidr: addr.clone(),
                        prefix_len,
                        port_min: port,
                        port_max: port,
                        protocol,
                    });
                }
            }
        }
    }
    Ok(out)
}

/// Reject a settled rule set that would overflow its fixed-capacity per-family cgroup-BPF
/// LPM trie. Counts v4 and v6 entries separately — they go to distinct maps (`*_v4`/`*_v6`),
/// matching how `kennel_lib_spawn::plan::encode` routes a rule by parsing its `cidr` — and
/// errors if either family exceeds `cap`, naming the limit so the author learns it at compile
/// time rather than hitting an opaque map-update failure at spawn. A `cidr` that parses as
/// neither family is left for `encode` to reject; it does not count toward either cap.
fn check_bpf_map_cap<'a>(
    label: &str,
    rules: impl Iterator<Item = &'a NetRule>,
    cap: usize,
) -> Result<(), PolicyError> {
    let (mut v4, mut v6) = (0usize, 0usize);
    for r in rules {
        if r.cidr.parse::<std::net::Ipv4Addr>().is_ok() {
            v4 = v4.saturating_add(1);
        } else if r.cidr.parse::<std::net::Ipv6Addr>().is_ok() {
            v6 = v6.saturating_add(1);
        }
    }
    let over = v4.max(v6);
    if over > cap {
        return Err(translation(format!(
            "net.bpf {label} rules expand to {over} entries for one address family; the cgroup-BPF \
             map holds {cap} per family (src/bpf/maps.h) — reduce the rule/port count"
        )));
    }
    Ok(())
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

    let mut read = subst_each(
        fs.read.as_ref().map_or(&[][..], PathField::resolved),
        deferred,
    );
    let write = subst_each(
        fs.write.as_ref().map_or(&[][..], PathField::resolved),
        deferred,
    );
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
    // every `[[fs.dev.passthrough]]` device path. Both bind identically at
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
    // Exclusive is a subset of write — a path bound exclusively must be a writable bind.
    // An exclusive path not in `write` is a policy error (the over-mount would shadow a host path
    // the kennel never binds). Ownership / write-access of the host path is verified separately
    // (host-side, at validate and again in the privhelper) — translate is pure.
    let exclusive = subst_each(fs.exclusive.as_deref().unwrap_or_default(), deferred);
    for ex in &exclusive {
        if !write.contains(ex) {
            return Err(translation(format!(
                "fs.exclusive path `{ex}` is not in fs.write — a path can only be bound exclusively if it is writable"
            )));
        }
    }

    // The kenneld control socket — the CLI→daemon trust boundary — is ungrantable by rule: reaching
    // it from inside a kennel is privilege escalation, not a footgun (the same refusal `[[unix.allow]]`
    // makes on the socket leaf, here extended to fs binds, which name a *directory* that can contain
    // it). `read` has already folded in every `write` path, and every `exclusive` path is in `write`,
    // so this one sweep covers fs.read, fs.write, and fs.exclusive.
    for p in &read {
        if kennel_lib_control::socket::grant_exposes_control_socket(std::path::Path::new(p)) {
            return Err(translation(format!(
                "fs grant `{p}` exposes the kenneld control socket — the CLI→daemon trust boundary. \
                 Reaching it from inside a kennel is privilege escalation; it is refused by rule, \
                 grantable by no policy"
            )));
        }
    }

    Ok(FsPolicy {
        home_shadow: home.shadow.unwrap_or(false),
        read,
        write,
        exclusive,
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

/// The unified `kennel` surface binaries a `[spawn]` grant derives into `exec.allow` (W10): the
/// shim on `$PATH` the workload execs, and the in-cage spawn unit it dispatches to (in the in-cage
/// facade directory, outside the blacklisted host `/usr/libexec/kennel` tree).
const SPAWN_SURFACE_BINARIES: [&str; 2] = ["/usr/bin/kennel", "/usr/libexec/kennel-facades/spawn"];

fn translate_exec(
    src: &SourcePolicy,
    deferred: &mut BTreeSet<String>,
) -> Result<ExecPolicy, PolicyError> {
    let exec = src.exec.as_ref();
    let flag =
        |f: fn(&crate::source::ExecSection) -> Option<bool>| exec.and_then(f).unwrap_or(false);
    let mut allow = subst_each(
        exec.and_then(|e| e.allow.as_ref())
            .map_or(&[][..], PathField::resolved),
        deferred,
    );
    // exec.deny is composed up the chain (folded in resolve) and carried into
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
    // The login shell: default /bin/sh. Execution is deny-by-default, so the
    // shell must itself be allowed or the kennel would set a shell it then refuses to
    // run. The exceptions: an empty allowlist (a no-exec floor like `base-confined` —
    // there is no shell to run, by design), and the explicit `**` permissive opt-in
    // (everything runs). Caught here at compile time (after the deny subtraction, so
    // denying your own shell is caught as the same contradiction).
    let shell = exec
        .and_then(|e| e.shell.clone())
        .map_or_else(kennel_lib_policy::settled::default_shell, |s| {
            subst(&s, deferred)
        });
    let permits_everything = allow.iter().any(|e| matches!(e.trim(), "**" | "/**"));
    if !allow.is_empty() && !permits_everything && !allow.contains(&shell) {
        return Err(translation(format!(
            "[exec].shell `{shell}` is not in exec.allow (the kennel would refuse to run its own shell)"
        )));
    }
    // W10: a `[spawn]` grant derives the unified `kennel` shim + the in-cage spawn unit into
    // `exec.allow`, so a spawn-capable kennel can run `kennel caps`/`kennel run` without the author
    // allow-listing the binaries by hand — a grant cannot leave the agent command-not-found. Spawning
    // stays double-gated: the `[spawn]` grant (*may this kennel spawn at all*) and this exec entry
    // (*may this binary run here*). Appended after the shell check so it never forces a shell onto a
    // no-exec spawn policy whose workload is the shim itself.
    if src.spawn.is_some() {
        for bin in SPAWN_SURFACE_BINARIES {
            if !allow.iter().any(|a| a == bin) {
                allow.push(bin.to_owned());
            }
        }
    }
    // The resolved `loaders` set (each allowlisted dynamic binary's PT_INTERP) is filled at
    // compile time by `kennel_lib_policy::libresolve` (it reads the binaries from disk), so it is
    // empty here. There is no `[lib]` section: libraries are not execute-gated.
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
    // Procfs visibility/hidepid come from [fs.proc] (procfs is part of the constructed
    // view, beside [fs.home]/[fs.tmp]/[fs.dev]); only "self" is valid.
    let fs_proc = src.fs.as_ref().and_then(|f| f.proc.as_ref());
    let visibility = fs_proc.and_then(|p| p.visibility.as_deref());
    match visibility {
        Some("self") | None => {}
        Some(other) => {
            return Err(translation(format!(
                "fs.proc.visibility `{other}` is not `self`"
            )))
        }
    }
    let hidepid = fs_proc.and_then(|p| p.hidepid);
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
    // The `ttl_action`: exit | warn | renew, defaulting to exit. "stop" is accepted as a
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

/// Default initial restart backoff when `[service].backoff` is unset.
const DEFAULT_BACKOFF_MS: u64 = 500;
/// Default crash-loop restart bound when `[service].max_attempts` is unset.
const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Translate `[service]` into the settled [`ServiceRuntime`] — the supervision discipline
/// `kenneld` applies to an enabled provider. Present only when the policy declares `[service]`; the
/// fields default (restart `on-failure`, 500ms backoff, 5 attempts) so an empty `[service]` is the
/// stated defaults. `max_attempts = 0` is rejected (use `restart = "never"` to not restart).
fn translate_service(src: &SourcePolicy) -> Result<Option<ServiceRuntime>, PolicyError> {
    let Some(svc) = src.service.as_ref() else {
        return Ok(None);
    };
    let backoff_ms = match svc.backoff.as_deref() {
        Some(s) => parse_duration_ms(s)?,
        None => DEFAULT_BACKOFF_MS,
    };
    let max_attempts = svc.max_attempts.unwrap_or(DEFAULT_MAX_ATTEMPTS);
    if max_attempts == 0 {
        return Err(translation(
            "[service].max_attempts must be at least 1 (use restart = \"never\" to not restart)"
                .to_owned(),
        ));
    }
    Ok(Some(ServiceRuntime {
        restart: svc.restart.unwrap_or(RestartPolicy::OnFailure),
        backoff_ms,
        max_attempts,
    }))
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

/// Split a human duration into its numeric part and a **millisecond** multiplier. `ms` is tested
/// before the bare `s`/`m` suffixes, or `"500ms"` would read as `"500m"` + a stray `s`.
fn duration_unit_ms(t: &str) -> (&str, u64) {
    if let Some(n) = t.strip_suffix("ms") {
        return (n, 1);
    }
    if let Some(n) = t.strip_suffix(['s', 'S']) {
        return (n, 1_000);
    }
    if let Some(n) = t.strip_suffix(['m', 'M']) {
        return (n, 60_000);
    }
    if let Some(n) = t.strip_suffix(['h', 'H']) {
        return (n, 3_600_000);
    }
    (t, 1)
}

/// Parse a human duration to **milliseconds** (`"500ms"`, `"2s"`, `"5m"`, `"1h"`, bare = ms) — for
/// the `[service]` restart backoff, which needs the sub-second resolution `parse_duration_secs` lacks.
fn parse_duration_ms(s: &str) -> Result<u64, PolicyError> {
    let bad = || {
        translation(format!(
            "backoff `{s}` is not a number with an optional ms/s/m/h suffix"
        ))
    };
    let (num, mult) = duration_unit_ms(s.trim());
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
    use crate::resolve::TemplateSource;
    use crate::source::parse;
    use crate::source_sig::Trust;
    use kennel_lib_policy::settled::{AuditSinkKind, Provenance, ResolvedArtifact, SettledPolicy};

    #[test]
    fn rootfs_requires_path_image_and_reason() {
        // Loud grant: each of the three fields is mandatory when [rootfs] is present.
        let missing_reason = parse(
            b"name = \"x\"\n[rootfs]\npath = \"~/img/rootfs\"\nimage = \"ghcr.io/o/a@sha256:abc\"\n",
        )
        .expect("parse");
        let err = validate_rootfs(&missing_reason).expect_err("missing reason");
        assert!(format!("{err}").contains("reason"));

        let missing_image =
            parse(b"name = \"x\"\n[rootfs]\npath = \"~/img/rootfs\"\nreason = \"v\"\n")
                .expect("parse");
        assert!(validate_rootfs(&missing_image).is_err());
    }

    #[test]
    fn rootfs_wellformed_and_absent_both_validate() {
        let ok = parse(
            b"name = \"x\"\n[rootfs]\npath = \"~/img/rootfs\"\n\
              image = \"ghcr.io/o/a@sha256:abc\"\nreason = \"vendor image\"\n",
        )
        .expect("parse");
        assert!(validate_rootfs(&ok).is_ok());
        // No [rootfs] at all ⇒ not OCI-model, nothing to validate.
        assert!(validate_rootfs(&parse(b"name = \"x\"\n").expect("parse")).is_ok());
    }

    #[test]
    fn spawn_grant_is_loud_and_bounded() {
        // A well-formed grant validates.
        let ok = parse(
            b"name = \"x\"\n[spawn]\nmax_instances = 8\nreason = \"agent spawns tools\"\n\
              [[spawn.allow]]\ntemplate = \"net-fetch@v1\"\n",
        )
        .expect("parse");
        assert!(validate_spawn(&ok).is_ok());
        // No [spawn] ⇒ nothing to validate.
        assert!(validate_spawn(&parse(b"name = \"x\"\n").expect("parse")).is_ok());

        // reason is mandatory (the waiver is loud).
        let no_reason = parse(
            b"name = \"x\"\n[spawn]\nmax_instances = 8\n[[spawn.allow]]\ntemplate = \"t@v1\"\n",
        )
        .expect("parse");
        assert!(
            format!("{}", validate_spawn(&no_reason).expect_err("no reason")).contains("reason")
        );

        // max_instances is mandatory and must be ≥ 1 (the fork-bomb ceiling).
        let no_max =
            parse(b"name = \"x\"\n[spawn]\nreason = \"r\"\n[[spawn.allow]]\ntemplate = \"t@v1\"\n")
                .expect("parse");
        assert!(
            format!("{}", validate_spawn(&no_max).expect_err("no max")).contains("max_instances")
        );
        let zero_max = parse(
            b"name = \"x\"\n[spawn]\nmax_instances = 0\nreason = \"r\"\n[[spawn.allow]]\n\
              template = \"t@v1\"\n",
        )
        .expect("parse");
        assert!(validate_spawn(&zero_max).is_err());

        // An empty allow set grants nothing.
        let no_allow =
            parse(b"name = \"x\"\n[spawn]\nmax_instances = 8\nreason = \"r\"\n").expect("parse");
        assert!(
            format!("{}", validate_spawn(&no_allow).expect_err("no allow")).contains("spawn.allow")
        );

        // A malformed template ref is rejected.
        let bad_ref = parse(
            b"name = \"x\"\n[spawn]\nmax_instances = 8\nreason = \"r\"\n[[spawn.allow]]\n\
              template = \"no-version\"\n",
        )
        .expect("parse");
        assert!(validate_spawn(&bad_ref).is_err());
    }

    #[test]
    fn mutable_manifest_requires_exactly_one_well_formed_bound() {
        // Each of the three bound kinds validates on its own.
        let ok = parse(
            b"name = \"t\"\n[[mutable]]\nfield = \"net.proxy.allow\"\nfrom = [\"pypi.org\"]\nmax = 4\n\
              [[mutable]]\nfield = \"rootfs.writable\"\noneof = [\"/opt/cache\"]\n\
              [[mutable]]\nfield = \"fs.write\"\ntype = \"relpath\"\nunder = \"workspace\"\n",
        )
        .expect("parse");
        assert!(validate_mutable_manifest(&ok).is_ok());
        // No manifest ⇒ nothing to validate (the most-fenced template).
        assert!(validate_mutable_manifest(&parse(b"name = \"t\"\n").expect("parse")).is_ok());

        // Zero bound kinds is rejected.
        let no_bound =
            parse(b"name = \"t\"\n[[mutable]]\nfield = \"net.proxy.allow\"\n").expect("parse");
        assert!(format!(
            "{}",
            validate_mutable_manifest(&no_bound).expect_err("no bound")
        )
        .contains("exactly one constraint"));

        // Two bound kinds (pool + oneof) on one field is rejected.
        let two_bounds = parse(
            b"name = \"t\"\n[[mutable]]\nfield = \"net.proxy.allow\"\nfrom = [\"a\"]\nmax = 1\n\
              oneof = [\"b\"]\n",
        )
        .expect("parse");
        assert!(validate_mutable_manifest(&two_bounds).is_err());

        // A pool without `max`, and a predicate with the wrong `type`, are rejected.
        let pool_no_max =
            parse(b"name = \"t\"\n[[mutable]]\nfield = \"net.proxy.allow\"\nfrom = [\"a\"]\n")
                .expect("parse");
        assert!(validate_mutable_manifest(&pool_no_max).is_err());
        let bad_pred = parse(
            b"name = \"t\"\n[[mutable]]\nfield = \"fs.read\"\ntype = \"abspath\"\nunder = \"w\"\n",
        )
        .expect("parse");
        assert!(format!(
            "{}",
            validate_mutable_manifest(&bad_pred).expect_err("bad pred")
        )
        .contains("relpath"));

        // A field declared twice is rejected.
        let dup = parse(
            b"name = \"t\"\n[[mutable]]\nfield = \"net.proxy.allow\"\noneof = [\"a\"]\n\
              [[mutable]]\nfield = \"net.proxy.allow\"\noneof = [\"b\"]\n",
        )
        .expect("parse");
        assert!(format!("{}", validate_mutable_manifest(&dup).expect_err("dup")).contains("twice"));
    }

    #[test]
    fn oversized_mutable_manifest_fails_the_patch_bound() {
        // A pool whose worst-case patch (max × longest member) blows the transaction bound is
        // rejected at install, not as a runtime transport error.
        let huge_value = "x".repeat(2048);
        let toml = format!(
            "name = \"t\"\n[[mutable]]\nfield = \"net.proxy.allow\"\nmax = 100\nfrom = [\"{huge_value}\"]\n"
        );
        let p = parse(toml.as_bytes()).expect("parse");
        let err = validate_mutable_manifest(&p).expect_err("oversized");
        assert!(format!("{err}").contains("worst-case patch"));
    }

    #[test]
    fn pattern_and_freeform_validate_and_translate_to_settled_variants() {
        // pattern: validates, and translate maps it onto a settled variant carrying the shapes.
        let p = parse(
            b"name = \"t\"\n[[mutable]]\nfield = \"net.proxy.allow\"\nmatch = [\"*.pypi.org:443\"]\n",
        )
        .expect("parse");
        assert!(validate_mutable_manifest(&p).is_ok());
        let manifest = translate_manifest(&p);
        let v = manifest.first().expect("one variant");
        assert_eq!(v.field, "net.proxy.allow");
        assert_eq!(v.pattern, vec!["*.pypi.org:443".to_owned()]);
        v.resolve().expect("resolves to a constraint");

        // A malformed pattern (interior wildcard) is rejected at compile, agreeing with the matcher.
        let bad = parse(
            b"name = \"t\"\n[[mutable]]\nfield = \"net.proxy.allow\"\nmatch = [\"a.*.b:443\"]\n",
        )
        .expect("parse");
        assert!(validate_mutable_manifest(&bad).is_err());

        // freeform: a `reason` is mandatory; present, it validates and maps.
        let nofr = parse(b"name = \"t\"\n[[mutable]]\nfield = \"fs.write\"\nfreeform = true\n")
            .expect("parse");
        assert!(validate_mutable_manifest(&nofr).is_err());
        let ok = parse(
            b"name = \"t\"\n[[mutable]]\nfield = \"fs.write\"\nfreeform = true\nreason = \"varies\"\n",
        )
        .expect("parse");
        assert!(validate_mutable_manifest(&ok).is_ok());
        let manifest_f = translate_manifest(&ok);
        let vf = manifest_f.first().expect("one variant");
        assert!(vf.freeform);
        assert_eq!(vf.reason, "varies");
    }

    #[test]
    fn a_variant_field_must_be_an_existing_registered_leaf() {
        // The variant system opens EXISTING schema leaves only — a coined or non-mutable field is a
        // hard compile reject (the structural guard against inventing schema).
        let invented =
            parse(b"name = \"t\"\n[[mutable]]\nfield = \"fs.workspace\"\noneof = [\"/x\"]\n")
                .expect("parse");
        assert!(format!(
            "{}",
            validate_mutable_manifest(&invented).expect_err("invented field")
        )
        .contains("not a mutable policy leaf"));
        // `net.bpf.allow` is a real schema area but a SEPARATE mechanism, not mutable via a variant.
        let bpf = parse(b"name = \"t\"\n[[mutable]]\nfield = \"net.bpf.allow\"\noneof = [\"x\"]\n")
            .expect("parse");
        assert!(validate_mutable_manifest(&bpf).is_err());
    }

    #[test]
    fn rootfs_and_workload_are_mutually_exclusive() {
        // An OCI policy carrying a [workload] is a category error (grammar partition).
        let both = parse(
            b"name = \"x\"\n[rootfs]\npath = \"~/img/rootfs\"\n\
              image = \"ghcr.io/o/a@sha256:abc\"\nreason = \"v\"\n\
              [workload]\nargv = [\"/bin/sh\"]\n",
        )
        .expect("parse");
        let err = validate_rootfs(&both).expect_err("rootfs + workload");
        assert!(format!("{err}").contains("mutually exclusive"), "{err}");
    }

    #[test]
    fn rootfs_persistence_is_binary() {
        let mk = |mode: &str| {
            parse(
                format!(
                    "name = \"x\"\n[rootfs]\npath = \"~/img/rootfs\"\n\
                     image = \"ghcr.io/o/a@sha256:abc\"\nreason = \"v\"\npersistence = \"{mode}\"\n"
                )
                .as_bytes(),
            )
            .expect("parse")
        };
        for ok in ["discard", "persist"] {
            assert!(validate_rootfs(&mk(ok)).is_ok(), "{ok} should validate");
        }
        // `readonly` is no longer a persistence mode — it is a closure-lock list now.
        let err = validate_rootfs(&mk("readonly")).expect_err("readonly not a mode");
        assert!(format!("{err}").contains("persistence"), "{err}");
    }

    #[test]
    fn persist_with_whole_tree_readonly_is_rejected() {
        let p = parse(
            b"name = \"x\"\n[rootfs]\npath = \"~/img/rootfs\"\n\
              image = \"ghcr.io/o/a@sha256:abc\"\nreason = \"v\"\n\
              persistence = \"persist\"\nreadonly = [\"/\"]\n",
        )
        .expect("parse");
        let err = validate_rootfs(&p).expect_err("persist + readonly=/");
        assert!(format!("{err}").contains("contradiction"), "{err}");
    }

    #[test]
    fn rootfs_runtime_carries_path_and_image_subst_resolved() {
        let p = parse(
            b"name = \"x\"\n[rootfs]\npath = \"~/img/rootfs\"\n\
              image = \"ghcr.io/o/a@sha256:abc\"\nreason = \"v\"\n",
        )
        .expect("parse");
        let mut d = BTreeSet::new();
        let rt = translate_rootfs_runtime(&p, &mut d);
        assert_eq!(rt.image, "ghcr.io/o/a@sha256:abc");
        assert!(rt.path.contains("img/rootfs"), "path: {}", rt.path);
        assert!(!rt.is_empty());
        // No [rootfs] ⇒ empty runtime, omitted from the canonical form.
        let none = translate_rootfs_runtime(&parse(b"name = \"x\"\n").expect("parse"), &mut d);
        assert!(none.is_empty());
    }

    #[test]
    fn dbus_translates_only_enabled_buses() {
        // session enabled with rules; system present but disabled ⇒ omitted.
        let src = parse(
            b"name = \"k\"\n\
              [dbus.session]\nenabled = true\n\
              [dbus.session.allow]\ntalk = [\"org.freedesktop.Notifications\"]\nbroadcast = [\"org.freedesktop.Notifications\"]\n\
              [dbus.session.deny]\ntalk = [\"org.freedesktop.UDisks2\"]\n\
              [dbus.system]\nenabled = false\n\
              [dbus.audit]\nlevel = \"full\"\n",
        )
        .expect("parse");
        let d = translate_dbus(&src);
        let session = d.session.as_ref().expect("session enabled");
        assert_eq!(session.talk, ["org.freedesktop.Notifications"]);
        assert_eq!(session.deny_talk, ["org.freedesktop.UDisks2"]);
        assert!(d.system.is_none(), "disabled bus is omitted");
        assert_eq!(d.audit_level.as_deref(), Some("full"));
        assert!(!d.is_empty());
        // No [dbus] ⇒ empty runtime.
        assert!(translate_dbus(&SourcePolicy::default()).is_empty());
    }

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
        let mut entries = vec![(
            "base-confined".to_owned(),
            "v1".to_owned(),
            BASE_CONFINED.as_bytes().to_vec(),
        )];
        for (name, body) in crate::TEST_FRAGMENTS {
            entries.push((
                (*name).to_owned(),
                "v1".to_owned(),
                body.as_bytes().to_vec(),
            ));
        }
        MapSource(entries)
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

    fn net_with_mode(mode: &str) -> SourcePolicy {
        SourcePolicy {
            net: Some(crate::source::NetSection {
                mode: Some(mode.to_owned()),
                // `host` is reason-gated; supply one so the mode-mapping tests exercise the
                // mode, not the gate (the gate has its own test below).
                reason: Some("test".to_owned()),
                // A non-default proxy_listen so we can prove the engine FORCES the proxy off
                // for the non-proxied modes (the host-mode composition-bug fix).
                proxy_listen_v4_address: Some("2:1080".to_owned()),
                ..crate::source::NetSection::default()
            }),
            ..SourcePolicy::default()
        }
    }

    fn mode_of(m: &str) -> NetMode {
        let mut d = BTreeSet::new();
        translate_net(&net_with_mode(m), &mut d)
            .expect("translate net")
            .mode
    }

    #[test]
    fn net_mode_strings_map_to_the_four_tiers() {
        assert_eq!(mode_of("none"), NetMode::None);
        assert_eq!(mode_of("constrained"), NetMode::Constrained);
        assert_eq!(mode_of("unconstrained"), NetMode::Unconstrained);
        assert_eq!(mode_of("host"), NetMode::Host);
        let mut d = BTreeSet::new();
        assert!(translate_net(&net_with_mode("bogus"), &mut d).is_err());
    }

    #[test]
    fn host_and_none_force_the_proxy_off_even_with_proxy_listen_set() {
        let mut d = BTreeSet::new();
        // Proxied modes honour the proxy_listen address (offset 2).
        for m in ["constrained", "unconstrained"] {
            let net = translate_net(&net_with_mode(m), &mut d).expect("translate");
            assert!(!net.proxy.is_disabled(), "{m} should be proxied");
            assert_eq!(net.proxy.offset, 2, "{m} honours proxy_listen");
        }
        // Non-proxied modes force the proxy OFF regardless of an inherited proxy_listen —
        // the engine-level fix for "mode=host but still proxied".
        for m in ["host", "none"] {
            let net = translate_net(&net_with_mode(m), &mut d).expect("translate");
            assert!(net.proxy.is_disabled(), "{m} must drop the proxy");
        }
    }

    #[test]
    fn host_mode_requires_a_reason() {
        let mut d = BTreeSet::new();
        // No reason → refused.
        let no_reason = SourcePolicy {
            net: Some(crate::source::NetSection {
                mode: Some("host".to_owned()),
                ..crate::source::NetSection::default()
            }),
            ..SourcePolicy::default()
        };
        let err = translate_net(&no_reason, &mut d).expect_err("host without reason");
        assert!(matches!(err, PolicyError::Translation(_)));
        // A whitespace-only reason is also rejected.
        let blank = SourcePolicy {
            net: Some(crate::source::NetSection {
                mode: Some("host".to_owned()),
                reason: Some("   ".to_owned()),
                ..crate::source::NetSection::default()
            }),
            ..SourcePolicy::default()
        };
        assert!(translate_net(&blank, &mut d).is_err());
        // A real reason → accepted.
        assert_eq!(mode_of("host"), NetMode::Host);
    }

    fn translate_template(src: &str) -> Translated {
        // Use the full effective fold (inheritance chain + included fragments), not bare `resolve`:
        // a retrofitted template draws its shell and userland from composed fragments, which only the
        // include-applying path materialises before translation's shell-in-allow invariant runs.
        let effective =
            crate::compile::effective_source(src.as_bytes(), &base_src(), &Trust::dev())
                .expect("effective source");
        translate(&effective).expect("translate")
    }

    // ---- [service] supervision discipline ----

    #[test]
    fn service_absent_yields_no_runtime() {
        use crate::source::SourcePolicy;
        assert!(translate_service(&SourcePolicy::default())
            .expect("ok")
            .is_none());
    }

    #[test]
    fn service_defaults_apply_for_an_empty_section() {
        use crate::source::{ServiceSection, SourcePolicy};
        let src = SourcePolicy {
            service: Some(ServiceSection::default()),
            ..SourcePolicy::default()
        };
        let svc = translate_service(&src).expect("ok").expect("present");
        assert_eq!(svc.restart, RestartPolicy::OnFailure);
        assert_eq!(svc.backoff_ms, 500);
        assert_eq!(svc.max_attempts, 5);
    }

    #[test]
    fn service_explicit_values_translate() {
        use crate::source::{ServiceSection, SourcePolicy};
        let src = SourcePolicy {
            service: Some(ServiceSection {
                restart: Some(RestartPolicy::Always),
                backoff: Some("2s".to_owned()),
                max_attempts: Some(3),
            }),
            ..SourcePolicy::default()
        };
        let svc = translate_service(&src).expect("ok").expect("present");
        assert_eq!(svc.restart, RestartPolicy::Always);
        assert_eq!(svc.backoff_ms, 2_000);
        assert_eq!(svc.max_attempts, 3);
    }

    #[test]
    fn service_zero_max_attempts_is_rejected() {
        use crate::source::{ServiceSection, SourcePolicy};
        let src = SourcePolicy {
            service: Some(ServiceSection {
                max_attempts: Some(0),
                ..ServiceSection::default()
            }),
            ..SourcePolicy::default()
        };
        assert!(translate_service(&src).is_err());
    }

    #[test]
    fn service_bad_backoff_is_rejected() {
        use crate::source::{ServiceSection, SourcePolicy};
        let src = SourcePolicy {
            service: Some(ServiceSection {
                backoff: Some("soon".to_owned()),
                ..ServiceSection::default()
            }),
            ..SourcePolicy::default()
        };
        assert!(translate_service(&src).is_err());
    }

    #[test]
    fn parse_duration_ms_handles_units() {
        assert_eq!(parse_duration_ms("500ms").expect("ms"), 500);
        assert_eq!(parse_duration_ms("2s").expect("s"), 2_000);
        assert_eq!(parse_duration_ms("5m").expect("m"), 300_000);
        assert_eq!(parse_duration_ms("1h").expect("h"), 3_600_000);
        assert_eq!(parse_duration_ms("250").expect("bare ms"), 250);
        assert!(parse_duration_ms("nope").is_err());
    }

    #[test]
    fn ssh_section_flattens_into_the_settled_runtime() {
        use crate::source::{SourcePolicy, SshDestination, SshSection};
        let src = SourcePolicy {
            ssh: Some(SshSection {
                allow_headless: Some(true),
                destinations: vec![SshDestination {
                    dest: Some("git@github.com".to_owned()),
                    options: vec!["-i".to_owned(), "~/.ssh/id_github".to_owned()],
                    reason: Some("push".to_owned()),
                    threats: None,
                }]
                .into(),
                ..SshSection::default()
            }),
            ..SourcePolicy::default()
        };
        let ssh = translate_ssh(&src);
        assert!(ssh.allow_headless);
        assert_eq!(ssh.grants.len(), 1);
        let grant = ssh.grants.first().expect("one grant");
        assert_eq!(grant.dest, "git@github.com");
        assert_eq!(grant.options, vec!["-i", "~/.ssh/id_github"]);
        assert!(!ssh.is_empty());
        // No [ssh] ⇒ empty runtime, omitted from the canonical form (back-compat).
        assert!(translate_ssh(&SourcePolicy::default()).is_empty());
    }

    #[test]
    fn provides_and_consumes_flatten_into_the_settled_mesh() {
        use crate::source::{ConsumesEntry, ProvidesEntry, Shape, SourcePolicy};
        let src = SourcePolicy {
            provides: vec![ProvidesEntry {
                name: Some("org.projectkennel.wayland".to_owned()),
                shape: Some(Shape::AfUnix),
                endpoint: Some("$XDG_RUNTIME_DIR/wayland-0".to_owned()),
                reason: Some("the display service".to_owned()),
                ..ProvidesEntry::default()
            }],
            consumes: vec![ConsumesEntry {
                name: Some("org.projectkennel.wayland".to_owned()),
                shape: Some(Shape::AfUnix),
                at: Some("$XDG_RUNTIME_DIR/wayland-0".to_owned()),
                env: vec!["WAYLAND_DISPLAY".to_owned()],
                required: true,
                reason: Some("render the window".to_owned()),
                ..ConsumesEntry::default()
            }],
            ..SourcePolicy::default()
        };
        let mesh = translate_mesh(&src);
        assert!(!mesh.is_empty());
        let p = mesh.provides.first().expect("one provide");
        assert_eq!(p.name, "org.projectkennel.wayland");
        assert_eq!(p.shape, Shape::AfUnix);
        assert_eq!(p.endpoint, "$XDG_RUNTIME_DIR/wayland-0");
        let c = mesh.consumes.first().expect("one consume");
        assert_eq!(c.name, "org.projectkennel.wayland");
        assert!(c.required);
        assert_eq!(c.env, vec!["WAYLAND_DISPLAY"]);
        assert_eq!(c.at.as_deref(), Some("$XDG_RUNTIME_DIR/wayland-0"));
        // No mesh ⇒ empty runtime, omitted from the canonical form (back-compat).
        assert!(translate_mesh(&SourcePolicy::default()).is_empty());

        // An omitted af-unix endpoint is defaulted to /run/<name>[.key]/sock.
        let defaulted = SourcePolicy {
            provides: vec![ProvidesEntry {
                name: Some("org.x.cache".to_owned()),
                shape: Some(Shape::AfUnix),
                key: Some("K1".to_owned()),
                reason: Some("a reason".to_owned()),
                ..ProvidesEntry::default()
            }],
            ..SourcePolicy::default()
        };
        let m = translate_mesh(&defaulted);
        assert_eq!(
            m.provides.first().expect("one provide").endpoint,
            "/run/org.x.cache.K1/sock"
        );
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
    fn spawn_grant_derives_the_kennel_surface_binaries_into_exec_allow() {
        // W10: a [spawn] grant auto-derives the `kennel` shim + the in-cage spawn unit into
        // exec.allow, so the agent can run `kennel caps`/`kennel run` without listing them by hand.
        let src = parse(
            b"name = \"k\"\n[spawn]\nreason = \"compose tools\"\nmax_instances = 2\n[[spawn.allow]]\ntemplate = \"echo-tool@v1\"\n[exec]\nallow = [\"/bin/sh\"]\nshell = \"/bin/sh\"\n",
        )
        .expect("parse");
        let ep = translate_exec(&src, &mut BTreeSet::new()).expect("translate");
        assert!(
            ep.allow.contains(&"/usr/bin/kennel".to_owned()),
            "shim derived"
        );
        assert!(
            ep.allow
                .contains(&"/usr/libexec/kennel-facades/spawn".to_owned()),
            "spawn unit derived"
        );
        assert!(
            ep.allow.contains(&"/bin/sh".to_owned()),
            "authored entries kept"
        );

        // No [spawn] grant ⇒ the surface binaries are NOT silently added.
        let plain = parse(b"name = \"k\"\n[exec]\nallow = [\"/bin/sh\"]\nshell = \"/bin/sh\"\n")
            .expect("parse");
        let ep2 = translate_exec(&plain, &mut BTreeSet::new()).expect("translate");
        assert_eq!(
            ep2.allow,
            vec!["/bin/sh".to_owned()],
            "no spawn surface added"
        );
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
    fn fs_exclusive_must_be_a_subset_of_write() {
        // Exclusive on a writable path carries through.
        let ok = parse(b"name = \"k\"\n[fs.home]\nshadow = true\n[fs]\nwrite = [\"~/proj\"]\nexclusive = [\"~/proj\"]\n")
            .expect("parse");
        let fs = translate_fs(&ok, &mut BTreeSet::new()).expect("translate_fs");
        assert_eq!(fs.exclusive, vec!["~/proj".to_owned()]);
        // Exclusive on a path that is not writable is a translation error.
        let bad = parse(b"name = \"k\"\n[fs.home]\nshadow = true\n[fs]\nwrite = [\"~/proj\"]\nexclusive = [\"~/other\"]\n")
            .expect("parse");
        let err = translate_fs(&bad, &mut BTreeSet::new()).expect_err("must reject");
        assert!(matches!(err, PolicyError::Translation(_)), "got {err:?}");
    }

    #[test]
    fn fs_grant_exposing_the_control_socket_is_refused() {
        // The control socket is ungrantable by rule, on the fs path as on the unix.allow path (W15 F1).
        // A directory grant that would drag it into the view is refused at compile, both as write…
        let w = parse(
            b"name = \"k\"\n[fs.home]\nshadow = true\n[fs]\nwrite = [\"/run/user/1000/kennel\"]\n",
        )
        .expect("parse");
        let err = translate_fs(&w, &mut BTreeSet::new()).expect_err("write must reject");
        assert!(matches!(err, PolicyError::Translation(_)), "got {err:?}");
        // …and as read.
        let r = parse(
            b"name = \"k\"\n[fs.home]\nshadow = true\n[fs]\nread = [\"/run/user/0/kennel/control.sock\"]\n",
        )
        .expect("parse");
        let err = translate_fs(&r, &mut BTreeSet::new()).expect_err("read must reject");
        assert!(matches!(err, PolicyError::Translation(_)), "got {err:?}");
        // A sibling runtime path is unaffected.
        let ok = parse(
            b"name = \"k\"\n[fs.home]\nshadow = true\n[fs]\nread = [\"/run/user/1000/kennel/agent.sock\"]\n",
        )
        .expect("parse");
        assert!(
            translate_fs(&ok, &mut BTreeSet::new()).is_ok(),
            "sibling must pass"
        );
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
                    name: Some("tool-daemon".to_owned()),
                    real: Some("~/.cache/kennel/<kennel>/tool.sock".to_owned()),
                    shim: Some("/run/tool.sock".to_owned()),
                    reason: Some("a project-scoped helper daemon, per kennel".to_owned()),
                    ..UnixAllow::default()
                }]
                .into(),
            }),
            ..SourcePolicy::default()
        };
        let mut deferred = BTreeSet::new();
        let unix = translate_unix(&src, &mut deferred);
        assert_eq!(unix.sockets.len(), 1);
        let s = unix.sockets.first().expect("socket");
        assert_eq!(s.name, "tool-daemon");
        assert_eq!(s.shim, "/run/tool.sock");
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
                    ]
                    .into(),
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
                    }]
                    .into(),
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
    fn ai_coding_strict_grants_no_agent_unix_shim() {
        let t = translate_template(AI_CODING_STRICT);
        // No agent shim at all: GPG signing cannot be made safe in a kennel (a signing
        // oracle), and an exposed ssh-agent is a destination-blind oracle (SSH
        // egress goes through the bastion, never a shim).
        assert!(
            t.unix.sockets.iter().all(|s| s.name != "gpg-agent"
                && s.name != "ssh-agent"
                && s.env.as_deref() != Some("SSH_AUTH_SOCK")),
            "ai-coding-strict ships no gpg-agent or ssh-agent shim"
        );
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
    }

    #[test]
    fn translated_policy_passes_framework_invariant_reassertion() {
        // The runtime re-asserts invariants on the settled policy; the compiler's
        // output must clear that bar.
        let t = translate_template(AI_CODING_STRICT);
        let policy = SettledPolicy {
            settled_schema_version: kennel_lib_policy::SETTLED_SCHEMA_VERSION,
            name: "myproj".to_owned(),
            deferred_substitutions: t.deferred_substitutions,
            framework_invariants_asserted: Vec::new(),
            effective_policy: t.effective_policy,
            provenance: Provenance {
                compiler_version: "0.0.0".to_owned(),
                schema_version: kennel_lib_policy::SETTLED_SCHEMA_VERSION,
                threat_catalogue_version: "0.1".to_owned(),
                resolved_artifacts: Vec::<ResolvedArtifact>::new(),
            },
            ssh: t.ssh,
            unix: t.unix,
            identity: t.identity,
            binder: t.binder,
            mesh: t.mesh,
            service: t.service,
            dbus: t.dbus,
            audit: t.audit,
            env: t.env,
            ulimits: t.ulimits,
            workload: t.workload,
            rootfs: t.rootfs,
            spawn: None,
            manifest: t.manifest,
        };
        kennel_lib_policy::invariant::validate(&policy).expect("framework invariants must hold");
    }

    #[test]
    fn untrusted_build_net_none_is_a_real_isolated_mode() {
        let t = translate_template(UNTRUSTED_BUILD);
        let net = &t.effective_policy.net;
        // `none` is now a distinct, fully-isolated mode (own empty net-ns, no interfaces),
        // not an alias for constrained-with-empty-allow.
        assert_eq!(net.mode, NetMode::None, "none => None");
        assert!(
            net.allow.is_empty() && net.allow_names.is_empty(),
            "no egress permitted"
        );
        // The mandatory cloud-metadata invariant deny still propagates (defence in depth,
        // even though a `none` kennel has no interface to reach it).
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
        // `[net.bind].min_port` → `NetPolicy.bind_port_min` (the BPF bind floor);
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

    /// Build a `mode = host` policy whose `[net.bpf].connect.deny` lists `n` distinct v4 CIDRs
    /// (10.<a>.<b>.0/24, incrementing), each one map entry. With no `[net.proxy]` section the
    /// settled deny set is exactly these `n` v4 rules — used to push the deny LPM trie to/over
    /// its per-family capacity.
    fn host_policy_with_n_connect_denies(n: usize) -> Vec<u8> {
        use std::fmt::Write as _;
        let mut s =
            String::from("name = \"k\"\n[net]\nmode = \"host\"\nreason = \"direct egress\"\n");
        for i in 0..n {
            // 10.<a>.<b>.0/24 — distinct CIDRs across the v4 space, one entry each.
            let a = (i / 256) % 256;
            let b = i % 256;
            let _ = write!(
                s,
                "[[net.bpf.connect.deny]]\ncidr = \"10.{a}.{b}.0/24\"\nreason = \"r\"\n"
            );
        }
        s.into_bytes()
    }

    #[test]
    fn bpf_deny_at_capacity_is_accepted() {
        // 256 v4 connect denies = the deny_v4 map's exact capacity (src/bpf/maps.h). At the cap
        // (not over it) translation succeeds and all 256 land in the settled deny set.
        let cap = kennel_lib_policy::settled::MAX_BPF_DENY_PER_FAMILY;
        let src = parse(&host_policy_with_n_connect_denies(cap)).expect("parse");
        let net = translate_net(&src, &mut BTreeSet::new()).expect("v4 deny set at cap");
        let v4 = net
            .bpf_connect_deny
            .iter()
            .filter(|r| r.cidr.parse::<std::net::Ipv4Addr>().is_ok())
            .count();
        assert_eq!(v4, cap, "all {cap} v4 denies survive translation");
    }

    #[test]
    fn bpf_deny_over_capacity_is_rejected_naming_the_limit() {
        // One past the deny_v4 cap must be a compile error that names the limit, rather than the
        // (cap+1)th map update failing opaquely with ENOSPC at spawn.
        let cap = kennel_lib_policy::settled::MAX_BPF_DENY_PER_FAMILY;
        let src = parse(&host_policy_with_n_connect_denies(cap + 1)).expect("parse");
        let err = translate_net(&src, &mut BTreeSet::new()).expect_err("over the deny_v4 cap");
        assert!(matches!(err, PolicyError::Translation(_)), "got {err:?}");
        let msg = format!("{err:?}");
        assert!(
            msg.contains(&cap.to_string()) && msg.contains("deny"),
            "the error must name the per-family deny cap; got: {msg}"
        );
    }

    #[test]
    fn bpf_cap_counts_families_separately() {
        // A v6 default-route deny plus a modest v4 set must NOT trip the v4 cap on the v6 rule:
        // the two families have independent maps. A small mixed policy translates cleanly.
        let src = parse(
            b"name = \"k\"\n[net]\nmode = \"host\"\nreason = \"r\"\n\
              [[net.bpf.connect.deny]]\ncidr = \"::/0\"\nreason = \"v6 default\"\n\
              [[net.bpf.connect.allow]]\ncidr = \"*\"\nports = [443]\nreason = \"any:443\"\n",
        )
        .expect("parse");
        // `cidr = "*"` expands to one v4 + one v6 allow; neither family is near its 1024 cap.
        let net = translate_net(&src, &mut BTreeSet::new()).expect("mixed families under cap");
        assert!(net
            .bpf_connect_allow
            .iter()
            .any(|r| r.cidr.parse::<std::net::Ipv4Addr>().is_ok()));
        assert!(net
            .bpf_connect_allow
            .iter()
            .any(|r| r.cidr.parse::<std::net::Ipv6Addr>().is_ok()));
    }

    #[test]
    fn ssh_destination_derives_no_kennel_egress() {
        // The SSH destination is reached host-side by the bastion's forced command, never by
        // the kennel itself, so an [[ssh.destinations]] entry derives NO net.allow rule. The
        // bastion endpoint is granted separately as a host-service literal at spawn.
        let src = parse(
            b"name = \"k\"\n[net]\nmode = \"constrained\"\n[[ssh.destinations]]\ndest = \"git@git.internal\"\nreason = \"push\"\n",
        )
        .expect("parse");
        let net = translate_net(&src, &mut BTreeSet::new()).expect("translate");
        assert!(
            !net.allow_names
                .iter()
                .any(|r| r.name.contains("git.internal")),
            "an ssh destination must NOT appear in the kennel egress allowlist; got {:?}",
            net.allow_names
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

    #[test]
    fn tty_filter_defaults_on_and_honours_an_explicit_false() {
        // Absent [tty] ⇒ filtering on (the secure default) — a real template has no
        // [tty] section.
        let default = translate_template(AI_CODING_STRICT);
        assert!(default.effective_policy.tty.filter_terminal_escapes);

        // An explicit `filter_terminal_escapes = false` is carried to the settled
        // policy (a leaf that turns the filter off, atop the base chain).
        let off = translate_template(concat!(
            "template_base = \"base-confined@v1\"\n",
            "template_name = \"tty-off\"\n",
            "template_version = \"1\"\n",
            "[tty]\nfilter_terminal_escapes = false\n",
        ));
        assert!(!off.effective_policy.tty.filter_terminal_escapes);
    }

    #[test]
    fn trust_manifest_defaults_on_and_honours_an_explicit_false() {
        // Absent [trust] ⇒ the manifest is maintained (secure default).
        let default = translate_template(AI_CODING_STRICT);
        assert!(default.effective_policy.trust.manifest);

        // An explicit `[trust] manifest = false` opts out, carried to the settled policy.
        let off = translate_template(concat!(
            "template_base = \"base-confined@v1\"\n",
            "template_name = \"trust-off\"\n",
            "template_version = \"1\"\n",
            "[trust]\nmanifest = false\n",
        ));
        assert!(!off.effective_policy.trust.manifest);
    }
}
