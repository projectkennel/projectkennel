//! Translate a resolved, folded source policy into the settled `EffectivePolicy`.
//!
//! # Purpose
//!
//! The compiler stage after [`crate::resolve`]: take the effective [`SourcePolicy`]
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
//! `seccomp`, `lifecycle`. The source-only sections (`unix`, `dbus`, `x11`, `env`,
//! `ptrace`, `signal`, and the informational `fs.deny`/`fs.scrub`/`exec.deny`) are
//! compile-time or shim-construction concerns and are intentionally dropped here —
//! their effects are realised by other mechanisms (Landlock grant-absence, the
//! shim builder, the env curator), not by the settled artefact.
//!
//! # Substitution
//!
//! Installation constants (`<tag>`, `<gid>`) are substituted now, at compile time.
//! Per-instance placeholders (`<kennel>`, `<ctx>`, `<uid>`, `<home>`, `<user>`) are
//! left in place and recorded in `deferred_substitutions`; the runtime fills exactly
//! those and refuses to spawn if any *other* placeholder survives (02-2 §Variable
//! substitution).
//!
//! # Non-goals
//!
//! - **Seccomp.** The source expresses a *denylist by name*; the settled form is an
//!   *allowlist by syscall number*. Inverting one into the other needs a syscall
//!   name→number table this workspace does not carry and must not hand-roll (the
//!   project's no-hand-roll rule) or pull in unvetted. Until that table is sourced
//!   (a dependency/approval decision), seccomp translates to an empty allowlist,
//!   which the runtime reads as "no seccomp filter installed" — the source seccomp
//!   is documented defence-in-depth, so this neither breaks workloads nor weakens
//!   the primary controls (Landlock, the cgroup BPF). Tracked as owed.
//! - Provenance, signing, and the lockfile: the next increment.

use crate::settled::{
    CapPolicy, DevPolicy, EffectivePolicy, ExecPolicy, FsPolicy, InstallConstants, LifecyclePolicy,
    NameRule, NetMode, NetPolicy, NetRule, ProcPolicy, ProcVisibility, Protocol, ProxyListen,
    SeccompAction, SeccompPolicy, TmpPolicy, TtlAction,
};
use crate::source::SourcePolicy;
use crate::PolicyError;
use std::collections::BTreeSet;

/// The product of translation: the settled effective policy plus the per-instance
/// placeholders the runtime must substitute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Translated {
    /// The flat, runtime-enforced policy.
    pub effective_policy: EffectivePolicy,
    /// Per-instance placeholders (`<kennel>`, `<ctx>`, …) still to be filled at spawn.
    pub deferred_substitutions: Vec<String>,
}

/// Translate an effective (resolved, folded) source policy into the settled form.
///
/// `effective` must be the output of [`crate::resolve::resolve`] (nothing left to
/// inherit). `install` supplies the installation constants substituted now.
///
/// # Errors
///
/// Returns [`PolicyError::Translation`] if a required field is missing or a human
/// form (CIDR, size, duration, port spec, net mode) is malformed.
pub fn translate(
    effective: &SourcePolicy,
    install: &InstallConstants,
) -> Result<Translated, PolicyError> {
    let mut deferred = BTreeSet::new();
    let net = translate_net(effective, install, &mut deferred)?;
    let fs = translate_fs(effective, install, &mut deferred)?;
    let exec = translate_exec(effective, install, &mut deferred);
    let proc = translate_proc(effective)?;
    let cap = CapPolicy {
        no_new_privs: effective.cap.as_ref().and_then(|c| c.no_new_privs).unwrap_or(false),
    };
    // Seccomp: empty allowlist => no filter installed (see module docs).
    let seccomp = SeccompPolicy { default_action: SeccompAction::Errno, allow: Vec::new() };
    let lifecycle = translate_lifecycle(effective)?;

    Ok(Translated {
        effective_policy: EffectivePolicy { net, fs, exec, proc, cap, seccomp, lifecycle },
        deferred_substitutions: deferred.into_iter().collect(),
    })
}

// ---- net -----------------------------------------------------------------------

fn translate_net(
    src: &SourcePolicy,
    install: &InstallConstants,
    deferred: &mut BTreeSet<String>,
) -> Result<NetPolicy, PolicyError> {
    let net = src.net.as_ref().ok_or_else(|| missing("net"))?;
    let mode = match net.mode.as_deref() {
        // `none` is "constrained with an empty allowlist" — the proxy denies all.
        Some("constrained" | "none") | None => NetMode::Constrained,
        Some("open") => NetMode::Open,
        Some(other) => return Err(translation(format!("net.mode `{other}` is not representable"))),
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
            let addr = subst(&addr, install, deferred);
            if entry.ports.is_empty() {
                allow.push(NetRule { cidr: addr, prefix_len, port_min: 0, port_max: u16::MAX, protocol });
            } else {
                for &p in &entry.ports {
                    allow.push(NetRule { cidr: addr.clone(), prefix_len, port_min: p, port_max: p, protocol });
                }
            }
        } else if let Some(name) = &entry.name {
            allow_names.push(NameRule { name: name.clone(), ports: entry.ports.clone(), protocol });
        } else {
            return Err(translation("net.allow entry has neither `name` nor `cidr`".to_owned()));
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

    Ok(NetPolicy { mode, proxy, allow, allow_names, deny_invariant })
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
        Some(other) => Err(translation(format!("protocol `{other}` is not tcp/udp/any"))),
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
    install: &InstallConstants,
    deferred: &mut BTreeSet<String>,
) -> Result<FsPolicy, PolicyError> {
    let fs = src.fs.as_ref().ok_or_else(|| missing("fs"))?;
    let home = fs.home.as_ref().ok_or_else(|| missing("fs.home"))?;
    let shim_root_raw = home.shim_root.as_deref().ok_or_else(|| missing("fs.home.shim_root"))?;
    let shim_root = subst(shim_root_raw, install, deferred);

    let read = subst_each(fs.read.as_deref().unwrap_or_default(), install, deferred);
    let write = subst_each(fs.write.as_deref().unwrap_or_default(), install, deferred);

    let tmp = match &fs.tmp {
        Some(t) => TmpPolicy {
            private: t.private.unwrap_or(false),
            size_mib: match &t.size {
                Some(s) => parse_size_mib(s)?,
                None => DEFAULT_TMP_MIB,
            },
            mode: t.mode.clone().unwrap_or_else(|| "0700".to_owned()),
        },
        None => TmpPolicy { private: false, size_mib: DEFAULT_TMP_MIB, mode: "0700".to_owned() },
    };

    let dev = DevPolicy {
        allow: subst_each(
            fs.dev.as_ref().and_then(|d| d.allow.as_deref()).unwrap_or_default(),
            install,
            deferred,
        ),
    };

    Ok(FsPolicy {
        home_shadow: home.shadow.unwrap_or(false),
        shim_root,
        read,
        write,
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
    let bad = || translation(format!("size `{s}` is not a number with an optional M/G suffix"));
    let (num, mult) = size_unit(s.trim());
    let value = num.trim().parse::<u32>().map_err(|_| bad())?;
    value.checked_mul(mult).ok_or_else(bad)
}

// ---- exec ----------------------------------------------------------------------

fn translate_exec(
    src: &SourcePolicy,
    install: &InstallConstants,
    deferred: &mut BTreeSet<String>,
) -> ExecPolicy {
    let exec = src.exec.as_ref();
    let flag = |f: fn(&crate::source::ExecSection) -> Option<bool>| {
        exec.and_then(f).unwrap_or(false)
    };
    ExecPolicy {
        deny_setuid: flag(|e| e.deny_setuid),
        deny_setgid: flag(|e| e.deny_setgid),
        deny_setcap: flag(|e| e.deny_setcap),
        deny_writable: flag(|e| e.deny_writable),
        allow: subst_each(
            exec.and_then(|e| e.allow.as_deref()).unwrap_or_default(),
            install,
            deferred,
        ),
    }
}

// ---- proc / lifecycle ----------------------------------------------------------

fn translate_proc(src: &SourcePolicy) -> Result<ProcPolicy, PolicyError> {
    // Visibility comes from [proc] or, failing that, [fs.proc]; only "self" is valid.
    let visibility = src
        .proc
        .as_ref()
        .and_then(|p| p.visibility.as_deref())
        .or_else(|| src.fs.as_ref().and_then(|f| f.proc.as_ref()).and_then(|p| p.visibility.as_deref()));
    match visibility {
        Some("self") | None => {}
        Some(other) => return Err(translation(format!("proc.visibility `{other}` is not `self`"))),
    }
    let hidepid = src.proc.as_ref().and_then(|p| p.hidepid).or_else(|| {
        src.fs.as_ref().and_then(|f| f.proc.as_ref()).and_then(|p| p.hidepid)
    });
    Ok(ProcPolicy { visibility: ProcVisibility::SelfOnly, hidepid: hidepid.unwrap_or(false) })
}

fn translate_lifecycle(src: &SourcePolicy) -> Result<LifecyclePolicy, PolicyError> {
    let lc = src.lifecycle.as_ref();
    let ttl_seconds = match lc.and_then(|l| l.ttl.as_deref()) {
        Some(s) => Some(parse_duration_secs(s)?),
        None => None,
    };
    let ttl_action = match lc.and_then(|l| l.ttl_action.as_deref()) {
        Some("stop") => TtlAction::Stop,
        Some("warn") | None => TtlAction::Warn,
        Some(other) => return Err(translation(format!("ttl_action `{other}` is not stop/warn"))),
    };
    Ok(LifecyclePolicy { ttl_seconds, ttl_action })
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
    let bad = || translation(format!("duration `{s}` is not a number with an optional s/m/h/d suffix"));
    let (num, mult) = duration_unit(s.trim());
    let value = num.trim().parse::<u64>().map_err(|_| bad())?;
    value.checked_mul(mult).ok_or_else(bad)
}

// ---- substitution --------------------------------------------------------------

/// Substitute install constants in `s` and record any remaining `<…>` placeholders.
fn subst(s: &str, install: &InstallConstants, deferred: &mut BTreeSet<String>) -> String {
    let out = s
        .replace("<tag>", &install.tag.to_string())
        .replace("<gid>", &install.ula_gid);
    collect_placeholders(&out, deferred);
    out
}

/// Apply [`subst`] to each element of a slice.
fn subst_each(items: &[String], install: &InstallConstants, deferred: &mut BTreeSet<String>) -> Vec<String> {
    items.iter().map(|s| subst(s, install, deferred)).collect()
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
    PolicyError::Translation(format!("required section/field `{field}` is absent from the effective policy"))
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

    const BASE_CONFINED: &str = include_str!("../../../templates/base-confined/policy.toml");
    const AI_CODING_STRICT: &str = include_str!("../../../templates/ai-coding-strict/policy.toml");
    const UNTRUSTED_BUILD: &str = include_str!("../../../templates/untrusted-build/policy.toml");

    struct MapSource(Vec<(String, String, Vec<u8>)>);
    impl TemplateSource for MapSource {
        fn fetch(&self, name: &str, version: &str) -> Option<Vec<u8>> {
            self.0.iter().find(|(n, v, _)| n == name && v == version).map(|(_, _, b)| b.clone())
        }
    }
    fn base_src() -> MapSource {
        MapSource(vec![("base-confined".to_owned(), "v1".to_owned(), BASE_CONFINED.as_bytes().to_vec())])
    }
    fn install() -> InstallConstants {
        InstallConstants { tag: 42, ula_gid: "fd00:abcd::".to_owned() }
    }

    fn translate_template(src: &str) -> Translated {
        let entry = parse(src.as_bytes()).expect("parse");
        let resolved = resolve(&entry, &base_src()).expect("resolve");
        translate(&resolved.effective, &install()).expect("translate")
    }

    #[test]
    fn ai_coding_strict_translates_to_a_runtime_policy() {
        let t = translate_template(AI_CODING_STRICT);
        let ep = &t.effective_policy;

        assert_eq!(ep.net.mode, NetMode::Constrained);
        assert!(ep.net.allow_names.iter().any(|n| n.name == "github.com" && n.ports == vec![22, 443]));
        assert!(ep.net.deny_invariant.iter().any(|r| r.cidr == "169.254.169.254" && r.prefix_len == 32));
        assert!(ep.net.deny_invariant.iter().any(|r| r.cidr == "fd00:ec2::254" && r.prefix_len == 128));

        assert!(ep.fs.home_shadow);
        assert_eq!(ep.fs.shim_root, "/run/kennel/<kennel>/home");
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

        // The per-instance placeholder is deferred, not the install constants.
        assert!(t.deferred_substitutions.iter().any(|p| p == "<kennel>"));
        assert!(!t.deferred_substitutions.iter().any(|p| p == "<tag>" || p == "<gid>"));
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
                install_constants: install(),
                resolved_artifacts: Vec::<ResolvedArtifact>::new(),
            },
        };
        crate::invariant::validate(&policy).expect("framework invariants must hold");
    }

    #[test]
    fn untrusted_build_net_none_becomes_constrained_with_empty_allow() {
        let t = translate_template(UNTRUSTED_BUILD);
        let net = &t.effective_policy.net;
        assert_eq!(net.mode, NetMode::Constrained, "none => constrained");
        assert!(net.allow.is_empty() && net.allow_names.is_empty(), "no egress permitted");
        // Invariant denies still propagate.
        assert!(net.deny_invariant.iter().any(|r| r.cidr == "10.0.0.0" && r.prefix_len == 8));
        // 2h TTL, stop.
        assert_eq!(t.effective_policy.lifecycle.ttl_seconds, Some(7_200));
        assert_eq!(t.effective_policy.lifecycle.ttl_action, TtlAction::Stop);
    }

    #[test]
    fn seccomp_is_an_empty_allowlist_pending_a_syscall_table() {
        let t = translate_template(AI_CODING_STRICT);
        assert!(t.effective_policy.seccomp.allow.is_empty());
        assert_eq!(t.effective_policy.seccomp.default_action, SeccompAction::Errno);
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
        assert_eq!(parse_cidr("10.0.0.0/8").expect("v4"), ("10.0.0.0".to_owned(), 8));
        assert_eq!(parse_cidr("169.254.169.254").expect("bare v4"), ("169.254.169.254".to_owned(), 32));
        assert_eq!(parse_cidr("fd00:ec2::254").expect("bare v6"), ("fd00:ec2::254".to_owned(), 128));
        assert!(parse_cidr("10.0.0.0/999").is_err());
    }

    #[test]
    fn install_constants_are_substituted_now() {
        let mut deferred = BTreeSet::new();
        let out = subst("addr-<tag>-<gid>-<kennel>", &install(), &mut deferred);
        assert_eq!(out, "addr-42-fd00:abcd::-<kennel>");
        assert!(deferred.contains("<kennel>"));
        assert!(!deferred.contains("<tag>"));
    }
}
