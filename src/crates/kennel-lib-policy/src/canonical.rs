// SPDX-License-Identifier: Apache-2.0

//! Canonical-form serialisation: the exact bytes a signature covers.
//!
//! The signature on a settled policy is computed over the canonical form of its
//! body (the [`SettledPolicy`], excluding the `[signature]` envelope, which is a
//! sibling table in the document). Because the signer and verifier both derive
//! the bytes the same way — a deterministic `kennel-lib-toml` serialisation of the
//! body struct in declaration order — they agree byte-for-byte.
//!
//! This pins the canonical form: a deterministic `kennel-lib-toml` serialisation of
//! the body in struct-field order. JSON's canonicalisation (sorted keys,
//! normalised numbers) buys nothing here — we control both ends, and the schema
//! has no floats (`02-2-config-schema.md` §Format).

use crate::error::PolicyError;
use crate::settled::SettledPolicy;

/// The canonical bytes for `policy` — the input to signing and verification.
///
/// The bytes must describe **exactly** the policy that will be honoured. The canonical form omits
/// a section it considers empty (a `[workload]` with no `argv`, a `[rootfs]` with no `path`, a
/// `[dbus]` with no bus), so a section that is empty by that test yet carries other fields would
/// be parsed and acted on without being covered by the signature. The body is therefore read back
/// from its own canonical form and must compare equal; signer and verifier both pass through here,
/// so such a policy can neither be signed nor loaded.
///
/// # Errors
///
/// Returns [`PolicyError::Canonical`] if the body cannot be serialised, or if it carries content
/// its canonical form leaves out.
pub fn canonical_bytes(policy: &SettledPolicy) -> Result<Vec<u8>, PolicyError> {
    let bytes = kennel_lib_toml::to_string(policy)
        .map(String::into_bytes)
        .map_err(|e| PolicyError::Canonical(e.to_string()))?;
    let covered: SettledPolicy = kennel_lib_toml::from_slice(&bytes)
        .map_err(|e| PolicyError::Canonical(format!("canonical form does not read back: {e}")))?;
    if &covered != policy {
        return Err(PolicyError::Canonical(format!(
            "the policy carries content its signature would not cover{}; a section is honoured \
             only when its defining field is set (`[workload].argv`, `[rootfs].path`, an enabled \
             `[dbus]` bus)",
            uncovered_sections(policy, &covered)
        )));
    }
    Ok(bytes)
}

/// Name the sections that differ between `policy` and what its canonical form `covered`, for the
/// error text. Empty when the difference is somewhere this list does not know about.
fn uncovered_sections(policy: &SettledPolicy, covered: &SettledPolicy) -> String {
    let mut names = Vec::new();
    if policy.workload != covered.workload {
        names.push("[workload]");
    }
    if policy.rootfs != covered.rootfs {
        names.push("[rootfs]");
    }
    if policy.dbus != covered.dbus {
        names.push("[dbus]");
    }
    if names.is_empty() {
        String::new()
    } else {
        format!(" (in {})", names.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::canonical_bytes;
    use crate::settled::{
        sample_settled, AuditFileConfig, AuditRuntime, AuditSinkKind, CapPolicy, ConsumeRuntime,
        CwdGrant, CwdPolicy, DbusBusRuntime, DbusRuntime, DevPolicy, EffectivePolicy, EnvRuntime,
        ExecPolicy, FsPolicy, FsRedirect, IdentityRuntime, LifecyclePolicy, MeshRuntime, NameRule,
        NetMode, NetPolicy, NetRule, OnChangeAction, ProcPolicy, Protocol, Provenance,
        ProvideRuntime, ProxyListen, ResolvedArtifact, RestartPolicy, RootfsRuntime, SeccompAction,
        SeccompPolicy, ServiceRuntime, SettledPolicy, Shape, SpawnGrant, SpawnTemplate, SshGrant,
        SshRuntime, TmpPolicy, TrustPolicy, TtlAction, TtyPolicy, UlimitsRuntime, UnixRuntime,
        UnixSocket, WorkloadRuntime,
    };
    use crate::variant::Variant;

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    fn rule(cidr: &str, prefix_len: u8, port: u16, protocol: Protocol) -> NetRule {
        NetRule {
            cidr: cidr.to_owned(),
            prefix_len,
            port_min: port,
            port_max: port.saturating_add(1),
            protocol,
        }
    }

    fn name_rule(name: &str, protocol: Protocol) -> NameRule {
        NameRule {
            name: name.to_owned(),
            ports: vec![443, 8443],
            protocol,
        }
    }

    fn bus(prefix: &str) -> DbusBusRuntime {
        DbusBusRuntime {
            talk: strings(&[&format!("{prefix}.Talk")]),
            call: strings(&[&format!(
                "{prefix}.Call=org.example.Iface.Method@/org/example"
            )]),
            broadcast: strings(&[&format!("{prefix}.Broadcast=org.example.Iface.Signal@/*")]),
            own: strings(&[&format!("{prefix}.Own")]),
            deny_talk: strings(&[&format!("{prefix}.Denied")]),
        }
    }

    fn variant(field: &str) -> Variant {
        Variant {
            field: field.to_owned(),
            one_of: Vec::new(),
            pool: Vec::new(),
            pool_max: 0,
            pattern: Vec::new(),
            relpath_under: String::new(),
            freeform: false,
            reason: String::new(),
        }
    }

    /// A settled policy with every field set to something other than its default.
    ///
    /// Every struct below is written out in full, with no `..Default::default()`: a field
    /// added to any of them stops this compiling until a value is chosen for it here, and that
    /// value then shows up in the golden file. The values are not a policy anyone would run.
    #[allow(clippy::too_many_lines)] // one fixture, written out field by field on purpose
    fn full_settled() -> SettledPolicy {
        SettledPolicy {
            settled_schema_version: sample_settled().settled_schema_version,
            name: "every-field".to_owned(),
            deferred_substitutions: strings(&["<ctx>", "<uid>"]),
            framework_invariants_asserted: strings(&["cap.no_new_privs"]),
            effective_policy: EffectivePolicy {
                net: NetPolicy {
                    mode: NetMode::Host,
                    udp: true,
                    bind_port_min: 1024,
                    bind_allowed_ports: vec![8080, 8081],
                    proxy: ProxyListen {
                        offset: 3,
                        port: 1081,
                    },
                    allow: vec![rule("93.184.216.0", 24, 443, Protocol::Tcp)],
                    allow_names: vec![name_rule("example.org", Protocol::Tcp)],
                    udp_allow_names: vec![name_rule("dns.example.org", Protocol::Udp)],
                    deny_invariant: vec![rule("169.254.169.254", 32, 80, Protocol::Any)],
                    deny_author: vec![rule("10.0.0.0", 8, 22, Protocol::Tcp)],
                    bpf_connect_allow: vec![rule("192.0.2.0", 24, 443, Protocol::Tcp)],
                    bpf_connect_deny: vec![rule("198.51.100.0", 24, 25, Protocol::Tcp)],
                    bpf_bind_allow: vec![rule("127.0.0.1", 32, 8080, Protocol::Tcp)],
                    bpf_bind_deny: vec![rule("0.0.0.0", 0, 9, Protocol::Udp)],
                },
                fs: FsPolicy {
                    home_shadow: true,
                    read: strings(&["/usr", "/etc/ssl/certs"]),
                    write: strings(&["/home/op/project", "/home/op/shared"]),
                    exclusive: strings(&["/home/op/shared"]),
                    home_persist: strings(&[".cache/tool"]),
                    home_readonly: true,
                    redirect: vec![FsRedirect {
                        path: "/etc/tool".to_owned(),
                        source: "/etc/kennel/config/tool".to_owned(),
                    }],
                    write_mmap_exec: strings(&["/home/op/project"]),
                    cwd: CwdPolicy {
                        grant: CwdGrant::Write,
                        required: strings(&[".git", ".agent/"]),
                    },
                    tmp: TmpPolicy {
                        writable: true,
                        size_mib: 256,
                        mmap_exec: true,
                    },
                    dev: DevPolicy {
                        allow: strings(&["/dev/dri/renderD128"]),
                    },
                },
                exec: ExecPolicy {
                    deny_setuid: true,
                    deny_setgid: true,
                    deny_setcap: true,
                    deny_writable: true,
                    allow: strings(&["/bin/sh", "/usr/bin/git"]),
                    deny: strings(&["/usr/bin/sudo"]),
                    path: strings(&["/usr/bin", "/bin"]),
                    shell: "/bin/sh".to_owned(),
                    loaders: strings(&["/lib64/ld-linux-x86-64.so.2"]),
                },
                proc: ProcPolicy { hidepid: true },
                cap: CapPolicy { no_new_privs: true },
                seccomp: SeccompPolicy {
                    deny_action: SeccompAction::KillProcess,
                    deny: strings(&["ptrace", "mount"]),
                },
                lifecycle: LifecyclePolicy {
                    ttl_seconds: Some(3600),
                    ttl_action: TtlAction::Renew,
                },
                tty: TtyPolicy {
                    filter_terminal_escapes: true,
                },
                trust: TrustPolicy {
                    manifest: true,
                    on_change: OnChangeAction::Kill,
                },
            },
            provenance: Provenance {
                compiler_version: "0.0.0".to_owned(),
                schema_version: sample_settled().provenance.schema_version,
                threat_catalogue_version: "0.1".to_owned(),
                resolved_artifacts: vec![ResolvedArtifact {
                    name: "base-confined".to_owned(),
                    signing_key_id: "maint-2026".to_owned(),
                    signature: "c2lnbmF0dXJl".to_owned(),
                }],
            },
            ssh: SshRuntime {
                allow_headless: true,
                grants: vec![SshGrant {
                    dest: "git@example.org".to_owned(),
                    options: strings(&["no-pty", "no-port-forwarding"]),
                    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA every-field".to_owned(),
                    key_file: "example-org.key".to_owned(),
                }],
            },
            unix: UnixRuntime {
                sockets: vec![UnixSocket {
                    name: "wayland".to_owned(),
                    real: "/run/user/<uid>/wayland-0".to_owned(),
                    shim: "~/.wayland-0".to_owned(),
                    env: Some("WAYLAND_DISPLAY".to_owned()),
                }],
            },
            identity: IdentityRuntime {
                user: "agent".to_owned(),
                group: "agents".to_owned(),
                groups: strings(&["video", "render"]),
                hostname: Some("every-field".to_owned()),
            },
            mesh: MeshRuntime {
                provides: vec![ProvideRuntime {
                    name: "org.example.provided".to_owned(),
                    shape: Shape::BinderConnector,
                    endpoint: "/run/mesh/provided/binder".to_owned(),
                    key: Some("provided-key".to_owned()),
                }],
                consumes: vec![ConsumeRuntime {
                    name: "org.example.consumed".to_owned(),
                    shape: Shape::DbusName,
                    at: Some("/run/mesh/consumed/binder".to_owned()),
                    env: strings(&["CONSUMED_SOCKET"]),
                    key: Some("consumed-key".to_owned()),
                    required: true,
                }],
            },
            service: Some(ServiceRuntime {
                restart: RestartPolicy::OnFailure,
                backoff_ms: 2500,
                max_attempts: 7,
            }),
            dbus: DbusRuntime {
                audit_level: Some("full".to_owned()),
                session: Some(bus("org.example.session")),
                system: Some(bus("org.example.system")),
            },
            audit: AuditRuntime {
                sinks: vec![
                    AuditSinkKind::File,
                    AuditSinkKind::Journald,
                    AuditSinkKind::Syslog,
                    AuditSinkKind::Stdout,
                ],
                network_level: Some("full".to_owned()),
                filesystem_level: Some("summary".to_owned()),
                exec_level: Some("denies-only".to_owned()),
                unix_level: Some("off".to_owned()),
                dbus_level: Some("full".to_owned()),
                syslog_facility: Some("local3".to_owned()),
                file: AuditFileConfig {
                    dir: Some("/var/log/kennel".to_owned()),
                    rotate_at_bytes: Some(1_048_576),
                    compress_after_seconds: Some(86_400),
                    retain_count: Some(14),
                },
            },
            env: EnvRuntime {
                vars: [("EDITOR", "vi"), ("LANG", "C.UTF-8")]
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
            },
            ulimits: UlimitsRuntime {
                limits: [("nofile", "1024:4096"), ("nproc", "512")]
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
            },
            workload: WorkloadRuntime {
                argv: strings(&["/usr/bin/git", "status"]),
                cwd: Some("~/project".to_owned()),
                pinned: true,
                allowed_args: true,
                sha256: strings(&[
                    "0000000000000000000000000000000000000000000000000000000000000000",
                ]),
            },
            rootfs: RootfsRuntime {
                path: "/var/lib/kennel/oci/tool/rootfs".to_owned(),
                image: "example.org/tool@sha256:1111".to_owned(),
                persistence: "persist".to_owned(),
                readonly: strings(&["/usr/**"]),
                writable: strings(&["/var/lib/tool/**"]),
            },
            spawn: Some(SpawnGrant {
                max_instances: 4,
                allow: vec![SpawnTemplate {
                    template: "net-fetch".to_owned(),
                    signing_key_id: "maint-2026".to_owned(),
                    signature: "dGVtcGxhdGU=".to_owned(),
                    mutable_narrow: strings(&["net.proxy.allow"]),
                }],
            }),
            manifest: vec![
                Variant {
                    one_of: strings(&["a", "b"]),
                    ..variant("exec.shell")
                },
                Variant {
                    pool: strings(&["/w/one", "/w/two"]),
                    pool_max: 2,
                    ..variant("fs.write")
                },
                Variant {
                    pattern: strings(&["*.example.org:443"]),
                    ..variant("net.proxy.allow")
                },
                Variant {
                    relpath_under: "/srv/data".to_owned(),
                    ..variant("fs.read")
                },
                Variant {
                    freeform: true,
                    reason: "the operator names the branch".to_owned(),
                    ..variant("env.BRANCH")
                },
            ],
        }
    }

    /// Compare `bytes` with the golden file `name`, writing the file first under `KENNEL_BLESS`.
    fn check_golden(name: &str, bytes: &[u8]) {
        let path = format!("{}/tests/golden/{name}", env!("CARGO_MANIFEST_DIR"));
        if std::env::var_os("KENNEL_BLESS").is_some() {
            std::fs::write(&path, bytes).expect("write the golden file");
        }
        let golden = std::fs::read(&path).expect("read the golden file (KENNEL_BLESS=1 writes it)");
        assert!(
            bytes == golden,
            "the canonical form in {path} changed; signatures made before this change will not \
             verify. If that is intended, re-run with KENNEL_BLESS=1 and commit the file"
        );
    }

    /// The canonical form is what a signature covers. If these bytes change, every policy signed
    /// before the change stops verifying, so a change has to be a decision and not a side effect
    /// of touching the serialiser or the policy struct.
    ///
    /// The golden file is the canonical form of [`sample_settled`]. To accept a deliberate
    /// change, run this test once with `KENNEL_BLESS=1` and commit the file.
    #[test]
    fn the_canonical_form_of_the_sample_policy_is_the_committed_bytes() {
        let bytes = canonical_bytes(&sample_settled()).expect("canonical form");
        check_golden("sample-settled.canonical", &bytes);
    }

    /// A policy that grants an `fs.redirect` and an `fs.write_mmap_exec` together has a canonical
    /// form. It did not: the plain array was declared after the array of tables, which the TOML
    /// writer refuses, so such a policy could not be signed.
    #[test]
    fn a_redirect_and_an_mmap_exec_grant_together_have_a_canonical_form() {
        let mut policy = sample_settled();
        policy.effective_policy.fs.redirect = vec![FsRedirect {
            path: "/etc/tool".to_owned(),
            source: "/etc/kennel/config/tool".to_owned(),
        }];
        policy.effective_policy.fs.write_mmap_exec = strings(&["/run/kennel/ai-coding/home"]);
        let bytes = canonical_bytes(&policy).expect("canonical form");
        let text = String::from_utf8(bytes).expect("text");
        let values = text.find("write_mmap_exec").expect("the mmap-exec grant");
        let tables = text
            .find("[[effective_policy.fs.redirect]]")
            .expect("the redirect");
        assert!(values < tables, "plain values come before sub-tables");
    }

    /// The same, for a policy with every field populated. The sample leaves most optional
    /// sections empty, and an empty section is not written, so on its own it would not notice a
    /// change to how one of them is serialised.
    #[test]
    fn the_canonical_form_of_a_fully_populated_policy_is_the_committed_bytes() {
        let policy = full_settled();
        let bytes = canonical_bytes(&policy).expect("canonical form");
        check_golden("every-field.canonical", &bytes);
        // Nothing in the fixture is at its default: every section it sets is in the bytes.
        let text = String::from_utf8(bytes).expect("canonical form is text");
        for key in [
            "[effective_policy.net.proxy]",
            "[[effective_policy.fs.redirect]]",
            "[effective_policy.fs.cwd]",
            "[effective_policy.lifecycle]",
            "[[ssh.grants]]",
            "[[unix.sockets]]",
            "[[mesh.provides]]",
            "[[mesh.consumes]]",
            "[service]",
            "[dbus.session]",
            "[dbus.system]",
            "[audit.file]",
            "[env.vars]",
            "[ulimits.limits]",
            "[workload]",
            "[rootfs]",
            "[[spawn.allow]]",
            "[[manifest]]",
        ] {
            assert!(text.contains(key), "the canonical form has no {key}");
        }
    }
}
