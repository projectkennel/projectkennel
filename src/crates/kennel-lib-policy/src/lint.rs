//! Coherence linting of a **settled** policy (`kennel policy lint`).
//!
//! Distinct from compile-time warnings (footgun grants on the *source*): the linter
//! inspects the fully-resolved [`SettledPolicy`] and flags combinations that are
//! internally incoherent — settings that contradict the resolved net mode, or grants
//! that the mode renders vacuous. It exists because template inheritance can fold a
//! field in that the leaf author never sees (the `interactive` net-mode bug: a leaf set
//! `mode = "host"` but inherited a proxy listener), and `policy show` describes while
//! `policy lint` judges.
//!
//! Each finding is a human-readable line. The shipped template corpus must lint clean
//! (a test asserts it); a non-empty result from `kennel policy lint` is a non-zero exit.

use crate::settled::{NetMode, SettledPolicy};

/// Lint a settled policy for incoherences, returning one line per finding (empty ⇒ clean).
#[must_use]
pub fn lint_settled(policy: &SettledPolicy) -> Vec<String> {
    let mut findings = Vec::new();
    let net = &policy.effective_policy.net;

    match net.mode {
        NetMode::None => {
            // A no-network kennel: any egress grant (proxy or BPF ACL) or proxy listener is
            // vacuous — there is no network to reach.
            if !net.allow.is_empty() || !net.allow_names.is_empty() {
                findings.push(
                    "net.mode = none but [net.proxy].allow is non-empty: the allowlist is vacuous \
                     (no network exists to reach)"
                        .to_owned(),
                );
            }
            if !net.bpf_connect_allow.is_empty() || !net.bpf_connect_deny.is_empty() {
                findings.push(
                    "net.mode = none but [net.bpf].connect has rules: the kernel ACL is vacuous \
                     (no network exists to reach)"
                        .to_owned(),
                );
            }
            if !net.proxy.is_disabled() {
                findings.push(
                    "net.mode = none but a proxy listener is configured: no proxy runs without a \
                     network"
                        .to_owned(),
                );
            }
        }
        NetMode::Host => {
            // `host` is host-netns DIRECT egress: no SOCKS proxy. A proxy listener here is the
            // composition bug the engine now forces off — flag it if it ever reappears.
            if !net.proxy.is_disabled() {
                findings.push(
                    "net.mode = host but a proxy listener is configured: host mode egresses \
                     directly (no SOCKS proxy) — the listener is enforced by nothing"
                        .to_owned(),
                );
            }
            // The compiler rejects an AUTHOR [net.proxy] rule under host (translate_net), but the
            // inherited invariant floor (deny_invariant) folds in everywhere. A by-name proxy
            // allow that somehow survived is enforced by nothing here — backstop it.
            if !net.allow_names.is_empty() {
                findings.push(
                    "net.mode = host but [net.proxy].allow carries by-name rule(s): host mode has \
                     no proxy to resolve names — use [net.bpf].connect (cidr) instead"
                        .to_owned(),
                );
            }
        }
        NetMode::Constrained | NetMode::Unconstrained => {
            // Proxied modes SHOULD carry a proxy listener; its absence means no egress path.
            if net.proxy.is_disabled() {
                findings.push(
                    "a proxied net.mode (constrained/unconstrained) has no proxy listener: the \
                     workload has no egress path"
                        .to_owned(),
                );
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::TemplateSource;
    use crate::source::parse;
    use crate::source_sig::Trust;
    use std::path::{Path, PathBuf};

    /// A [`TemplateSource`] backed by the shipped `templates/` dir (read at test time).
    struct TemplatesDir(PathBuf);
    impl TemplateSource for TemplatesDir {
        fn fetch(&self, name: &str, version: &str) -> Option<Vec<u8>> {
            // Templates are `templates/<name>/policy.toml`; the `@v<ver>` contract is checked
            // by the chain resolver, so a name lookup suffices here.
            let _ = version;
            std::fs::read(self.0.join(name).join("policy.toml")).ok()
        }
    }

    fn templates_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../templates")
    }

    /// Compile a shipped template to its settled form via the real `compile` path (dev trust,
    /// so unsigned in-tree templates resolve), exactly as `policy lint` would.
    fn settle(name: &str) -> SettledPolicy {
        let dir = templates_dir();
        let bytes = std::fs::read(dir.join(name).join("policy.toml")).expect("read template");
        let entry = parse(&bytes).expect("parse template");
        crate::compile::compile(&entry, &TemplatesDir(dir), &Trust::dev(), "0.0.0")
            .expect("compile template")
            .policy
    }

    #[test]
    fn every_shipped_template_lints_clean() {
        let dir = templates_dir();
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir)
            .expect("read templates dir")
            .flatten()
        {
            let path = entry.path();
            if !path.join("policy.toml").is_file() {
                continue;
            }
            let name = path
                .file_name()
                .expect("name")
                .to_string_lossy()
                .into_owned();
            let findings = lint_settled(&settle(&name));
            assert!(
                findings.is_empty(),
                "template `{name}` lints with findings: {findings:?}"
            );
            checked += 1;
        }
        assert!(
            checked >= 5,
            "expected several shipped templates, saw {checked}"
        );
    }

    #[test]
    fn detects_open_mode_with_a_proxy_listener() {
        // Take a real template and inject the composition bug the engine now prevents, to prove
        // the linter would catch a regression.
        let mut p = settle("interactive");
        assert_eq!(p.effective_policy.net.mode, NetMode::Host);
        p.effective_policy.net.proxy = crate::settled::ProxyListen::default(); // a real listener
        let findings = lint_settled(&p);
        assert!(
            findings
                .iter()
                .any(|f| f.contains("host") && f.contains("proxy")),
            "expected a host+proxy finding, got {findings:?}"
        );
    }
}
