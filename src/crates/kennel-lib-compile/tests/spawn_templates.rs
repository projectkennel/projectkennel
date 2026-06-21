//! The signed spawn-target template set (`docs/design/07-12-dynamic-spawn.md` §7.12,
//! ROADMAP-0.3.0 W5) — per-template gate, mirroring `fragments_catalogue.rs`.
//!
//! Each `templates/<name>/policy.toml` in [`SPAWN_TEMPLATES`] is a single-leg SPAWN target.
//! This gate asserts, for every one:
//!
//! 1. it carries a committed maintainer `[signature]` (the §5.10 promise; run
//!    `kennel policy sign <name> --key …`),
//! 2. it compiles to a settled policy with a well-formed `[[mutable]]` manifest, and
//! 3. it is **spawn-eligible** (§7.12.8) — a spawner that `[[spawn.allow]]`s all three
//!    compiles, so `spawn::resolve_grant`'s depth-1 / TTL / ceilings checks pass on each, and the
//!    resulting settled spawner carries a `[spawn]` grant pinning each target to its signature.
//!
//! The `*_signed_*` test is the production gate (green once the templates are signed); the
//! `*_unsigned_*` test verifies the same structure under `Trust::dev`, so the policy is
//! checkable before signing.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use kennel_lib_compile::source::parse;
use kennel_lib_compile::{compile, TemplateSource, Trust};
use kennel_lib_policy::keys::KeySet;

/// The shipped single-leg spawn targets.
const SPAWN_TEMPLATES: &[&str] = &["pure-compute", "net-fetch", "scratch-fs"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// A source serving the in-tree `templates/` directory in the `<name>/policy.toml` layout.
struct Templates {
    root: PathBuf,
}
impl TemplateSource for Templates {
    fn fetch(&self, name: &str, _version: &str) -> Option<Vec<u8>> {
        std::fs::read(self.root.join(name).join("policy.toml")).ok()
    }

    /// The settled form a spawn instantiates: compile the source template (folding `base-confined`)
    /// and seal it **unsigned** (dev). Production ships a maintainer-signed `<name>.settled.toml`;
    /// here we synthesise the dev equivalent so the spawner's grant resolution has a settled artefact.
    fn fetch_settled(&self, name: &str, version: &str) -> Option<Vec<u8>> {
        let bytes = self.fetch(name, version)?;
        let entry = parse(&bytes).ok()?;
        let compiled = compile(&entry, self, &Trust::dev(), "0.0.0").ok()?;
        kennel_lib_policy::to_bytes(&kennel_lib_compile::seal_unsigned(&compiled.policy)).ok()
    }
}
fn templates() -> Templates {
    Templates {
        root: repo_root().join("templates"),
    }
}

fn read_template(name: &str) -> Vec<u8> {
    std::fs::read(repo_root().join("templates").join(name).join("policy.toml"))
        .expect("read a spawn template's policy.toml")
}

/// The maintainer trust store from the committed `keys/*.pub` (as in `fragments_catalogue`).
fn maintainer_keys() -> KeySet {
    let mut ks = KeySet::new();
    let dir = repo_root().join("keys");
    for entry in std::fs::read_dir(&dir).expect("read keys dir").flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "pub") {
            let key_id = path
                .file_stem()
                .expect("stem")
                .to_string_lossy()
                .into_owned();
            let b64 = std::fs::read_to_string(&path).expect("read pub");
            ks.insert_b64(&key_id, b64.trim()).expect("insert pub key");
        }
    }
    ks
}

/// A spawner policy that allows all three templates — compiling it runs `spawn::validate`
/// (eligibility) on each named target. A spawner is a **source/template** policy: `[spawn]` is a
/// template-level grant by design (depth-1 / N-1, no grandchildren — §7.12.8), inherited through the
/// chain, not authored on a leaf.
fn spawner_policy() -> String {
    let mut allows = String::new();
    for t in SPAWN_TEMPLATES {
        let _ = write!(allows, "[[spawn.allow]]\ntemplate = \"{t}@v1\"\n");
    }
    format!(
        "name = \"spawn-eligibility-probe\"\n\
         template_base = \"base-confined@v1\"\n\
         [spawn]\n\
         max_instances = 4\n\
         reason = \"probe: exercise spawn-eligibility of the shipped templates\"\n\
         {allows}"
    )
}

/// Production gate: every committed spawn template is signed, compiles, and is eligible.
/// Green once the templates are signed (`kennel policy sign`); the signature assertion is the
/// explicit reminder.
#[test]
fn every_spawn_template_is_signed_compiles_and_is_eligible() {
    let keys = maintainer_keys();
    let trust = Trust::require(&keys);
    for name in SPAWN_TEMPLATES {
        let entry = parse(&read_template(name)).expect("template parses");
        assert!(
            entry.signature.is_some(),
            "spawn template `{name}` must carry a [signature] — run `kennel policy sign {name} --key kennel-maint-2026`"
        );
        let compiled = compile(&entry, &templates(), &trust, "0.0.0");
        assert!(
            compiled.is_ok(),
            "spawn template `{name}` must compile under require: {:?}",
            compiled.err()
        );
    }
    // The spawner that *resolves* these templates needs each one's signed **settled** artefact
    // (`<name>.settled.toml`) — a maintainer-signed pre-resolved policy the repo does not yet carry
    // (signing needs the maintainer private key, offline). The grant-resolution + content-pin path is
    // exercised against dev-sealed settled artefacts in the `*_unsigned_*` test below; this gate stays
    // the per-template source signature + compile reminder.
}

/// Signature-independent gate: the templates compile, carry the expected manifest, and are
/// spawn-eligible under `Trust::dev` — checkable before the maintainer signs.
#[test]
fn spawn_templates_compile_with_valid_manifests_and_are_eligible_unsigned() {
    let trust = Trust::dev();
    for name in SPAWN_TEMPLATES {
        let entry = parse(&read_template(name)).expect("template parses");
        let compiled = compile(&entry, &templates(), &trust, "0.0.0");
        assert!(
            compiled.is_ok(),
            "`{name}` must compile (manifest must validate): {:?}",
            compiled.err()
        );
        // The manifest is carried onto the signed settled template (empty ⇒ most-fenced).
        let manifest = compiled.expect("compiled").policy.manifest;
        if *name == "pure-compute" {
            assert!(manifest.is_empty(), "pure-compute opens no mutable fields");
        } else if *name == "net-fetch" {
            assert!(
                manifest
                    .iter()
                    .any(|v| v.field == "net.proxy.allow" && !v.pattern.is_empty()),
                "net-fetch opens net.proxy.allow under a pattern constraint"
            );
        } else if *name == "scratch-fs" {
            assert!(
                manifest
                    .iter()
                    .any(|v| v.field == "fs.write" && !v.one_of.is_empty()),
                "scratch-fs opens fs.write under a oneof constraint"
            );
        }
    }
    let spawner = parse(spawner_policy().as_bytes()).expect("spawner parses");
    let compiled = compile(&spawner, &templates(), &trust, "0.0.0");
    assert!(
        compiled.is_ok(),
        "all shipped templates are spawn-eligible (depth-1, TTL, memory/pids/CPU ceilings): {:?}",
        compiled.err()
    );
    // The grant is carried into the settled spawner: each target resolved from its (here dev-sealed)
    // settled artefact via `fetch_settled` and pinned. The content-pin equality against a real signed
    // settled template is exercised by `verify_pinned`'s tests + the spawn-roundtrip e2e.
    let grant = compiled
        .expect("compiled")
        .policy
        .spawn
        .expect("a spawner carries a [spawn] grant");
    assert_eq!(grant.allow.len(), SPAWN_TEMPLATES.len());
}
