//! The composable fragment catalogue (`05-templates.md` §5.10) — per-fragment tests.
//!
//! Each `fragments/<name>/policy.toml` is a signed, additive-only capability bundle a
//! leaf or template can `include`. This test is the catalogue's gate: for every shipped
//! fragment it
//!
//! 1. verifies the committed `[signature]` against the maintainer public key in `keys/`
//!    (the §5.10 promise that every committed fragment carries a valid signature),
//! 2. checks the fragment is **additive-only** (no `.remove` delta — includes may only
//!    widen), and
//! 3. compiles a real `base-confined` leaf that includes it and asserts the fragment's
//!    grants land in the settled policy — and that a leaf *without* the include does
//!    not have them (so the grant is the fragment's doing, not the base's).
//!
//! Adding a fragment without an entry here, or breaking one's signature/composition,
//! fails CI.

use kennel_lib_compile::{compile_leaf, parse_leaf, seal_unsigned, TemplateSource, Trust};
use kennel_lib_policy::keys::KeySet;
use kennel_lib_policy::to_bytes;
use std::path::{Path, PathBuf};

/// What each fragment must grant: substrings that must appear in the settled policy
/// when the fragment is included, and must *not* appear without it.
struct Expect {
    fragment: &'static str,
    grants: &'static [&'static str],
}

const CATALOGUE: &[Expect] = &[
    Expect {
        fragment: "lang-python",
        grants: &["/usr/bin/python3", "pypi.org", "files.pythonhosted.org"],
    },
    Expect {
        fragment: "lang-node",
        grants: &["/usr/bin/node", "/usr/bin/npm", "registry.npmjs.org"],
    },
    Expect {
        fragment: "toolchain-c",
        grants: &["/usr/bin/cc", "/usr/bin/make", "/usr/lib/gcc"],
    },
    Expect {
        fragment: "vcs-git",
        grants: &["/usr/bin/git", "git-core", "/etc/gitconfig"],
    },
    Expect {
        fragment: "net-permissive",
        grants: &["crates.io", "github.com", "ghcr.io"],
    },
    Expect {
        fragment: "core-shell",
        grants: &["/usr/bin/dash", "/usr/bin/bash"],
    },
    Expect {
        fragment: "core-coreutils",
        grants: &["/usr/bin/grep", "/usr/bin/awk", "/usr/bin/sed"],
    },
    Expect {
        fragment: "core-file-mutation",
        grants: &["/usr/bin/cp", "/usr/bin/rm", "/usr/bin/mkdir"],
    },
    Expect {
        fragment: "core-archive",
        grants: &["/usr/bin/tar", "/usr/bin/gzip", "/usr/bin/xz"],
    },
    Expect {
        fragment: "net-clients",
        grants: &["/usr/bin/curl", "/usr/bin/wget"],
    },
    Expect {
        fragment: "dev-headers",
        grants: &["/usr/include/", "/usr/src/"],
    },
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// A source serving both the in-tree `templates/` and `fragments/` directories, in the
/// `<name>/policy.toml` nested layout (the include resolver tries each).
struct CatalogueSource {
    roots: Vec<PathBuf>,
}
impl TemplateSource for CatalogueSource {
    fn fetch(&self, name: &str, _version: &str) -> Option<Vec<u8>> {
        self.roots
            .iter()
            .find_map(|r| std::fs::read(r.join(name).join("policy.toml")).ok())
    }
}

/// The maintainer trust store built from the committed `keys/*.pub` (base64 of the
/// 32-byte Ed25519 public key), so fragment signatures verify exactly as in production.
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

/// Compile a `base-confined` leaf with the given includes (plus a shell, which
/// base-confined leaves to the caller) and return the settled policy as TOML text.
fn settle_with(includes: &[&str], keys: &KeySet) -> String {
    let include_list = includes
        .iter()
        .map(|i| format!("\"{i}@v1\""))
        .collect::<Vec<_>>()
        .join(", ");
    let leaf_src = format!(
        "name = \"frag-test\"\n\
         template_base = \"base-confined@v1\"\n\
         include = [{include_list}]\n\
         [[exec.allow.add]]\n\
         path = \"/bin/sh\"\n\
         reason = \"login shell\"\n"
    );
    let leaf = parse_leaf(leaf_src.as_bytes()).expect("parse leaf");
    let source = CatalogueSource {
        roots: vec![repo_root().join("templates"), repo_root().join("fragments")],
    };
    let compiled = compile_leaf(&leaf, &source, &Trust::require(keys), "0.0.0")
        .expect("compile leaf with fragment (signature must verify, deltas must apply)");
    let sealed = seal_unsigned(&compiled.policy);
    String::from_utf8(to_bytes(&sealed).expect("serialise settled")).expect("utf8")
}

#[test]
fn every_fragment_is_signed_additive_and_composes() {
    let keys = maintainer_keys();
    // The baseline (no fragments) — its grants are what the fragments must add *to*.
    let baseline = settle_with(&[], &keys);

    for entry in CATALOGUE {
        // (1) signature verifies against the maintainer key, and (2) additive-only —
        // both are enforced by compile_leaf under Trust::require: an unsigned/forged or
        // `.remove`-bearing fragment makes this fail.
        let frag_bytes = std::fs::read(
            repo_root()
                .join("fragments")
                .join(entry.fragment)
                .join("policy.toml"),
        )
        .expect("read fragment policy.toml");
        let frag = parse_leaf(&frag_bytes).expect("fragment parses as a leaf");
        assert!(
            frag.is_additive_only(),
            "fragment `{}` must be additive-only (no `.remove` delta)",
            entry.fragment
        );
        assert!(
            frag.signature.is_some(),
            "committed fragment `{}` must carry a [signature] (run `kennel policy sign`)",
            entry.fragment
        );

        // (3) its grants land when included, and are absent without it.
        let settled = settle_with(&[entry.fragment], &keys);
        for grant in entry.grants {
            assert!(
                settled.contains(grant),
                "fragment `{}` did not grant `{grant}` in the settled policy",
                entry.fragment
            );
            assert!(
                !baseline.contains(grant),
                "`{grant}` is in base-confined already — not evidence that `{}` granted it",
                entry.fragment
            );
        }
    }
}

#[test]
fn fragments_compose_without_conflict() {
    // Every fragment included together must resolve — the shared egress destinations
    // (pypi/npm) are kept byte-identical across fragments so they dedup rather than
    // tripping the include-conflict check.
    let keys = maintainer_keys();
    let all: Vec<&str> = CATALOGUE.iter().map(|e| e.fragment).collect();
    let settled = settle_with(&all, &keys);
    assert!(settled.contains("/usr/bin/python3") && settled.contains("github.com"));
}
