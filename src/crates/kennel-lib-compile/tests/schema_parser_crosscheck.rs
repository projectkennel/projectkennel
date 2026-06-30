//! Schema↔parser cross-check — the drift guard that makes the generated
//! `schema/policy.toml.schema` trustworthy.
//!
//! The schema is emitted from `gen_schema::model` (a hand-kept data table). This test
//! pins that table to the real parser (`kennel_lib_compile::source::parse`), so the two
//! cannot silently diverge — the same role `gen-man`'s `SYNC_*` tables play for the CLI:
//!
//! 1. **schema ⊆ parser.** A TOML document that exercises *every* field the schema
//!    declares must parse. If the schema declares a field — or a field type — the parser
//!    does not accept, the parser's `#[serde(deny_unknown_fields)]` (or a type mismatch)
//!    rejects it and this test fails. So the schema never lies about the parser.
//! 2. **the schema is the allowlist.** A document with a field the schema does not
//!    declare is rejected by the parser, confirming `deny_unknown_fields` is in force
//!    (the property the published schema's `additionalProperties: false` mirrors).
//! 3. **the real corpus validates.** Every in-tree template parses — a field a template
//!    uses that the schema forgot would surface here (the template exercises it, the
//!    schema-built kitchen sink would then be missing it, breaking the field census).
//!
//! A parser field added without the matching `gen_schema::model` entry (and a
//! regenerated schema) fails CI here. See `src/tools/gen-schema`.

use gen_schema::model::{root, table, Table, Ty};
use kennel_lib_compile::source;

/// Emit a TOML document that sets every field the schema declares to a type-correct
/// value, so the parser can confirm it accepts the entire schema surface.
fn kitchen_sink() -> String {
    let mut out = String::new();
    emit_table(&mut out, "", root());
    out
}

/// Emit `t`'s scalar leaves under the already-opened header `prefix` (empty = root),
/// then its sub-tables / maps / arrays-of-tables under their own headers. TOML requires
/// a table's bare keys before any of its sub-headers, which the two passes guarantee.
fn emit_table(out: &mut String, prefix: &str, t: &Table) {
    use std::fmt::Write as _;
    for field in t.fields {
        if let Some(value) = scalar_value(&field.ty) {
            let _ = writeln!(out, "{} = {value}", field.key);
        }
    }
    for field in t.fields {
        let path = if prefix.is_empty() {
            field.key.to_owned()
        } else {
            format!("{prefix}.{}", field.key)
        };
        match &field.ty {
            Ty::Obj(name) => {
                let _ = writeln!(out, "[{path}]");
                emit_table(out, &path, def(name));
            }
            Ty::ObjArray(name) => {
                let _ = writeln!(out, "[[{path}]]");
                emit_table(out, &path, def(name));
            }
            Ty::Map => {
                let _ = writeln!(out, "[{path}]");
                out.push_str("example = \"1\"\n");
            }
            _ => {}
        }
    }
}

/// A type-correct literal for a scalar/array field, or `None` for the table-shaped
/// variants (which get their own header in the second pass).
fn scalar_value(ty: &Ty) -> Option<String> {
    Some(match ty {
        Ty::Str => "\"x\"".to_owned(),
        Ty::Enum(values) => format!("\"{}\"", values.first().copied().unwrap_or("x")),
        Ty::Bool => "true".to_owned(),
        Ty::Int => "1".to_owned(),
        Ty::Port => "8080".to_owned(),
        Ty::StrArray => "[\"x\"]".to_owned(),
        Ty::PortArray => "[8080]".to_owned(),
        Ty::Obj(_) | Ty::ObjArray(_) | Ty::Map => return None,
    })
}

fn def(name: &str) -> &'static Table {
    table(name).expect("schema references an undefined table")
}

#[test]
fn every_schema_field_is_accepted_by_the_parser() {
    let toml = kitchen_sink();
    let parsed = source::parse(toml.as_bytes());
    assert!(
        parsed.is_ok(),
        "the schema declares a field the parser rejects — schema and parser have \
         drifted. Update src/tools/gen-schema/src/model.rs (and regenerate \
         schema/policy.toml.schema) to match kennel-lib-compile's source structs.\n\
         parse error: {:?}\n--- generated document ---\n{toml}",
        parsed.err()
    );
}

#[test]
fn an_undeclared_field_is_rejected() {
    // `deny_unknown_fields` is what makes the published schema's `additionalProperties:
    // false` faithful: a key the schema does not declare must be a hard parse error.
    let bogus = b"[exec]\nallow = []\nnot_a_real_field = true\n";
    assert!(
        source::parse(bogus).is_err(),
        "parser accepted an undeclared field — deny_unknown_fields is not in force, so \
         the schema's additionalProperties:false would over-promise"
    );
}

/// Resolution of a dotted TOML table path against the schema tree.
enum Resolved {
    /// The path names a known object/array-of-tables definition.
    Table(&'static Table),
    /// The path descends into a free `Map` (`[ulimits]`, `[env.set]`) — arbitrary keys.
    FreeMap,
    /// The path names a table the schema does not model (a real drift — fail).
    Unknown,
}

/// Walk a dotted TOML header path (`""` = root, `"fs.home"`, `"net.proxy.allow"`)
/// through the schema tree.
fn resolve(path: &str) -> Resolved {
    let mut current = root();
    if path.is_empty() {
        return Resolved::Table(current);
    }
    for segment in path.split('.') {
        let Some(field) = current.fields.iter().find(|f| f.key == segment) else {
            return Resolved::Unknown;
        };
        match &field.ty {
            Ty::Obj(name) | Ty::ObjArray(name) => current = def(name),
            Ty::Map => return Resolved::FreeMap,
            _ => return Resolved::Unknown, // a scalar cannot carry sub-keys
        }
    }
    Resolved::Table(current)
}

/// Every `[table]` header and `key =` in the in-tree templates must be schema-declared —
/// the completeness direction (parser ⊆ schema) over the real authoring corpus. A parser
/// field a template exercises that `gen_schema::model` forgot fails here.
#[test]
fn every_template_table_and_key_is_schema_declared() {
    let root_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../toml/templates");
    for entry in std::fs::read_dir(root_dir).expect("templates dir") {
        let policy = entry.expect("dir entry").path().join("policy.toml");
        if !policy.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&policy).expect("read template");
        let label = policy.display();
        let mut path = String::new();
        for raw in text.lines() {
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if let Some(header) = table_header(line) {
                path = header.to_owned();
                assert!(
                    !matches!(resolve(&path), Resolved::Unknown),
                    "{label}: table [{path}] is not declared in the schema \
                     (src/tools/gen-schema/src/model.rs)"
                );
            } else if let Some(key) = leading_key(line) {
                match resolve(&path) {
                    Resolved::Table(t) => assert!(
                        t.fields.iter().any(|f| f.key == key),
                        "{label}: key `{key}` under [{path}] is not declared in the \
                         schema (src/tools/gen-schema/src/model.rs) — the parser accepts \
                         a field the schema forgot"
                    ),
                    // FreeMap → arbitrary map keys; Unknown → the header already failed above.
                    Resolved::FreeMap | Resolved::Unknown => {}
                }
            }
        }
    }
}

/// The bare key of a `key = value` line, or `None` (array continuation, value line, …).
/// Matches a leading TOML bare key (letters/digits/`_`/`-`) immediately before `=`.
fn leading_key(line: &str) -> Option<&str> {
    let (lhs, _) = line.split_once('=')?;
    let key = lhs.trim();
    let ok = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    ok.then_some(key)
}

/// The inner path of a `[table]` / `[[table]]` header line, or `None`.
fn table_header(line: &str) -> Option<&str> {
    let inner = line.strip_prefix('[')?.strip_suffix(']')?;
    Some(
        inner
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(inner),
    )
}

/// Drop a trailing `# comment` (templates have no `#` inside string values worth caring
/// about for header/key extraction).
fn strip_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(head, _)| head)
}

#[test]
fn every_in_tree_template_parses() {
    // The real authoring corpus must round-trip through the same parser the schema
    // mirrors; a template field the schema forgot would be one the parser accepts but
    // the kitchen sink (built from the schema) never exercises.
    let root_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../toml/templates");
    let mut checked = 0;
    for entry in std::fs::read_dir(root_dir).expect("templates dir") {
        let dir = entry.expect("dir entry").path();
        let policy = dir.join("policy.toml");
        if !policy.is_file() {
            continue;
        }
        let bytes = std::fs::read(&policy).expect("read template");
        assert!(
            source::parse(&bytes).is_ok(),
            "in-tree template failed to parse: {}",
            policy.display()
        );
        checked += 1;
    }
    assert!(
        checked >= 6,
        "expected the in-tree template corpus, found {checked}"
    );
}
