//! Schema↔parser agreement — now by construction, not by a hand-kept mirror.
//!
//! `schema/policy.toml.schema` is *derived* from these parser structs (`#[derive(SchemaType)]`,
//! emitted by `gen-schema`), so it can no longer describe a field the parser lacks or omit one
//! it has — the drift the old data-table model risked is structurally impossible. What remains
//! to guard is mechanical: that the committed schema was regenerated after a struct change, and
//! that the in-tree templates still parse.

#[test]
fn regenerating_the_schema_is_idempotent() {
    let committed = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../schema/policy.toml.schema"
    ))
    .expect("read committed schema");
    let fresh = gen_schema::schema_document();
    assert_eq!(
        committed, fresh,
        "schema/policy.toml.schema is stale — a source struct changed without regenerating it. \
         Run: cargo run -p gen-schema -- --out schema/policy.toml.schema"
    );
}

#[test]
fn every_in_tree_template_parses() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../toml/templates");
    for entry in std::fs::read_dir(dir).expect("templates dir") {
        let policy = entry.expect("dir entry").path().join("policy.toml");
        if !policy.is_file() {
            continue;
        }
        let bytes = std::fs::read(&policy).expect("read template");
        let parsed = kennel_lib_compile::source::parse(&bytes);
        assert!(parsed.is_ok(), "{}: {:?}", policy.display(), parsed.err());
    }
}

#[test]
fn an_undeclared_field_is_rejected() {
    // `deny_unknown_fields` is what makes the schema's `additionalProperties: false` faithful:
    // a key the structs do not declare must be a hard parse error.
    let bogus = b"[exec]\nallow = []\nnot_a_real_field = true\n";
    assert!(
        kennel_lib_compile::source::parse(bogus).is_err(),
        "parser accepted an undeclared field — deny_unknown_fields is not in force"
    );
}
