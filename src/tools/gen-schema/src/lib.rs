//! Project Kennel policy-schema generator (library half).
//!
//! Emits the JSON Schema (draft-07) for the authored policy TOML by walking
//! [`SchemaType::schema_node`] from [`SourcePolicy`] — the parser's own structs, reflected
//! by `#[derive(SchemaType)]`. The schema is a *pure export* of the one source (the
//! structs); there is no hand-kept model to drift from, so the schema↔parser cross-check
//! degenerates to "regenerating is idempotent."
//!
//! Rendered with the already-vendored `serde_json` (the project ships it CLI-side; this is
//! tooling, in no TCB closure).

#![forbid(unsafe_code)]

use kennel_lib_compile::source::SourcePolicy;
use kennel_schema::{Defs, Node, Obj, Prop, SchemaType};
use serde_json::{json, Map, Value};

/// The canonical published schema id (the website/editors fetch it here).
pub const SCHEMA_ID: &str = "https://projectkennel.org/schema/policy.toml.schema.json";

/// Render the whole policy schema as a pretty-printed JSON document (trailing newline).
///
/// # Panics
/// Never in practice: the root `SourcePolicy` always registers a `policy` def, and a schema
/// tree of plain data always serialises. The `expect`s document those invariants.
#[must_use]
pub fn schema_document() -> String {
    let mut defs = Defs::new();
    let _root_ref = <SourcePolicy as SchemaType>::schema_node(&mut defs);
    let root = defs
        .take("policy")
        .expect("SourcePolicy registers the `policy` root def");
    let definitions = defs.into_ordered();

    let mut doc = Map::new();
    doc.insert(
        "$schema".to_owned(),
        json!("http://json-schema.org/draft-07/schema#"),
    );
    doc.insert("$id".to_owned(), json!(SCHEMA_ID));
    doc.insert("title".to_owned(), json!("Project Kennel policy"));
    // The root object's body (description/type/additionalProperties/properties/required)
    // sits at the document top level; every other def goes under `definitions`.
    if let Value::Object(body) = object_body(&root) {
        for (key, value) in body {
            doc.insert(key, value);
        }
    }
    let mut defs_map = Map::new();
    for (name, obj) in definitions {
        defs_map.insert(name, object_body(&obj));
    }
    doc.insert("definitions".to_owned(), Value::Object(defs_map));

    let mut out = serde_json::to_string_pretty(&Value::Object(doc)).expect("schema serialises");
    out.push('\n');
    out
}

/// The JSON-Schema object body for one [`Obj`]: description, `type: object`,
/// `additionalProperties: false` (mirroring `deny_unknown_fields`), properties, required.
fn object_body(obj: &Obj) -> Value {
    let mut props = Map::new();
    for prop in &obj.props {
        props.insert(prop.key.clone(), property(prop));
    }
    let required: Vec<&str> = obj
        .props
        .iter()
        .filter(|p| p.required)
        .map(|p| p.key.as_str())
        .collect();

    let mut body = Map::new();
    if !obj.title.is_empty() {
        body.insert("description".to_owned(), json!(obj.title));
    }
    body.insert("type".to_owned(), json!("object"));
    body.insert("additionalProperties".to_owned(), json!(false));
    body.insert("properties".to_owned(), Value::Object(props));
    if !required.is_empty() {
        body.insert("required".to_owned(), json!(required));
    }
    Value::Object(body)
}

/// One property's schema, carrying its field-site description.
///
/// A `$ref` ignores sibling keywords in draft-07, so a referenced object is wrapped in
/// `allOf` to keep the field description alongside it.
fn property(prop: &Prop) -> Value {
    if let Node::Ref(name) = &prop.node {
        return json!({
            "description": prop.desc,
            "allOf": [ { "$ref": format!("#/definitions/{name}") } ],
        });
    }
    let mut value = node(&prop.node);
    if let Value::Object(map) = &mut value {
        map.insert("description".to_owned(), json!(prop.desc));
    }
    value
}

/// The schema node for one [`Node`].
fn node(n: &Node) -> Value {
    match n {
        Node::Bool => json!({ "type": "boolean" }),
        Node::Str => json!({ "type": "string" }),
        Node::Int => json!({ "type": "integer", "minimum": 0 }),
        Node::Port => json!({ "type": "integer", "minimum": 0, "maximum": 65535 }),
        Node::StringEnum(values) => json!({ "type": "string", "enum": values }),
        Node::Array(inner) => json!({ "type": "array", "items": node(inner) }),
        Node::Map(inner) => json!({ "type": "object", "additionalProperties": node(inner) }),
        Node::Ref(name) => json!({ "$ref": format!("#/definitions/{name}") }),
        Node::OneOf(nodes) => json!({ "oneOf": nodes.iter().map(node).collect::<Vec<_>>() }),
        Node::Object(obj) => object_body(obj),
    }
}
