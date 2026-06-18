//! Emit the [`model`](crate::model) as a JSON Schema (draft-07) document.
//!
//! The top table (`policy`) becomes the root object; every other table becomes a
//! `#/definitions/<name>` entry referenced by `$ref`. `additionalProperties: false` on
//! every object mirrors the parser's `#[serde(deny_unknown_fields)]`, so the schema is
//! the same allowlist the compiler enforces.

use crate::json::Json;
use crate::model::{Field, Table, Ty, TABLES};

/// The canonical published schema id (the website/editors fetch it here).
pub const SCHEMA_ID: &str = "https://projectkennel.org/schema/policy.toml.schema.json";

/// Render the whole policy schema as a pretty-printed JSON document (trailing newline).
#[must_use]
pub fn schema_document() -> String {
    let mut top = object_body(crate::model::root());

    // Definitions for every non-root table, in declaration order.
    let defs: Vec<(String, Json)> = TABLES
        .iter()
        .skip(1)
        .map(|t| (t.name.to_owned(), Json::Obj(object_body(t))))
        .collect();

    // Prepend the document-level keywords, then the root object body, then definitions.
    let mut doc: Vec<(String, Json)> = vec![
        (
            "$schema".to_owned(),
            Json::s("http://json-schema.org/draft-07/schema#"),
        ),
        ("$id".to_owned(), Json::s(SCHEMA_ID)),
        ("title".to_owned(), Json::s("Project Kennel policy")),
    ];
    doc.append(&mut top);
    doc.push(("definitions".to_owned(), Json::Obj(defs)));
    Json::Obj(doc).to_pretty()
}

/// The object body for one table: `description`, `type`, `additionalProperties: false`,
/// `properties`, and (if any) `required`.
fn object_body(table: &Table) -> Vec<(String, Json)> {
    let props: Vec<(String, Json)> = table
        .fields
        .iter()
        .map(|field| (field.key.to_owned(), property(field)))
        .collect();

    let required: Vec<Json> = table
        .fields
        .iter()
        .filter(|f| f.required)
        .map(|f| Json::s(f.key))
        .collect();

    let mut body = vec![
        ("description".to_owned(), Json::s(table.title)),
        ("type".to_owned(), Json::s("object")),
        ("additionalProperties".to_owned(), Json::Bool(false)),
        ("properties".to_owned(), Json::Obj(props)),
    ];
    if !required.is_empty() {
        body.push(("required".to_owned(), Json::Arr(required)));
    }
    body
}

/// The schema node for one field's value, carrying its `description`.
fn property(field: &Field) -> Json {
    let desc = (field.key, field.desc);
    match &field.ty {
        Ty::Str => scalar(desc, "string", vec![]),
        Ty::Enum(values) => scalar(
            desc,
            "string",
            vec![(
                "enum".to_owned(),
                Json::Arr(values.iter().map(|v| Json::s(*v)).collect()),
            )],
        ),
        Ty::Bool => scalar(desc, "boolean", vec![]),
        Ty::Int => scalar(desc, "integer", vec![("minimum".to_owned(), Json::Int(0))]),
        Ty::Port => scalar(desc, "integer", port_bounds()),
        Ty::StrArray => array(
            desc,
            Json::Obj(vec![("type".to_owned(), Json::s("string"))]),
        ),
        Ty::PortArray => array(
            desc,
            Json::Obj(
                std::iter::once(("type".to_owned(), Json::s("integer")))
                    .chain(port_bounds())
                    .collect(),
            ),
        ),
        Ty::Map => scalar(
            desc,
            "object",
            vec![(
                "additionalProperties".to_owned(),
                Json::Obj(vec![("type".to_owned(), Json::s("string"))]),
            )],
        ),
        // A `$ref` ignores sibling validation keywords in draft-07, so wrap it in `allOf`
        // to keep the field-site description as an annotation alongside the reference.
        Ty::Obj(name) => Json::Obj(vec![
            ("description".to_owned(), Json::s(field.desc)),
            ("allOf".to_owned(), Json::Arr(vec![ref_to(name)])),
        ]),
        // The `$ref` is nested under `items`, so `description`/`type` coexist with it.
        Ty::ObjArray(name) => array(desc, ref_to(name)),
    }
}

/// A scalar schema node: `description`, `type`, plus any extra keywords (enum, bounds).
fn scalar(desc: (&str, &str), ty: &str, extra: Vec<(String, Json)>) -> Json {
    let mut node = vec![
        ("description".to_owned(), Json::s(desc.1)),
        ("type".to_owned(), Json::s(ty)),
    ];
    node.extend(extra);
    Json::Obj(node)
}

/// An array schema node with the given `items` schema and the field's description.
fn array(desc: (&str, &str), items: Json) -> Json {
    Json::Obj(vec![
        ("description".to_owned(), Json::s(desc.1)),
        ("type".to_owned(), Json::s("array")),
        ("items".to_owned(), items),
    ])
}

/// `{"$ref": "#/definitions/<name>"}`.
fn ref_to(name: &str) -> Json {
    Json::Obj(vec![(
        "$ref".to_owned(),
        Json::s(format!("#/definitions/{name}")),
    )])
}

/// The `minimum`/`maximum` keywords bounding a `u16` port.
fn port_bounds() -> Vec<(String, Json)> {
    vec![
        ("minimum".to_owned(), Json::Int(0)),
        ("maximum".to_owned(), Json::Int(65535)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_is_wellformed_draft07() {
        let doc = schema_document();
        assert!(doc.starts_with("{\n  \"$schema\": \"http://json-schema.org/draft-07/schema#\""));
        assert!(doc.contains("\"definitions\""));
        // The root mirrors deny_unknown_fields.
        assert!(doc.contains("\"additionalProperties\": false"));
        // A representative ref + a port bound made it in.
        assert!(doc.contains("\"#/definitions/exec\""));
        assert!(doc.contains("\"maximum\": 65535"));
        assert!(doc.ends_with("}\n"));
    }
}
