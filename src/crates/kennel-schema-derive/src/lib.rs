//! `#[derive(SchemaType)]` — reflect a policy struct/enum into a `kennel-schema` node.
//!
//! A struct becomes a named object definition: each field's value schema is delegated to
//! that field's own `SchemaType` impl, its description is the field's doc-comment, and it
//! is required unless it is `Option<_>` or carries `#[serde(default)]`. A (unit-variant)
//! enum becomes a string `enum`, honouring `#[serde(rename)]` / `#[serde(rename_all)]`.
//!
//! Because every field delegates to its type, the schema is exactly the parser's shape —
//! the derive cannot describe a field the struct does not have.

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Expr, Fields, Lit, Meta, Type};

/// Derive `kennel_schema::SchemaType` for a policy struct or unit-variant enum.
#[proc_macro_derive(SchemaType, attributes(schema))]
pub fn derive_schema_type(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    match &input.data {
        Data::Struct(data) => derive_struct(&input, data).into(),
        Data::Enum(data) => derive_enum(&input, data).into(),
        Data::Union(_) => syn::Error::new_spanned(&input, "SchemaType: unions are not supported")
            .to_compile_error()
            .into(),
    }
}

/// A struct → a named object definition referenced by `$ref`.
fn derive_struct(input: &DeriveInput, data: &syn::DataStruct) -> proc_macro2::TokenStream {
    let ident = &input.ident;
    let def_name =
        schema_rename(&input.attrs).unwrap_or_else(|| default_def_name(&ident.to_string()));
    let title = first_doc_line(&input.attrs);
    let container_default = container_has_default(&input.attrs);

    let Fields::Named(named) = &data.fields else {
        return syn::Error::new_spanned(
            input,
            "SchemaType: only named-field structs are supported",
        )
        .to_compile_error();
    };

    let props = named.named.iter().map(|field| {
        let (rename, field_default) = serde_field(&field.attrs);
        let key = rename.unwrap_or_else(|| {
            strip_raw(
                &field
                    .ident
                    .as_ref()
                    .expect("named-field struct fields have idents")
                    .to_string(),
            )
        });
        let required = !is_option(&field.ty) && !field_default && !container_default;
        let desc = first_doc_line(&field.attrs);
        let ty = &field.ty;
        // A `String` field that authors a closed value set (kept `String` for authoring
        // leniency — aliases the strict enum rejects) sources its schema enum from the real
        // type via `#[schema(values_from = "path::Enum")]`, so the values are derived, not
        // hand-listed. Absent ⇒ delegate to the field's own type.
        let node = schema_values_from(&field.attrs).map_or_else(
            || quote! { <#ty as kennel_schema::SchemaType>::schema_node(defs) },
            |path| quote! { <#path as kennel_schema::SchemaType>::schema_node(defs) },
        );
        quote! {
            kennel_schema::Prop {
                key: #key.to_owned(),
                required: #required,
                desc: #desc.to_owned(),
                node: #node,
            }
        }
    });

    quote! {
        impl kennel_schema::SchemaType for #ident {
            fn schema_node(defs: &mut kennel_schema::Defs) -> kennel_schema::Node {
                defs.define(#def_name, |defs| kennel_schema::Obj {
                    title: #title.to_owned(),
                    props: vec![ #(#props),* ],
                })
            }
        }
    }
}

/// A unit-variant enum → an inline string `enum`.
fn derive_enum(input: &DeriveInput, data: &syn::DataEnum) -> proc_macro2::TokenStream {
    let ident = &input.ident;
    let rename_all = serde_rename_all(&input.attrs);

    let variants = data.variants.iter().map(|variant| {
        if !matches!(variant.fields, Fields::Unit) {
            return syn::Error::new_spanned(
                variant,
                "SchemaType: only unit enum variants are supported",
            )
            .to_compile_error();
        }
        let wire = variant_rename(&variant.attrs)
            .unwrap_or_else(|| apply_rename_all(&variant.ident.to_string(), rename_all.as_deref()));
        quote! { #wire.to_owned() }
    });

    quote! {
        impl kennel_schema::SchemaType for #ident {
            fn schema_node(_defs: &mut kennel_schema::Defs) -> kennel_schema::Node {
                kennel_schema::Node::StringEnum(vec![ #(#variants),* ])
            }
        }
    }
}

/// The first non-empty line of the item's `///` doc comment (one-line schema descriptions).
fn first_doc_line(attrs: &[syn::Attribute]) -> String {
    let mut lines = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("doc") {
            continue;
        }
        if let Meta::NameValue(nv) = &attr.meta {
            if let Expr::Lit(syn::ExprLit {
                lit: Lit::Str(s), ..
            }) = &nv.value
            {
                lines.push(s.value().trim().to_owned());
            }
        }
    }
    lines
        .iter()
        .find(|l| !l.is_empty())
        .cloned()
        .unwrap_or_default()
}

/// Read `#[serde(rename = "...")]` and whether the field carries `#[serde(default)]`.
fn serde_field(attrs: &[syn::Attribute]) -> (Option<String>, bool) {
    let mut rename = None;
    let mut has_default = false;
    for attr in attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename") {
                rename = Some(meta.value()?.parse::<syn::LitStr>()?.value());
            } else if meta.path.is_ident("default") {
                has_default = true;
                consume_optional_value(&meta)?;
            } else {
                consume_optional_value(&meta)?;
            }
            Ok(())
        });
    }
    (rename, has_default)
}

/// Whether the container carries `#[serde(default)]` (making every field optional).
fn container_has_default(attrs: &[syn::Attribute]) -> bool {
    let mut found = false;
    for attr in attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("default") {
                found = true;
            }
            consume_optional_value(&meta)
        });
    }
    found
}

/// Read a container-level `#[serde(rename_all = "...")]`.
fn serde_rename_all(attrs: &[syn::Attribute]) -> Option<String> {
    let mut rule = None;
    for attr in attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename_all") {
                rule = Some(meta.value()?.parse::<syn::LitStr>()?.value());
            } else {
                consume_optional_value(&meta)?;
            }
            Ok(())
        });
    }
    rule
}

/// Read a variant-level `#[serde(rename = "...")]`.
fn variant_rename(attrs: &[syn::Attribute]) -> Option<String> {
    serde_field(attrs).0
}

/// Read a field-level `#[schema(values_from = "path::Enum")]` — the type whose schema
/// node (a string `enum`) supplies this field's closed value set.
fn schema_values_from(attrs: &[syn::Attribute]) -> Option<syn::Path> {
    let mut path = None;
    for attr in attrs {
        if !attr.path().is_ident("schema") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("values_from") {
                let raw = meta.value()?.parse::<syn::LitStr>()?;
                path = raw.parse().ok();
            } else {
                consume_optional_value(&meta)?;
            }
            Ok(())
        });
    }
    path
}

/// Read a struct-level `#[schema(rename = "...")]` def-name override.
fn schema_rename(attrs: &[syn::Attribute]) -> Option<String> {
    let mut rename = None;
    for attr in attrs {
        if !attr.path().is_ident("schema") {
            continue;
        }
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename") {
                rename = Some(meta.value()?.parse::<syn::LitStr>()?.value());
            } else {
                consume_optional_value(&meta)?;
            }
            Ok(())
        });
    }
    rename
}

/// Consume an optional `= value` after a meta key, so unknown serde keys do not break parsing.
fn consume_optional_value(meta: &syn::meta::ParseNestedMeta<'_>) -> syn::Result<()> {
    if meta.input.peek(syn::Token![=]) {
        let _: Expr = meta.value()?.parse()?;
    }
    Ok(())
}

/// Whether the field type's outermost segment is `Option`.
fn is_option(ty: &Type) -> bool {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            return seg.ident == "Option";
        }
    }
    false
}

/// Strip a raw-identifier `r#` prefix (e.g. the `abstract` field key).
fn strip_raw(ident: &str) -> String {
    ident.strip_prefix("r#").unwrap_or(ident).to_owned()
}

/// Default def name: the type name in `snake_case` with a `Section`/`Envelope` suffix dropped.
fn default_def_name(ident: &str) -> String {
    let trimmed = ident
        .strip_suffix("Section")
        .or_else(|| ident.strip_suffix("Envelope"))
        .unwrap_or(ident);
    snake_case(trimmed)
}

/// Split a `PascalCase`/`camelCase` identifier into lowercase words.
fn camel_words(s: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    for ch in s.chars() {
        if ch.is_uppercase() && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        current.push(ch.to_ascii_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// `PascalCase` → `snake_case`.
fn snake_case(s: &str) -> String {
    camel_words(s).join("_")
}

/// Apply a serde `rename_all` rule to a variant identifier.
fn apply_rename_all(ident: &str, rule: Option<&str>) -> String {
    match rule {
        Some("lowercase") => ident.to_ascii_lowercase(),
        Some("UPPERCASE") => ident.to_ascii_uppercase(),
        Some("snake_case") => camel_words(ident).join("_"),
        Some("kebab-case") => camel_words(ident).join("-"),
        Some("SCREAMING_SNAKE_CASE") => camel_words(ident).join("_").to_ascii_uppercase(),
        _ => ident.to_owned(),
    }
}
