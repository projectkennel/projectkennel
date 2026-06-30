//! Policy-schema IR and the [`SchemaType`] reflection trait.
//!
//! This is the *target* of the single-source schema: the `kennel-lib-compile` /
//! `kennel-lib-policy` source structs implement [`SchemaType`] (via the
//! `kennel-schema-derive` proc-macro, behind their `schema` feature), and the
//! `gen-schema` tool walks [`SchemaType::schema_node`] from the root policy struct to
//! emit `schema/policy.toml.schema`. Because the schema is *derived* from the parser
//! structs, the two cannot drift — there is no hand-kept mirror to keep in sync.
//!
//! Dependency-free: the IR is plain data; `gen-schema` renders it to JSON.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

/// One node of a JSON-Schema-shaped tree.
///
/// Scalars and arrays are inline; a named object is registered in [`Defs`] and referenced
/// by [`Node::Ref`], mirroring the published schema's `#/definitions/<name>` layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A boolean.
    Bool,
    /// A free string.
    Str,
    /// A non-negative integer (`minimum: 0`).
    Int,
    /// A TCP/UDP port (`integer`, `0..=65535`).
    Port,
    /// A string constrained to an explicit set of values (JSON Schema `enum`).
    StringEnum(Vec<String>),
    /// An array with the given item schema.
    Array(Box<Self>),
    /// An object of `string = <inner>` pairs (`additionalProperties`).
    Map(Box<Self>),
    /// A reference to a named object definition.
    Ref(String),
    /// An untagged union (the `Set | Delta` compose forms).
    OneOf(Vec<Self>),
    /// An inline anonymous object (the `{ add, remove }` delta table).
    Object(Obj),
}

/// A named or inline object: a title, its properties, and `additionalProperties: false`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Obj {
    /// One-line description (the type's doc-comment first line).
    pub title: String,
    /// The object's fields, in declaration order.
    pub props: Vec<Prop>,
}

/// One property of an [`Obj`]: key, required-ness, description, and value schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prop {
    /// The TOML key (after any `#[serde(rename)]`).
    pub key: String,
    /// Whether the field is mandatory (not `Option<_>` and no `#[serde(default)]`).
    pub required: bool,
    /// The field's doc-comment first line.
    pub desc: String,
    /// The value's schema.
    pub node: Node,
}

/// The accumulator of named object definitions, collected while walking the type graph.
///
/// Insertion order is preserved so the emitted `definitions` block is deterministic.
#[derive(Debug, Default)]
pub struct Defs {
    order: Vec<String>,
    tables: BTreeMap<String, Obj>,
}

impl Defs {
    /// A fresh, empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `name`'s object definition (building it once) and return a [`Node::Ref`] to it.
    ///
    /// A placeholder is inserted before `build` runs so a type that refers back to itself
    /// terminates instead of recursing forever.
    pub fn define(&mut self, name: &str, build: impl FnOnce(&mut Self) -> Obj) -> Node {
        if !self.tables.contains_key(name) {
            self.order.push(name.to_owned());
            self.tables.insert(name.to_owned(), Obj::default());
            let obj = build(self);
            self.tables.insert(name.to_owned(), obj);
        }
        Node::Ref(name.to_owned())
    }

    /// Take the named object out of the collector (used to lift the root inline).
    #[must_use]
    pub fn take(&mut self, name: &str) -> Option<Obj> {
        self.order.retain(|n| n != name);
        self.tables.remove(name)
    }

    /// The registered definitions in insertion order.
    #[must_use]
    pub fn into_ordered(self) -> Vec<(String, Obj)> {
        let mut out = Vec::with_capacity(self.order.len());
        let mut tables = self.tables;
        for name in self.order {
            if let Some(obj) = tables.remove(&name) {
                out.push((name, obj));
            }
        }
        out
    }
}

/// A type that can describe its own JSON-Schema node — the single-source reflection hook.
///
/// Implemented for the std leaf types here, for the two untagged compose enums by hand in
/// `kennel-lib-compile`, and for every policy struct/enum by `#[derive(SchemaType)]`.
pub trait SchemaType {
    /// This type's schema node, registering any named object definitions into `defs`.
    fn schema_node(defs: &mut Defs) -> Node;
}

impl SchemaType for String {
    fn schema_node(_defs: &mut Defs) -> Node {
        Node::Str
    }
}

impl SchemaType for bool {
    fn schema_node(_defs: &mut Defs) -> Node {
        Node::Bool
    }
}

impl SchemaType for u16 {
    fn schema_node(_defs: &mut Defs) -> Node {
        Node::Port
    }
}

macro_rules! impl_int {
    ($($t:ty),*) => {$(
        impl SchemaType for $t {
            fn schema_node(_defs: &mut Defs) -> Node { Node::Int }
        }
    )*};
}
impl_int!(u32, u64, usize, i32, i64);

impl<T: SchemaType> SchemaType for Vec<T> {
    fn schema_node(defs: &mut Defs) -> Node {
        Node::Array(Box::new(T::schema_node(defs)))
    }
}

impl<T: SchemaType> SchemaType for Option<T> {
    fn schema_node(defs: &mut Defs) -> Node {
        T::schema_node(defs)
    }
}

impl<V: SchemaType> SchemaType for BTreeMap<String, V> {
    fn schema_node(defs: &mut Defs) -> Node {
        Node::Map(Box::new(V::schema_node(defs)))
    }
}
