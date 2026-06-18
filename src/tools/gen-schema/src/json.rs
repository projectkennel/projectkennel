//! A minimal, std-only JSON value + pretty-printer.
//!
//! Just enough to emit a JSON Schema document deterministically (stable key order,
//! two-space indent, `\n`-terminated) so the generated `schema/policy.toml.schema` is
//! diffable and the CI no-drift check (`git diff --exit-code`) is meaningful. Object
//! keys preserve insertion order — the emitter controls ordering, not a hash map — so
//! the output is byte-stable across runs and platforms.

/// A JSON value. `Obj` keeps insertion order (a `Vec` of pairs, not a map) so the
/// emitted document is deterministic.
pub enum Json {
    /// A JSON string (escaped on write).
    Str(String),
    /// A JSON boolean.
    Bool(bool),
    /// A JSON integer (schema sizes/counts are always non-negative here).
    Int(u64),
    /// A JSON array.
    Arr(Vec<Self>),
    /// A JSON object, insertion-ordered.
    Obj(Vec<(String, Self)>),
}

impl Json {
    /// A string node from anything `Display`-ish.
    pub fn s(v: impl Into<String>) -> Self {
        Self::Str(v.into())
    }

    /// Serialise to a pretty-printed document with a trailing newline.
    #[must_use]
    pub fn to_pretty(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out.push('\n');
        out
    }

    fn write(&self, out: &mut String, indent: usize) {
        match self {
            Self::Str(s) => write_escaped(out, s),
            Self::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Self::Int(n) => out.push_str(&n.to_string()),
            Self::Arr(items) => write_seq(out, indent, '[', ']', items, |o, i, item| {
                item.write(o, i);
            }),
            Self::Obj(pairs) => write_seq(out, indent, '{', '}', pairs, |o, i, (k, v)| {
                write_escaped(o, k);
                o.push_str(": ");
                v.write(o, i);
            }),
        }
    }
}

/// Write a bracketed, comma-separated, indented sequence (`[]` or `{}`), empty as `[]`/`{}`.
fn write_seq<T>(
    out: &mut String,
    indent: usize,
    open: char,
    close: char,
    items: &[T],
    mut each: impl FnMut(&mut String, usize, &T),
) {
    if items.is_empty() {
        out.push(open);
        out.push(close);
        return;
    }
    out.push(open);
    out.push('\n');
    let inner = indent.saturating_add(1);
    for (i, item) in items.iter().enumerate() {
        push_indent(out, inner);
        each(out, inner, item);
        if i.saturating_add(1) < items.len() {
            out.push(',');
        }
        out.push('\n');
    }
    push_indent(out, indent);
    out.push(close);
}

fn push_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

/// Write `s` as a quoted JSON string with the mandatory escapes (RFC 8259).
fn write_escaped(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_orders_deterministically() {
        let v = Json::Obj(vec![
            ("b".to_owned(), Json::Int(1)),
            ("a".to_owned(), Json::s("x\"y")),
        ]);
        // Insertion order preserved (b before a); quote escaped; trailing newline.
        let out = v.to_pretty();
        assert_eq!(out, "{\n  \"b\": 1,\n  \"a\": \"x\\\"y\"\n}\n");
    }

    #[test]
    fn empty_containers_are_compact() {
        assert_eq!(Json::Arr(vec![]).to_pretty(), "[]\n");
        assert_eq!(Json::Obj(vec![]).to_pretty(), "{}\n");
    }
}
