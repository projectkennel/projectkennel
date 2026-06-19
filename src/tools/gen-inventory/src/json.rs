//! A tiny hand-rolled JSON writer for the inventory artifact (std-only, no `serde_json`).
//!
//! Emits `crate-inventory.json` — the committed source of truth other tooling can read. Stable key
//! order + two-space indent so the file diffs cleanly in the CI regen check.

use crate::Inventory;
use std::fmt::Write as _;

/// Render the inventory as pretty JSON (trailing newline).
#[must_use]
pub fn render(inv: &Inventory) -> String {
    let mut s = String::new();
    // Writing to a `String` is infallible, so the `write!` results are discarded.
    let _ = writeln!(s, "{{");
    let _ = writeln!(s, "  \"crate_count\": {},", inv.crate_count);
    let _ = writeln!(s, "  \"total_sloc\": {},", inv.total_sloc);
    let _ = writeln!(s, "  \"tcb_crate_count\": {},", inv.tcb_count);
    let _ = writeln!(s, "  \"tcb_sloc\": {},", inv.tcb_sloc);
    let _ = writeln!(s, "  \"crates\": [");
    let last = inv.crates.len().saturating_sub(1);
    for (i, c) in inv.crates.iter().enumerate() {
        let _ = writeln!(s, "    {{");
        let _ = writeln!(s, "      \"name\": {},", quote(&c.name));
        let _ = writeln!(s, "      \"sloc\": {},", c.sloc);
        let _ = writeln!(s, "      \"uses_unsafe\": {},", c.uses_unsafe);
        let _ = writeln!(s, "      \"in_tcb\": {},", c.in_tcb);
        let _ = writeln!(s, "      \"bins\": {},", array(&c.bins));
        let _ = writeln!(s, "      \"consumers\": {},", array(&c.consumers));
        let _ = writeln!(s, "      \"first_party_deps\": {},", array(&c.fp_deps));
        let _ = writeln!(s, "      \"external_deps\": {}", array(&c.ext_deps));
        s.push_str("    }");
        s.push_str(if i < last { ",\n" } else { "\n" });
    }
    s.push_str("  ]\n");
    s.push_str("}\n");
    s
}

/// A JSON array of strings on one line: `["a", "b"]`.
fn array(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| quote(s)).collect();
    format!("[{}]", inner.join(", "))
}

/// A JSON string with the mandatory escapes.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::quote;

    #[test]
    fn quotes_and_escapes() {
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }
}
