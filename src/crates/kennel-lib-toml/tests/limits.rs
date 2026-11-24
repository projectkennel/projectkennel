//! The parser's resource limits: it runs on files before their signature is checked, so its cost
//! must not be set by the file.

type Doc = serde_json::Value;

fn parse(text: &str) -> Result<Doc, kennel_lib_toml::Error> {
    kennel_lib_toml::from_str(text)
}

#[test]
fn deep_nesting_is_an_error_not_a_stack_overflow() {
    // 64 levels parse; far more is refused (it used to recurse once per bracket).
    let ok = format!("a = {}{}\n", "[".repeat(64), "]".repeat(64));
    assert!(parse(&ok).is_ok(), "64 levels are within the limit");
    let deep = format!("a = {}{}\n", "[".repeat(100_000), "]".repeat(100_000));
    let err = parse(&deep).expect_err("refused");
    assert!(err.to_string().contains("nested"), "{err}");
    let tables = format!("a = {}1{}\n", "{ b = ".repeat(200), " }".repeat(200));
    assert!(parse(&tables).is_err(), "inline tables count too");
}

#[test]
fn too_many_tables_is_an_error() {
    let mut text = String::new();
    for i in 0..5000 {
        text.push_str("[t");
        text.push_str(&i.to_string());
        text.push_str("]\n");
    }
    let err = parse(&text).expect_err("refused");
    assert!(err.to_string().contains("tables"), "{err}");
}

#[test]
fn an_oversized_document_is_refused_before_parsing() {
    let big = format!("a = \"{}\"\n", "x".repeat(2 << 20));
    let err = parse(&big).expect_err("refused");
    assert!(err.to_string().contains("bytes"), "{err}");
}

#[test]
fn a_header_with_too_many_parts_is_an_error() {
    let header = format!("[{}]\n", vec!["a"; 100].join("."));
    assert!(parse(&header).is_err());
}

#[test]
fn a_dotted_key_with_too_many_parts_is_an_error_not_a_stack_overflow() {
    // Each part of a dotted key is one more level of table, and used to cost one recursion with
    // no bound: 100,000 parts (200 KB, well under the size cap) overflowed the stack.
    let ok = format!("{} = 1\n", vec!["a"; 60].join("."));
    assert!(parse(&ok).is_ok(), "60 parts are within the limit");
    let deep = format!("{} = 1\n", vec!["a"; 100_000].join("."));
    let err = parse(&deep).expect_err("refused");
    assert!(err.to_string().contains("nested"), "{err}");
    assert!(err.line_col().is_some(), "the error says where: {err}");
    let inline = format!("t = {{ {} = 1 }}\n", vec!["a"; 100_000].join("."));
    assert!(parse(&inline).is_err(), "inside an inline table too");
}

#[test]
fn dotted_keys_and_brackets_share_one_nesting_budget() {
    // 30 inline tables each reached through a four-part key are 120 levels, though neither the
    // brackets (30) nor any one key (4) is over the limit by itself.
    let text = format!("x = {}1{}\n", "{ a.b.c.d = ".repeat(30), " }".repeat(30));
    let err = parse(&text).expect_err("refused");
    assert!(err.to_string().contains("nested"), "{err}");
    let shallow = format!("x = {}1{}\n", "{ a.b.c.d = ".repeat(10), " }".repeat(10));
    assert!(parse(&shallow).is_ok(), "40 levels are within the limit");
}
