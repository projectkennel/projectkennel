// SPDX-License-Identifier: Apache-2.0

//! CRLF line endings inside multi-line strings.
//!
//! The tokenizer folds a CRLF pair into one line feed. Inside a multi-line string the value may
//! be a borrowed slice of the input, so the pair has to be taken out of it explicitly. A comment
//! in the tokenizer once said that branch could not be reached; these inputs reach it.

use std::collections::BTreeMap;

#[test]
fn a_crlf_inside_a_multi_line_string_reads_as_a_line_feed() {
    for (doc, want) in [
        // A basic multi-line string, and a literal one.
        ("a = \"\"\"x\r\ny\"\"\"\r\n", "x\ny"),
        ("a = '''x\r\ny'''\r\n", "x\ny"),
        // Two pairs, so the value is already owned at the second.
        ("a = \"\"\"x\r\ny\r\nz\"\"\"\r\n", "x\ny\nz"),
        // A line break straight after the opening delimiter is dropped, CRLF or LF.
        ("a = \"\"\"\r\nx\"\"\"\r\n", "x"),
        ("a = \"\"\"\nx\"\"\"\n", "x"),
        // The same text with bare line feeds reads the same.
        ("a = \"\"\"x\ny\"\"\"\n", "x\ny"),
    ] {
        let got: BTreeMap<String, String> = kennel_lib_toml::from_str(doc).expect(doc);
        assert_eq!(got.get("a").map(String::as_str), Some(want), "{doc:?}");
    }
}
