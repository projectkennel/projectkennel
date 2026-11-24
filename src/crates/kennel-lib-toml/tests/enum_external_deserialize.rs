// SPDX-License-Identifier: Apache-2.0

// Upstream basic-toml 0.1.10 test, kept unchanged as the behavioural reference for the in-tree
// parser (#228); the workspace's test-code lints are relaxed for these upstream files alone.
#![allow(
    missing_docs,
    elided_lifetimes_in_paths,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]
#![allow(clippy::wildcard_imports)]

use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq)]
struct Struct {
    value: Enum,
}

#[derive(Debug, Deserialize, PartialEq)]
enum Enum {
    Variant,
}

#[test]
fn unknown_variant() {
    let error = kennel_lib_toml::from_str::<Struct>("value = \"NonExistent\"").unwrap_err();

    assert_eq!(
        error.to_string(),
        "unknown variant `NonExistent`, expected `Variant` for key `value` at line 1 column 1"
    );
}

#[test]
fn from_str() {
    let s = kennel_lib_toml::from_str::<Struct>("value = \"Variant\"").unwrap();

    assert_eq!(Enum::Variant, s.value);
}
