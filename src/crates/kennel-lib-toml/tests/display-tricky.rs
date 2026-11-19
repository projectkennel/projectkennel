// Upstream basic-toml 0.1.10 test, kept unchanged as the behavioural reference for the in-tree
// parser (#228); the workspace's test-code lints are relaxed for these upstream files alone.
#![allow(
    missing_docs,
    elided_lifetimes_in_paths,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Recipe {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub modules: Vec<Modules>,
    #[serde(default)]
    pub packages: Vec<Packages>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Modules {
    pub name: String,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Packages {
    pub name: String,
    pub version: Option<String>,
}

#[test]
fn both_ends() {
    let recipe_works = kennel_lib_toml::from_str::<Recipe>(
        r#"
        name = "testing"
        description = "example"
        modules = []

        [[packages]]
        name = "base"
    "#,
    )
    .unwrap();
    kennel_lib_toml::to_string(&recipe_works).unwrap();

    let recipe_fails = kennel_lib_toml::from_str::<Recipe>(
        r#"
        name = "testing"
        description = "example"
        packages = []

        [[modules]]
        name = "base"
    "#,
    )
    .unwrap();
    let err = kennel_lib_toml::to_string(&recipe_fails).unwrap_err();
    assert_eq!(err.to_string(), "values must be emitted before tables");
}
