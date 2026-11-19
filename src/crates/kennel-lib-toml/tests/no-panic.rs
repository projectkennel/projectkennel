//! Robustness guard for the parser on the TCB path (#228): it must return a value or an `Error`
//! on any input, and never panic. Built from upstream's own fixtures: every prefix (on a char
//! boundary) of every valid and invalid document, plus a set of single-byte corruptions of each
//! valid one. Deserialising into `IgnoredAny` drives the whole parser without a target schema.

use serde::de::IgnoredAny;
use std::panic;
use std::path::Path;

fn fixtures(dir: &str) -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(dir);
    let mut out: Vec<(String, String)> = std::fs::read_dir(&root)
        .expect("fixture dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .map(|p| {
            let text = std::fs::read_to_string(&p).expect("utf-8 fixture");
            (p.display().to_string(), text)
        })
        .collect();
    out.sort();
    out
}

fn parse_never_panics(label: &str, input: &str) {
    let owned = input.to_owned();
    let r = panic::catch_unwind(move || {
        let _ = kennel_lib_toml::from_str::<IgnoredAny>(&owned);
        let _ = kennel_lib_toml::from_slice::<IgnoredAny>(owned.as_bytes());
    });
    assert!(r.is_ok(), "parser panicked on {label}: {input:?}");
}

#[test]
fn every_prefix_of_every_fixture_parses_without_panicking() {
    let mut cases = 0usize;
    for dir in ["valid", "invalid"] {
        for (name, text) in fixtures(dir) {
            for cut in (0..=text.len()).filter(|&i| text.is_char_boundary(i)) {
                parse_never_panics(&format!("{name}[..{cut}]"), text.get(..cut).unwrap_or(""));
                cases = cases.saturating_add(1);
            }
        }
    }
    assert!(
        cases > 1000,
        "the fixture corpus went missing ({cases} cases)"
    );
}

#[test]
fn single_byte_corruptions_of_valid_fixtures_parse_without_panicking() {
    // Bytes that change TOML structure: delimiters, quotes, escapes, comment/newline, separators.
    const SWAPS: &[u8] = b"[]{}\"'\\=.,#\n\r\t 0-+_";
    for (name, text) in fixtures("valid") {
        let bytes = text.as_bytes();
        // Every position, two substitutes each, rotating through SWAPS so every substitute is
        // used across the corpus (all 20 at every position is ~320k parses — too slow for CI).
        let picks = (0..bytes.len()).flat_map(|i| {
            [i, i.wrapping_mul(7).wrapping_add(3)]
                .map(|k| (i, SWAPS.get(k % SWAPS.len()).copied().unwrap_or(b' ')))
        });
        for (i, swap) in picks {
            let mut b = bytes.to_vec();
            if let Some(slot) = b.get_mut(i) {
                *slot = swap;
            }
            // from_slice must also cope with the non-UTF-8 result of a mid-codepoint swap.
            let r = panic::catch_unwind(|| {
                let _ = kennel_lib_toml::from_slice::<IgnoredAny>(&b);
            });
            assert!(
                r.is_ok(),
                "parser panicked on {name} with byte {i} = {swap:#04x}"
            );
        }
    }
}
