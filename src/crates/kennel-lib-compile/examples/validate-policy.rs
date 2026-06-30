//! Validation oracle for policy TOML: parse a file as a leaf or a template/source policy and
//! report success or the exact error. Used to prove the worked examples + templates in the docs
//! actually parse against the real schema (not eyeballed).
//!
//! Usage:
//!   cargo run -p kennel-lib-policy --example validate-policy -- leaf   <file.toml>
//!   cargo run -p kennel-lib-policy --example validate-policy -- source <file.toml>
//!
//! `leaf`   parses via `parse_source` + `SourcePolicy::validate` (a user's policy: needs `name` +
//!          `template_base`, every delta carries a reason).
//! `source` parses via `parse_source` (a template/fragment). A leaf and a template are the one
//!          `SourcePolicy` type now — list fields replace (bare sequence) or increment
//!          (`[[….add]]`) at the same key — so both kinds share the parser.
//! Exit 0 on success, 1 on any parse/validate error (printed to stderr).

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [kind, path] = args.as_slice() else {
        eprintln!("usage: validate-policy <leaf|source> <file.toml>");
        return ExitCode::from(2);
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let result: Result<(), String> = match kind.as_str() {
        "leaf" => kennel_lib_compile::parse_source(&bytes)
            .map_err(|e| e.to_string())
            .and_then(|leaf| leaf.validate().map_err(|e| e.to_string())),
        "source" => kennel_lib_compile::parse_source(&bytes)
            .map(|_| ())
            .map_err(|e| e.to_string()),
        other => {
            eprintln!("unknown kind `{other}` (expected `leaf` or `source`)");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => {
            println!("OK: {path} parses + validates as a {kind} policy");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FAIL: {path}: {e}");
            ExitCode::FAILURE
        }
    }
}
