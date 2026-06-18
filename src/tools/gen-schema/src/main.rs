//! `gen-schema --out <path>` — write the policy JSON Schema.
//!
//! Mirrors `gen-man`: a tiny std-only generator run from CI. CI emits to the in-tree
//! `schema/policy.toml.schema` and `git diff --exit-code`s the result, so a parser
//! change that is not reflected in [`gen_schema::model`] (and re-generated) fails the
//! build. Usage: `gen-schema --out schema/policy.toml.schema`.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut out: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => out = args.next(),
            "-h" | "--help" => {
                println!("usage: gen-schema --out <path>");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("gen-schema: unexpected argument `{other}` (usage: --out <path>)");
                return ExitCode::FAILURE;
            }
        }
    }
    let Some(path) = out else {
        eprintln!("gen-schema: --out <path> is required");
        return ExitCode::FAILURE;
    };

    let document = gen_schema::schema_document();
    if let Some(parent) = std::path::Path::new(&path).parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("gen-schema: could not create {}: {e}", parent.display());
                return ExitCode::FAILURE;
            }
        }
    }
    match std::fs::write(&path, document.as_bytes()) {
        Ok(()) => {
            eprintln!("gen-schema: wrote {path}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("gen-schema: could not write {path}: {e}");
            ExitCode::FAILURE
        }
    }
}
