//! `gen-inventory --json <path> [--doc <path>] [--crates <dir>]` — emit the crate inventory.
//!
//! Mirrors `gen-man`/`gen-schema`: a std-only generator run from CI. It computes the per-crate
//! SLOC / `unsafe` / TCB-membership / consumer / external-dep table from the workspace, writes the
//! `crate-inventory.json` source of truth, and (with `--doc`) rewrites the generated block in
//! `03-crate-decomposition.md`. CI runs it and `git diff --exit-code`s both outputs, so a
//! crate-graph change that is not regenerated fails the build.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut json: Option<String> = None;
    let mut doc: Option<String> = None;
    let mut crates = String::from("src/crates");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json = args.next(),
            "--doc" => doc = args.next(),
            "--crates" => {
                if let Some(v) = args.next() {
                    crates = v;
                }
            }
            "-h" | "--help" => {
                println!("usage: gen-inventory --json <path> [--doc <path>] [--crates <dir>]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("gen-inventory: unexpected argument `{other}`");
                return ExitCode::FAILURE;
            }
        }
    }
    let Some(json_path) = json else {
        eprintln!("gen-inventory: --json <path> is required");
        return ExitCode::FAILURE;
    };

    let inv = match gen_inventory::Inventory::compute(std::path::Path::new(&crates)) {
        Ok(inv) => inv,
        Err(e) => {
            eprintln!("gen-inventory: reading {crates}: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = std::fs::write(&json_path, gen_inventory::json::render(&inv)) {
        eprintln!("gen-inventory: writing {json_path}: {e}");
        return ExitCode::FAILURE;
    }

    if let Some(doc_path) = doc {
        let current = match std::fs::read_to_string(&doc_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("gen-inventory: reading {doc_path}: {e}");
                return ExitCode::FAILURE;
            }
        };
        let updated = gen_inventory::render::splice_into(&current, &inv);
        if let Err(e) = std::fs::write(&doc_path, updated) {
            eprintln!("gen-inventory: writing {doc_path}: {e}");
            return ExitCode::FAILURE;
        }
    }

    eprintln!(
        "gen-inventory: {} crates, {} SLOC ({} TCB / {} SLOC)",
        inv.crate_count, inv.total_sloc, inv.tcb_count, inv.tcb_sloc
    );
    ExitCode::SUCCESS
}
