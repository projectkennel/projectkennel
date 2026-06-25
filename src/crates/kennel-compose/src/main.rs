// kennel-compose — standalone policy-authoring tool (W9).
//
// A fully standalone binary (separate optional install, no runtime dependency,
// not part of the `kennel` dispatch tree) that emits a source policy TOML the
// operator owns and reviews.
//
// Modes:
//   kennel-compose <name> <binary>              Mode A: binary/script probe
//   kennel-compose <name> --compose             Mode B: interactive composer
//   kennel-compose --no-prompts <name> <binary>  Mode A, non-interactive
//
// This is NOT an LLM and NOT a policy compiler. It emits a leaf policy the
// operator reviews and tightens. `--no-prompts` produces a maximally-restrictive
// skeleton for CI.

mod emit;
mod probe;
mod questionnaire;
mod templates;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Parsed command-line arguments.
struct Args {
    /// The kennel name (required positional — becomes `name = "…"` in the policy).
    name: String,
    /// Mode A: the binary/script to probe (resolved to an absolute path).
    binary: Option<PathBuf>,
    /// Mode B: `--compose` (interactive template/fragment selection).
    compose: bool,
    /// Non-interactive mode: all defaults, maximally restrictive.
    no_prompts: bool,
    /// Output file (default: stdout).
    output: Option<PathBuf>,
    /// Additional template search directories.
    template_dirs: Vec<PathBuf>,
    /// Additional trust-store directories.
    trust_dirs: Vec<PathBuf>,
}

fn main() -> ExitCode {
    match parse_args() {
        Ok(args) => run(args),
        Err(e) => {
            eprintln!("kennel-compose: {e}");
            eprintln!();
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn run(args: Args) -> ExitCode {
    if args.compose {
        eprintln!("kennel-compose: --compose mode is not yet implemented");
        return ExitCode::from(2);
    }

    let binary = match &args.binary {
        Some(b) => b,
        None => {
            eprintln!("kennel-compose: no binary specified (use --compose for interactive mode)");
            return ExitCode::from(2);
        }
    };

    // Phase 2: probe the binary/script.
    let probe_result = match probe::probe(binary) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("kennel-compose: probe failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    for warning in &probe_result.warnings {
        eprintln!("warning: {warning}");
    }

    // Phase 3: capability questionnaire.
    let answers = if args.no_prompts {
        questionnaire::Answers::defaults(&args.name)
    } else {
        match questionnaire::ask(&args.name, &probe_result) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("kennel-compose: {e}");
                return ExitCode::FAILURE;
            }
        }
    };

    // Phase 4: emit the policy TOML.
    let policy_text = emit::render(&probe_result, &answers, &args.template_dirs, &args.trust_dirs);

    // Write output.
    match &args.output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &policy_text) {
                eprintln!("kennel-compose: writing {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
            eprintln!("wrote {}", path.display());
        }
        None => print!("{policy_text}"),
    }

    ExitCode::SUCCESS
}

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() {
        return Err("no arguments".to_owned());
    }

    let mut no_prompts = false;
    let mut compose = false;
    let mut output: Option<PathBuf> = None;
    let mut template_dirs: Vec<PathBuf> = Vec::new();
    let mut trust_dirs: Vec<PathBuf> = Vec::new();
    let mut positionals: Vec<String> = Vec::new();

    let mut it = raw.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--no-prompts" => no_prompts = true,
            "--compose" => compose = true,
            "--output" => {
                output = Some(it.next().ok_or("--output needs a value")?.into());
            }
            "--template-dir" => {
                template_dirs.push(it.next().ok_or("--template-dir needs a value")?.into());
            }
            "--trust-dir" => {
                trust_dirs.push(it.next().ok_or("--trust-dir needs a value")?.into());
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            _ => positionals.push(arg.clone()),
        }
    }

    // First positional is always the kennel name.
    let name = positionals
        .first()
        .ok_or("missing kennel name")?
        .clone();

    // In --compose mode, no binary is needed.
    let binary = if compose {
        if positionals.len() > 1 {
            return Err("--compose does not take a binary argument".to_owned());
        }
        None
    } else {
        let raw_binary = positionals
            .get(1)
            .ok_or("missing binary path (or use --compose)")?;
        Some(resolve_binary(raw_binary)?)
    };

    if positionals.len() > 2 {
        return Err("too many positional arguments".to_owned());
    }

    Ok(Args {
        name,
        binary,
        compose,
        no_prompts,
        output,
        template_dirs,
        trust_dirs,
    })
}

/// Resolve a binary argument to an absolute path.
///
/// - Absolute paths are used as-is.
/// - Relative paths (starting with `.` or `..`) are resolved against CWD.
/// - Bare names (no `/`) are searched via `$PATH` (like `which`).
fn resolve_binary(raw: &str) -> Result<PathBuf, String> {
    let path = Path::new(raw);

    if path.is_absolute() {
        if !path.exists() {
            return Err(format!("{raw}: not found"));
        }
        return Ok(path.to_owned());
    }

    // Relative path (contains `/` — e.g. `./run.sh`, `../scripts/app.py`).
    if raw.contains('/') {
        return std::fs::canonicalize(path)
            .map_err(|e| format!("{raw}: {e}"));
    }

    // Bare name — search $PATH.
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = Path::new(dir).join(raw);
        if candidate.is_file() {
            return std::fs::canonicalize(&candidate)
                .map_err(|e| format!("{}: {e}", candidate.display()));
        }
    }

    Err(format!("`{raw}` not found on $PATH"))
}

fn print_usage() {
    eprintln!("usage: kennel-compose <name> <binary>              probe a binary/script");
    eprintln!("       kennel-compose <name> --compose             interactive composer");
    eprintln!("       kennel-compose --no-prompts <name> <binary> non-interactive (CI)");
    eprintln!();
    eprintln!("options:");
    eprintln!("  --output <path>        write to file (default: stdout)");
    eprintln!("  --template-dir <dir>   additional template search directory");
    eprintln!("  --trust-dir <dir>      additional trust-store directory");
    eprintln!("  --no-prompts           all defaults, maximally restrictive");
    eprintln!("  -h, --help             print this help");
}
