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
        return run_compose(&args);
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

/// Mode B: interactive policy composition from templates + fragments on the
/// deployed system.
///
/// Discovers templates and fragments from the live cascade:
///   ~/.config/kennel/templates/  →  /etc/kennel/templates/  →  /usr/lib/kennel/templates/
/// (same for fragments), then walks the operator through selection.
fn run_compose(args: &Args) -> ExitCode {
    use std::io::{self, BufRead, Write};

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    // Discover available templates and fragments from the live system.
    let available_templates = templates::discover_templates(&args.template_dirs);
    let available_fragments = templates::discover_fragments(&args.template_dirs);

    if available_templates.is_empty() && available_fragments.is_empty() {
        eprintln!("kennel-compose: no templates or fragments found in the search path");
        eprintln!("  searched: ~/.config/kennel/templates/, /etc/kennel/templates/, /usr/lib/kennel/templates/");
        for d in &args.template_dirs {
            eprintln!("  searched: {}", d.display());
        }
        eprintln!("  install kennel templates or use --template-dir to point at a template directory");
        return ExitCode::from(2);
    }

    // --- Step 1: pick a base template ---
    // Filter to templates that can serve as a base (those that derive from
    // base-confined or are base-confined itself, but not fragments).
    let base_candidates: Vec<&templates::TemplateEntry> = available_templates
        .iter()
        .filter(|t| !t.is_fragment)
        .collect();

    let selected_base = if base_candidates.is_empty() {
        eprintln!("kennel-compose: no base templates found — using base-confined@v1 (default)");
        "base-confined@v1".to_owned()
    } else {
        eprintln!("Available templates:\n");
        for (i, t) in base_candidates.iter().enumerate() {
            let marker = if t.name == "base-confined" { " (root)" } else { "" };
            eprintln!("  {:>2}. {:<30} {}{}", i + 1, t.reference(), t.description, marker);
        }
        eprintln!();
        write!(stdout, "Base template [1]: ").unwrap_or(());
        stdout.flush().unwrap_or(());
        let mut line = String::new();
        stdin.lock().read_line(&mut line).unwrap_or(0);
        let choice = line.trim();
        if choice.is_empty() {
            base_candidates.first().map(|t| t.reference()).unwrap_or_else(|| "base-confined@v1".to_owned())
        } else if let Ok(n) = choice.parse::<usize>() {
            if n >= 1 && n <= base_candidates.len() {
                base_candidates[n - 1].reference()
            } else {
                eprintln!("kennel-compose: invalid choice {n}");
                return ExitCode::from(2);
            }
        } else {
            // Treat as a literal template reference.
            choice.to_owned()
        }
    };

    // --- Step 2: pick fragments to include ---
    let selected_fragments = if available_fragments.is_empty() {
        eprintln!("No fragments found in the search path.");
        Vec::new()
    } else {
        eprintln!("\nAvailable fragments:\n");
        for (i, f) in available_fragments.iter().enumerate() {
            eprintln!("  {:>2}. {:<30} {}", i + 1, f.reference(), f.description);
        }
        eprintln!();
        write!(stdout, "Include fragments (comma-separated numbers, or blank for none): ").unwrap_or(());
        stdout.flush().unwrap_or(());
        let mut line = String::new();
        stdin.lock().read_line(&mut line).unwrap_or(0);
        let choices = line.trim();
        if choices.is_empty() {
            Vec::new()
        } else {
            let mut selected = Vec::new();
            for part in choices.split(',') {
                let part = part.trim();
                if let Ok(n) = part.parse::<usize>() {
                    if n >= 1 && n <= available_fragments.len() {
                        selected.push(available_fragments[n - 1].reference());
                    } else {
                        eprintln!("kennel-compose: ignoring invalid fragment number {n}");
                    }
                } else if !part.is_empty() {
                    // Treat as a literal fragment reference.
                    selected.push(part.to_owned());
                }
            }
            selected
        }
    };

    // --- Step 3: build a synthetic probe result (no binary to probe) ---
    let probe_result = probe::ProbeResult {
        workload: "(composed — no binary probed)".to_owned(),
        exec_allow: Vec::new(),
        extra_exec_path: Vec::new(),
        extra_fs_read: Vec::new(),
        is_script: false,
        interpreter_name: None,
        warnings: Vec::new(),
    };

    // --- Step 4: capability questionnaire ---
    let mut answers = match questionnaire::ask(&args.name, &probe_result) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("kennel-compose: {e}");
            return ExitCode::FAILURE;
        }
    };
    answers.template_base = selected_base;
    answers.include = selected_fragments;

    // --- Step 5: emit ---
    let policy_text = emit::render(&probe_result, &answers, &args.template_dirs, &args.trust_dirs);

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
    eprintln!();
    eprintln!("Template/fragment search path:");
    eprintln!("  ~/.config/kennel/templates/   (user)");
    eprintln!("  /etc/kennel/templates/        (system)");
    eprintln!("  /usr/lib/kennel/templates/    (vendor)");
    eprintln!("  (same pattern for fragments/)");
}
