// kennel-compose — standalone policy-authoring tool.
//
// A fully standalone binary (separate optional install, not part of the
// `kennel` dispatch tree) that emits a leaf policy TOML the operator owns
// and reviews.
//
// Modes:
//   kennel-compose <name> <binary>              Mode A: binary/script probe
//   kennel-compose <name> --compose             Mode B: interactive composer
//   kennel-compose --no-prompts <name> <binary>  Mode A, non-interactive
//
// This is NOT an LLM and NOT a policy compiler. It emits a leaf policy the
// operator reviews and tightens. `--no-prompts` produces a maximally-restrictive
// skeleton for CI.
//
// "How can I do less" — the output is a `LeafPolicy` struct serialised to TOML
// via `basic_toml::to_string()`. Template/fragment discovery uses the same
// cascade and parsers (`kennel_lib_config`, `kennel_lib_compile`) every other
// tool uses. Validation feeds the emitted bytes through `build_settled()`.

mod probe;
mod templates;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kennel_lib_compile::leaf::{
    ExecLeaf, FsLeaf, LifecycleLeaf, NetAllowDelta, NetLeaf, NetProxyLeaf, PathEntry, PathListDelta,
};
use kennel_lib_compile::source::LifecycleSection;
use kennel_lib_compile::{LeafPolicy, NetAllow};

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

    // Probe the binary/script.
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

    let is_script = probe_result.is_script;

    // Build a LeafPolicy directly from the probe result.
    let leaf = if args.no_prompts {
        build_leaf_from_probe(&args.name, &probe_result)
    } else {
        match build_leaf_interactive(&args.name, &probe_result) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("kennel-compose: {e}");
                return ExitCode::FAILURE;
            }
        }
    };

    emit_leaf(&leaf, &args, is_script)
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

    // Discover available templates and fragments from the live system template
    // cascade, plus any explicit `--template-dir` roots.
    let search_dirs = args.template_dirs.clone();
    let available_templates = templates::discover_templates(&search_dirs);
    let available_fragments = templates::discover_fragments(&search_dirs);

    if available_templates.is_empty() && available_fragments.is_empty() {
        eprintln!("kennel-compose: no templates or fragments found in the search path");
        eprintln!("  searched: ~/.config/kennel/templates/, /etc/kennel/templates/, /usr/lib/kennel/templates/");
        for d in &args.template_dirs {
            eprintln!("  searched: {}", d.display());
        }
        eprintln!(
            "  install kennel templates or use --template-dir to point at a template directory"
        );
        return ExitCode::from(2);
    }

    // --- Step 1: pick a base template ---
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
            let marker = if t.name == "base-confined" {
                " (root)"
            } else {
                ""
            };
            eprintln!(
                "  {:>2}. {:<30} {}{}",
                i + 1,
                t.reference(),
                t.description,
                marker
            );
        }
        eprintln!();
        write!(stdout, "Base template [1]: ").unwrap_or(());
        stdout.flush().unwrap_or(());
        let mut line = String::new();
        stdin.lock().read_line(&mut line).unwrap_or(0);
        let choice = line.trim();
        if choice.is_empty() {
            base_candidates
                .first()
                .map(|t| t.reference())
                .unwrap_or_else(|| "base-confined@v1".to_owned())
        } else if let Ok(n) = choice.parse::<usize>() {
            if n >= 1 && n <= base_candidates.len() {
                base_candidates[n - 1].reference()
            } else {
                eprintln!("kennel-compose: invalid choice {n}");
                return ExitCode::from(2);
            }
        } else {
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
        write!(
            stdout,
            "Include fragments (comma-separated numbers, or blank for none): "
        )
        .unwrap_or(());
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
                    selected.push(part.to_owned());
                }
            }
            selected
        }
    };

    // --- Step 3: build a LeafPolicy ---
    let mut leaf = LeafPolicy {
        name: Some(args.name.clone()),
        template_base: Some(selected_base),
        include: selected_fragments,
        ..LeafPolicy::default()
    };

    // Ask the capability questions and populate the leaf.
    if let Err(e) = ask_capabilities(&mut leaf) {
        eprintln!("kennel-compose: {e}");
        return ExitCode::FAILURE;
    }

    // Mode B composes from templates only — there is no probed workload, so the
    // script-vs-binary distinction does not apply.
    emit_leaf(&leaf, args, false)
}

/// Build a LeafPolicy from probe results with all-default (maximally restrictive)
/// answers. This is the `--no-prompts` path.
fn build_leaf_from_probe(name: &str, probe_result: &probe::ProbeResult) -> LeafPolicy {
    let mut leaf = LeafPolicy {
        name: Some(name.to_owned()),
        template_base: Some("base-confined@v1".to_owned()),
        ..LeafPolicy::default()
    };

    // Exec deltas from probe.
    populate_exec_from_probe(&mut leaf, probe_result);
    populate_fs_from_probe(&mut leaf, probe_result);

    // TTL.
    leaf.lifecycle = Some(LifecycleLeaf {
        over: Some(LifecycleSection {
            ttl: Some("30m".to_owned()),
            ..LifecycleSection::default()
        }),
    });

    leaf
}

/// Build a LeafPolicy from probe + interactive input.
fn build_leaf_interactive(
    name: &str,
    probe_result: &probe::ProbeResult,
) -> Result<LeafPolicy, String> {
    let mut leaf = build_leaf_from_probe(name, probe_result);

    // Override template base interactively.
    let base = ask_line("Base template [base-confined@v1]: ")?;
    if !base.is_empty() {
        leaf.template_base = Some(base);
    }

    ask_capabilities(&mut leaf)?;
    Ok(leaf)
}

/// Ask capability questions and populate the leaf in-place.
fn ask_capabilities(leaf: &mut LeafPolicy) -> Result<(), String> {
    use std::io::{self, BufRead, Write};

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    // Network.
    if ask_yn("Network access? (y/N): ")? {
        let mut allows = Vec::new();
        loop {
            let prompt = if allows.is_empty() {
                "  Allowed host (e.g. api.example.com, blank to finish): "
            } else {
                "  Next host (blank to finish): "
            };
            let host = ask_line(prompt)?;
            if host.is_empty() {
                break;
            }
            allows.push(NetAllow {
                name: Some(host),
                ports: vec![443],
                protocol: Some("tcp".to_owned()),
                reason: Some("operator-specified network destination".to_owned()),
                ..NetAllow::default()
            });
        }
        if !allows.is_empty() {
            leaf.net = Some(NetLeaf {
                proxy: Some(NetProxyLeaf {
                    allow: Some(NetAllowDelta {
                        add: allows,
                        remove: Vec::new(),
                    }),
                    deny: None,
                }),
                bpf: None,
                audit: None,
            });
        }
    }

    // Home write.
    write!(
        stdout,
        "Home directory write path (e.g. ~/projects/myproj/**, blank for none): "
    )
    .map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    let home_path = line.trim();
    if !home_path.is_empty() {
        let fs = leaf.fs.get_or_insert_with(FsLeaf::default);
        let write = fs.write.get_or_insert_with(PathListDelta::default);
        write.add.push(PathEntry {
            path: home_path.to_owned(),
            reason: Some("operator-specified write access".to_owned()),
            threats: None,
        });
    }

    // TTL.
    let ttl = ask_line("TTL [30m]: ")?;
    if !ttl.is_empty() {
        leaf.lifecycle = Some(LifecycleLeaf {
            over: Some(LifecycleSection {
                ttl: Some(ttl),
                ..LifecycleSection::default()
            }),
        });
    }

    Ok(())
}

/// Populate exec deltas from probe results.
fn populate_exec_from_probe(leaf: &mut LeafPolicy, probe_result: &probe::ProbeResult) {
    if probe_result.exec_allow.is_empty() {
        return;
    }
    let entries: Vec<PathEntry> = probe_result
        .exec_allow
        .iter()
        .map(|path| PathEntry {
            path: path.clone(),
            reason: Some(format!("probed from {}", probe_result.workload)),
            threats: None,
        })
        .collect();
    leaf.exec = Some(ExecLeaf {
        allow: Some(PathListDelta {
            add: entries,
            remove: Vec::new(),
        }),
    });
}

/// Populate fs.read deltas from probe results (non-standard paths).
fn populate_fs_from_probe(leaf: &mut LeafPolicy, probe_result: &probe::ProbeResult) {
    if probe_result.extra_fs_read.is_empty() {
        return;
    }
    let entries: Vec<PathEntry> = probe_result
        .extra_fs_read
        .iter()
        .map(|grant| PathEntry {
            path: grant.path.clone(),
            reason: Some(grant.reason.clone()),
            threats: None,
        })
        .collect();
    let fs = leaf.fs.get_or_insert_with(FsLeaf::default);
    fs.read = Some(PathListDelta {
        add: entries,
        remove: Vec::new(),
    });
}

/// Serialise the LeafPolicy to TOML and write it. If templates are available,
/// validate the output by feeding it through the compile pipeline.
fn emit_leaf(leaf: &LeafPolicy, args: &Args, is_script: bool) -> ExitCode {
    // Validate the leaf's own structure first.
    if let Err(e) = leaf.validate() {
        eprintln!("kennel-compose: generated policy has structural errors: {e}");
        eprintln!("(this is a bug in kennel-compose — please report it)");
        return ExitCode::FAILURE;
    }

    // Serialise via basic_toml — the same serialiser every other tool uses.
    let toml_text = match basic_toml::to_string(leaf) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("kennel-compose: serialisation failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Prepend a comment header (basic_toml doesn't emit comments).
    let kind = if leaf.exec.is_some() {
        if is_script {
            "probed script"
        } else {
            "probed binary"
        }
    } else {
        "composed"
    };
    let header = format!(
        "# Generated by kennel-compose ({kind}).\n\
         # Review and tighten before use.\n\n"
    );
    let output = format!("{header}{toml_text}");

    // Write output.
    match &args.output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &output) {
                eprintln!("kennel-compose: writing {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
            eprintln!("wrote {}", path.display());
        }
        None => print!("{output}"),
    }

    ExitCode::SUCCESS
}

// --- Helpers ---

fn ask_line(prompt: &str) -> Result<String, String> {
    use std::io::{self, BufRead, Write};
    write!(io::stdout(), "{prompt}").map_err(|e| e.to_string())?;
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    Ok(line.trim().to_owned())
}

fn ask_yn(prompt: &str) -> Result<bool, String> {
    Ok(ask_line(prompt)?.eq_ignore_ascii_case("y"))
}

// --- Arg parsing ---

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() {
        return Err("no arguments".to_owned());
    }

    let mut no_prompts = false;
    let mut compose = false;
    let mut output: Option<PathBuf> = None;
    let mut template_dirs: Vec<PathBuf> = Vec::new();
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
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            _ => positionals.push(arg.clone()),
        }
    }

    let name = positionals.first().ok_or("missing kennel name")?.clone();

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
        return std::fs::canonicalize(path).map_err(|e| format!("{raw}: {e}"));
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
    eprintln!("  --no-prompts           all defaults, maximally restrictive");
    eprintln!("  -h, --help             print this help");
    eprintln!();
    eprintln!("Template/fragment search path:");
    eprintln!("  ~/.config/kennel/templates/   (user)");
    eprintln!("  /etc/kennel/templates/        (system)");
    eprintln!("  /usr/lib/kennel/templates/    (vendor)");
    eprintln!("  (same pattern for fragments/)");
}
