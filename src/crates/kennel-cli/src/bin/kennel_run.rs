//! `kennel-run` — the runtime verb sub-binary (W10).
//!
//! Handles: `run`, `attach`, `stop`, `list`, `review`, `release`, `daemon-reload`.
//! Installed at `/usr/libexec/kennel/run`; reached through the `kennel` shim.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use kennel_cli::{wants_help, usage_of, COMMANDS};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("kennel: {message}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(args: &[String]) -> Result<ExitCode, String> {
    let Some((cmd, rest)) = args.split_first() else {
        // Sub-binary invoked with no args — print the run-group help.
        print_help();
        return Ok(ExitCode::SUCCESS);
    };
    if cmd == "--help" || cmd == "-h" || cmd == "help" {
        print_help();
        return Ok(ExitCode::SUCCESS);
    }
    if wants_help(rest) {
        println!("{}", usage_of(COMMANDS, cmd));
        return Ok(ExitCode::SUCCESS);
    }
    match cmd.as_str() {
        "run" => kennel_cli::run::run(rest),
        "attach" => kennel_cli::run::attach(rest),
        "stop" => kennel_cli::runtime::stop(rest),
        "list" => kennel_cli::runtime::list(),
        "review" => kennel_cli::review::review(rest),
        "release" => kennel_cli::review::release(rest),
        "daemon-reload" => kennel_cli::runtime::daemon_reload(),
        other => Err(format!("unknown command `{other}` — run `kennel --help`")),
    }
}

fn print_help() {
    eprintln!("kennel-run: runtime commands (run/attach/stop/list/review/release/daemon-reload)");
    eprintln!("  normally reached through `kennel <verb>`; direct invocation is for debugging.");
}
