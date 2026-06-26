//! `kennel-misc` — smaller verbs without their own binary yet (W10).
//!
//! Handles: `keygen`, `subkennel`, `audit`.
//! Installed at `/usr/libexec/kennel/misc`; reached through `kennel <verb>`.

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
        "keygen" => kennel_cli::misc::keygen(rest),
        "subkennel" => kennel_cli::misc::subkennel(rest),
        "audit" => kennel_cli::misc::audit(rest),
        other => Err(format!("unknown command `{other}` — run `kennel --help`")),
    }
}

fn print_help() {
    eprintln!("kennel-misc: keygen/subkennel/audit");
    eprintln!("  normally reached through `kennel <verb>`; direct invocation is for debugging.");
}
