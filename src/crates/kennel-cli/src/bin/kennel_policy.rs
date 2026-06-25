//! `kennel-policy` — the policy-authoring verb sub-binary (W10).
//!
//! Handles all `kennel policy <verb>` sub-verbs: compile, validate, sign, lint,
//! risks, diff, upgrade, show, edit, generate, list.
//! Installed at `/usr/libexec/kennel/policy`; reached through `kennel policy ...`.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use kennel_cli::{wants_help, usage_of, print_policy_help, POLICY_VERBS};

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
    let Some((verb, rest)) = args.split_first() else {
        print_policy_help();
        return Ok(ExitCode::SUCCESS);
    };
    if verb == "help" || verb == "--help" || verb == "-h" {
        print_policy_help();
        return Ok(ExitCode::SUCCESS);
    }
    if wants_help(rest) && POLICY_VERBS.iter().any(|c| c.name == verb) {
        println!("{}", usage_of(POLICY_VERBS, verb));
        return Ok(ExitCode::SUCCESS);
    }
    match verb.as_str() {
        "list" => kennel_cli::policy::policy_list(rest),
        "show" => kennel_cli::policy::policy_show(rest),
        "edit" => kennel_cli::policy::policy_edit(rest),
        "generate" => kennel_cli::policy::policy_generate(rest),
        "compile" => kennel_cli::policy::compile(rest),
        "validate" => kennel_cli::policy::validate(rest),
        "sign" => kennel_cli::policy::sign(rest),
        "lint" => kennel_cli::policy::policy_lint(rest),
        "risks" => kennel_cli::policy::policy_risks(rest),
        "diff" => kennel_cli::policy::policy_diff(rest),
        "upgrade" => kennel_cli::policy::upgrade(rest),
        other => Err(format!(
            "unknown policy verb `{other}` — run `kennel policy --help`"
        )),
    }
}
