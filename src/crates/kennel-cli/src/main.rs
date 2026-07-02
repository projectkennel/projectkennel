//! `kennel-host` — the host-side execution unit of the `kennel` CLI.
//!
//! Installed at `/usr/libexec/kennel/host` and reached through the `kennel` shim (which
//! detects host-vs-cage context). Dispatches every operator verb — `run`, `attach`, `stop`,
//! `list`, `review`, `release`, `daemon-reload`, `policy`, `oci`, `keygen`,
//! `audit` — over the `kennel_cli` library crate.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use kennel_cli::{print_help, print_policy_help, usage_of, wants_help, COMMANDS, POLICY_VERBS};

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
    if cmd == "help" || cmd == "--help" || cmd == "-h" {
        print_help();
        return Ok(ExitCode::SUCCESS);
    }
    if cmd != "policy" && wants_help(rest) && COMMANDS.iter().any(|c| c.name == cmd) {
        println!("{}", usage_of(COMMANDS, cmd));
        return Ok(ExitCode::SUCCESS);
    }
    match cmd.as_str() {
        "run" => kennel_cli::run::run(rest),
        "attach" => kennel_cli::run::attach(rest),
        "review" => kennel_cli::review::review(rest),
        "release" => kennel_cli::review::release(rest),
        "oci" => kennel_cli::oci::dispatch(rest),
        "stop" => kennel_cli::runtime::stop(rest),
        "list" => kennel_cli::runtime::list(),
        "daemon-reload" => kennel_cli::runtime::daemon_reload(),
        "policy" => dispatch_policy(rest),
        "keygen" => kennel_cli::misc::keygen(rest),
        "audit" => kennel_cli::misc::audit(rest),
        other => Err(format!("unknown command `{other}` — run `kennel --help`")),
    }
}

fn dispatch_policy(args: &[String]) -> Result<ExitCode, String> {
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
        "inspect" => kennel_cli::policy::policy_inspect(rest),
        other => Err(format!(
            "unknown policy verb `{other}` — run `kennel policy --help`"
        )),
    }
}

#[cfg(test)]
mod tests {
    use kennel_cli::policy::{is_source_policy, policy_kind, TempSettled};
    use kennel_cli::{
        is_valid_policy_name, policy_name_from_path, resolve_policy, COMMANDS, POLICY_VERBS,
    };
    use std::path::Path;

    const BASE_CONFINED: &[u8] =
        include_bytes!("../../../../toml/templates/base-confined/policy.toml");

    #[test]
    fn a_template_is_detected_as_a_source_policy() {
        assert!(is_source_policy(BASE_CONFINED));
    }

    #[test]
    fn a_settled_document_is_not_a_source_policy() {
        let settled = br#"
settled_schema_version = 2
name = "demo"
[signature]
algorithm = "none"
key_id = ""
signature = ""
signed_fields = []
"#;
        assert!(!is_source_policy(settled));
    }

    #[test]
    fn policy_name_derives_from_the_path_shape() {
        assert_eq!(
            policy_name_from_path(Path::new("/c/policies/ai-coding/policy.toml")),
            "ai-coding"
        );
        assert_eq!(
            policy_name_from_path(Path::new("/c/policies/ai-coding/ai-coding.settled.toml")),
            "ai-coding"
        );
        assert_eq!(
            policy_name_from_path(Path::new("/tmp/demo.settled.toml")),
            "demo"
        );
        assert_eq!(policy_name_from_path(Path::new("/tmp/demo.toml")), "demo");
    }

    #[test]
    fn policy_kind_distinguishes_template_leaf_and_fragment() {
        let dir = std::env::temp_dir().join(format!("kennel-kind-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let write = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(&p, body).expect("write");
            p
        };
        let tmpl = write("t.toml", "template_name = \"x\"\n[exec]\nallow = []\n");
        assert_eq!(policy_kind(&tmpl), "template");
        let leaf_src = write("l.toml", "name = \"k\"\n[exec]\nallow = []\n");
        assert_eq!(policy_kind(&leaf_src), "leaf");
        let frag = write(
            "f.toml",
            "name = \"lang-x\"\n[[exec.allow.add]]\npath = \"/usr/bin/x\"\nreason = \"r\"\n",
        );
        assert_eq!(policy_kind(&frag), "fragment");
        let chained = write(
            "c.toml",
            "name = \"k\"\ntemplate_base = \"ai-coding-strict\"\n[[fs.read.add]]\npath = \"~/p/**\"\nreason = \"r\"\n",
        );
        assert_eq!(policy_kind(&chained), "leaf");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn policy_names_reject_traversal_and_separators() {
        assert!(is_valid_policy_name("ai-coding"));
        assert!(is_valid_policy_name("my_policy.v2"));
        assert!(!is_valid_policy_name(""));
        assert!(!is_valid_policy_name(".."));
        assert!(!is_valid_policy_name("a/b"));
        assert!(!is_valid_policy_name("../escape"));
        assert!(!is_valid_policy_name("has space"));
    }

    #[test]
    fn resolve_policy_uses_a_literal_path_verbatim() {
        let dir = std::env::temp_dir().join(format!("kennel-resolve-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("loose.settled.toml");
        std::fs::write(&file, b"x").expect("write");
        let (path, name) = resolve_policy(file.to_str().expect("utf8"), true).expect("resolve");
        assert_eq!(path, file);
        assert_eq!(name, "loose");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_policy_rejects_an_unknown_name() {
        let err = resolve_policy("definitely-no-such-policy-xyz", true).expect_err("must fail");
        assert!(err.contains("no policy named"), "got {err}");
    }

    #[test]
    fn temp_settled_is_removed_on_drop() {
        let path = {
            let temp = TempSettled::write("unit-test", b"x").expect("write temp");
            let p = temp.path().to_path_buf();
            assert!(p.exists(), "temp settled file should exist while held");
            p
        };
        assert!(
            !path.exists(),
            "temp settled file should be removed on drop"
        );
    }

    /// The manpage generator keeps its own copy of the command tables.
    #[test]
    fn man_pages_in_sync_with_cli_tables() {
        let live: Vec<(&str, &str, &str)> = COMMANDS
            .iter()
            .map(|c| (c.name, c.summary, c.usage))
            .collect();
        assert_eq!(
            live,
            gen_man::pages::SYNC_COMMANDS.to_vec(),
            "COMMANDS drifted from gen-man SYNC_COMMANDS — update src/tools/gen-man/src/pages.rs and regenerate man/"
        );

        let live_policy: Vec<(&str, &str, &str)> = POLICY_VERBS
            .iter()
            .map(|c| (c.name, c.summary, c.usage))
            .collect();
        assert_eq!(
            live_policy,
            gen_man::pages::SYNC_POLICY.to_vec(),
            "POLICY_VERBS drifted from gen-man SYNC_POLICY — update src/tools/gen-man/src/pages.rs and regenerate man/"
        );
    }
}
