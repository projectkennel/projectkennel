//! Shared CLI surface grammar for the unified `kennel` command (W10).
//!
//! One definition of the verb grammar the two execution units link — the host unit
//! (`/usr/libexec/kennel/host`) and the in-cage spawn unit (`/usr/libexec/kennel-facades/spawn`)
//! behind the `kennel` shim. An **overlapping verb is defined once here** (its name and
//! summary), so a command present in both contexts cannot drift in how it reads. A verb's
//! *operand* may still differ where the operation genuinely differs — `run` takes a policy
//! path host-side and a `template@version` + field patch in-cage — but the verb name, the
//! summary, and the `--`-separates-argv convention are one definition both sides spend.
//!
//! The surface is unification at the **interface** layer only: the two authority paths
//! (host-direct construction vs Node 0 `SPAWN`) stay distinct and separately validated.
//! Nothing in this crate touches enforcement.

#![forbid(unsafe_code)]

/// One CLI command, for both the top-level command list and its `--help`.
///
/// The single source of truth for a verb's surface: the help renders from these, so the
/// listing cannot drift from what dispatch actually accepts.
pub struct CommandSpec {
    /// The verb (`run`, `caps`, `policy`, …).
    pub name: &'static str,
    /// One-line summary for the command list.
    pub summary: &'static str,
    /// The full usage line (the program name is prepended when shown). Context-specific:
    /// a shared verb's operand legitimately differs between the host and in-cage units.
    pub usage: &'static str,
}

/// The `run` verb, present in **both** contexts.
///
/// Its name and summary are shared so the two surfaces cannot drift; only the usage operand
/// differs (a policy path host-side, a `template@version` + mutable-field patch in-cage). A unit
/// test in each execution unit pins its `run` entry to these constants, making the overlap a
/// structural guarantee.
pub const RUN: &str = "run";

/// The shared one-line summary for [`RUN`].
///
/// Phrased to cover both the host (policy) and the in-cage (template) operand, so the command list
/// reads the same in either context.
pub const RUN_SUMMARY: &str = "run a workload confined by a policy or template, in the foreground";

// ─── The host unit's command tables ──────────────────────────────────────────
//
// The live definition of the host-side `kennel` surface: dispatch, `--help`, and
// the generated man pages (`gen-man`) all read these tables, so a verb cannot
// exist in one and not the others. The in-cage spawn unit keeps its own (much
// smaller) table; the shared verbs pin to the constants above.

/// Top-level `kennel` commands (the unified help surface).
pub const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: RUN,
        summary: RUN_SUMMARY,
        usage: "run <policy> [<name>] [--force] [-- <cmd...>]",
    },
    CommandSpec {
        name: "attach",
        summary: "reattach a terminal to a running kennel (Ctrl-\\ d to detach)",
        usage: "attach <name>",
    },
    CommandSpec {
        name: "review",
        summary: "review a workspace's trust manifest: re-pin legitimate edits, or --revert tampering",
        usage: "review <policy> [--yes] [--revert]",
    },
    CommandSpec {
        name: "release",
        summary: "release a leaked exclusive over-mount (fs.exclusive crash recovery)",
        usage: "release <policy>",
    },
    CommandSpec {
        name: "stop",
        summary: "stop a running kennel",
        usage: "stop <name>",
    },
    CommandSpec {
        name: "list",
        summary: "list running kennels and the cross-kennel service mesh",
        usage: "list",
    },
    CommandSpec {
        name: "daemon-reload",
        summary: "re-derive the service catalogue from the enablement links",
        usage: "daemon-reload",
    },
    CommandSpec {
        name: "policy",
        summary: "author, inspect, and check runnable policies (the leaf house)",
        usage: "policy <list|show|edit|generate|clone|install|compile|validate|risks|diff|inspect> [...]",
    },
    CommandSpec {
        name: "template",
        summary: "inspect and sign shared base templates and fragments (the template house)",
        usage: "template <list|show|clone|install|sign|lint> [...]",
    },
    CommandSpec {
        name: "key",
        summary: "manage tier-bound signing keys (the key house)",
        usage: "key <generate|list|show|trust|untrust|rotate> [...]",
    },
    CommandSpec {
        name: "audit",
        summary: "show a kennel's audit log",
        usage: "audit <name> [--resource CLASS] [--since DUR] [--novel-only] [--follow] [--print-journalctl-command]",
    },
    CommandSpec {
        name: "oci",
        summary: "build and run an OCI image as a confined kennel substrate (§7.11)",
        usage: "oci <build|run|revert|update> <name> [--image <ref>] [--key K] [--force] [-- <cmd...>]",
    },
];

/// Sub-verbs of `kennel policy`.
pub const POLICY_VERBS: &[CommandSpec] = &[
    CommandSpec {
        name: "list",
        summary: "list policies in the search path",
        usage: "policy list",
    },
    CommandSpec {
        name: "show",
        summary: "show what a policy resolves to (the effective policy)",
        usage: "policy show <policy> [--template-dir D]... [--trust-dir D]...",
    },
    CommandSpec {
        name: "edit",
        summary: "edit a policy's source in $EDITOR",
        usage: "policy edit <name>",
    },
    CommandSpec {
        name: "generate",
        summary: "scaffold a new leaf policy",
        usage: "policy generate <name> [--from <template>]",
    },
    CommandSpec {
        name: "clone",
        summary: "fork a higher-tier policy's source into the user house (your copy, your key)",
        usage: "policy clone <name> [<new-name>] [--key K]",
    },
    CommandSpec {
        name: "install",
        summary: "place and sign a source policy at the invoking tier (receive, install, run)",
        usage: "policy install <file.toml> [--host] [--force] [--key K]",
    },
    CommandSpec {
        name: "compile",
        summary: "compile a source policy into a signed settled artefact",
        usage: "policy compile <policy> [--output P] [--key K | --unsigned] [--key-id ID] [--require-signed] [--no-lock] [--template-dir D]... [--trust-dir D]...",
    },
    CommandSpec {
        name: "validate",
        summary: "resolve and check a policy without writing an artefact",
        usage: "policy validate <policy> [--require-signed] [--template-dir D]... [--trust-dir D]...",
    },
    CommandSpec {
        name: "risks",
        summary: "evaluate a policy against the threat catalogue (exposures, residuals)",
        usage: "policy risks <policy> [--template-dir D]... [--trust-dir D]... [--json]",
    },
    CommandSpec {
        name: "diff",
        summary: "interpreted grant delta between a policy and its baseline (or another policy)",
        usage: "policy diff <policy> [<other>] [--template-dir D]... [--trust-dir D]... [--json]",
    },
    CommandSpec {
        name: "inspect",
        summary: "inspect grants in a settled policy (--unix: AF_UNIX sockets)",
        usage: "policy inspect <policy> --unix [--template-dir D]... [--trust-dir D]...",
    },
];

/// Sub-verbs of `kennel template` — the template house (shared bases and fragments; a
/// template is signed source others inherit, never a runnable policy).
pub const TEMPLATE_VERBS: &[CommandSpec] = &[
    CommandSpec {
        name: "list",
        summary: "list templates and fragments in the search path",
        usage: "template list",
    },
    CommandSpec {
        name: "show",
        summary: "show what a template resolves to (its effective floor)",
        usage: "template show <template> [--template-dir D]... [--trust-dir D]...",
    },
    CommandSpec {
        name: "clone",
        summary: "fork an unreserved template/fragment's source into the user house",
        usage: "template clone <name> [<new-name>] [--key K]",
    },
    CommandSpec {
        name: "install",
        summary: "place and sign a source template/fragment at the invoking tier",
        usage: "template install <file.toml> [--host] [--force] [--key K]",
    },
    CommandSpec {
        name: "sign",
        summary: "sign a source template or fragment (use `policy compile` for a policy you run)",
        usage: "template sign <template> --key <key> [--key-id <id>] [--output <path>]",
    },
    CommandSpec {
        name: "lint",
        summary: "check the shipped template corpus for incoherences",
        usage: "template lint [--template-dir D]... [--trust-dir D]...",
    },
];

/// Sub-verbs of `kennel key` — the key house (tier-bound signing-key management; a key's
/// tier is where it lives, and that is the only level it signs at).
pub const KEY_VERBS: &[CommandSpec] = &[
    CommandSpec {
        name: "generate",
        summary: "generate a signing key at the invoking tier (user; as root: host)",
        usage: "key generate <name> [--force]",
    },
    CommandSpec {
        name: "list",
        summary: "list keys across all tiers: name, tier, fingerprint, mine-vs-trusted",
        usage: "key list",
    },
    CommandSpec {
        name: "show",
        summary: "show a key's fingerprint and everything it signs across the repos",
        usage: "key show <name>",
    },
    CommandSpec {
        name: "trust",
        summary: "add a public key to the host trust store (root; host level only)",
        usage: "key trust <file.pub> [--force]",
    },
    CommandSpec {
        name: "untrust",
        summary: "remove a key from the host trust store, impact report first (root)",
        usage: "key untrust <name> [--yes]",
    },
    CommandSpec {
        name: "rotate",
        summary: "rotate a key: successor, re-sign what it signs, retire the old",
        usage: "key rotate <name> [--yes]",
    },
];

/// Render a command table as the aligned help body.
///
/// One `  verb  summary` line per command, in table order (the program name lives in the caller's
/// `usage:` header, not per line). Both units render their listing through this, so the help format
/// is identical across contexts.
#[must_use]
pub fn render_commands(commands: &[CommandSpec]) -> String {
    use std::fmt::Write as _;
    let width = commands.iter().map(|c| c.name.len()).max().unwrap_or(0);
    let mut out = String::new();
    for c in commands {
        let _ = writeln!(
            out,
            "  {name:<width$}  {summary}",
            name = c.name,
            summary = c.summary
        );
    }
    out
}

/// Split argv at the first bare `--`.
///
/// Everything before is the verb's own arguments, everything after is the workload command line —
/// the shared convention both contexts honour (`kennel run … -- <cmd>`). The tail is `None` when
/// there is no `--`, and `Some(&[])` for a trailing `--` with nothing after it.
#[must_use]
pub fn split_trailing_argv(args: &[String]) -> (&[String], Option<&[String]>) {
    args.iter()
        .position(|a| a == "--")
        .map_or((args, None), |i| {
            let (before, after) = args.split_at(i);
            (before, Some(after.get(1..).unwrap_or(&[])))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_trailing_argv_partitions_on_the_first_double_dash() {
        let args: Vec<String> = ["run", "p", "--", "ls", "-l"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let (before, after) = split_trailing_argv(&args);
        assert_eq!(before, ["run", "p"]);
        assert_eq!(after.expect("a trailing argv"), ["ls", "-l"]);
    }

    #[test]
    fn split_trailing_argv_no_double_dash_is_all_before() {
        let args: Vec<String> = vec!["caps".to_owned()];
        let (before, after) = split_trailing_argv(&args);
        assert_eq!(before, ["caps"]);
        assert!(after.is_none());
    }

    /// The `policy` command's usage line enumerates its sub-verbs by hand (a const
    /// string cannot be derived from the table); this pins the enumeration to the
    /// live [`POLICY_VERBS`] so adding a verb without listing it fails here.
    #[test]
    fn policy_usage_names_every_sub_verb() {
        let policy = COMMANDS
            .iter()
            .find(|c| c.name == "policy")
            .expect("a `policy` top-level command");
        for verb in POLICY_VERBS {
            assert!(
                policy.usage.contains(verb.name),
                "`policy` usage is missing sub-verb `{}`: {}",
                verb.name,
                policy.usage
            );
        }
    }

    /// Same pin for the `key` house: its usage line enumerates the live sub-verbs.
    #[test]
    fn key_usage_names_every_sub_verb() {
        let key = COMMANDS
            .iter()
            .find(|c| c.name == "key")
            .expect("a `key` top-level command");
        for verb in KEY_VERBS {
            assert!(
                key.usage.contains(verb.name),
                "`key` usage is missing sub-verb `{}`: {}",
                verb.name,
                key.usage
            );
        }
    }

    #[test]
    fn render_commands_aligns_the_verb_column() {
        let cmds = [
            CommandSpec {
                name: "run",
                summary: "run a thing",
                usage: "run <x>",
            },
            CommandSpec {
                name: "caps",
                summary: "show grant",
                usage: "caps",
            },
        ];
        let help = render_commands(&cmds);
        assert_eq!(help, "  run   run a thing\n  caps  show grant\n");
    }
}
