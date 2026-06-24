//! Shared CLI surface grammar for the unified `kennel` command (W10).
//!
//! One definition of the verb grammar the two execution units link — the host unit
//! (`/usr/libexec/kennel/host`) and the in-cage spawn unit (`/usr/libexec/kennel/spawn`)
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
