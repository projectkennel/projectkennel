//! `gen_man` — the manpage data and the roff emitter.
//!
//! The binary (`main.rs`) is a thin CLI over this library. The `.1` command
//! synopses derive from the live `CommandSpec` tables in `kennel-lib-cli` (the
//! ones dispatch and `--help` read), so the pages cannot drift from the CLI.
//! No third-party crates, no roff library.

pub mod pages;

use pages::Page;

/// The `.TH` header's right-hand project field. Generation is reproducible (a CI
/// diff-check forbids a changing date), so the page carries the project, not a
/// build timestamp.
const PROJECT: &str = "Project Kennel";

/// Render one page to groff `man(7)` source.
#[must_use]
pub fn render(p: &Page) -> String {
    let mut o = String::new();
    let upper = p.name.to_uppercase();
    push_line(
        &mut o,
        &format!(
            ".TH \"{}\" \"{}\" \"\" \"{}\" \"{}\"",
            upper,
            p.section,
            PROJECT,
            section_title(p.section)
        ),
    );

    section(&mut o, "NAME");
    push_line(&mut o, &format!("{} \\- {}", esc(p.name), esc(p.summary)));

    section(&mut o, "SYNOPSIS");
    // The synopsis field is already roff (it carries \fB markup), so it is not escaped.
    push_line(&mut o, p.synopsis);

    section(&mut o, "DESCRIPTION");
    push_para(&mut o, p.description);

    let specs = p.command_source.specs();
    if !specs.is_empty() {
        section(&mut o, "COMMANDS");
        for spec in specs {
            push_line(&mut o, ".TP");
            push_line(&mut o, &format!("\\fBkennel {}\\fR", esc(spec.usage)));
            push_line(&mut o, &esc(spec.summary));
            let options = p
                .command_options
                .iter()
                .find(|(name, _)| *name == spec.name)
                .map_or(&[] as &[_], |(_, opts)| *opts);
            for (flag, desc) in options {
                push_line(&mut o, ".RS");
                push_line(&mut o, ".TP");
                push_line(&mut o, &format!("\\fB{}\\fR", esc(flag)));
                push_line(&mut o, &esc(desc));
                push_line(&mut o, ".RE");
            }
        }
    }

    for group in p.fields {
        if group.heading.is_empty() {
            section(&mut o, "FIELDS");
        } else {
            subsection(&mut o, group.heading);
        }
        if !group.intro.is_empty() {
            push_para(&mut o, group.intro);
        }
        for f in group.fields {
            push_line(&mut o, ".TP");
            push_line(
                &mut o,
                &format!("\\fB{}\\fR \\(em {}", esc(f.name), esc(f.kind)),
            );
            push_line(&mut o, &esc(f.desc));
        }
    }

    if !p.exit_status.is_empty() {
        section(&mut o, "EXIT STATUS");
        for (code, meaning) in p.exit_status {
            push_line(&mut o, ".TP");
            push_line(&mut o, &format!("\\fB{}\\fR", esc(code)));
            push_line(&mut o, &esc(meaning));
        }
    }

    if !p.files.is_empty() {
        section(&mut o, "FILES");
        for (path, meaning) in p.files {
            push_line(&mut o, ".TP");
            push_line(&mut o, &format!("\\fI{}\\fR", esc(path)));
            push_line(&mut o, &esc(meaning));
        }
    }

    if !p.examples.is_empty() {
        section(&mut o, "EXAMPLES");
        for (cmd, what) in p.examples {
            push_line(&mut o, ".TP");
            push_line(&mut o, &format!("\\fB{}\\fR", esc(cmd)));
            push_line(&mut o, &esc(what));
        }
    }

    if !p.see_also.is_empty() {
        section(&mut o, "SEE ALSO");
        let refs: Vec<String> = p.see_also.iter().map(|r| bold_ref(r)).collect();
        push_line(&mut o, &refs.join(", "));
    }

    o
}

/// Check one page's curated OPTIONS keys against its live command table.
///
/// A key naming no live verb (a renamed or removed command with stale curation)
/// is an error — the generation fails instead of silently dropping the rows.
///
/// # Errors
///
/// Returns a message naming the page and the stale key.
pub fn check_page_options(p: &Page) -> Result<(), String> {
    let specs = p.command_source.specs();
    for (name, _) in p.command_options {
        if !specs.iter().any(|s| s.name == *name) {
            return Err(format!(
                "{}.{}: OPTIONS are curated for `{name}`, which names no live command \
                 — update pages.rs to match the CLI tables",
                p.name, p.section
            ));
        }
    }
    Ok(())
}

/// [`check_page_options`] over every page.
///
/// # Errors
///
/// Returns the first stale-curation message.
pub fn check_pages() -> Result<(), String> {
    pages::PAGES.iter().try_for_each(check_page_options)
}

/// The right-hand manual title for a section number.
const fn section_title(section: u8) -> &'static str {
    match section {
        1 => "User Commands",
        5 => "File Formats",
        _ => "System Administration",
    }
}

/// `.SH` section header.
fn section(o: &mut String, name: &str) {
    push_line(o, &format!(".SH {name}"));
}

/// `.SS` subsection header.
fn subsection(o: &mut String, name: &str) {
    push_line(o, &format!(".SS {}", esc(name)));
}

/// Push one roff source line (always newline-terminated).
fn push_line(o: &mut String, line: &str) {
    o.push_str(line);
    o.push('\n');
}

/// Push free prose as one or more paragraphs (a blank source line → `.PP`).
fn push_para(o: &mut String, text: &str) {
    let mut first = true;
    for para in text.split("\n\n") {
        let para = para.trim();
        if para.is_empty() {
            continue;
        }
        if !first {
            push_line(o, ".PP");
        }
        first = false;
        // Collapse the readability wrapping; roff fills the paragraph itself.
        let joined = para
            .split('\n')
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(" ");
        push_line(o, &guard(&esc(&joined)));
    }
}

/// Escape text for roff: neutralise a literal `-` to `\-` so it renders as a
/// hyphen (not a typographic minus) and option flags copy-paste cleanly.
/// Intentional escapes already in the data (`\fB`, `\fR`, `\fI`, `\(em`) contain
/// no `-`, so they pass through untouched.
fn esc(s: &str) -> String {
    s.replace('-', "\\-")
}

/// Guard a line so a leading `.`/`'` is not taken as a roff request (`\&` is a
/// zero-width no-op).
fn guard(line: &str) -> String {
    if line.starts_with('.') || line.starts_with('\'') {
        format!("\\&{line}")
    } else {
        line.to_owned()
    }
}

/// Render a `name(section)` SEE ALSO reference with the name in bold.
fn bold_ref(r: &str) -> String {
    r.rsplit_once('(').map_or_else(
        || esc(r),
        |(name, sect)| format!("\\fB{}\\fR({}", esc(name), esc(sect)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pages::PAGES;

    #[test]
    fn every_page_renders_nonempty_with_required_sections() {
        for p in PAGES {
            let out = render(p);
            assert!(out.starts_with(".TH "), "{}: missing .TH", p.name);
            assert!(out.contains(".SH NAME"), "{}: missing NAME", p.name);
            assert!(out.contains(".SH SYNOPSIS"), "{}: missing SYNOPSIS", p.name);
            assert!(
                out.contains(".SH DESCRIPTION"),
                "{}: missing DESCRIPTION",
                p.name
            );
        }
    }

    /// The `.1` pages carry every live verb — the derivation, not a mirror: a verb
    /// added to the CLI tables appears on the page with no gen-man edit.
    #[test]
    fn command_pages_carry_every_live_verb() {
        for (page_name, specs) in [
            ("kennel", kennel_lib_cli::COMMANDS),
            ("kennel-policy", kennel_lib_cli::POLICY_VERBS),
        ] {
            let page = PAGES
                .iter()
                .find(|p| p.name == page_name && p.section == 1)
                .expect("the page exists");
            let out = render(page);
            for spec in specs {
                assert!(
                    out.contains(&esc(spec.usage)),
                    "{page_name}(1) is missing the `{}` synopsis",
                    spec.name
                );
            }
        }
    }

    /// Every curated OPTIONS key names a live verb (the shipped data passes its
    /// own stale-curation gate).
    #[test]
    fn shipped_option_curation_matches_the_live_tables() {
        check_pages().expect("no stale OPTIONS keys");
    }

    /// A curated key for a verb the tables no longer carry is a hard error.
    #[test]
    fn stale_option_key_is_a_generation_error() {
        let bogus = Page {
            name: "t",
            section: 1,
            summary: "t",
            synopsis: "t",
            description: "t",
            command_source: pages::CommandSource::TopLevel,
            command_options: &[("no-such-verb", &[])],
            fields: &[],
            exit_status: &[],
            files: &[],
            examples: &[],
            see_also: &[],
        };
        let err = check_page_options(&bogus).map_or_else(|e| e, |()| String::new());
        assert!(err.contains("no-such-verb"), "names the stale key: {err}");
    }

    #[test]
    fn hyphens_are_escaped_for_roff() {
        assert_eq!(esc("--key"), "\\-\\-key");
        assert_eq!(esc("plain"), "plain");
    }

    #[test]
    fn leading_dot_line_is_guarded() {
        assert_eq!(guard(".foo"), "\\&.foo");
        assert_eq!(guard("foo"), "foo");
    }

    #[test]
    fn see_also_reference_is_bold() {
        assert_eq!(bold_ref("kenneld(8)"), "\\fBkenneld\\fR(8)");
    }
}
