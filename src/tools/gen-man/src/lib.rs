//! `gen_man` — the manpage data and the roff emitter.
//!
//! The binary (`main.rs`) is a thin CLI over this library. The library half exists
//! so the kenneld crate can dev-depend on [`pages::SYNC_COMMANDS`] /
//! [`pages::SYNC_POLICY`] in its CLI-sync test (dev-only; never linked into the
//! shipped daemon). Std-only: no third-party crates, no roff library.

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

    if !p.commands.is_empty() {
        section(&mut o, "COMMANDS");
        for c in p.commands {
            push_line(&mut o, ".TP");
            push_line(&mut o, &format!("\\fBkennel {}\\fR", esc(c.usage)));
            push_line(&mut o, &esc(c.summary));
            for (flag, desc) in c.options {
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
