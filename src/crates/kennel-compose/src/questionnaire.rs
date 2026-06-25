// Capability questionnaire — the structured set of questions kennel-compose asks.
//
// In --no-prompts mode, all answers are defaults (maximally restrictive).
// In interactive mode, termion-based prompts guide the operator.

use crate::probe::ProbeResult;

/// The answers to the capability questionnaire.
pub struct Answers {
    /// The kennel name.
    pub name: String,
    /// Base template reference (e.g. "base-confined@v1").
    pub template_base: String,
    /// Include fragments (e.g. ["core-shell@v1", "vcs-git@v1"]).
    pub include: Vec<String>,
    /// Network mode: "none", or list of allowed destinations.
    pub net_allow: Vec<NetEntry>,
    /// Home directory write paths (e.g. "~/projects/myproj/**").
    pub home_write: Vec<String>,
    /// Whether Wayland display access is needed.
    pub wayland: bool,
    /// Whether audio playback access is needed.
    pub audio: bool,
    /// Whether SSH egress is needed.
    pub ssh: bool,
    /// TTL duration string (e.g. "30m").
    pub ttl: String,
}

/// A network allowlist entry.
pub struct NetEntry {
    pub name: String,
    pub ports: Vec<u16>,
    pub reason: String,
}

impl Answers {
    /// The maximally-restrictive defaults (for `--no-prompts`).
    pub fn defaults(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            template_base: "base-confined@v1".to_owned(),
            include: Vec::new(),
            net_allow: Vec::new(),
            home_write: Vec::new(),
            wayland: false,
            audio: false,
            ssh: false,
            ttl: "30m".to_owned(),
        }
    }
}

/// Ask the interactive questionnaire. Uses termion for styled prompts.
pub fn ask(name: &str, _probe: &ProbeResult) -> Result<Answers, String> {
    use std::io::{self, BufRead, Write};

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    let mut answers = Answers::defaults(name);

    // Template base.
    write!(stdout, "Base template [base-confined@v1]: ")
        .map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    stdin.lock().read_line(&mut line).map_err(|e| e.to_string())?;
    let trimmed = line.trim();
    if !trimmed.is_empty() {
        answers.template_base = trimmed.to_owned();
    }

    // Network.
    write!(stdout, "Network access? (y/N): ")
        .map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())?;
    line.clear();
    stdin.lock().read_line(&mut line).map_err(|e| e.to_string())?;
    if line.trim().eq_ignore_ascii_case("y") {
        write!(stdout, "  Allowed host (e.g. api.example.com, blank to finish): ")
            .map_err(|e| e.to_string())?;
        stdout.flush().map_err(|e| e.to_string())?;
        loop {
            line.clear();
            stdin.lock().read_line(&mut line).map_err(|e| e.to_string())?;
            let host = line.trim();
            if host.is_empty() {
                break;
            }
            answers.net_allow.push(NetEntry {
                name: host.to_owned(),
                ports: vec![443],
                reason: format!("operator-specified network destination"),
            });
            write!(stdout, "  Next host (blank to finish): ")
                .map_err(|e| e.to_string())?;
            stdout.flush().map_err(|e| e.to_string())?;
        }
    }

    // Home write.
    write!(stdout, "Home directory write path (e.g. ~/projects/myproj/**, blank for none): ")
        .map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())?;
    line.clear();
    stdin.lock().read_line(&mut line).map_err(|e| e.to_string())?;
    let home_path = line.trim();
    if !home_path.is_empty() {
        answers.home_write.push(home_path.to_owned());
    }

    // Wayland.
    answers.wayland = ask_yn(&stdin, &mut stdout, "Wayland display access? (y/N): ")?;

    // Audio.
    answers.audio = ask_yn(&stdin, &mut stdout, "Audio playback access? (y/N): ")?;

    // SSH.
    answers.ssh = ask_yn(&stdin, &mut stdout, "SSH egress? (y/N): ")?;

    // TTL.
    write!(stdout, "TTL [30m]: ")
        .map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())?;
    line.clear();
    stdin.lock().read_line(&mut line).map_err(|e| e.to_string())?;
    let ttl = line.trim();
    if !ttl.is_empty() {
        answers.ttl = ttl.to_owned();
    }

    Ok(answers)
}

fn ask_yn(
    stdin: &std::io::Stdin,
    stdout: &mut std::io::Stdout,
    prompt: &str,
) -> Result<bool, String> {
    use std::io::{BufRead, Write};
    write!(stdout, "{prompt}").map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    stdin.lock().read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line.trim().eq_ignore_ascii_case("y"))
}
