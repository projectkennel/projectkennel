//! `kennel-ssh-reorigin`: the SSH re-origination forced command (`docs/design/07-10-ssh.md` §7.10.4).
//!
//! # Role
//!
//! The per-kennel bastion (`kennel-sshd`) runs this — unprivileged, as the user — as
//! the forced `command=` bound to a synthetic key in the bastion's `authorized_keys`
//! (§7.10.3):
//!
//! ```text
//! restrict,pty,command="kennel-ssh-reorigin --dest github.com --key SHA256:<K>" <synthetic-pub>
//! ```
//!
//! Both `--dest` and `--key` are **baked in by `kenneld`**, not sent by the
//! workload: the destination is fixed by *which synthetic key authenticated*, so a
//! workload holding `synthetic-github` can only ever reach github with key K. This
//! binary then confirms the publickey auth (`$SSH_USER_AUTH`, exposed by sshd's
//! `ExposeAuthInfo`), selects the **real** key K from the user's own agent, and
//! re-execs a fresh `ssh` to the destination — `IdentitiesOnly` to that one key,
//! `StrictHostKeyChecking` against the bastion's host-side `known_hosts`. The
//! workload never holds a real key and cannot redirect the connection.
//!
//! # Trust model and why this is hardened anyway
//!
//! The forced command *is* the security boundary: sshd only runs this argv because
//! the matching synthetic key authenticated. So `--dest`/`--key` are trusted. But
//! `$SSH_ORIGINAL_COMMAND` is **attacker-controlled** (the workload chooses it), and
//! a bug that let a crafted value inject ssh options or a different destination would
//! defeat the whole design. So this crate treats every input as hostile: it
//! validates `--dest` and `--key` to strict grammars (no option-injection, no shell
//! metacharacters), refuses to run unless a *publickey* method authenticated, and
//! passes the destination with a `--` terminator so `$SSH_ORIGINAL_COMMAND` can never
//! be read as an ssh flag. The logic is pure and unit-tested; `main` is the thin IO
//! shell (run `ssh-add`, write the identity file, `execvp` ssh).
//!
//! # The host-side identity seam
//!
//! "Use key K from the user's store" is resolved against the **agent**: this lists
//! loaded public keys, matches the one whose fingerprint is K, and pins it. A key in
//! a file or a hardware token the user has added to their agent is reached the same
//! way; a key K that is *not* in the agent fails closed (the user must add it — there
//! is no fallback that would let an unintended key sign). This is the one place the
//! host-side custody model (§7.10.7) meets the tool, and it is deliberately explicit.

use std::fmt;

/// The maximum length of a DNS name (RFC 1035 §3.1).
const MAX_HOSTNAME: usize = 253;

/// Everything that can go wrong assembling the re-origination, as a refusal with a
/// reason. Every variant is fail-closed: on any error the bastion denies the session.
#[derive(Debug, PartialEq, Eq)]
pub enum ReoriginError {
    /// The forced-command argv was malformed (missing/duplicate/unknown flag).
    Args(String),
    /// `--dest` is not a syntactically valid, non-injecting hostname.
    Dest(String),
    /// `--key` is not a well-formed `SHA256:<base64>` fingerprint.
    Key(String),
    /// `$SSH_USER_AUTH` did not show a completed publickey authentication.
    Auth(String),
    /// The fingerprint K was not found among the agent's loaded keys.
    NoIdentity(String),
}

impl fmt::Display for ReoriginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Args(m) => write!(f, "malformed forced command: {m}"),
            Self::Dest(m) => write!(f, "invalid --dest: {m}"),
            Self::Key(m) => write!(f, "invalid --key: {m}"),
            Self::Auth(m) => write!(f, "publickey authentication not confirmed: {m}"),
            Self::NoIdentity(m) => write!(f, "no usable identity: {m}"),
        }
    }
}

impl std::error::Error for ReoriginError {}

/// A validated re-origination request: the fixed destination and the real key to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The destination host the bastion re-originates to (fixed by the forced command).
    pub dest: String,
    /// The real key's `SHA256:<base64>` fingerprint, selected host-side.
    pub key: String,
}

/// Parse and validate the forced-command argv (everything after the program name).
///
/// Accepts exactly `--dest <host> --key <SHA256:...>` in any order; rejects unknown
/// flags, duplicates, missing values, and values that begin with `-` (which would let
/// a value masquerade as a flag). Both values are then validated to their grammars.
///
/// # Errors
///
/// [`ReoriginError::Args`], [`ReoriginError::Dest`], or [`ReoriginError::Key`].
pub fn parse_args(args: &[String]) -> Result<Request, ReoriginError> {
    let mut dest: Option<String> = None;
    let mut key: Option<String> = None;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let slot = match flag.as_str() {
            "--dest" => &mut dest,
            "--key" => &mut key,
            other => return Err(ReoriginError::Args(format!("unknown argument `{other}`"))),
        };
        if slot.is_some() {
            return Err(ReoriginError::Args(format!(
                "`{flag}` given more than once"
            )));
        }
        let value = it
            .next()
            .ok_or_else(|| ReoriginError::Args(format!("`{flag}` needs a value")))?;
        // A value that looks like a flag is almost certainly an injection attempt or a
        // missing operand — refuse rather than let it bind as the next option.
        if value.starts_with('-') {
            return Err(ReoriginError::Args(format!(
                "`{flag}` value `{value}` looks like a flag"
            )));
        }
        *slot = Some(value.clone());
    }
    let dest = dest.ok_or_else(|| ReoriginError::Args("missing `--dest`".to_owned()))?;
    let key = key.ok_or_else(|| ReoriginError::Args("missing `--key`".to_owned()))?;
    validate_dest(&dest)?;
    validate_fingerprint(&key)?;
    Ok(Request { dest, key })
}

/// Validate `host` as a DNS hostname safe to hand to `ssh` as a positional argument.
///
/// Labels of `[A-Za-z0-9-]` separated by single dots, each 1–63 chars, no leading or
/// trailing hyphen on a label, total ≤253. This excludes every shell metacharacter,
/// whitespace, `@`/`:` (user/port smuggling), and a leading `-` (option injection) by
/// construction — the destination is fixed by policy, so a strict grammar costs
/// nothing and closes the injection surface.
///
/// # Errors
///
/// [`ReoriginError::Dest`] with the reason.
pub fn validate_dest(host: &str) -> Result<(), ReoriginError> {
    let bad = |m: &str| Err(ReoriginError::Dest(format!("{m}: `{host}`")));
    if host.is_empty() {
        return bad("empty");
    }
    if host.len() > MAX_HOSTNAME {
        return bad("longer than 253 characters");
    }
    for label in host.split('.') {
        if label.is_empty() {
            return bad("has an empty label (leading/trailing/double dot)");
        }
        if label.len() > 63 {
            return bad("has a label longer than 63 characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return bad("has a label with a leading or trailing hyphen");
        }
        if !label
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return bad("has a label with a character outside [A-Za-z0-9-]");
        }
    }
    Ok(())
}

/// Validate `fp` as an OpenSSH `SHA256:<base64>` key fingerprint.
///
/// The literal `SHA256:` followed by the unpadded standard-base64 of the 32-byte
/// digest — exactly 43 chars over `[A-Za-z0-9+/]`, the form `ssh-add -l` prints.
///
/// # Errors
///
/// [`ReoriginError::Key`] if the shape is wrong.
pub fn validate_fingerprint(fp: &str) -> Result<(), ReoriginError> {
    let b64 = fp
        .strip_prefix("SHA256:")
        .ok_or_else(|| ReoriginError::Key(format!("not a `SHA256:` fingerprint: `{fp}`")))?;
    if b64.len() != 43
        || !b64
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
    {
        return Err(ReoriginError::Key(format!("malformed digest in `{fp}`")));
    }
    Ok(())
}

/// The publickey that authenticated to the bastion, as read from `$SSH_USER_AUTH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthInfo {
    /// The key algorithm (`ssh-ed25519`, …) of the authenticating (synthetic) key.
    pub key_type: String,
    /// The base64 public-key blob of the authenticating (synthetic) key.
    pub key_blob: String,
}

/// Parse the contents of the `$SSH_USER_AUTH` file (`ExposeAuthInfo yes`).
///
/// The file holds one line per authentication method that succeeded, e.g.
/// `publickey ssh-ed25519 AAAA…`. Re-origination requires that a **publickey** method
/// completed; anything else (an empty file, `password`, `keyboard-interactive` only)
/// is refused. Returns the first publickey line's type and blob — the synthetic key
/// the bastion accepted, recorded for the audit trail.
///
/// # Errors
///
/// [`ReoriginError::Auth`] if no well-formed publickey line is present.
pub fn parse_user_auth(contents: &str) -> Result<AuthInfo, ReoriginError> {
    for line in contents.lines() {
        let mut f = line.split_whitespace();
        if f.next() != Some("publickey") {
            continue;
        }
        let (Some(key_type), Some(key_blob)) = (f.next(), f.next()) else {
            continue;
        };
        return Ok(AuthInfo {
            key_type: key_type.to_owned(),
            key_blob: key_blob.to_owned(),
        });
    }
    Err(ReoriginError::Auth(
        "no `publickey` line in $SSH_USER_AUTH".to_owned(),
    ))
}

/// One public key loaded in the agent: its fingerprint and its full public-key line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedKey {
    /// The key's `SHA256:<base64>` fingerprint (from `ssh-add -l` / `ssh-keygen -lf`).
    pub fingerprint: String,
    /// The full `ssh-ed25519 AAAA… comment` line (from `ssh-add -L`), to pin via `-i`.
    pub pubkey_line: String,
}

/// Select the loaded key whose fingerprint is exactly `want` (the real key K).
///
/// Exact fingerprint equality — no prefix or fuzzy match — so only the intended key
/// can ever be chosen. Returns its public-key line, which the caller writes to a file
/// and pins with `ssh -i … -o IdentitiesOnly=yes`.
///
/// # Errors
///
/// [`ReoriginError::NoIdentity`] if no loaded key matches (the user must add K to
/// their agent — there is no fallback that would let a different key sign).
pub fn select_identity<'a>(loaded: &'a [LoadedKey], want: &str) -> Result<&'a str, ReoriginError> {
    loaded
        .iter()
        .find(|k| k.fingerprint == want)
        .map(|k| k.pubkey_line.as_str())
        .ok_or_else(|| {
            ReoriginError::NoIdentity(format!("fingerprint `{want}` is not loaded in the agent"))
        })
}

/// Inputs for building the outbound `ssh` argv.
#[derive(Debug, Clone)]
pub struct Outbound<'a> {
    /// The validated destination host.
    pub dest: &'a str,
    /// Path to the file holding the selected public key (pinned via `-i`).
    pub identity_file: &'a str,
    /// The bastion's host-side `known_hosts` for the real destinations, if one is
    /// configured; the outbound connection is verified against it.
    pub known_hosts_file: Option<&'a str>,
    /// A `kenneld`-owned `ssh_config` for the outbound hop (`ssh -F`), if set. This
    /// is the host-side config seam (§7.10.7): `kenneld` controls per-destination
    /// `HostName`/`Port`/`ProxyJump` here, and the workload cannot influence it.
    /// `None` ⇒ `ssh` uses its defaults (the destination on `:22`).
    pub config_file: Option<&'a str>,
    /// `$SSH_ORIGINAL_COMMAND`, forwarded verbatim. `None`/empty ⇒ an interactive
    /// session (request a pty); a command ⇒ no pty.
    pub original_command: Option<&'a str>,
}

/// Build the argv for the outbound `ssh`, fail-closed against the selected key.
///
/// `IdentitiesOnly=yes` + a single `-i` pins exactly the chosen key (the agent offers
/// nothing else); `StrictHostKeyChecking=yes` fails closed if the destination's host
/// key is unknown; `--` terminates options so `$SSH_ORIGINAL_COMMAND`, attacker-
/// controlled, can never be read as a flag. A command is forwarded as a single
/// trailing argument; an empty/absent command requests a pty for an interactive shell.
#[must_use]
pub fn outbound_argv(o: &Outbound<'_>) -> Vec<String> {
    let interactive = o.original_command.is_none_or(str::is_empty);
    let mut argv = vec!["ssh".to_owned()];
    // Pty: force one for an interactive re-origination, suppress it for a command.
    argv.push(if interactive { "-tt" } else { "-T" }.to_owned());
    // A kenneld-owned config (if any) is applied first; the -o options below still
    // override it for the security-critical settings.
    if let Some(cfg) = o.config_file {
        argv.push("-F".to_owned());
        argv.push(cfg.to_owned());
    }
    argv.push("-o".to_owned());
    argv.push("IdentitiesOnly=yes".to_owned());
    argv.push("-o".to_owned());
    argv.push("StrictHostKeyChecking=yes".to_owned());
    if let Some(kh) = o.known_hosts_file {
        argv.push("-o".to_owned());
        argv.push(format!("UserKnownHostsFile={kh}"));
        // Ignore the system-wide store too; the bastion pins what it trusts.
        argv.push("-o".to_owned());
        argv.push("GlobalKnownHostsFile=/dev/null".to_owned());
    }
    argv.push("-i".to_owned());
    argv.push(o.identity_file.to_owned());
    argv.push("--".to_owned());
    argv.push(o.dest.to_owned());
    if let Some(cmd) = o.original_command {
        if !cmd.is_empty() {
            argv.push(cmd.to_owned());
        }
    }
    argv
}

/// Environment variables to unset before `exec`ing the outbound `ssh`.
///
/// The bastion-session variables must not leak into the re-originated connection:
/// `$SSH_ORIGINAL_COMMAND` has already been consumed (forwarded as an argument), and
/// the bastion's `$SSH_USER_AUTH`/connection variables describe the *inbound* hop, not
/// the outbound one. `$SSH_AUTH_SOCK` is deliberately **kept** — the agent is how the
/// real key signs host-side.
pub const SCRUB_ENV: &[&str] = &[
    "SSH_ORIGINAL_COMMAND",
    "SSH_USER_AUTH",
    "SSH_CONNECTION",
    "SSH_CLIENT",
    "SSH_TTY",
];

#[cfg(test)]
mod tests {
    use super::*;

    const K: &str = "SHA256:n0Vd5Bn8j3p2q1rStUvWxYzAbCdEfGhIjKlMnOpQrSt";

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parses_a_well_formed_forced_command() {
        let r = parse_args(&args(&["--dest", "github.com", "--key", K])).expect("parse");
        assert_eq!(r.dest, "github.com");
        assert_eq!(r.key, K);
        // Order-independent.
        let r2 = parse_args(&args(&["--key", K, "--dest", "github.com"])).expect("parse");
        assert_eq!(r, r2);
    }

    #[test]
    fn rejects_unknown_duplicate_and_missing_flags() {
        assert!(matches!(
            parse_args(&args(&["--evil", "x"])),
            Err(ReoriginError::Args(_))
        ));
        assert!(matches!(
            parse_args(&args(&["--dest", "a.com", "--dest", "b.com"])),
            Err(ReoriginError::Args(_))
        ));
        assert!(matches!(
            parse_args(&args(&["--dest"])),
            Err(ReoriginError::Args(_))
        ));
        assert!(matches!(
            parse_args(&args(&["--key", K])),
            Err(ReoriginError::Args(_))
        )); // no --dest
    }

    #[test]
    fn rejects_a_value_that_looks_like_a_flag() {
        // An option-injection attempt: --dest -oProxyCommand=...
        let err =
            parse_args(&args(&["--dest", "-oProxyCommand=evil", "--key", K])).expect_err("inject");
        assert!(matches!(err, ReoriginError::Args(_)));
    }

    #[test]
    fn dest_grammar_rejects_injection_and_smuggling() {
        for bad in [
            "",
            "-evil",         // leading hyphen
            "a b.com",       // whitespace
            "host;rm -rf",   // shell metachar
            "user@host",     // user smuggling
            "host:22",       // port smuggling
            "a..b.com",      // empty label
            "-a.com",        // label leading hyphen
            "a-.com",        // label trailing hyphen
            "evil$(whoami)", // command substitution
            "a/b",           // path
        ] {
            assert!(validate_dest(bad).is_err(), "expected `{bad}` rejected");
        }
        for good in [
            "github.com",
            "git.internal",
            "a",
            "x1-y2.example.co.uk",
            "host123",
        ] {
            assert!(validate_dest(good).is_ok(), "expected `{good}` accepted");
        }
    }

    #[test]
    fn fingerprint_grammar_matches_the_policy_layer() {
        assert!(validate_fingerprint(K).is_ok());
        for bad in [
            "github-key",
            "MD5:aa:bb",
            "SHA256:tooshort",
            "SHA256:has=pad+xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ] {
            assert!(
                validate_fingerprint(bad).is_err(),
                "expected `{bad}` rejected"
            );
        }
    }

    #[test]
    fn user_auth_requires_a_publickey_line() {
        let info = parse_user_auth("publickey ssh-ed25519 AAAABlob comment\n").expect("publickey");
        assert_eq!(info.key_type, "ssh-ed25519");
        assert_eq!(info.key_blob, "AAAABlob");
        // Fail closed: no publickey method present.
        assert!(matches!(parse_user_auth(""), Err(ReoriginError::Auth(_))));
        assert!(matches!(
            parse_user_auth("password\n"),
            Err(ReoriginError::Auth(_))
        ));
        assert!(matches!(
            parse_user_auth("keyboard-interactive\n"),
            Err(ReoriginError::Auth(_))
        ));
    }

    #[test]
    fn user_auth_reads_publickey_among_multiple_methods() {
        let info =
            parse_user_auth("keyboard-interactive\npublickey ssh-ed25519 AAAABlob\n").expect("pk");
        assert_eq!(info.key_blob, "AAAABlob");
    }

    #[test]
    fn identity_selection_is_exact() {
        let loaded = vec![
            LoadedKey {
                fingerprint: "SHA256:other".to_owned(),
                pubkey_line: "ssh-ed25519 OTHER".to_owned(),
            },
            LoadedKey {
                fingerprint: K.to_owned(),
                pubkey_line: "ssh-ed25519 WANTED real@host".to_owned(),
            },
        ];
        assert_eq!(
            select_identity(&loaded, K).expect("found"),
            "ssh-ed25519 WANTED real@host"
        );
        // A key not loaded fails closed — no fallback to a different key.
        assert!(matches!(
            select_identity(&loaded, "SHA256:absent"),
            Err(ReoriginError::NoIdentity(_))
        ));
        assert!(matches!(
            select_identity(&[], K),
            Err(ReoriginError::NoIdentity(_))
        ));
    }

    #[test]
    fn outbound_argv_pins_the_key_and_terminates_options() {
        let o = Outbound {
            dest: "github.com",
            identity_file: "/run/kennel/id.pub",
            known_hosts_file: Some("/etc/kennel/bastion_known_hosts"),
            config_file: Some("/run/kennel/ssh_config"),
            original_command: Some("git-receive-pack 'repo.git'"),
        };
        let argv = outbound_argv(&o);
        assert!(argv
            .windows(2)
            .any(|w| w.first().map(String::as_str) == Some("-F")
                && w.get(1).map(String::as_str) == Some("/run/kennel/ssh_config")));
        // The command is the single trailing element, after the `--` terminator.
        assert_eq!(
            argv.last().map(String::as_str),
            Some("git-receive-pack 'repo.git'")
        );
        let dd = argv.iter().position(|a| a == "--").expect("-- present");
        assert_eq!(
            argv.get(dd + 1).map(String::as_str),
            Some("github.com"),
            "dest right after --"
        );
        assert!(argv.iter().any(|a| a == "IdentitiesOnly=yes"));
        assert!(argv.iter().any(|a| a == "StrictHostKeyChecking=yes"));
        assert!(argv
            .windows(2)
            .any(|w| w.first().map(String::as_str) == Some("-i")
                && w.get(1).map(String::as_str) == Some("/run/kennel/id.pub")));
        assert!(argv
            .iter()
            .any(|a| a == "UserKnownHostsFile=/etc/kennel/bastion_known_hosts"));
        // A command suppresses the pty.
        assert!(argv.contains(&"-T".to_owned()));
        assert!(!argv.contains(&"-tt".to_owned()));
    }

    #[test]
    fn outbound_argv_requests_a_pty_for_an_interactive_session() {
        for cmd in [None, Some("")] {
            let o = Outbound {
                dest: "git.internal",
                identity_file: "/k.pub",
                known_hosts_file: None,
                config_file: None,
                original_command: cmd,
            };
            let argv = outbound_argv(&o);
            assert!(argv.contains(&"-tt".to_owned()), "interactive ⇒ force pty");
            // No trailing command, dest is last.
            assert_eq!(argv.last().map(String::as_str), Some("git.internal"));
        }
    }

    #[test]
    fn scrub_env_keeps_the_agent_socket() {
        assert!(SCRUB_ENV.contains(&"SSH_ORIGINAL_COMMAND"));
        assert!(SCRUB_ENV.contains(&"SSH_USER_AUTH"));
        assert!(
            !SCRUB_ENV.contains(&"SSH_AUTH_SOCK"),
            "the agent socket must survive to sign host-side"
        );
    }
}
