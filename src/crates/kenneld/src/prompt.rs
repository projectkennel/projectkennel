//! The daemon end of the operator-prompt channel (§9.7).
//!
//! kenneld is a daemon with no session of its own, so it cannot ask the operator a
//! question directly. But the `Start`/`Attach` control connection — owned by the
//! `run_kennel` thread, idle between [`Started`] and [`Exited`] — is a live, bidirectional
//! path to the attached CLI. A [`PromptPort`] is a clone of that connection handed to the
//! binder [`Lifecycle`](crate::binder::Lifecycle): a binder looper thread (kenneld's, not
//! the kennel's — never frozen) can write a [`Response::Prompt`] and block for the matching
//! [`Request::PromptReply`].
//!
//! The single caller today is the TTL `renew` prompt: when a kennel hits its deadline the
//! handler freezes the cgroup, asks the operator "renew?", and re-arms / terminates / falls
//! back on the answer. The `interactive` teardown disposition (W1/W2) will reuse the same
//! port unchanged.
//!
//! **Write-safety.** The port writes `Prompt` on the *same* socket `run_kennel` uses for
//! `Started`/`Exited`. These never interleave: `Started` is sent before the kennel can hit
//! its TTL, and a prompt is only issued while the cgroup is *frozen* — the workload cannot
//! exit frozen, so `Exited` cannot be sent until after the prompt transaction completes and
//! the kennel resumes or is killed. The freeze is the serialisation.
//!
//! [`Started`]: crate::control::Response::Started
//! [`Exited`]: crate::control::Response::Exited

use std::io;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crate::control::{self, Request, Response};

/// How long the daemon waits for an operator's answer before falling back. Generous —
/// an attached operator answers in seconds; this only bounds the "prompt shown, operator
/// walked away" case so a kennel cannot stay frozen indefinitely. On timeout the caller
/// takes its no-operator fallback (resume without renewing), never a kill.
const ANSWER_TIMEOUT: Duration = Duration::from_mins(5);

/// A clone of a kennel's control connection, used to ask the operator a question.
///
/// Cheap to clone (an `Arc`); carried by value in the binder
/// [`Lifecycle`](crate::binder::Lifecycle).
#[derive(Clone, Debug)]
pub struct PromptPort {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// A `try_clone` of the `Start`/`Attach` connection. Reads here see the CLI's
    /// `PromptReply` frames; `run_kennel` does not read the connection during the run, so
    /// there is no reader contention.
    conn: Mutex<UnixStream>,
    /// Correlates each `Prompt` with its `PromptReply`. A stale reply (wrong id) is
    /// ignored rather than mistaken for the answer.
    next_id: AtomicU32,
}

impl PromptPort {
    /// Build a port over `conn` — a `try_clone` of the live control connection.
    #[must_use]
    pub fn new(conn: UnixStream) -> Self {
        Self {
            inner: Arc::new(Inner {
                conn: Mutex::new(conn),
                next_id: AtomicU32::new(1),
            }),
        }
    }

    /// Ask the operator `prompt`; block for the answer.
    ///
    /// Returns `Some(true)` on an affirmative answer, `Some(false)` on a negative one, and
    /// `None` when no answer is obtainable — the CLI cannot prompt, the operator detached
    /// (EOF), the answer timed out, or any I/O error. The caller distinguishes "operator
    /// said no" (`Some(false)`) from "could not ask" (`None`): the first is an explicit
    /// decision, the second falls back to a safe default that never destroys the kennel.
    #[must_use]
    pub fn ask(&self, prompt: &str) -> Option<bool> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let mut conn = self.inner.conn.lock().ok()?;
        conn.set_read_timeout(Some(ANSWER_TIMEOUT)).ok()?;
        control::send_response(
            &mut *conn,
            &Response::Prompt {
                id,
                prompt: prompt.to_owned(),
            },
        )
        .ok()?;
        // Read until the reply matching this prompt's id; ignore any stray frame.
        loop {
            match control::recv_request(&mut *conn) {
                Ok(Request::PromptReply {
                    id: reply_id,
                    answer,
                }) if reply_id == id => {
                    return Some(affirmative(&answer));
                }
                Ok(_) => {} // a stale/unrelated frame — keep waiting for our id
                Err(_) => return None, // EOF, timeout, or malformed → no answer
            }
        }
    }
}

/// Whether an operator's free-text answer counts as yes. Conservative: only an explicit
/// affirmative is yes; anything else (including empty — the `[y/N]` default) is no.
fn affirmative(answer: &str) -> bool {
    matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes" | "renew"
    )
}

/// Build a port from a borrowed connection, cloning it. `None` if the clone fails.
///
/// # Errors
/// The OS error if `try_clone` fails.
pub fn from_conn(conn: &UnixStream) -> io::Result<PromptPort> {
    Ok(PromptPort::new(conn.try_clone()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn affirmative_is_explicit_yes_only() {
        for yes in ["y", "Y", "yes", "YES", " yes ", "renew", "Renew"] {
            assert!(affirmative(yes), "{yes:?} should be affirmative");
        }
        for no in ["n", "no", "", "  ", "nope", "later", "x", "yeah"] {
            assert!(!affirmative(no), "{no:?} should not be affirmative");
        }
    }

    #[test]
    fn ask_returns_the_operators_answer() {
        // A socketpair stands in for the control connection: one end is the port (daemon),
        // the other plays the CLI — read the Prompt, send a PromptReply with the same id.
        let (daemon_end, cli_end) = UnixStream::pair().expect("pair");
        let port = PromptPort::new(daemon_end);
        let cli = std::thread::spawn(move || {
            let mut cli_end = cli_end;
            let Response::Prompt { id, prompt } =
                control::recv_response(&mut cli_end).expect("recv prompt")
            else {
                unreachable!("expected a Prompt");
            };
            assert!(prompt.contains("renew"));
            control::send_request(
                &mut cli_end,
                &Request::PromptReply {
                    id,
                    answer: "y".to_owned(),
                },
            )
            .expect("send reply");
        });
        assert_eq!(
            port.ask("kennel 'x' reached its TTL — renew? [y/N]"),
            Some(true)
        );
        cli.join().expect("cli thread");
    }

    #[test]
    fn ask_is_none_when_the_operator_detaches() {
        // The CLI drops its end without answering → EOF → no answer (the safe fallback).
        let (daemon_end, cli_end) = UnixStream::pair().expect("pair");
        let port = PromptPort::new(daemon_end);
        drop(cli_end);
        assert_eq!(port.ask("renew?"), None);
    }

    #[test]
    fn ask_ignores_a_stale_reply_then_takes_the_matching_one() {
        let (daemon_end, cli_end) = UnixStream::pair().expect("pair");
        let port = PromptPort::new(daemon_end);
        let cli = std::thread::spawn(move || {
            let mut cli_end = cli_end;
            let Response::Prompt { id, .. } =
                control::recv_response(&mut cli_end).expect("recv prompt")
            else {
                unreachable!("expected a Prompt");
            };
            // A reply for the wrong id (a late answer to an earlier prompt) is ignored…
            control::send_request(
                &mut cli_end,
                &Request::PromptReply {
                    id: id.wrapping_sub(1),
                    answer: "y".to_owned(),
                },
            )
            .expect("send stale");
            // …then the real one lands.
            control::send_request(
                &mut cli_end,
                &Request::PromptReply {
                    id,
                    answer: "n".to_owned(),
                },
            )
            .expect("send real");
        });
        assert_eq!(port.ask("renew?"), Some(false));
        cli.join().expect("cli thread");
    }
}
