//! The server side of the D-Bus SASL authentication handshake (§7.7.2).
//!
//! Before any D-Bus message flows, a client opens with a single NUL byte and then a
//! line-based SASL exchange (D-Bus spec, "Authentication protocol"). `facade-dbus` is the
//! *server* of that exchange for the workload's bus connection: it terminates the connection
//! in the kennel, so the SASL identity is not a trust boundary — the facade already speaks
//! only for the workload (§7.7.2). It accepts `EXTERNAL` and `ANONYMOUS`, declines unix-fd
//! negotiation (out of scope for the mediated path), and on `BEGIN` hands the rest of the
//! buffer to the binary message loop.
//!
//! # Trust
//!
//! The auth bytes are fully workload-controlled, so [`SaslServer::push`] is an untrusted-input
//! parser: it is line-bounded ([`MAX_LINE`]), never panics, and is fuzzed (CODING-STANDARDS
//! §10.6). It is ASCII-only command matching — not the D-Bus binary grammar (that is
//! `mini-sansio-dbus`, driven by [`crate::server`]).

/// The largest SASL line we accept. The D-Bus spec caps auth lines at 16 KiB; a line longer
/// than this from the client is a protocol error, refused without unbounded buffering.
pub const MAX_LINE: usize = 16 * 1024;

/// A fixed server GUID reported in the `OK` response. The GUID identifies the server end of
/// the connection; D-Bus does not require it to be unique for correct operation, and the
/// facade is a per-kennel server with no cross-connection identity to expose.
const SERVER_GUID: &str = "00000000000000000000000000000000";

/// The outcome of feeding bytes to the [`SaslServer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Auth is still in progress: write `reply` to the client and feed more bytes. `reply`
    /// may be empty if only a partial line has arrived.
    Continue {
        /// The bytes to write back to the client (possibly empty).
        reply: Vec<u8>,
    },
    /// The client sent `BEGIN`: write `reply`, then the binary message protocol starts.
    Begin {
        /// Any final response bytes to write before the binary phase (usually empty —
        /// `OK` was sent on the prior `AUTH` line).
        reply: Vec<u8>,
        /// Bytes already received after `BEGIN\r\n` — the first of the message stream.
        leftover: Vec<u8>,
    },
}

/// A SASL protocol violation. The connection is dropped on any of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslError {
    /// A line exceeded [`MAX_LINE`] without a terminator.
    LineTooLong,
    /// The client sent `BEGIN` before authenticating.
    BeginBeforeAuth,
    /// A non-UTF-8 / non-ASCII byte appeared in an auth line.
    NotAscii,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Awaiting the initial NUL byte that opens the auth conversation.
    WaitNul,
    /// In the line-based exchange, not yet authenticated.
    Unauthed,
    /// Authenticated (an `OK` was sent); awaiting `BEGIN` / `NEGOTIATE_UNIX_FD`.
    Authed,
}

/// The server-side SASL state machine for one workload bus connection. Sans-IO: feed it the
/// bytes read off the socket with [`SaslServer::push`] and write back the replies it returns.
#[derive(Debug)]
pub struct SaslServer {
    phase: Phase,
    line: Vec<u8>,
}

impl Default for SaslServer {
    fn default() -> Self {
        Self::new()
    }
}

impl SaslServer {
    /// A fresh handshake awaiting the client's opening NUL byte.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: Phase::WaitNul,
            line: Vec::new(),
        }
    }

    /// Feed bytes received from the client. Accumulates partial lines internally and
    /// processes each complete `\r\n`-terminated command, returning the bytes to write back
    /// and whether the binary phase has begun.
    ///
    /// # Errors
    ///
    /// Returns [`SaslError`] on a protocol violation; the caller drops the connection.
    pub fn push(&mut self, data: &[u8]) -> Result<Outcome, SaslError> {
        let mut input = data;

        // The connection opens with a single NUL byte before any line.
        if self.phase == Phase::WaitNul {
            let Some((first, rest)) = input.split_first() else {
                return Ok(Outcome::Continue { reply: Vec::new() });
            };
            if *first != 0 {
                // Some clients omit nothing; the spec mandates the NUL. A non-NUL opener is
                // a protocol error — but be lenient only insofar as treating it as auth data
                // would; we require the NUL.
                return Err(SaslError::NotAscii);
            }
            self.phase = Phase::Unauthed;
            input = rest;
        }

        let mut reply = Vec::new();
        for &byte in input {
            if self.line.len() >= MAX_LINE {
                return Err(SaslError::LineTooLong);
            }
            self.line.push(byte);
            if self.line.ends_with(b"\r\n") {
                let line_len = self.line.len().saturating_sub(2);
                let line_bytes = self.line.get(..line_len).unwrap_or(&[]);
                let command = core::str::from_utf8(line_bytes).map_err(|_| SaslError::NotAscii)?;
                let command = command.to_owned();
                self.line.clear();
                match self.handle(&command, &mut reply)? {
                    LineResult::Continue => {}
                    LineResult::Begin => {
                        // Everything after this `BEGIN\r\n` in the current push is the first
                        // of the binary message stream; hand it back as leftover.
                        return Ok(Outcome::Begin {
                            reply,
                            leftover: drain_after_begin(input, &command),
                        });
                    }
                }
            }
        }
        Ok(Outcome::Continue { reply })
    }

    /// Handle one complete command line, appending any response to `reply`.
    fn handle(&mut self, command: &str, reply: &mut Vec<u8>) -> Result<LineResult, SaslError> {
        // Commands are `KEYWORD [args]`; matching is on the keyword.
        let keyword = command.split(' ').next().unwrap_or("");
        match keyword {
            "AUTH" => {
                let mech = command.split(' ').nth(1).unwrap_or("");
                match mech {
                    "EXTERNAL" | "ANONYMOUS" => {
                        // Accept: the SASL identity is not a trust boundary here (§7.7.2).
                        reply.extend_from_slice(b"OK ");
                        reply.extend_from_slice(SERVER_GUID.as_bytes());
                        reply.extend_from_slice(b"\r\n");
                        self.phase = Phase::Authed;
                    }
                    _ => {
                        // No mechanism, or one we do not offer: list what we support.
                        reply.extend_from_slice(b"REJECTED EXTERNAL ANONYMOUS\r\n");
                    }
                }
                Ok(LineResult::Continue)
            }
            "NEGOTIATE_UNIX_FD" => {
                // Decline fd passing on the mediated path (out of scope, §7.7 phase 3).
                reply.extend_from_slice(b"ERROR unix fd passing not available\r\n");
                Ok(LineResult::Continue)
            }
            "CANCEL" => {
                reply.extend_from_slice(b"REJECTED EXTERNAL ANONYMOUS\r\n");
                self.phase = Phase::Unauthed;
                Ok(LineResult::Continue)
            }
            "BEGIN" => {
                if self.phase == Phase::Authed {
                    Ok(LineResult::Begin)
                } else {
                    Err(SaslError::BeginBeforeAuth)
                }
            }
            "ERROR" => {
                reply.extend_from_slice(b"REJECTED EXTERNAL ANONYMOUS\r\n");
                Ok(LineResult::Continue)
            }
            // Unknown command: the spec says reply ERROR and continue.
            _ => {
                reply.extend_from_slice(b"ERROR unknown command\r\n");
                Ok(LineResult::Continue)
            }
        }
    }
}

enum LineResult {
    Continue,
    Begin,
}

/// The binary-stream bytes that arrived in the same push after `BEGIN\r\n`: find the BEGIN
/// line (plus its terminator) in `input` and return everything past it.
fn drain_after_begin(input: &[u8], begin_line: &str) -> Vec<u8> {
    let mut needle = begin_line.as_bytes().to_vec();
    needle.extend_from_slice(b"\r\n");
    find_subslice(input, &needle).map_or_else(Vec::new, |at| {
        let start = at.saturating_add(needle.len());
        input.get(start..).unwrap_or(&[]).to_vec()
    })
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let last = haystack.len().saturating_sub(needle.len());
    (0..=last).find(|&i| haystack.get(i..i.saturating_add(needle.len())) == Some(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `OK` line the server sends on accepting a mechanism.
    fn ok_reply() -> Vec<u8> {
        let mut v = b"OK ".to_vec();
        v.extend_from_slice(SERVER_GUID.as_bytes());
        v.extend_from_slice(b"\r\n");
        v
    }

    /// Drive a full handshake in one push: NUL, AUTH EXTERNAL, BEGIN, then a binary byte.
    #[test]
    fn external_auth_then_begin() {
        let mut s = SaslServer::new();
        let mut input = vec![0u8];
        input.extend_from_slice(b"AUTH EXTERNAL 31303030\r\nBEGIN\r\n");
        input.push(0xAB); // first binary byte after BEGIN
        assert_eq!(
            s.push(&input).expect("handshake"),
            Outcome::Begin {
                reply: ok_reply(),
                leftover: vec![0xAB],
            }
        );
    }

    /// The handshake split across two pushes (partial line) must work.
    #[test]
    fn handshake_split_across_pushes() {
        let mut s = SaslServer::new();
        assert_eq!(
            s.push(&[0]).expect("nul"),
            Outcome::Continue { reply: Vec::new() }
        );
        // A partial AUTH line yields no complete command yet.
        assert_eq!(
            s.push(b"AUTH EXTER").expect("partial"),
            Outcome::Continue { reply: Vec::new() }
        );
        assert_eq!(
            s.push(b"NAL\r\n").expect("rest of auth"),
            Outcome::Continue { reply: ok_reply() }
        );
        assert_eq!(
            s.push(b"BEGIN\r\n").expect("begin"),
            Outcome::Begin {
                reply: Vec::new(),
                leftover: Vec::new(),
            }
        );
    }

    #[test]
    fn bare_auth_lists_mechanisms() {
        let mut s = SaslServer::new();
        let _ = s.push(&[0]).expect("nul");
        assert_eq!(
            s.push(b"AUTH\r\n").expect("auth"),
            Outcome::Continue {
                reply: b"REJECTED EXTERNAL ANONYMOUS\r\n".to_vec(),
            }
        );
    }

    #[test]
    fn unix_fd_negotiation_is_declined_not_fatal() {
        let mut s = SaslServer::new();
        let _ = s.push(&[0]).expect("nul");
        let _ = s.push(b"AUTH EXTERNAL\r\n").expect("auth");
        let declined = s.push(b"NEGOTIATE_UNIX_FD\r\n").expect("negotiate");
        assert_eq!(
            declined,
            Outcome::Continue {
                reply: b"ERROR unix fd passing not available\r\n".to_vec(),
            }
        );
        // The client falls back and proceeds to BEGIN.
        assert_eq!(
            s.push(b"BEGIN\r\n").expect("begin"),
            Outcome::Begin {
                reply: Vec::new(),
                leftover: Vec::new(),
            }
        );
    }

    #[test]
    fn begin_before_auth_is_rejected() {
        let mut s = SaslServer::new();
        let _ = s.push(&[0]).expect("nul");
        assert_eq!(s.push(b"BEGIN\r\n"), Err(SaslError::BeginBeforeAuth));
    }

    #[test]
    fn missing_nul_opener_is_rejected() {
        let mut s = SaslServer::new();
        assert_eq!(s.push(b"AUTH EXTERNAL\r\n"), Err(SaslError::NotAscii));
    }

    #[test]
    fn over_long_line_is_bounded() {
        let mut s = SaslServer::new();
        let _ = s.push(&[0]).expect("nul");
        let huge = vec![b'A'; MAX_LINE + 10];
        assert_eq!(s.push(&huge), Err(SaslError::LineTooLong));
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // A crude robustness sweep (the fuzz target is the real one): random-ish bytes must
        // only ever yield Ok/Err, never panic.
        for seed in 0u32..2000 {
            let mut s = SaslServer::new();
            let bytes: Vec<u8> = (0..64u32)
                .map(|i| u8::try_from(seed.wrapping_mul(i).wrapping_add(i) & 0xff).unwrap_or(0))
                .collect();
            let _ = s.push(&bytes);
        }
    }
}
