//! The control-socket protocol between the `kennel` CLI and the kenneld daemon.
//!
//! Like the privhelper IPC, this is *hand-rolled structured messages* — not a
//! serialisation language. Because a request carries variable-length data (a
//! policy path, an argv), the framing is length-prefixed: a `u32` body length,
//! then a body that begins with an op byte and continues with primitively-encoded
//! fields. All integers are native-endian (the CLI and daemon are the same host).
//!
//! The workload's stdio is **not** carried here: fds travel as `SCM_RIGHTS`
//! ancillary data alongside the [`Request::Start`] frame. A non-interactive run
//! passes three fds (the CLI's stdin/stdout/stderr). An interactive run
//! ([`StartRequest::interactive`]) passes one connected socket instead, over which
//! the spawn seal returns a controlling pty allocated inside the kennel's own
//! devpts. The fd transfer is the server/syscall layer's concern; this module is
//! the bytes.

use std::io::{self, Read, Write};
use std::path::PathBuf;

/// Largest control message accepted, a guard against a malformed length prefix.
const MAX_MESSAGE: usize = 1 << 20;
/// Largest single string field (paths, argv elements).
const MAX_STRING: usize = 64 * 1024;
/// Largest element count in a list field (argv, kennel listing).
const MAX_COUNT: usize = 4096;

/// A request from the CLI to the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Start a kennel running `argv`, confined by the policy at `policy`.
    Start(StartRequest),
    /// Stop the kennel named `kennel`.
    Stop {
        /// The kennel's name.
        kennel: String,
    },
    /// List the running kennels.
    List,
    /// Ask for the SSH bastion's forced-command `authorized_keys` line(s) bound to
    /// an offered public key (§7.10.7). The bastion's root-owned
    /// `AuthorizedKeysCommand` (`kennel-akc`) makes this query on each auth; the
    /// daemon answers from its live, verified edge state — there is no file.
    AuthorizedKeys {
        /// The offered public key as `"<type> <base64>"` (sshd's `%t %k`); the
        /// comment is ignored on lookup.
        key: String,
    },
}

/// The payload of a [`Request::Start`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartRequest {
    /// Path to the signed settled-policy file (the daemon verifies it against its
    /// trust store).
    pub policy: PathBuf,
    /// The kennel's name — used for the cgroup label and name-keyed ctx reuse.
    pub kennel: String,
    /// The command and its arguments.
    pub argv: Vec<String>,
    /// The working directory for the workload.
    pub cwd: PathBuf,
    /// The caller's `TERM` (forwarded so an interactive workload gets a usable
    /// terminal). Empty if unset. The synthesised env is otherwise built from
    /// policy + the framework vars (`HOME`/`PATH`/`USER`/…), never inherited.
    pub term: String,
    /// Whether this is an interactive run. When true, the CLI passes a single
    /// connected socket (not three stdio fds) over `SCM_RIGHTS`; the spawn seal
    /// allocates a controlling pty inside the kennel's own devpts and hands its
    /// master back over that socket for the CLI to proxy (§7.9.2). When false, the
    /// three passed fds are the workload's stdio.
    pub interactive: bool,
}

/// A response from the daemon to the CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The kennel started: its assigned context and the workload's pid.
    Started {
        /// The allocated context number.
        ctx: u16,
        /// The workload's process id.
        pid: u32,
    },
    /// The kennel was stopped.
    Stopped,
    /// The running kennels.
    Listing(Vec<KennelInfo>),
    /// The workload exited (sent on a `Start` connection after [`Started`]); the
    /// code is the exit status, or `128 + signal` if it was killed.
    ///
    /// [`Started`]: Self::Started
    Exited {
        /// The workload's exit code (or `128 + signal`).
        code: i32,
    },
    /// The forced-command `authorized_keys` line(s) for an offered key (the answer
    /// to [`Request::AuthorizedKeys`]); empty when no edge matches (the bastion
    /// then refuses the key).
    AuthorizedKeys {
        /// One `restrict,pty,command=…` line per matching edge.
        lines: Vec<String>,
    },
    /// The request failed; the string is a human-readable reason.
    Error(String),
}

/// A summary of one running kennel, for [`Response::Listing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KennelInfo {
    /// The kennel's name.
    pub kennel: String,
    /// Its context number.
    pub ctx: u16,
    /// The workload's pid.
    pub pid: u32,
    /// Whether the workload is still running.
    pub running: bool,
}

/// A malformed control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The buffer ended mid-field.
    Truncated,
    /// An op/tag byte was not recognised.
    BadTag,
    /// A string field was not valid UTF-8.
    BadString,
    /// A length/count field exceeded its sanity cap.
    TooLarge,
}

// --- Encoding primitives (no serde): append to a byte vector. ---

fn put_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_ne_bytes());
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_ne_bytes());
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_u32(buf, u32::try_from(s.len()).unwrap_or(u32::MAX));
    buf.extend_from_slice(s.as_bytes());
}

fn put_strs(buf: &mut Vec<u8>, items: &[String]) {
    put_u32(buf, u32::try_from(items.len()).unwrap_or(u32::MAX));
    for item in items {
        put_str(buf, item);
    }
}

// --- Decoding primitives: a bounds-checked cursor over a byte slice. ---

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(WireError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        self.take(1)?.first().copied().ok_or(WireError::Truncated)
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u16::from_ne_bytes(bytes))
    }

    fn u32_len(&mut self) -> Result<usize, WireError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u32::from_ne_bytes(bytes) as usize)
    }

    fn i32(&mut self) -> Result<i32, WireError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(i32::from_ne_bytes(bytes))
    }

    fn string(&mut self) -> Result<String, WireError> {
        let n = self.u32_len()?;
        if n > MAX_STRING {
            return Err(WireError::TooLarge);
        }
        let bytes = self.take(n)?;
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| WireError::BadString)
    }

    fn strings(&mut self) -> Result<Vec<String>, WireError> {
        let n = self.u32_len()?;
        if n > MAX_COUNT {
            return Err(WireError::TooLarge);
        }
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.string()?);
        }
        Ok(out)
    }
}

impl Request {
    /// Encode this request's body (op byte + fields).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Self::Start(req) => {
                put_u8(&mut b, 1);
                put_str(&mut b, &req.policy.to_string_lossy());
                put_str(&mut b, &req.kennel);
                put_strs(&mut b, &req.argv);
                put_str(&mut b, &req.cwd.to_string_lossy());
                put_str(&mut b, &req.term);
                put_u8(&mut b, u8::from(req.interactive));
            }
            Self::Stop { kennel } => {
                put_u8(&mut b, 2);
                put_str(&mut b, kennel);
            }
            Self::List => put_u8(&mut b, 3),
            Self::AuthorizedKeys { key } => {
                put_u8(&mut b, 4);
                put_str(&mut b, key);
            }
        }
        b
    }

    /// Decode a request body.
    ///
    /// # Errors
    /// [`WireError`] if the op is unknown or a field is truncated/oversized/non-UTF-8.
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        match r.u8()? {
            1 => Ok(Self::Start(StartRequest {
                policy: PathBuf::from(r.string()?),
                kennel: r.string()?,
                argv: r.strings()?,
                cwd: PathBuf::from(r.string()?),
                term: r.string()?,
                interactive: r.u8()? != 0,
            })),
            2 => Ok(Self::Stop {
                kennel: r.string()?,
            }),
            3 => Ok(Self::List),
            4 => Ok(Self::AuthorizedKeys { key: r.string()? }),
            _ => Err(WireError::BadTag),
        }
    }
}

impl Response {
    /// Encode this response's body (tag byte + fields).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Self::Started { ctx, pid } => {
                put_u8(&mut b, 0);
                put_u16(&mut b, *ctx);
                put_u32(&mut b, *pid);
            }
            Self::Stopped => put_u8(&mut b, 1),
            Self::Listing(kennels) => {
                put_u8(&mut b, 2);
                put_u32(&mut b, u32::try_from(kennels.len()).unwrap_or(u32::MAX));
                for k in kennels {
                    put_str(&mut b, &k.kennel);
                    put_u16(&mut b, k.ctx);
                    put_u32(&mut b, k.pid);
                    put_u8(&mut b, u8::from(k.running));
                }
            }
            Self::Exited { code } => {
                put_u8(&mut b, 3);
                b.extend_from_slice(&code.to_ne_bytes());
            }
            Self::AuthorizedKeys { lines } => {
                put_u8(&mut b, 5);
                put_strs(&mut b, lines);
            }
            Self::Error(message) => {
                put_u8(&mut b, 4);
                put_str(&mut b, message);
            }
        }
        b
    }

    /// Decode a response body.
    ///
    /// # Errors
    /// [`WireError`] if the tag is unknown or a field is truncated/oversized/non-UTF-8.
    pub fn decode(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        match r.u8()? {
            0 => Ok(Self::Started {
                ctx: r.u16()?,
                pid: u32::try_from(r.u32_len()?).unwrap_or(u32::MAX),
            }),
            1 => Ok(Self::Stopped),
            2 => {
                let n = r.u32_len()?;
                if n > MAX_COUNT {
                    return Err(WireError::TooLarge);
                }
                let mut kennels = Vec::with_capacity(n);
                for _ in 0..n {
                    kennels.push(KennelInfo {
                        kennel: r.string()?,
                        ctx: r.u16()?,
                        pid: u32::try_from(r.u32_len()?).unwrap_or(u32::MAX),
                        running: r.u8()? != 0,
                    });
                }
                Ok(Self::Listing(kennels))
            }
            3 => Ok(Self::Exited { code: r.i32()? }),
            4 => Ok(Self::Error(r.string()?)),
            5 => Ok(Self::AuthorizedKeys {
                lines: r.strings()?,
            }),
            _ => Err(WireError::BadTag),
        }
    }
}

// --- Stream framing: u32 length prefix + body. ---

/// Write `body` as a length-prefixed frame.
///
/// # Errors
/// An OS error if the write fails, or if `body` exceeds [`u32::MAX`].
pub fn write_frame<W: Write>(w: &mut W, body: &[u8]) -> io::Result<()> {
    let len =
        u32::try_from(body.len()).map_err(|_| io::Error::other("control message too large"))?;
    w.write_all(&len.to_ne_bytes())?;
    w.write_all(body)
}

/// Read one length-prefixed frame body.
///
/// # Errors
/// An OS error if the read fails or the frame exceeds `MAX_MESSAGE`.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_ne_bytes(len_buf) as usize;
    if len > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame too large",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Send a request as a framed message.
///
/// # Errors
/// As [`write_frame`].
pub fn send_request<W: Write>(w: &mut W, request: &Request) -> io::Result<()> {
    write_frame(w, &request.encode())
}

/// Receive and decode a framed request.
///
/// # Errors
/// An OS error on read failure, or `InvalidData` if the body is malformed.
pub fn recv_request<R: Read>(r: &mut R) -> io::Result<Request> {
    let body = read_frame(r)?;
    Request::decode(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad request: {e:?}")))
}

/// Send a response as a framed message.
///
/// # Errors
/// As [`write_frame`].
pub fn send_response<W: Write>(w: &mut W, response: &Response) -> io::Result<()> {
    write_frame(w, &response.encode())
}

/// Receive and decode a framed response.
///
/// # Errors
/// An OS error on read failure, or `InvalidData` if the body is malformed.
pub fn recv_response<R: Read>(r: &mut R) -> io::Result<Response> {
    let body = read_frame(r)?;
    Response::decode(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad response: {e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_request(req: &Request) {
        let mut framed = Vec::new();
        send_request(&mut framed, req).expect("send");
        let mut cursor = io::Cursor::new(framed);
        assert_eq!(&recv_request(&mut cursor).expect("recv"), req);
    }

    fn round_trip_response(resp: &Response) {
        let mut framed = Vec::new();
        send_response(&mut framed, resp).expect("send");
        let mut cursor = io::Cursor::new(framed);
        assert_eq!(&recv_response(&mut cursor).expect("recv"), resp);
    }

    #[test]
    fn start_request_round_trips() {
        round_trip_request(&Request::Start(StartRequest {
            policy: PathBuf::from("/etc/kennel/policies/ai-coding.policy"),
            kennel: "ai-coding".to_owned(),
            argv: vec![
                "python3".to_owned(),
                "agent.py".to_owned(),
                "--flag".to_owned(),
            ],
            cwd: PathBuf::from("/home/dev/project"),
            term: "xterm-256color".to_owned(),
            interactive: true,
        }));
    }

    #[test]
    fn stop_and_list_requests_round_trip() {
        round_trip_request(&Request::Stop {
            kennel: "ai-coding".to_owned(),
        });
        round_trip_request(&Request::List);
    }

    #[test]
    fn authorized_keys_messages_round_trip() {
        round_trip_request(&Request::AuthorizedKeys {
            key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5".to_owned(),
        });
        round_trip_request(&Request::AuthorizedKeys { key: String::new() });
        round_trip_response(&Response::AuthorizedKeys { lines: Vec::new() });
        round_trip_response(&Response::AuthorizedKeys {
            lines: vec![
                "restrict,pty,command=\"/opt/kennel/bin/kennel-ssh-reorigin --dest github.com --key SHA256:AAA\" ssh-ed25519 AAAASYN ka\n".to_owned(),
            ],
        });
    }

    #[test]
    fn responses_round_trip() {
        round_trip_response(&Response::Started { ctx: 7, pid: 4242 });
        round_trip_response(&Response::Stopped);
        round_trip_response(&Response::Exited { code: 137 });
        round_trip_response(&Response::Exited { code: 0 });
        round_trip_response(&Response::Error("no such kennel".to_owned()));
        round_trip_response(&Response::Listing(vec![
            KennelInfo {
                kennel: "ai-coding".to_owned(),
                ctx: 7,
                pid: 4242,
                running: true,
            },
            KennelInfo {
                kennel: "build".to_owned(),
                ctx: 8,
                pid: 99,
                running: false,
            },
        ]));
    }

    #[test]
    fn truncated_body_is_rejected() {
        assert_eq!(Request::decode(&[]), Err(WireError::Truncated));
        // op=Start but no following fields.
        assert_eq!(Request::decode(&[1]), Err(WireError::Truncated));
    }

    #[test]
    fn unknown_tag_is_rejected() {
        assert_eq!(Request::decode(&[99]), Err(WireError::BadTag));
        assert_eq!(Response::decode(&[99]), Err(WireError::BadTag));
    }

    #[test]
    fn oversized_string_length_is_rejected() {
        // op=Stop, then a u32 length far beyond MAX_STRING.
        let mut body = vec![2u8];
        body.extend_from_slice(&u32::MAX.to_ne_bytes());
        assert_eq!(Request::decode(&body), Err(WireError::TooLarge));
    }
}
