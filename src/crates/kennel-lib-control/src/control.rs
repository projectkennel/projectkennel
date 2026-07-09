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
    /// Attach a terminal to a running kennel's PTY (`kennel attach`). The CLI passes
    /// one connected socket over `SCM_RIGHTS` (its proxied-terminal end), exactly as
    /// `Start { interactive: true }` does; kenneld fans the kennel's filtered PTY
    /// output to it and forwards its input to the master. Detaching is a client-side
    /// action (the CLI closes the socket), so there is no detach request.
    Attach {
        /// The kennel to attach to.
        kennel: String,
    },
    /// Resize a running kennel's PTY (the broker holds the master, so the window-size
    /// `ioctl` happens in kenneld). The attached CLI sends this on `SIGWINCH` and once
    /// at attach time; it carries no fds and gets no body response — fire and forget.
    Resize {
        /// The kennel whose master to resize.
        kennel: String,
        /// New terminal height in rows.
        rows: u16,
        /// New terminal width in columns.
        cols: u16,
    },
    /// The operator's answer to a daemon [`Response::Prompt`] (the CLI→daemon half of the
    /// operator-prompt channel, §9.7). Sent on the same `Start`/`Attach` connection the
    /// prompt arrived on; `id` echoes the prompt's id so the daemon matches it to the
    /// pending question (the TTL `renew` prompt, later an `interactive` teardown). `answer`
    /// is the operator's free text — the daemon interprets it (an affirmative for renew).
    PromptReply {
        /// The id of the [`Response::Prompt`] being answered.
        id: u32,
        /// The operator's answer (free text; the daemon decides what counts as yes).
        answer: String,
    },
    /// Re-derive the service catalogue from the enablement links on disk (`kennel daemon-reload`, the
    /// `systemctl daemon-reload` analogue, §7.13.6). Carries no payload; the daemon answers
    /// [`Response::Reloaded`] with the resulting capability count.
    DaemonReload,
    /// Snapshot the cross-kennel service mesh (`kennel mesh`, §7.13.7): the catalogued providers,
    /// each capability they offer, and its readiness — the operability surface over the standing
    /// mesh. Carries no payload; the daemon answers [`Response::Mesh`].
    Mesh,
    /// Ask the live daemon its identity (`kennel version`, 0.7.0 W5): build version plus the
    /// settled-schema range it parses — the daemon leg of the whole-stack skew report. Carries no
    /// payload; the daemon answers [`Response::Version`]. Additive: a pre-0.7.0 daemon drops the
    /// connection on the unknown tag, which the CLI reports as "daemon predates the version query".
    Version,
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
    /// Force a CLI `argv` override of a `pinned` policy workload (`kennel run … --force`).
    /// Ignored unless the policy's `[workload]` is pinned and `argv` is non-empty; then
    /// the daemon refuses the override without it (§7.4).
    pub force: bool,
    /// Host paths for `kenneld`'s live trigger tripwire to watch (§2.5, T2.8) — each writable
    /// bind's pinned trigger files and trigger directories, resolved by the CLI (which owns the
    /// catalogue). The daemon just watches the list; it links no manifest/catalogue logic.
    /// Empty when `[trust].manifest = false`, when there are no writable triggers, or for a
    /// non-CLI caller.
    pub watch_paths: Vec<PathBuf>,
    /// For an OCI-model run (`kennel oci run`, §7.11): the host path of the store entry's
    /// `config.json`. When the policy is OCI and no argv is supplied, kenneld binds this
    /// read-only into the view and runs the launcher (`kennel-bin-oci-entry`) over it. `None`
    /// for a non-OCI run, or an OCI run given an explicit `-- <cmd>`/`[workload].argv` (which
    /// runs in-root without the launcher).
    pub oci_config: Option<PathBuf>,
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
        /// Whether the attached client must filter dangerous terminal escapes from the
        /// workload's PTY output (`[tty].filter_terminal_escapes`, §7.9.5 / §4.8). The
        /// daemon's broker is a raw-byte router; the client owns the `kennel-lib-term`
        /// filter, so the daemon conveys the policy decision here. False for a
        /// non-interactive (piped) launch, which has no proxied terminal.
        filter_escapes: bool,
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
    /// A terminal attached to a running kennel (the answer to [`Request::Attach`], or
    /// the confirmation on a `Start` connection that has become the first client). The
    /// CLI then proxies its terminal until the workload exits or it detaches.
    Attached {
        /// The kennel's context number.
        ctx: u16,
        /// The workload's process id.
        pid: u32,
        /// Whether this client must filter dangerous terminal escapes from the
        /// workload's PTY output (see [`Started::filter_escapes`]) — the broker is a
        /// raw-byte router, so a reattaching client learns the policy here.
        ///
        /// [`Started::filter_escapes`]: Self::Started::filter_escapes
        filter_escapes: bool,
    },
    /// The client detached (or was detached by a takeover) without ending the
    /// workload — the kennel keeps running, reattachable by name. `reason` is a short
    /// human note (`"another client attached"`, `"detach key"`).
    Detached {
        /// Why the client detached.
        reason: String,
    },
    /// The daemon is asking the attached operator a question (the daemon→CLI half of the
    /// operator-prompt channel, §9.7): the TTL `renew` prompt at a deadline, later an
    /// `interactive` teardown disposition. Sent unsolicited on the live `Start`/`Attach`
    /// connection mid-run; the CLI surfaces `prompt`, reads a line, and replies with a
    /// [`Request::PromptReply`] carrying the same `id`. The kennel stays frozen until the
    /// answer arrives (or the daemon's own fallback fires).
    Prompt {
        /// A correlator the operator's [`Request::PromptReply`] must echo.
        id: u32,
        /// The question to show the operator (`"kennel 'ai-coding' hit its TTL — renew? [y/N]"`).
        prompt: String,
    },
    /// The request failed; the string is a human-readable reason.
    Error(String),
    /// A [`Request::DaemonReload`] completed; `catalogued` is the number of capability names the
    /// re-derived catalogue resolves (§7.13.6).
    Reloaded {
        /// The count of catalogued capability names after the reload.
        catalogued: u32,
    },
    /// The cross-kennel mesh snapshot (the answer to [`Request::Mesh`]): one row per catalogued
    /// provider→capability, with its readiness (§7.13.7).
    Mesh(Vec<MeshProvider>),
    /// The daemon's identity (the answer to [`Request::Version`]): the live half of the
    /// `kennel version` skew report.
    Version {
        /// The daemon's build version (its `CARGO_PKG_VERSION`).
        build: String,
        /// The newest `settled_schema_version` this daemon parses.
        schema_version: u32,
        /// The oldest `settled_schema_version` this daemon still accepts (the MIN floor).
        min_schema_version: u32,
    },
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
    /// Whether a terminal is currently attached to this (interactive) kennel. False
    /// for a detached or non-interactive kennel.
    pub attached: bool,
    /// The mesh capability names this kennel's `[[consumes]]` declares, with their
    /// expected shapes and required/optional status — the consumer leg of the topology
    /// (`kennel list`, §7.13.6). Empty for a kennel with no `[[consumes]]`.
    pub consumed: Vec<ConsumedCapability>,
}

/// One consumed capability for the consumer-side topology (`kennel list`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedCapability {
    /// The capability name (the `[[consumes]]` name resolved against the catalogue).
    pub name: String,
    /// The expected connector shape (`af-unix` / `dbus-name` / `binder-connector`).
    pub shape: String,
    /// Whether the capability is required (`true`) or optional (`false`).
    pub required: bool,
}

/// One catalogued provider→capability row, for [`Response::Mesh`] (`kennel mesh`, §7.13.7).
///
/// One row per (provider, offered capability) — the standing-mesh analogue of [`KennelInfo`]. The
/// enum-valued fields ride as their canonical lower-case strings (`shape`: `af-unix`…; `tier`:
/// `user`/`host`; `enablement`: `autorun`/`ondemand`; `readiness`: `pending`/`ready`/`failed`) so the
/// control wire stays free of the catalogue's and policy's enums.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshProvider {
    /// The offered capability name (a `[[provides]]` name).
    pub capability: String,
    /// The provider kennel offering it (the broker's resolution + socket-activation target).
    pub provider: String,
    /// The connector shape (`af-unix` / `dbus-name` / `binder-connector`).
    pub shape: String,
    /// The enablement tier the provider was enabled at (`user` / `host`).
    pub tier: String,
    /// Eager (`autorun`) or lazy (`ondemand`) bring-up.
    pub enablement: String,
    /// The provider's readiness (`pending` / `ready` / `failed`).
    pub readiness: String,
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

    fn u32(&mut self) -> Result<u32, WireError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| WireError::Truncated)?;
        Ok(u32::from_ne_bytes(bytes))
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
                put_u8(&mut b, u8::from(req.force));
                put_u32(
                    &mut b,
                    u32::try_from(req.watch_paths.len()).unwrap_or(u32::MAX),
                );
                for p in &req.watch_paths {
                    put_str(&mut b, &p.to_string_lossy());
                }
                match &req.oci_config {
                    None => put_u8(&mut b, 0),
                    Some(p) => {
                        put_u8(&mut b, 1);
                        put_str(&mut b, &p.to_string_lossy());
                    }
                }
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
            Self::Attach { kennel } => {
                put_u8(&mut b, 5);
                put_str(&mut b, kennel);
            }
            Self::Resize { kennel, rows, cols } => {
                put_u8(&mut b, 6);
                put_str(&mut b, kennel);
                put_u16(&mut b, *rows);
                put_u16(&mut b, *cols);
            }
            Self::PromptReply { id, answer } => {
                put_u8(&mut b, 7);
                put_u32(&mut b, *id);
                put_str(&mut b, answer);
            }
            Self::DaemonReload => put_u8(&mut b, 8),
            Self::Mesh => put_u8(&mut b, 9),
            Self::Version => put_u8(&mut b, 10),
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
                force: r.u8()? != 0,
                watch_paths: r.strings()?.into_iter().map(PathBuf::from).collect(),
                oci_config: if r.u8()? != 0 {
                    Some(PathBuf::from(r.string()?))
                } else {
                    None
                },
            })),
            2 => Ok(Self::Stop {
                kennel: r.string()?,
            }),
            3 => Ok(Self::List),
            4 => Ok(Self::AuthorizedKeys { key: r.string()? }),
            5 => Ok(Self::Attach {
                kennel: r.string()?,
            }),
            6 => Ok(Self::Resize {
                kennel: r.string()?,
                rows: r.u16()?,
                cols: r.u16()?,
            }),
            7 => Ok(Self::PromptReply {
                id: u32::try_from(r.u32_len()?).unwrap_or(u32::MAX),
                answer: r.string()?,
            }),
            8 => Ok(Self::DaemonReload),
            9 => Ok(Self::Mesh),
            10 => Ok(Self::Version),
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
            Self::Started {
                ctx,
                pid,
                filter_escapes,
            } => {
                put_u8(&mut b, 0);
                put_u16(&mut b, *ctx);
                put_u32(&mut b, *pid);
                put_u8(&mut b, u8::from(*filter_escapes));
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
                    put_u8(&mut b, u8::from(k.attached));
                    put_u32(&mut b, u32::try_from(k.consumed.len()).unwrap_or(u32::MAX));
                    for c in &k.consumed {
                        put_str(&mut b, &c.name);
                        put_str(&mut b, &c.shape);
                        put_u8(&mut b, u8::from(c.required));
                    }
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
            Self::Attached {
                ctx,
                pid,
                filter_escapes,
            } => {
                put_u8(&mut b, 6);
                put_u16(&mut b, *ctx);
                put_u32(&mut b, *pid);
                put_u8(&mut b, u8::from(*filter_escapes));
            }
            Self::Detached { reason } => {
                put_u8(&mut b, 7);
                put_str(&mut b, reason);
            }
            Self::Prompt { id, prompt } => {
                put_u8(&mut b, 8);
                put_u32(&mut b, *id);
                put_str(&mut b, prompt);
            }
            Self::Reloaded { catalogued } => {
                put_u8(&mut b, 9);
                put_u32(&mut b, *catalogued);
            }
            Self::Mesh(providers) => {
                put_u8(&mut b, 10);
                put_u32(&mut b, u32::try_from(providers.len()).unwrap_or(u32::MAX));
                for p in providers {
                    put_str(&mut b, &p.capability);
                    put_str(&mut b, &p.provider);
                    put_str(&mut b, &p.shape);
                    put_str(&mut b, &p.tier);
                    put_str(&mut b, &p.enablement);
                    put_str(&mut b, &p.readiness);
                }
            }
            Self::Version {
                build,
                schema_version,
                min_schema_version,
            } => {
                put_u8(&mut b, 11);
                put_str(&mut b, build);
                put_u32(&mut b, *schema_version);
                put_u32(&mut b, *min_schema_version);
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
                filter_escapes: r.u8()? != 0,
            }),
            1 => Ok(Self::Stopped),
            2 => {
                let n = r.u32_len()?;
                if n > MAX_COUNT {
                    return Err(WireError::TooLarge);
                }
                let mut kennels = Vec::with_capacity(n);
                for _ in 0..n {
                    let kennel = r.string()?;
                    let ctx = r.u16()?;
                    let pid = u32::try_from(r.u32_len()?).unwrap_or(u32::MAX);
                    let running = r.u8()? != 0;
                    let attached = r.u8()? != 0;
                    let nc = r.u32_len()?;
                    if nc > MAX_COUNT {
                        return Err(WireError::TooLarge);
                    }
                    let mut consumed = Vec::with_capacity(nc);
                    for _ in 0..nc {
                        consumed.push(ConsumedCapability {
                            name: r.string()?,
                            shape: r.string()?,
                            required: r.u8()? != 0,
                        });
                    }
                    kennels.push(KennelInfo {
                        kennel,
                        ctx,
                        pid,
                        running,
                        attached,
                        consumed,
                    });
                }
                Ok(Self::Listing(kennels))
            }
            3 => Ok(Self::Exited { code: r.i32()? }),
            4 => Ok(Self::Error(r.string()?)),
            5 => Ok(Self::AuthorizedKeys {
                lines: r.strings()?,
            }),
            6 => Ok(Self::Attached {
                ctx: r.u16()?,
                pid: u32::try_from(r.u32_len()?).unwrap_or(u32::MAX),
                filter_escapes: r.u8()? != 0,
            }),
            7 => Ok(Self::Detached {
                reason: r.string()?,
            }),
            8 => Ok(Self::Prompt {
                id: u32::try_from(r.u32_len()?).unwrap_or(u32::MAX),
                prompt: r.string()?,
            }),
            9 => Ok(Self::Reloaded {
                catalogued: u32::try_from(r.u32_len()?).unwrap_or(u32::MAX),
            }),
            10 => {
                let n = r.u32_len()?;
                if n > MAX_COUNT {
                    return Err(WireError::TooLarge);
                }
                let mut providers = Vec::with_capacity(n);
                for _ in 0..n {
                    providers.push(MeshProvider {
                        capability: r.string()?,
                        provider: r.string()?,
                        shape: r.string()?,
                        tier: r.string()?,
                        enablement: r.string()?,
                        readiness: r.string()?,
                    });
                }
                Ok(Self::Mesh(providers))
            }
            11 => Ok(Self::Version {
                build: r.string()?,
                schema_version: r.u32()?,
                min_schema_version: r.u32()?,
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

// ---- W17: the control-plane version handshake -----------------------------------------------
//
// The first exchange on every control connection, before any request or policy is read. The client
// sends a [`Preamble`] carrying the **settled-policy schema version** it compiles to (plus a
// diagnostic build identity); the daemon refuses a client whose schema it cannot parse — a too-new
// CLI against an older daemon — with a typed remediation ("restart the daemon"), not the cryptic
// parse error a schema-drift would otherwise surface five layers down (the 0.3.1 field finding).
//
// The gate is the *schema* version, not a binary/build version: the wire ABI is frozen by the
// contract discipline, and what actually drifts is the settled policy the daemon loads. The check
// mirrors the policy-load gate (`settled_schema_version > SETTLED_SCHEMA_VERSION`) but at the
// connection boundary, so it fires before a request body or policy file is parsed and for every
// command, not just `run`. An honest limit: it only binds versions that *have* it — a pre-handshake
// daemon cannot speak it — so it ends the cryptic-skew class going forward, not retroactively.

/// The connection preamble a client sends first (W17).
///
/// Carries the settled-policy schema version it compiles to, and a diagnostic build identity named
/// in the daemon's refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preamble {
    /// The newest `settled_schema_version` this client produces (`kennel_lib_policy::SETTLED_SCHEMA_VERSION`).
    pub schema_version: u32,
    /// A human-readable build identity (e.g. the package version), for the diagnostic only.
    pub build: String,
}

impl Preamble {
    #[must_use]
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        put_u32(&mut b, self.schema_version);
        put_str(&mut b, &self.build);
        b
    }

    fn decode(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        Ok(Self {
            schema_version: r.u32()?,
            build: r.string()?,
        })
    }
}

/// The daemon's handshake verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// The daemon can parse what this client compiles — proceed to the request.
    Compatible,
    /// The client compiles a schema newer than the daemon parses — refused.
    Incompatible {
        daemon_schema: u32,
        client_schema: u32,
        daemon_build: String,
    },
}

impl Verdict {
    fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Self::Compatible => put_u8(&mut b, 0),
            Self::Incompatible {
                daemon_schema,
                client_schema,
                daemon_build,
            } => {
                put_u8(&mut b, 1);
                put_u32(&mut b, *daemon_schema);
                put_u32(&mut b, *client_schema);
                put_str(&mut b, daemon_build);
            }
        }
        b
    }

    fn decode(body: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        match r.u8()? {
            0 => Ok(Self::Compatible),
            1 => Ok(Self::Incompatible {
                daemon_schema: r.u32()?,
                client_schema: r.u32()?,
                daemon_build: r.string()?,
            }),
            _ => Err(WireError::BadTag),
        }
    }
}

/// A control-plane version skew the handshake caught.
///
/// The daemon cannot parse what this client compiles. Carries both versions and the remedy, so the
/// caller surfaces "restart the daemon" rather than a cryptic parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSkew {
    /// The newest schema the daemon parses.
    pub daemon_schema: u32,
    /// The schema this client compiles to (newer than the daemon's).
    pub client_schema: u32,
    /// The daemon's build identity, for the diagnostic.
    pub daemon_build: String,
}

impl std::fmt::Display for VersionSkew {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "kenneld is older than this `kennel`: the daemon parses settled-policy schema v{} \
             but this CLI compiles v{} (daemon build {}). Restart the daemon to pick up the newer \
             build: `systemctl --user restart kenneld`",
            self.daemon_schema, self.client_schema, self.daemon_build
        )
    }
}

impl std::error::Error for VersionSkew {}

/// A handshake failure: a transport error, or a version skew the daemon reported.
#[derive(Debug)]
pub enum HandshakeError {
    /// The connection failed during the handshake.
    Io(io::Error),
    /// The daemon refused this client's schema version (the typed remediation).
    Skew(VersionSkew),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "control handshake failed: {e}"),
            Self::Skew(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<io::Error> for HandshakeError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Client side of the W17 handshake: send the preamble, read the daemon's verdict.
///
/// Call this once, immediately after connecting, before any request. `schema_version` is this
/// build's `kennel_lib_policy::SETTLED_SCHEMA_VERSION`; `build` is a diagnostic identity.
///
/// # Errors
/// [`HandshakeError::Skew`] (typed, with the remedy) if the daemon cannot parse this client's
/// schema, or [`HandshakeError::Io`] on a transport failure or malformed verdict.
pub fn client_handshake<S: Read + Write>(
    s: &mut S,
    schema_version: u32,
    build: &str,
) -> Result<(), HandshakeError> {
    write_frame(
        s,
        &Preamble {
            schema_version,
            build: build.to_owned(),
        }
        .encode(),
    )?;
    let verdict = Verdict::decode(&read_frame(s)?)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad verdict: {e:?}")))?;
    match verdict {
        Verdict::Compatible => Ok(()),
        Verdict::Incompatible {
            daemon_schema,
            client_schema,
            daemon_build,
        } => Err(HandshakeError::Skew(VersionSkew {
            daemon_schema,
            client_schema,
            daemon_build,
        })),
    }
}

/// Server side of the W17 handshake: read the client's preamble, decide, send the verdict.
///
/// The **first** thing the daemon does on a control connection, before reading any request.
/// `schema_version` is this daemon's `kennel_lib_policy::SETTLED_SCHEMA_VERSION`. Returns `Ok(true)`
/// to proceed to the request, `Ok(false)` if the client was refused (the verdict has been sent; the
/// caller drops the connection without parsing anything).
///
/// # Errors
/// [`io::Error`] on a transport failure or a malformed preamble — the caller drops the connection.
pub fn server_handshake<S: Read + Write>(
    s: &mut S,
    schema_version: u32,
    build: &str,
) -> io::Result<bool> {
    let preamble = Preamble::decode(&read_frame(s)?)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad preamble: {e:?}")))?;
    // The daemon parses any schema up to its own; a client compiling a NEWER schema is the skew that
    // bit 0.3.1. Mirror the policy-load gate, but here, before the request body is read.
    if preamble.schema_version > schema_version {
        write_frame(
            s,
            &Verdict::Incompatible {
                daemon_schema: schema_version,
                client_schema: preamble.schema_version,
                daemon_build: build.to_owned(),
            }
            .encode(),
        )?;
        return Ok(false);
    }
    write_frame(s, &Verdict::Compatible.encode())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- W17 handshake -----------------------------------------------------------------------

    /// Drive both sides of the handshake over a socketpair (the server in a thread, since each side
    /// writes then blocks reading the other's frame). Returns (client result, server proceed).
    fn run_handshake(
        client_schema: u32,
        daemon_schema: u32,
    ) -> (Result<(), HandshakeError>, io::Result<bool>) {
        use std::os::unix::net::UnixStream;
        let (mut client, mut server) = UnixStream::pair().expect("socketpair");
        let srv = std::thread::spawn(move || {
            server_handshake(&mut server, daemon_schema, "daemon-1.2.3")
        });
        let cli = client_handshake(&mut client, client_schema, "cli-1.2.3");
        (cli, srv.join().expect("server thread"))
    }

    #[test]
    fn equal_schema_versions_accept() {
        let (cli, proceed) = run_handshake(1, 1);
        assert!(cli.is_ok(), "client accepted");
        assert!(proceed.expect("server"), "server proceeds to the request");
    }

    #[test]
    fn an_older_client_is_accepted_the_daemon_parses_its_schema() {
        // Client compiles schema v1, daemon parses up to v2 — forward-compatible, accepted.
        let (cli, proceed) = run_handshake(1, 2);
        assert!(cli.is_ok());
        assert!(proceed.expect("server"));
    }

    #[test]
    fn a_too_new_client_gets_the_typed_remediation_not_a_parse_error() {
        // Client compiles schema v3, daemon parses only up to v1 — the 0.3.1 skew. Refused, typed.
        let (cli, proceed) = run_handshake(3, 1);
        assert!(
            !proceed.expect("server"),
            "server refuses, does not proceed to the request"
        );
        let err = cli.expect_err("a too-new client is refused");
        // Typed (a version skew, not an Io/parse error) and carrying both versions.
        assert!(
            matches!(&err, HandshakeError::Skew(s)
                if s.daemon_schema == 1 && s.client_schema == 3 && s.daemon_build == "daemon-1.2.3"),
            "got {err:?}"
        );
        // The remedy is legible, not a cryptic parse failure five layers down.
        let msg = err.to_string();
        assert!(msg.contains("Restart the daemon"), "{msg}");
        assert!(msg.contains("schema v1"), "{msg}");
    }

    #[test]
    fn preamble_and_verdict_round_trip() {
        let p = Preamble {
            schema_version: 7,
            build: "build-xyz".to_owned(),
        };
        assert_eq!(Preamble::decode(&p.encode()).expect("preamble"), p);
        let v = Verdict::Incompatible {
            daemon_schema: 1,
            client_schema: 9,
            daemon_build: "d".to_owned(),
        };
        assert_eq!(Verdict::decode(&v.encode()).expect("verdict"), v);
        assert_eq!(
            Verdict::decode(&Verdict::Compatible.encode()).expect("ok"),
            Verdict::Compatible
        );
    }

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
            force: false,
            watch_paths: vec![
                PathBuf::from("/home/dev/project/Makefile"),
                PathBuf::from("/home/dev/project/.git/hooks"),
            ],
            oci_config: Some(PathBuf::from(
                "/home/dev/.local/share/kennel/images/app/config.json",
            )),
        }));
    }

    #[test]
    fn stop_and_list_requests_round_trip() {
        round_trip_request(&Request::Stop {
            kennel: "ai-coding".to_owned(),
        });
        round_trip_request(&Request::List);
        round_trip_request(&Request::DaemonReload);
    }

    #[test]
    fn daemon_reload_messages_round_trip() {
        round_trip_request(&Request::DaemonReload);
        round_trip_response(&Response::Reloaded { catalogued: 7 });
        round_trip_response(&Response::Reloaded { catalogued: 0 });
    }

    #[test]
    fn mesh_messages_round_trip() {
        round_trip_request(&Request::Mesh);
        round_trip_response(&Response::Mesh(vec![]));
        round_trip_response(&Response::Mesh(vec![
            MeshProvider {
                capability: "org.projectkennel.wayland".to_owned(),
                provider: "gui".to_owned(),
                shape: "af-unix".to_owned(),
                tier: "user".to_owned(),
                enablement: "ondemand".to_owned(),
                readiness: "ready".to_owned(),
            },
            MeshProvider {
                capability: "com.acme.vault".to_owned(),
                provider: "secrets".to_owned(),
                shape: "af-unix".to_owned(),
                tier: "host".to_owned(),
                enablement: "autorun".to_owned(),
                readiness: "failed".to_owned(),
            },
        ]));
    }

    #[test]
    fn version_messages_round_trip() {
        round_trip_request(&Request::Version);
        round_trip_response(&Response::Version {
            build: "0.7.0".to_owned(),
            schema_version: 4,
            min_schema_version: 3,
        });
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
                "restrict,pty,command=\"ssh -- 'git@github.com' \\\"$SSH_ORIGINAL_COMMAND\\\"\" ssh-ed25519 AAAASYN ka\n".to_owned(),
            ],
        });
    }

    #[test]
    fn attach_messages_round_trip() {
        round_trip_request(&Request::Attach {
            kennel: "ai-coding".to_owned(),
        });
        round_trip_response(&Response::Attached {
            ctx: 7,
            pid: 4242,
            filter_escapes: true,
        });
        round_trip_response(&Response::Attached {
            ctx: 1,
            pid: 9,
            filter_escapes: false,
        });
        round_trip_response(&Response::Detached {
            reason: "another client attached".to_owned(),
        });
        round_trip_response(&Response::Detached {
            reason: String::new(),
        });
        round_trip_request(&Request::Resize {
            kennel: "ai-coding".to_owned(),
            rows: 50,
            cols: 200,
        });
        round_trip_request(&Request::Resize {
            kennel: String::new(),
            rows: 0,
            cols: 0,
        });
    }

    #[test]
    fn responses_round_trip() {
        round_trip_response(&Response::Started {
            ctx: 7,
            pid: 4242,
            filter_escapes: true,
        });
        round_trip_response(&Response::Started {
            ctx: 0,
            pid: 1,
            filter_escapes: false,
        });
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
                attached: true,
                consumed: vec![
                    ConsumedCapability {
                        name: "wayland-display".to_owned(),
                        shape: "af-unix".to_owned(),
                        required: true,
                    },
                    ConsumedCapability {
                        name: "audio-playback".to_owned(),
                        shape: "af-unix".to_owned(),
                        required: false,
                    },
                ],
            },
            KennelInfo {
                kennel: "build".to_owned(),
                ctx: 8,
                pid: 99,
                running: false,
                attached: false,
                consumed: vec![],
            },
        ]));
    }

    #[test]
    fn operator_prompt_channel_round_trips() {
        // The daemon→CLI question and the CLI→daemon answer, correlated by id.
        round_trip_response(&Response::Prompt {
            id: 1,
            prompt: "kennel 'ai-coding' hit its TTL — renew for another 30m? [y/N]".to_owned(),
        });
        round_trip_response(&Response::Prompt {
            id: u32::MAX,
            prompt: String::new(),
        });
        round_trip_request(&Request::PromptReply {
            id: 1,
            answer: "y".to_owned(),
        });
        round_trip_request(&Request::PromptReply {
            id: 0,
            answer: String::new(),
        });
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
