//! The blocking, thread-per-connection proxy server (the pipeline).
//!
//! Ties the pure modules together for a live connection: peek the first byte
//! ([`protocol::detect`]), parse the handshake ([`socks5`] or [`http`]), decide
//! against the [`Ruleset`], resolve names through the [`Resolver`] seam, connect
//! upstream, signal the client, relay bytes, and write one [`audit`] record. One
//! thread per connection, matching `kenneld`'s server and the OpenSSH bar; a
//! proxy is bounded by policy, not by connection count.
//!
//! # Operating contract
//!
//! Per the 2026-05-31 maintainer decision, `kenneld` owns the signed-policy
//! crypto: it resolves the settled policy, derives the [`Ruleset`], the
//! [`Resolver`], and the listen address, and launches this proxy as a per-kennel
//! child with that config plus an audit sink. This crate holds *no* signature
//! verification and *no* DNS wire parsing — it is a dumb enforcer of an
//! already-resolved ruleset, which keeps its TCB small.
//!
//! # Invariants
//!
//! - **Fail closed.** A handshake parse error, an unsupported command, a denied
//!   destination, an unresolvable name, or a failed upstream connect all end the
//!   connection without relaying, after an audit record is written.
//! - **The handshake is time-bounded.** A client that connects and never speaks
//!   is dropped after [`HANDSHAKE_TIMEOUT`]; the read timeout is cleared only
//!   once relaying begins, so legitimate long-lived tunnels are not cut.
//! - **Resolved addresses are re-checked.** A name that clears the allowlist is
//!   connected only to a resolved address that clears the deny rules
//!   ([`Ruleset::decide_resolved`]) and — unless `accept_private_resolved` is set
//!   — is not in special-use space ([`is_special_use`], the rebinding defence).
//!
//! # Threat bearing
//!
//! T1.8 and the "only talk to the proxy" thesis: this is the user-space half of
//! egress control. The kernel (cgroup BPF) guarantees the workload can reach
//! nothing but this proxy; this code decides what the proxy reaches on the
//! workload's behalf, and records every decision.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::allow::{
    is_special_use, Decision, DenyReason, Destination, RequestDecision, Ruleset, Transport,
};
use crate::audit::{Outcome, Record, Wire};
use crate::dns::Resolver;
use crate::{http, protocol, socks5};

/// How long the proxy waits for a client to send its handshake before dropping
/// the connection. Cleared once relaying starts.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on a buffered SOCKS5 handshake message. The largest request is
/// `4 + 1 + 255 + 2` bytes; 512 leaves margin without allowing unbounded growth.
const SOCKS5_MAX: usize = 512;

/// Read-chunk size for handshake reads.
const CHUNK: usize = 256;

/// The HTTP `CONNECT` success response sent before a tunnel begins relaying.
const HTTP_200: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// A per-kennel egress proxy: a resolved ruleset, a name resolver, the
/// resolved-address private-space opinion, and an audit sink.
pub struct Proxy<W, R> {
    ruleset: Ruleset,
    resolver: R,
    /// Whether a name may be connected to a resolved address in special-use
    /// space (RFC1918 / ULA / loopback / ...). Default posture is `false`; set
    /// only for a kennel that legitimately reaches internal services by name.
    accept_private_resolved: bool,
    audit: Mutex<W>,
}

/// Why [`Proxy::resolve_and_connect`] did not yield an upstream connection.
enum ConnectError {
    /// Policy refused the destination, with a stable reason token.
    Denied(&'static str),
    /// Policy allowed it but the connection could not be made.
    Failed(&'static str),
}

impl<W: Write + Send, R: Resolver> Proxy<W, R> {
    /// Build a proxy over an already-resolved `ruleset`, a name `resolver`, the
    /// `accept_private_resolved` opinion, and an `audit` sink (one JSON Lines
    /// record is written per request).
    pub const fn new(
        ruleset: Ruleset,
        resolver: R,
        accept_private_resolved: bool,
        audit: W,
    ) -> Self {
        Self {
            ruleset,
            resolver,
            accept_private_resolved,
            audit: Mutex::new(audit),
        }
    }

    /// Accept connections on `listener` forever, handling each on its own thread.
    ///
    /// # Errors
    ///
    /// An OS error if accepting a connection fails.
    pub fn serve(self: &Arc<Self>, listener: &TcpListener) -> io::Result<()>
    where
        W: 'static,
        R: 'static,
    {
        for conn in listener.incoming() {
            let stream = conn?;
            let me = Arc::clone(self);
            // A connection that fails is logged via audit; its thread just ends.
            std::thread::spawn(move || drop(me.handle(stream)));
        }
        Ok(())
    }

    /// Accept on every `listener` forever, each listener on its own thread (and
    /// each connection on its own thread, as [`serve`](Self::serve)).
    ///
    /// One `TcpListener` binds a single address family, so a dual-stack kennel —
    /// one with both a v4 and a v6 loopback proxy address — serves both through
    /// this. Returns when any listener fails; the rest keep running until the
    /// process exits (a listener failure is fatal to the proxy either way).
    ///
    /// # Errors
    ///
    /// The first listener error observed (an OS accept failure), or an error if a
    /// listener thread panicked.
    pub fn serve_all(self: &Arc<Self>, listeners: Vec<TcpListener>) -> io::Result<()>
    where
        W: 'static,
        R: 'static,
    {
        let handles: Vec<_> = listeners
            .into_iter()
            .map(|listener| {
                let me = Arc::clone(self);
                std::thread::spawn(move || me.serve(&listener))
            })
            .collect();
        for handle in handles {
            handle.join().map_err(|_| io::Error::other("listener thread panicked"))??;
        }
        Ok(())
    }

    /// Write one audit record. A poisoned lock or a write error is swallowed: an
    /// audit-sink failure must not take down request handling.
    fn write_audit(&self, record: &Record) {
        if let Ok(mut sink) = self.audit.lock() {
            let _ = writeln!(sink, "{}", record.to_jsonl());
        }
    }

    /// Handle one connection: detect the protocol from the first byte and
    /// dispatch. An unrecognised front-door byte just closes the connection.
    ///
    /// # Errors
    ///
    /// An I/O error from the underlying socket.
    pub fn handle(&self, client: TcpStream) -> io::Result<()> {
        client.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        let mut head = [0u8; 1];
        let n = client.peek(&mut head)?;
        match protocol::detect(head.get(..n).unwrap_or(&[])) {
            Ok(protocol::Protocol::Socks5) => self.handle_socks5(client),
            Ok(protocol::Protocol::Http) => self.handle_http(client),
            Err(_) => Ok(()),
        }
    }

    /// Drive a SOCKS5 connection: greeting, method reply, request, then fulfil.
    fn handle_socks5(&self, mut client: TcpStream) -> io::Result<()> {
        let mut buf = Vec::new();
        let Some(greeting) = read_parsed(
            &mut client,
            &mut buf,
            SOCKS5_MAX,
            socks5::parse_greeting,
            |e| *e == socks5::Socks5Error::Incomplete,
        )?
        else {
            return Ok(());
        };
        client.write_all(&socks5::method_reply(greeting.offers_no_auth))?;
        if !greeting.offers_no_auth {
            return Ok(());
        }
        buf.drain(..greeting.consumed);

        let Some(parsed) = read_parsed(
            &mut client,
            &mut buf,
            SOCKS5_MAX,
            socks5::parse_request,
            |e| *e == socks5::Socks5Error::Incomplete,
        )?
        else {
            return Ok(());
        };
        let req = parsed.request;

        if req.command != socks5::Command::Connect {
            client.write_all(&socks5::encode_reply(
                socks5::Reply::CommandNotSupported,
                unspecified(),
            ))?;
            self.write_audit(&record(
                Wire::Socks5,
                &req.dest,
                req.port,
                None,
                Outcome::Denied("command-not-supported"),
            ));
            return Ok(());
        }

        match self.resolve_and_connect(&req.dest, req.port, Transport::Tcp) {
            Ok((upstream, resolved)) => {
                let bound = upstream.local_addr().unwrap_or_else(|_| unspecified());
                client.write_all(&socks5::encode_reply(socks5::Reply::Success, bound))?;
                self.relay_and_audit(
                    Wire::Socks5,
                    &req.dest,
                    req.port,
                    resolved,
                    client,
                    upstream,
                );
                Ok(())
            }
            Err(ConnectError::Denied(reason)) => {
                client.write_all(&socks5::encode_reply(
                    socks5::Reply::NotAllowed,
                    unspecified(),
                ))?;
                self.write_audit(&record(
                    Wire::Socks5,
                    &req.dest,
                    req.port,
                    None,
                    Outcome::Denied(reason),
                ));
                Ok(())
            }
            Err(ConnectError::Failed(reason)) => {
                client.write_all(&socks5::encode_reply(
                    socks5::Reply::HostUnreachable,
                    unspecified(),
                ))?;
                self.write_audit(&record(
                    Wire::Socks5,
                    &req.dest,
                    req.port,
                    None,
                    Outcome::Failed(reason),
                ));
                Ok(())
            }
        }
    }

    /// Drive an HTTP-proxy connection: parse the head, then fulfil as a tunnel
    /// (`CONNECT`) or a plaintext forward (absolute-form).
    fn handle_http(&self, mut client: TcpStream) -> io::Result<()> {
        let mut buf = Vec::new();
        let Some(req) = read_parsed(
            &mut client,
            &mut buf,
            http::MAX_HEAD,
            http::parse_request,
            |e| *e == http::HttpError::Incomplete,
        )?
        else {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
            return Ok(());
        };
        let wire = match req.kind {
            http::Kind::Connect => Wire::HttpConnect,
            http::Kind::Forward => Wire::HttpForward,
        };
        // Anything the client already sent past the head is body / early tunnel
        // data; forward it once the upstream connection is up.
        let extra = buf.split_off(req.head_len.min(buf.len()));

        match self.resolve_and_connect(&req.dest, req.port, Transport::Tcp) {
            Ok((mut upstream, resolved)) => {
                match req.kind {
                    http::Kind::Connect => client.write_all(HTTP_200)?,
                    http::Kind::Forward => upstream.write_all(&req.upstream_head)?,
                }
                if !extra.is_empty() {
                    upstream.write_all(&extra)?;
                }
                self.relay_and_audit(wire, &req.dest, req.port, resolved, client, upstream);
                Ok(())
            }
            Err(ConnectError::Denied(reason)) => {
                client.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")?;
                self.write_audit(&record(
                    wire,
                    &req.dest,
                    req.port,
                    None,
                    Outcome::Denied(reason),
                ));
                Ok(())
            }
            Err(ConnectError::Failed(reason)) => {
                client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")?;
                self.write_audit(&record(
                    wire,
                    &req.dest,
                    req.port,
                    None,
                    Outcome::Failed(reason),
                ));
                Ok(())
            }
        }
    }

    /// Evaluate the destination, resolve a name through the [`Resolver`] if
    /// needed, and connect upstream. Each resolved address is re-checked against
    /// the deny rules and (unless `accept_private_resolved`) the special-use
    /// refusal before it is connected.
    fn resolve_and_connect(
        &self,
        dest: &Destination,
        port: u16,
        transport: Transport,
    ) -> Result<(TcpStream, Option<IpAddr>), ConnectError> {
        match self.ruleset.decide_request(dest, port, transport) {
            RequestDecision::Deny(reason) => Err(ConnectError::Denied(deny_token(reason))),
            RequestDecision::Allow => match dest {
                Destination::Addr(addr) => {
                    let stream = TcpStream::connect((*addr, port))
                        .map_err(|_| ConnectError::Failed("connect-refused"))?;
                    Ok((stream, Some(*addr)))
                }
                // decide_request only yields Allow for a literal address.
                Destination::Name(_) => Err(ConnectError::Failed("internal")),
            },
            RequestDecision::Resolve => match dest {
                Destination::Name(name) => {
                    let addrs = self
                        .resolver
                        .resolve(name)
                        .map_err(|_| ConnectError::Failed("resolve-error"))?;
                    for addr in addrs {
                        if self.ruleset.decide_resolved(addr, port, transport) != Decision::Allow {
                            continue;
                        }
                        if !self.accept_private_resolved && is_special_use(addr) {
                            continue;
                        }
                        if let Ok(stream) = TcpStream::connect((addr, port)) {
                            return Ok((stream, Some(addr)));
                        }
                    }
                    Err(ConnectError::Failed("host-unreachable"))
                }
                // decide_request only yields Resolve for a name.
                Destination::Addr(_) => Err(ConnectError::Failed("internal")),
            },
        }
    }

    /// Relay bytes in both directions until either side closes, then write the
    /// allowed-with-byte-counts audit record.
    fn relay_and_audit(
        &self,
        wire: Wire,
        dest: &Destination,
        port: u16,
        resolved: Option<IpAddr>,
        client: TcpStream,
        upstream: TcpStream,
    ) {
        let (up, down) = relay(client, upstream);
        self.write_audit(&record(
            wire,
            dest,
            port,
            resolved,
            Outcome::Allowed {
                bytes_up: up,
                bytes_down: down,
            },
        ));
    }
}

/// Relay bytes between `client` and `upstream` until both directions close,
/// returning `(client→upstream, upstream→client)` byte counts. The handshake
/// read timeout is cleared so a quiet but open tunnel is not cut.
fn relay(client: TcpStream, upstream: TcpStream) -> (u64, u64) {
    let _ = client.set_read_timeout(None);
    let _ = upstream.set_read_timeout(None);
    let (Ok(mut client_rd), Ok(mut upstream_wr)) = (client.try_clone(), upstream.try_clone())
    else {
        return (0, 0);
    };
    let mut upstream_rd = upstream;
    let mut client_wr = client;

    let up = std::thread::spawn(move || {
        let n = io::copy(&mut client_rd, &mut upstream_wr).unwrap_or(0);
        let _ = upstream_wr.shutdown(Shutdown::Write);
        n
    });
    let down = io::copy(&mut upstream_rd, &mut client_wr).unwrap_or(0);
    let _ = client_wr.shutdown(Shutdown::Write);
    let up_bytes = up.join().unwrap_or(0);
    (up_bytes, down)
}

/// Read from `stream` into `buf` until `parse` succeeds or definitively fails.
///
/// `Ok(Some(v))` on a successful parse; `Ok(None)` when the peer sent a
/// malformed message, closed early, or exceeded `cap` (the caller closes the
/// connection). `incomplete` identifies the parser's "need more bytes" error.
fn read_parsed<T, E>(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    cap: usize,
    parse: impl Fn(&[u8]) -> Result<T, E>,
    incomplete: impl Fn(&E) -> bool,
) -> io::Result<Option<T>> {
    loop {
        match parse(buf) {
            Ok(value) => return Ok(Some(value)),
            Err(ref e) if incomplete(e) => {}
            Err(_) => return Ok(None),
        }
        if buf.len() >= cap {
            return Ok(None);
        }
        let mut chunk = [0u8; CHUNK];
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
    }
}

/// The all-zero `0.0.0.0:0` address, used for the bound-address field of a
/// failure reply (where no upstream socket exists).
fn unspecified() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 0))
}

/// The stable audit token for a policy-deny reason.
const fn deny_token(reason: DenyReason) -> &'static str {
    match reason {
        DenyReason::ModeNone => "mode-none",
        DenyReason::DeniedByRule => "denied-by-rule",
        DenyReason::NotAllowed => "not-allowed",
    }
}

/// Build an audit record, rendering the destination to its host string.
fn record(
    wire: Wire,
    dest: &Destination,
    port: u16,
    resolved: Option<IpAddr>,
    outcome: Outcome,
) -> Record {
    let host = match dest {
        Destination::Name(name) => name.clone(),
        Destination::Addr(addr) => addr.to_string(),
    };
    Record {
        wire,
        host,
        port,
        resolved,
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allow::{Cidr, Matcher, NetMode, Rule, RuleProtocol};
    use crate::dns::ResolveError;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    /// A resolver backed by a fixed name->addresses map (no network).
    struct FakeResolver(HashMap<String, Vec<IpAddr>>);

    impl Resolver for FakeResolver {
        fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, ResolveError> {
            self.0.get(name).cloned().ok_or(ResolveError::NotFound)
        }
    }

    fn no_resolver() -> FakeResolver {
        FakeResolver(HashMap::new())
    }

    /// Spawn a loopback echo server; return its address and the join handle.
    fn echo_server() -> (SocketAddr, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        let handle = std::thread::spawn(move || {
            if let Ok((mut conn, _)) = listener.accept() {
                let mut buf = [0u8; 1024];
                while let Ok(n) = conn.read(&mut buf) {
                    if n == 0 || conn.write_all(buf.get(..n).unwrap_or(&[])).is_err() {
                        break;
                    }
                }
            }
        });
        (addr, handle)
    }

    /// A ruleset that allows TCP to a CIDR on a single port.
    fn allow_cidr(addr: &str, prefix: u8, port: u16) -> Ruleset {
        Ruleset {
            mode: NetMode::Constrained,
            allow: vec![Rule {
                matcher: Matcher::Cidr(
                    Cidr::new(addr.parse().expect("addr"), prefix).expect("cidr"),
                ),
                ports: vec![port],
                protocol: RuleProtocol::Tcp,
            }],
            deny: vec![],
        }
    }

    /// A ruleset that allows TCP to a name on a single port.
    fn allow_name(name: &str, port: u16) -> Ruleset {
        Ruleset {
            mode: NetMode::Constrained,
            allow: vec![Rule {
                matcher: Matcher::Name(name.to_owned()),
                ports: vec![port],
                protocol: RuleProtocol::Tcp,
            }],
            deny: vec![],
        }
    }

    /// Run a proxy on a loopback listener for exactly one connection.
    fn serve_one<R: Resolver + Send + 'static>(proxy: Arc<Proxy<io::Sink, R>>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let addr = listener.local_addr().expect("proxy addr");
        std::thread::spawn(move || {
            if let Ok((conn, _)) = listener.accept() {
                let _ = proxy.handle(conn);
            }
        });
        addr
    }

    fn socks5_request_v4(addr: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&addr.octets());
        req.extend_from_slice(&port.to_be_bytes());
        req
    }

    fn socks5_request_name(name: &str, port: u16) -> Vec<u8> {
        let mut req = vec![
            0x05,
            0x01,
            0x00,
            0x03,
            u8::try_from(name.len()).expect("short name"),
        ];
        req.extend_from_slice(name.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        req
    }

    /// Perform the SOCKS5 greeting and read the method reply.
    fn socks5_greet(client: &mut TcpStream) {
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        client.write_all(&[0x05, 0x01, 0x00]).expect("greeting");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("method reply");
        assert_eq!(method, [0x05, 0x00]);
    }

    #[test]
    fn socks5_connect_relays_through_to_upstream() {
        let (echo, echo_handle) = echo_server();
        let echo_port = echo.port();
        let proxy = Arc::new(Proxy::new(
            allow_cidr("127.0.0.0", 8, echo_port),
            no_resolver(),
            false,
            io::sink(),
        ));
        let proxy_addr = serve_one(proxy);

        let mut client = TcpStream::connect(proxy_addr).expect("connect proxy");
        socks5_greet(&mut client);
        client
            .write_all(&socks5_request_v4(Ipv4Addr::LOCALHOST, echo_port))
            .expect("request");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("connect reply");
        assert_eq!(
            reply.get(..2),
            Some([0x05, 0x00].as_slice()),
            "success reply"
        );
        client.write_all(b"ping").expect("send");
        let mut got = [0u8; 4];
        client.read_exact(&mut got).expect("echo");
        assert_eq!(&got, b"ping");

        drop(client);
        let _ = echo_handle.join();
    }

    #[test]
    fn serve_all_serves_every_listener() {
        // The dual-stack case: one proxy serving two listeners (two loopback
        // listeners stand in for the v4 + v6 pair). Each must run the handshake —
        // a completed SOCKS5 greeting (method-selection reply) proves the listener
        // was accepted and handled. socks5_greet sets a 5s read timeout, so a
        // listener that is not served fails rather than hangs.
        let proxy = Arc::new(Proxy::new(allow_cidr("127.0.0.0", 8, 9), no_resolver(), false, io::sink()));
        let l1 = TcpListener::bind("127.0.0.1:0").expect("bind l1");
        let a1 = l1.local_addr().expect("a1");
        let l2 = TcpListener::bind("127.0.0.1:0").expect("bind l2");
        let a2 = l2.local_addr().expect("a2");
        let serving = Arc::clone(&proxy);
        std::thread::spawn(move || drop(serving.serve_all(vec![l1, l2])));

        for addr in [a1, a2] {
            let mut client = TcpStream::connect(addr).expect("connect proxy");
            socks5_greet(&mut client); // its internal asserts are the per-listener check
        }
    }

    #[test]
    fn socks5_connect_to_denied_destination_is_refused() {
        let (echo, echo_handle) = echo_server();
        // Allow only 10.0.0.0/8, but the client asks for loopback -> denied.
        let proxy = Arc::new(Proxy::new(
            allow_cidr("10.0.0.0", 8, echo.port()),
            no_resolver(),
            false,
            io::sink(),
        ));
        let proxy_addr = serve_one(proxy);

        let mut client = TcpStream::connect(proxy_addr).expect("connect proxy");
        socks5_greet(&mut client);
        client
            .write_all(&socks5_request_v4(Ipv4Addr::LOCALHOST, echo.port()))
            .expect("request");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("refusal reply");
        // REP 0x02 = connection not allowed by ruleset.
        assert_eq!(
            reply.get(1),
            Some(&0x02),
            "not-allowed reply, got {reply:?}"
        );

        drop(client);
        // Unblock the never-used echo server.
        let _ = TcpStream::connect(echo);
        let _ = echo_handle.join();
    }

    #[test]
    fn socks5_resolved_name_relays_when_private_accepted() {
        let (echo, echo_handle) = echo_server();
        let echo_port = echo.port();
        let mut map = HashMap::new();
        // The echo server is on loopback (special-use), so resolving a name to
        // it requires accept_private_resolved = true.
        map.insert(
            "echo.test".to_owned(),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        );
        let proxy = Arc::new(Proxy::new(
            allow_name("echo.test", echo_port),
            FakeResolver(map),
            true,
            io::sink(),
        ));
        let proxy_addr = serve_one(proxy);

        let mut client = TcpStream::connect(proxy_addr).expect("connect proxy");
        socks5_greet(&mut client);
        client
            .write_all(&socks5_request_name("echo.test", echo_port))
            .expect("request");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("connect reply");
        assert_eq!(reply.get(1), Some(&0x00), "success, got {reply:?}");
        client.write_all(b"pong").expect("send");
        let mut got = [0u8; 4];
        client.read_exact(&mut got).expect("echo");
        assert_eq!(&got, b"pong");

        drop(client);
        let _ = echo_handle.join();
    }

    #[test]
    fn socks5_resolved_name_into_private_space_is_refused_by_default() {
        let (echo, echo_handle) = echo_server();
        let echo_port = echo.port();
        let mut map = HashMap::new();
        map.insert(
            "echo.test".to_owned(),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        );
        // accept_private_resolved = false: the name clears the allowlist but
        // resolves into loopback (special-use) -> refused.
        let proxy = Arc::new(Proxy::new(
            allow_name("echo.test", echo_port),
            FakeResolver(map),
            false,
            io::sink(),
        ));
        let proxy_addr = serve_one(proxy);

        let mut client = TcpStream::connect(proxy_addr).expect("connect proxy");
        socks5_greet(&mut client);
        client
            .write_all(&socks5_request_name("echo.test", echo_port))
            .expect("request");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("refusal reply");
        // REP 0x04 = host unreachable (the Failed path; no acceptable address).
        assert_eq!(
            reply.get(1),
            Some(&0x04),
            "host-unreachable reply, got {reply:?}"
        );

        drop(client);
        let _ = TcpStream::connect(echo);
        let _ = echo_handle.join();
    }

    #[test]
    fn http_connect_relays_through_to_upstream() {
        let (echo, echo_handle) = echo_server();
        let echo_port = echo.port();
        let proxy = Arc::new(Proxy::new(
            allow_cidr("127.0.0.0", 8, echo_port),
            no_resolver(),
            false,
            io::sink(),
        ));
        let proxy_addr = serve_one(proxy);

        let mut client = TcpStream::connect(proxy_addr).expect("connect proxy");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let req = format!("CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        client.write_all(req.as_bytes()).expect("connect req");
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            client.read_exact(&mut byte).expect("status byte");
            line.push(byte[0]);
            if line.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(
            line.starts_with(b"HTTP/1.1 200"),
            "got {:?}",
            String::from_utf8_lossy(&line)
        );
        client.write_all(b"ping").expect("send");
        let mut got = [0u8; 4];
        client.read_exact(&mut got).expect("echo");
        assert_eq!(&got, b"ping");

        drop(client);
        let _ = echo_handle.join();
    }
}
