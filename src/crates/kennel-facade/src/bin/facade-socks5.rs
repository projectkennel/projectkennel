//! In-kennel egress shim: present a SOCKS5 **and** HTTP-proxy endpoint on the kennel's loopback and
//! broker each `CONNECT` to the `org.projectkennel.INet/default` binder facade.
//!
//! # Purpose
//!
//! The egress facade (Kennel book Vol 2 ch.8 (The Network)): the workload speaks SOCKS5 or
//! HTTP-proxy to this shim at the kennel's loopback `:1080`. One listener serves both — the first
//! byte routes ([`protocol::detect`]: `0x05` → SOCKS5, an uppercase method letter → HTTP). Either
//! way the *name* (never a resolved address) rides the request: SOCKS5 via `socks5h://`, HTTP via a
//! `CONNECT host:port` / absolute-form `GET http://...`. On each request the shim transacts a
//! [`verb::CONNECT_INET`] to node 0; kenneld decides under `[net.proxy]`, resolves the name, pins
//! the vetted address, drives its host-side `host-netproxy` delegate to dial it, and returns one
//! end of a socketpair conduit. The shim completes the handshake (SOCKS5 reply, or HTTP
//! `200 Connection Established` / origin-form-rewritten forward) and splices. The TCP analogue of
//! `facade-afunix`. Serving HTTP too lets `http://`-only clients (Go net/http, Node fetch, the JVM,
//! Python requests) egress — they ignore a `socks5h://` `HTTP_PROXY`.
//!
//! # Invocation
//!
//! `facade-socks5 <binder-device> <listen-addr>`, spawned by kenneld into the kennel's view.
//! `<binder-device>` is `/dev/binder`; `<listen-addr>` is the kennel loopback proxy endpoint.
//!
//! # Non-goals
//!
//! No policy, no resolver, no host socket: kenneld decides, resolves, and pins. This process only
//! speaks the two proxy protocols and splices bytes.
//!
//! [`verb::CONNECT_INET`]: kennel_lib_binder::service::verb::CONNECT_INET

#![forbid(unsafe_code)]

// The two untrusted-input parsers live in the crate library (`src/socks5/`) so the
// fuzz harness can reach them (CODING-STANDARDS §10.6); this bin consumes them.
use kennel_facade::socks5::{http, protocol};

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::thread;

use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::service::{inet, transport, verb};

/// The binder buffer mapping size for the shim's facade client.
const MAP_SIZE: usize = 128 * 1024;
/// The largest host name the shim forwards (the facade enforces the same bound).
const MAX_HOST: usize = 255;
/// The largest HTTP-proxy request head (`CONNECT … \r\n\r\n`) the shim will buffer. A well-formed
/// CONNECT head is well under this; the cap fails closed on a client that streams bytes without ever
/// terminating the head, so it cannot grow the buffer until the kennel's `memory.max` OOM-kills the
/// proxy (a self-DoS). 16 KiB is generous for a method line + a few headers.
const MAX_REQUEST_HEAD: usize = 16 * 1024;

// SOCKS5 reply codes (RFC 1928 §6).
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(device), Some(listen)) = (args.next(), args.next()) else {
        eprintln!("facade-socks5: usage: <binder-device> <listen-addr>");
        return ExitCode::FAILURE;
    };
    match serve(&device, &listen) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("facade-socks5: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Bind the endpoint and broker each accepted connection. One listener serves BOTH SOCKS5 and
/// HTTP-proxy clients: the first byte routes (`protocol::detect`). One thread per connection; a
/// failed connection logs and is dropped (the application sees a refused request), the others serve.
fn serve(device: &str, listen: &str) -> io::Result<()> {
    let listener = TcpListener::bind(listen)?;
    for incoming in listener.incoming() {
        let client = incoming?;
        let device = device.to_owned();
        thread::spawn(move || {
            if let Err(e) = handle(&device, client) {
                eprintln!("facade-socks5: {e}");
            }
        });
    }
    Ok(())
}

/// Peek the first byte to classify the protocol, then dispatch to the SOCKS5 or HTTP handler.
fn handle(device: &str, client: TcpStream) -> io::Result<()> {
    // MSG_PEEK one byte, leaving the stream intact for the chosen handler. A 0-byte peek = the
    // client opened and closed without sending (a TCP readiness probe) — a clean disconnect.
    let mut head = [0u8; 1];
    let n = client.peek(&mut head)?;
    match protocol::detect(head.get(..n).unwrap_or(&[])) {
        Ok(protocol::Protocol::Socks5) => handle_socks5(device, client),
        Ok(protocol::Protocol::Http) => handle_http(device, client),
        // SOCKS4, an empty connect/close probe, or an unknown lead byte: drop silently (a probe is
        // not an error; an unknown byte we fail closed on without engaging a handler).
        Err(_) => Ok(()),
    }
}

/// Handle one SOCKS5 connection: negotiate, broker the `CONNECT` to the facade, and splice.
fn handle_socks5(device: &str, mut client: TcpStream) -> io::Result<()> {
    let Some((host, port)) = socks5_accept(&mut client)? else {
        // The client opened the SOCKS port and closed without sending anything (a TCP
        // readiness/health probe). Not an error — drop it silently.
        return Ok(());
    };
    match broker(device, &host, port) {
        Ok(conduit) => {
            socks5_reply(&mut client, REP_SUCCEEDED)?;
            splice(client, conduit);
            Ok(())
        }
        Err(e) => {
            // Granted-but-unreachable or denied: the facade refused. Tell the client and drop.
            let _ = socks5_reply(&mut client, REP_GENERAL_FAILURE);
            Err(e)
        }
    }
}

/// Handle one HTTP-proxy connection: read the request head, broker the `CONNECT` to the facade,
/// then either tunnel (`CONNECT`, reply `200`) or forward (absolute-form, write the rewritten head
/// upstream first), and splice.
fn handle_http(device: &str, mut client: TcpStream) -> io::Result<()> {
    let req = read_http_request(&mut client)?;
    match broker(device, &req.host, req.port) {
        Ok(conduit) => {
            match req.kind {
                http::Kind::Connect => {
                    // Raw tunnel: tell the client the tunnel is up, then splice blind.
                    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                }
                http::Kind::Forward => {
                    // Plaintext forward proxy: send the origin-form-rewritten head upstream, then
                    // splice the rest of the exchange (response + any request body).
                    (&conduit).write_all(&req.upstream_head)?;
                }
            }
            splice(client, conduit);
            Ok(())
        }
        Err(e) => {
            // Denied or unreachable: an HTTP status line the client understands, then drop.
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            Err(e)
        }
    }
}

/// Read an HTTP-proxy request head from `client`, accumulating until [`http::parse_request`] has a
/// complete head (or the bound is hit). Mirrors `socks5_accept`'s read discipline.
fn read_http_request(client: &mut TcpStream) -> io::Result<http::HttpRequest> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match http::parse_request(&buf) {
            Ok(req) => return Ok(req),
            Err(http::HttpError::Incomplete) => {
                let n = client.read(&mut chunk)?;
                if n == 0 {
                    return Err(invalid(
                        "HTTP request head truncated (EOF before CRLF CRLF)",
                    ));
                }
                buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
                // Fail closed before an unterminated head can grow without bound (self-DoS:
                // a client streaming bytes with no CRLF CRLF would otherwise OOM the proxy).
                if buf.len() > MAX_REQUEST_HEAD {
                    return Err(invalid("HTTP-proxy request head exceeds the size limit"));
                }
            }
            Err(e) => {
                return Err(invalid_owned(format!(
                    "malformed HTTP-proxy request: {e:?}"
                )))
            }
        }
    }
}

/// Ask the facade (node 0) to `CONNECT` `host:port`, returning the conduit end to splice.
fn broker(device: &str, host: &str, port: u16) -> io::Result<UnixStream> {
    let fd = OpenOptions::new().read(true).write(true).open(device)?;
    let conn = Connection::open(fd.into(), MAP_SIZE)?;
    let request = inet::encode_request(transport::TCP, port, host);
    let conduit = conn.transact_fd(CONTEXT_MANAGER_HANDLE, verb::CONNECT_INET, &request)?;
    Ok(UnixStream::from(conduit))
}

/// Negotiate the SOCKS5 greeting + `CONNECT` request, returning the requested `(host, port)`. Only
/// the no-auth method and the `CONNECT` command are supported (the workload's `socks5h://` egress).
fn socks5_accept<S: Read + Write>(client: &mut S) -> io::Result<Option<(String, u16)>> {
    // Greeting: VER=5, NMETHODS, METHODS… → reply NO-AUTH. A client that closes BEFORE sending
    // any byte (a bare connect/close — a TCP readiness probe) is a clean disconnect, not an
    // error: report `None` so the caller drops it silently. A partial greeting (some bytes then
    // EOF) is a genuine protocol error and propagates.
    let Some([ver, nmethods]) = read_greeting(client)? else {
        return Ok(None);
    };
    if ver != 5 {
        return Err(invalid("not a SOCKS5 greeting"));
    }
    let mut methods = vec![0u8; usize::from(nmethods)];
    client.read_exact(&mut methods)?;
    client.write_all(&[5, 0])?; // VER=5, METHOD=NO-AUTH

    // Request: VER=5, CMD, RSV=0, ATYP, ADDR, PORT.
    let [ver, cmd, _rsv, atyp] = read_array::<4, S>(client)?;
    if ver != 5 {
        return Err(invalid("not a SOCKS5 request"));
    }
    if cmd != 1 {
        socks5_reply(client, REP_CMD_NOT_SUPPORTED)?;
        return Err(invalid("only SOCKS5 CONNECT is supported"));
    }
    let host = match atyp {
        1 => Ipv4Addr::from(read_array::<4, S>(client)?).to_string(),
        4 => Ipv6Addr::from(read_array::<16, S>(client)?).to_string(),
        3 => {
            let [len] = read_array::<1, S>(client)?;
            let mut name = vec![0u8; usize::from(len)];
            client.read_exact(&mut name)?;
            String::from_utf8(name).map_err(|_| invalid("non-UTF-8 SOCKS5 domain"))?
        }
        _ => {
            socks5_reply(client, REP_ATYP_NOT_SUPPORTED)?;
            return Err(invalid("unsupported SOCKS5 address type"));
        }
    };
    if host.is_empty() || host.len() > MAX_HOST {
        return Err(invalid("SOCKS5 host out of range"));
    }
    let port = u16::from_be_bytes(read_array::<2, S>(client)?);
    Ok(Some((host, port)))
}

/// Read the 2-byte SOCKS5 greeting prefix, distinguishing a clean pre-greeting close from a
/// partial one. `Ok(None)` = the client closed before sending ANY byte (a bare connect/close, e.g.
/// a TCP readiness probe — normal, not logged). `Ok(Some(..))` = a full 2-byte prefix. `Err` = a
/// partial greeting (1 byte then EOF) or a read error — a genuine protocol fault.
fn read_greeting<S: Read>(client: &mut S) -> io::Result<Option<[u8; 2]>> {
    let mut first = [0u8; 1];
    if client.read(&mut first)? == 0 {
        return Ok(None); // EOF at offset 0 — clean disconnect.
    }
    let [second] = read_array::<1, S>(client)?; // partial greeting now propagates as Err.
    Ok(Some([first[0], second]))
}

/// Send a SOCKS5 reply with code `rep` and a `0.0.0.0:0` bound address (the workload ignores it).
fn socks5_reply<S: Write>(client: &mut S, rep: u8) -> io::Result<()> {
    client.write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0])
}

/// Read exactly `N` bytes into a fixed array (no slice indexing).
fn read_array<const N: usize, S: Read>(client: &mut S) -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    client.read_exact(&mut buf)?;
    Ok(buf)
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn invalid_owned(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Splice the workload's TCP connection against the conduit bidirectionally until either closes.
/// The bidirectional relay is shared (`kennel_lib_scm::splice`) across the facades and delegates.
fn splice(client: TcpStream, conduit: UnixStream) {
    kennel_lib_scm::splice::splice(client, conduit);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive `socks5_accept` over a socketpair: the test plays the workload on one end, the shim
    /// reads/replies on the other. The workload end is dropped after writing, so the shim sees EOF
    /// once the written bytes are consumed (modelling a client that closes after its request).
    fn negotiate(request: &[u8]) -> io::Result<Option<(String, u16)>> {
        let (workload, mut shim) = UnixStream::pair().expect("socketpair");
        let req = request.to_vec();
        // Write the request, then keep draining the shim's replies (the NO-AUTH ack etc.) so the
        // shim never blocks/EPIPEs on a full pipe, and close (EOF) only once the shim is done
        // reading — modelling a client that finishes its request then disconnects.
        let driver = thread::spawn(move || {
            let mut w = workload;
            w.write_all(&req).expect("send socks5");
            w.shutdown(std::net::Shutdown::Write)
                .expect("half-close write");
            let _ = io::copy(&mut &w, &mut io::sink()); // drain replies until the shim closes
        });
        let result = socks5_accept(&mut shim);
        drop(shim); // let the driver's drain see EOF and finish
        driver.join().expect("driver");
        result
    }

    #[test]
    fn parses_a_domain_connect() {
        // greeting(5,1,no-auth) + request CONNECT atyp=domain "example.com":443
        let mut req = vec![5, 1, 0, 5, 1, 0, 3, 11];
        req.extend_from_slice(b"example.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            negotiate(&req)
                .expect("parse")
                .expect("a connect, not a bare close"),
            ("example.com".to_owned(), 443)
        );
    }

    #[test]
    fn parses_an_ipv4_connect() {
        let req = vec![5, 1, 0, 5, 1, 0, 1, 93, 184, 216, 34, 0x01, 0xBB];
        assert_eq!(
            negotiate(&req)
                .expect("parse")
                .expect("a connect, not a bare close"),
            ("93.184.216.34".to_owned(), 443)
        );
    }

    #[test]
    fn rejects_a_non_connect_command() {
        // CMD=2 (BIND) is unsupported.
        let req = vec![5, 1, 0, 5, 2, 0, 1, 1, 2, 3, 4, 0, 80];
        assert!(negotiate(&req).is_err());
    }

    #[test]
    fn rejects_a_non_socks5_greeting() {
        assert!(negotiate(&[4, 1, 0]).is_err());
    }

    #[test]
    fn bare_connect_then_close_is_a_clean_disconnect_not_an_error() {
        // A client that opens the SOCKS port and closes WITHOUT sending a greeting (a TCP
        // health/readiness probe — exactly what the net-* e2e cases do) is normal: the shim must
        // report a clean disconnect (`Ok(None)`), NOT an error that logs "failed to fill whole
        // buffer". A connection that sends a PARTIAL greeting then closes IS a protocol error.
        assert_eq!(negotiate(&[]).expect("bare close is clean"), None);
        assert!(
            negotiate(&[5]).is_err(),
            "a partial greeting (1 of 2 bytes) is a real protocol error"
        );
    }
}
