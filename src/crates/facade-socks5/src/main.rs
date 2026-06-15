//! In-kennel SOCKS5 egress shim: present a SOCKS5 endpoint on the kennel's loopback and broker each
//! `CONNECT` to the `org.projectkennel.INet/default` binder facade.
//!
//! # Purpose
//!
//! The egress facade (`docs/design/07-5-network.md` §7.5.2/§7.5.6): the workload speaks SOCKS5 to
//! this shim at the kennel's loopback `:1080` (the `socks5h://` form, so the *name* — never a
//! resolved address — rides the request). On each `CONNECT` the shim transacts a
//! [`verb::CONNECT_INET`] to node 0; kenneld decides under `[net.proxy]`, resolves the name, pins
//! the vetted address, drives its host-side `host-netproxy` delegate to dial it, and returns one
//! end of a socketpair conduit. The shim completes the SOCKS5 handshake and splices the workload to
//! that conduit. It is the TCP analogue of `facade-afunix`.
//!
//! # Invocation
//!
//! `facade-socks5 <binder-device> <listen-addr>`, spawned by kenneld into the kennel's view.
//! `<binder-device>` is `/dev/binder`; `<listen-addr>` is the kennel loopback SOCKS endpoint.
//!
//! # Non-goals
//!
//! No policy, no resolver, no host socket: kenneld decides, resolves, and pins. This process only
//! speaks SOCKS5 and splices bytes.
//!
//! [`verb::CONNECT_INET`]: kennel_lib_binder::service::verb::CONNECT_INET

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::thread;

use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::service::{inet, transport, verb};

/// The binder buffer mapping size for the shim's facade client.
const MAP_SIZE: usize = 128 * 1024;
/// The largest host name the shim forwards (the facade enforces the same bound).
const MAX_HOST: usize = 255;

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

/// Bind the SOCKS endpoint and broker each accepted connection. One thread per connection; a failed
/// connection logs and is dropped (the application sees a refused SOCKS request), the others serve.
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

/// Handle one SOCKS5 connection: negotiate, broker the `CONNECT` to the facade, and splice.
fn handle(device: &str, mut client: TcpStream) -> io::Result<()> {
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

/// Splice the workload's TCP connection against the conduit bidirectionally until either closes.
fn splice(client: TcpStream, conduit: UnixStream) {
    let (Ok(client_r), Ok(conduit_r)) = (client.try_clone(), conduit.try_clone()) else {
        return;
    };
    let up = thread::spawn(move || {
        let _ = io::copy(&mut &client_r, &mut &conduit);
        let _ = conduit.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut &conduit_r, &mut &client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = up.join();
    drop(client); // own the connection to its close (the splice's end of life)
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
            w.shutdown(Shutdown::Write).expect("half-close write");
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
