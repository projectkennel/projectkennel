//! `kennel-socks-connect` binary: the TCP + splice around the pure SOCKS5 core.
//!
//! Usage (as an `ssh` `ProxyCommand`): `kennel-socks-connect <host> <port>`, with the
//! proxy address in `$KENNEL_SOCKS_PROXY` (`host:port`). It opens the proxy, performs
//! the SOCKS5 CONNECT handshake for `<host>:<port>`, then splices `stdin → socket` and
//! `socket → stdout` until either side closes. Any failure exits non-zero, so `ssh`
//! sees a dead `ProxyCommand` and fails closed.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;

use kennel_socks_connect::{
    check_method_selection, check_reply_header, connect_request, reply_tail_len, GREETING,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [host, port] = args.as_slice() else {
        eprintln!("usage: kennel-socks-connect <host> <port>  (proxy in $KENNEL_SOCKS_PROXY)");
        return ExitCode::from(2);
    };
    match run(host, port) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kennel-socks-connect: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(host: &str, port_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let proxy = std::env::var("KENNEL_SOCKS_PROXY")
        .map_err(|_| io::Error::other("$KENNEL_SOCKS_PROXY is not set"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| io::Error::other(format!("bad port `{port_str}`")))?;

    let mut sock = TcpStream::connect(&proxy)?;
    // SOCKS5 greeting → method selection (must be no-auth).
    sock.write_all(&GREETING)?;
    let mut method = [0u8; 2];
    sock.read_exact(&mut method)?;
    check_method_selection(method)?;

    // CONNECT request → reply (status + bound address we drain and ignore).
    sock.write_all(&connect_request(host, port)?)?;
    let mut header = [0u8; 4];
    sock.read_exact(&mut header)?;
    let atyp = check_reply_header(&header)?;
    // For a domain reply we must first read the 1-byte length to know the tail; that
    // length byte is already consumed, so drain the remaining (domain + port) bytes.
    let tail = if atyp == 0x03 {
        let mut len = [0u8; 1];
        sock.read_exact(&mut len)?;
        let [len_byte] = len;
        reply_tail_len(atyp, len_byte)
            .ok_or("bad SOCKS5 reply address type")?
            .saturating_sub(1)
    } else {
        reply_tail_len(atyp, 0).ok_or("bad SOCKS5 reply address type")?
    };
    let mut drain = vec![0u8; tail];
    sock.read_exact(&mut drain)?;

    // Connected: splice stdio ↔ socket until either direction closes.
    splice(sock)
}

/// Splice `stdin → socket` on a second thread and `socket → stdout` on this one,
/// returning when either direction ends (mirroring `nc`'s behaviour as a
/// `ProxyCommand`).
fn splice(sock: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut up = sock.try_clone()?;
    // The uplink (stdin → socket) runs detached: when the downlink ends (the peer
    // closed), we return and the process exits, reaping this thread. Joining it would
    // deadlock — it blocks reading stdin, which `ssh` keeps open. (This mirrors how
    // `nc` exits as a ProxyCommand when the remote half-closes.)
    let _uplink = std::thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        // The socket is unbuffered, so io::copy streams fine in this direction.
        let _ = io::copy(&mut stdin, &mut up);
        let _ = up.shutdown(std::net::Shutdown::Write);
    });
    // Downlink (socket → stdout) with an explicit flush per chunk: `io::stdout()` is a
    // LineWriter, and SSH's binary key-exchange carries no newlines — left to the
    // line buffer it would never reach `ssh`, stalling the handshake. Pump and flush.
    pump_flushing(sock, io::stdout().lock())
}

/// Copy `reader → writer`, flushing after every chunk so a line-buffered writer
/// (stdout) forwards binary data immediately. Returns when the reader hits EOF.
fn pump_flushing<R: io::Read, W: Write>(
    mut reader: R,
    mut writer: W,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 16384];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(buf.get(..n).ok_or("short read")?)?;
        writer.flush()?;
    }
    Ok(())
}
