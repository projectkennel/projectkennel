#![forbid(unsafe_code)]

//! `kennel-ssh-connect`: the in-kennel ssh `ProxyCommand`, dialing through binder.
//!
//! A confined kennel has no network path off its loopback (its own net-ns); every outbound
//! connection crosses the binder gateway. `ssh` reaches the bastion the same way: this command,
//! invoked as `ProxyCommand kennel-ssh-connect %h %p`, issues an `INet` `CONNECT_INET` transaction
//! to kenneld (binder node 0), receives the connection fd, and splices it to stdin/stdout. The
//! bastion is a sanctioned host-loopback service kenneld dials on the kennel's behalf.
//!
//! The binder device defaults to the in-view `/dev/binderfs/binder`; `KENNEL_BINDER_DEVICE`
//! overrides it (for tests). Any failure exits non-zero, so `ssh` sees a dead `ProxyCommand` and
//! fails closed.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use kennel_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_binder::service::{inet, transport, verb};

/// The kennel-side binder device the `ProxyCommand` transacts on (the constructed view's binderfs).
const DEFAULT_BINDER_DEVICE: &str = "/dev/binderfs/binder";

/// The binder receive-buffer size (matches `kennel-netshim`).
const MAP_SIZE: usize = 128 * 1024;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [host, port] = args.as_slice() else {
        eprintln!("usage: kennel-ssh-connect <host> <port>");
        return ExitCode::from(2);
    };
    match run(host, port) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kennel-ssh-connect: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(host: &str, port_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = port_str
        .parse()
        .map_err(|_| io::Error::other(format!("bad port `{port_str}`")))?;
    let device =
        std::env::var("KENNEL_BINDER_DEVICE").unwrap_or_else(|_| DEFAULT_BINDER_DEVICE.to_owned());
    let conduit = broker(&device, host, port)?;
    splice(conduit)
}

/// Ask kenneld (node 0) to `CONNECT` `host:port`, returning the conduit end to splice.
fn broker(device: &str, host: &str, port: u16) -> io::Result<UnixStream> {
    let fd = OpenOptions::new().read(true).write(true).open(device)?;
    let conn = Connection::open(fd.into(), MAP_SIZE)?;
    let request = inet::encode_request(transport::TCP, port, host);
    let conduit = conn.transact_fd(CONTEXT_MANAGER_HANDLE, verb::CONNECT_INET, &request)?;
    Ok(UnixStream::from(conduit))
}

/// Splice `stdin → conduit` on a detached thread and `conduit → stdout` on this one, returning when
/// the downlink ends (mirrors `nc` as a `ProxyCommand`).
fn splice(conduit: UnixStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut up = conduit.try_clone()?;
    // The uplink runs detached: when the downlink ends (peer closed) we return and the process
    // exits, reaping this thread. Joining would deadlock — it blocks reading stdin, which ssh keeps
    // open.
    let _uplink = std::thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        let _ = io::copy(&mut stdin, &mut up);
        let _ = up.shutdown(std::net::Shutdown::Write);
    });
    // Downlink with an explicit flush per chunk: stdout is a LineWriter and SSH's binary key
    // exchange carries no newlines, so the line buffer would never flush — pump and flush.
    pump_flushing(conduit, io::stdout().lock())
}

/// Copy `reader → writer`, flushing after every chunk so a line-buffered writer (stdout) forwards
/// binary data immediately. Returns when the reader hits EOF.
fn pump_flushing<R: Read, W: Write>(
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
