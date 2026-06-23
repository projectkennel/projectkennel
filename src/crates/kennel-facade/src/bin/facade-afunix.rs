//! In-kennel `AF_UNIX` proxy: present each granted socket at its in-view path and
//! broker connections to the `org.projectkennel.IAfUnix` binder facade.
//!
//! # Purpose
//!
//! The af-unix facade (`07-1-binder.md` §7.1.5 / `02-4`) replaces the bind-mount socket
//! shim: instead of binding a host socket into the kennel's view, kenneld brokers the
//! connection and returns a connected fd over binder, so the workload never holds a
//! path into the host `AF_UNIX` namespace and every connect is mediated at call time.
//! Applications still expect a socket at the standard path, so this proxy listens
//! there: on each accept it asks the facade to `CONNECT` the named socket
//! (`transact_fd`), receives the connected host fd, and splices the two. It is the
//! `AF_UNIX` analogue of the `facade-socks5` SOCKS facade (§7.11).
//!
//! # Invocation
//!
//! `facade-afunix <binder-device> <shim-path>=<service-name> [...]`, spawned by
//! `kenneld` into the kennel's constructed view. `<binder-device>` is `/dev/binder`;
//! each pair binds a listener at `<shim-path>` brokering the facade service
//! `<service-name>` (the `[[unix.allow]]` `name`).
//!
//! # Non-goals
//!
//! No policy: the facade (kenneld) decides which sockets connect. This process only
//! presents the paths and splices bytes. It holds no host socket path.

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::ExitCode;
use std::thread;

use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::service::verb;

/// The binder buffer mapping size for the proxy's facade client.
const MAP_SIZE: usize = 128 * 1024;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(device) = args.next() else {
        eprintln!("facade-afunix: usage: <binder-device> <shim-path>=<service> ...");
        return ExitCode::FAILURE;
    };
    let sockets: Vec<(String, String)> = args.filter_map(|a| split_pair(&a)).collect();
    if sockets.is_empty() {
        eprintln!("facade-afunix: no <shim-path>=<service> pairs given");
        return ExitCode::FAILURE;
    }

    // One listener thread per granted socket; the process lives for the kennel's
    // lifetime (kenneld reaps it). A thread that fails to set up logs and exits; the
    // others keep serving.
    let mut handles = Vec::new();
    for (shim, service) in sockets {
        let device = device.clone();
        handles.push(thread::spawn(move || {
            if let Err(e) = serve_socket(&device, &shim, &service) {
                eprintln!("facade-afunix: {shim} ({service}): {e}");
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    ExitCode::SUCCESS
}

/// Parse a `shim-path=service-name` argument.
fn split_pair(arg: &str) -> Option<(String, String)> {
    let (shim, service) = arg.split_once('=')?;
    if shim.is_empty() || service.is_empty() {
        return None;
    }
    Some((shim.to_owned(), service.to_owned()))
}

/// Bind a listener at `shim` and broker each accepted connection to the facade
/// service `service`, splicing the in-kennel client to the returned host fd.
fn serve_socket(device: &str, shim: &str, service: &str) -> io::Result<()> {
    let _ = std::fs::remove_file(shim); // a stale socket from a prior run
    if let Some(parent) = Path::new(shim).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(shim)?;

    for incoming in listener.incoming() {
        let client = incoming?;
        // A fresh facade client per accepted connection: binder transactions stay
        // simple (no cross-thread sharing of one connection), and the connect is the
        // rare, short part. The splice that follows touches no binder.
        match broker(device, service) {
            Ok(host) => {
                // Forward bytes *and* SCM_RIGHTS fds (Wayland and any fd-passing protocol ride this).
                thread::spawn(move || kennel_lib_scm::splice::splice_with_fds(client, host));
            }
            Err(e) => {
                eprintln!("facade-afunix: facade refused {service}: {e}");
                // Dropping `client` closes it; the application sees a failed connect.
            }
        }
    }
    Ok(())
}

/// Ask the facade to connect `service`, returning the connected host socket.
fn broker(device: &str, service: &str) -> io::Result<UnixStream> {
    let fd = OpenOptions::new().read(true).write(true).open(device)?;
    let conn = Connection::open(fd.into(), MAP_SIZE)?;
    let host = conn.transact_fd(
        CONTEXT_MANAGER_HANDLE,
        verb::CONNECT_AFUNIX,
        service.as_bytes(),
    )?;
    Ok(UnixStream::from(host))
}
