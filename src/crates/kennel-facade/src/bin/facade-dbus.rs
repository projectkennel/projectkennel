//! In-kennel D-Bus facade: present a D-Bus server endpoint on the kennel's bus address and
//! mediate each connection to the `org.projectkennel.IDBus` facade (§7.7.2).
//!
//! # Purpose
//!
//! D-Bus is never granted as a direct socket (§7.7.1). Instead the kennel's
//! `DBUS_SESSION_BUS_ADDRESS` (and/or system bus address) points at this process, which
//! terminates the workload's bus connection in the kennel, parses the adversarial D-Bus wire
//! (the sole such parser, [`kennel_lib_dbus::server::Facade`]), and emits **typed**
//! transactions. On each accepted connection it brokers a conduit to the `host-dbus` delegate
//! via [`verb::CONNECT_DBUS`] (`transact_fd`) and then relays: workload bytes → the facade
//! engine → typed frames over the conduit, and frames back → reconstructed messages → the
//! workload. `Hello` is answered locally and the refuse-to-broker set (§7.7.5) is refused at
//! the facade; everything else is decided by the delegate against the compiled `[dbus]` table.
//! The D-Bus analogue of `facade-socks5`, but framed (typed transactions, not a byte splice).
//!
//! # Invocation
//!
//! `facade-dbus <binder-device> <listen-path>=<session|system> [...]`, spawned by `kenneld`
//! into the kennel's view. Each pair binds a `UnixListener` at `<listen-path>` whose
//! connections are mediated against the named bus.
//!
//! # Non-goals
//!
//! No policy, no bus socket: kenneld decides (via the delegate's compiled table) and holds the
//! real bus connection. This process only terminates the workload's connection and frames
//! typed transactions across the conduit.

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;

use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::service::{dbus, verb};
use kennel_lib_dbus::server::{Action, Facade};
use kennel_lib_dbus::wire::{self, Bus};

/// The binder buffer mapping size for the facade's client.
const MAP_SIZE: usize = 128 * 1024;
/// The read chunk for the workload connection.
const CHUNK: usize = 16 * 1024;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(device) = args.next() else {
        eprintln!("facade-dbus: usage: <binder-device> <listen-path>=<session|system> ...");
        return ExitCode::FAILURE;
    };
    let listeners: Vec<(String, Bus)> = args.filter_map(|a| split_pair(&a)).collect();
    if listeners.is_empty() {
        eprintln!("facade-dbus: no <listen-path>=<session|system> pairs given");
        return ExitCode::FAILURE;
    }

    // One listener thread per bus address; the process lives for the kennel's lifetime.
    let mut handles = Vec::new();
    for (path, bus) in listeners {
        let device = device.clone();
        handles.push(thread::spawn(move || {
            if let Err(e) = serve(&device, &path, bus) {
                eprintln!("facade-dbus: {path}: {e}");
            }
        }));
    }
    for handle in handles {
        let _ = handle.join();
    }
    ExitCode::SUCCESS
}

/// Parse a `listen-path=session|system` argument.
fn split_pair(arg: &str) -> Option<(String, Bus)> {
    let (path, bus) = arg.split_once('=')?;
    let bus = match bus {
        "session" => Bus::Session,
        "system" => Bus::System,
        _ => return None,
    };
    if path.is_empty() {
        return None;
    }
    Some((path.to_owned(), bus))
}

/// Bind a D-Bus server endpoint at `path` and mediate each accepted connection against `bus`.
fn serve(device: &str, path: &str, bus: Bus) -> io::Result<()> {
    let _ = std::fs::remove_file(path); // a stale socket from a prior run
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(path)?;

    for incoming in listener.incoming() {
        let workload = incoming?;
        // Broker a fresh conduit to the delegate per accepted connection (no multiplexing —
        // each workload bus connection gets its own conduit, as CONNECT_INET does per dial).
        match broker(device, bus) {
            Ok(conduit) => {
                thread::spawn(move || mediate(workload, conduit, bus));
            }
            Err(e) => {
                eprintln!("facade-dbus: facade refused the conduit: {e}");
                // Dropping `workload` closes it; the client sees "cannot connect to bus".
            }
        }
    }
    Ok(())
}

/// Ask the facade (node 0) for a D-Bus mediation conduit for `bus`.
fn broker(device: &str, bus: Bus) -> io::Result<UnixStream> {
    let bus_byte = match bus {
        Bus::Session => dbus::SESSION,
        Bus::System => dbus::SYSTEM,
    };
    let fd = OpenOptions::new().read(true).write(true).open(device)?;
    let conn = Connection::open(fd.into(), MAP_SIZE)?;
    let conduit = conn.transact_fd(
        CONTEXT_MANAGER_HANDLE,
        verb::CONNECT_DBUS,
        &dbus::encode_request(bus_byte),
    )?;
    Ok(UnixStream::from(conduit))
}

/// Mediate one workload bus connection: run the facade engine, relaying workload bytes to
/// typed frames on the conduit and delegate frames back to reconstructed messages.
///
/// Two directions run concurrently and share the engine behind a mutex (its methods do no
/// blocking I/O, so the lock is held only across the fast parse/encode). Writes to each
/// stream are serialised through their own handle.
fn mediate(workload: UnixStream, conduit: UnixStream, bus: Bus) {
    let facade = Arc::new(Mutex::new(Facade::new(bus)));
    let (Ok(workload_w), Ok(conduit_w)) = (workload.try_clone(), conduit.try_clone()) else {
        return;
    };
    let workload_w = Arc::new(Mutex::new(workload_w));
    let conduit_w = Arc::new(Mutex::new(conduit_w));

    // Conduit → workload: read framed delegate replies/signals, reconstruct, write to workload.
    let inbound = {
        let facade = Arc::clone(&facade);
        let workload_w = Arc::clone(&workload_w);
        thread::spawn(move || delegate_to_workload(conduit, &facade, &workload_w))
    };

    // Workload → conduit: read the bus stream, drive the engine, dispatch its actions.
    workload_to_delegate(workload, &facade, &workload_w, &conduit_w);

    // The workload side ended (EOF/error); dropping the conduit write half unblocks the
    // inbound reader, which then joins.
    drop(conduit_w);
    let _ = inbound.join();
}

/// Drive the engine over workload bytes until EOF, dispatching each action.
fn workload_to_delegate(
    mut workload: UnixStream,
    facade: &Mutex<Facade>,
    workload_w: &Mutex<UnixStream>,
    conduit_w: &Mutex<UnixStream>,
) {
    let mut buf = [0u8; CHUNK];
    while let Ok(n) = workload.read(&mut buf) {
        if n == 0 {
            break; // clean EOF
        }
        let actions = {
            let Ok(mut f) = facade.lock() else {
                break;
            };
            match f.on_workload_bytes(buf.get(..n).unwrap_or(&[])) {
                Ok(actions) => actions,
                Err(e) => {
                    eprintln!("facade-dbus: {e}");
                    break;
                }
            }
        };
        if dispatch(&actions, workload_w, conduit_w).is_err() {
            break;
        }
    }
}

/// Read framed frames from the conduit until EOF, reconstruct, and write to the workload.
fn delegate_to_workload(
    mut conduit: UnixStream,
    facade: &Mutex<Facade>,
    workload_w: &Mutex<UnixStream>,
) {
    while let Some(frame) = read_frame(&mut conduit).unwrap_or(None) {
        let actions = {
            let Ok(mut f) = facade.lock() else {
                break;
            };
            match f.on_delegate_frame(frame) {
                Ok(actions) => actions,
                Err(e) => {
                    eprintln!("facade-dbus: {e}");
                    break;
                }
            }
        };
        for action in &actions {
            if let Action::ToWorkload(bytes) = action {
                let Ok(mut w) = workload_w.lock() else {
                    return;
                };
                if w.write_all(bytes).is_err() {
                    return;
                }
            }
        }
    }
}

/// Write each action to its destination stream.
fn dispatch(
    actions: &[Action],
    workload_w: &Mutex<UnixStream>,
    conduit_w: &Mutex<UnixStream>,
) -> io::Result<()> {
    for action in actions {
        match action {
            Action::ToWorkload(bytes) => {
                let mut w = workload_w.lock().map_err(|_| broken())?;
                w.write_all(bytes)?;
            }
            Action::ToDelegate(frame) => {
                let mut w = conduit_w.lock().map_err(|_| broken())?;
                w.write_all(&frame.encode())?;
            }
        }
    }
    Ok(())
}

/// Read one length-prefixed [`wire::Frame`] from `stream`. `Ok(None)` on a clean EOF.
fn read_frame(stream: &mut UnixStream) -> io::Result<Option<wire::Frame>> {
    let mut len_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf) {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(e);
    }
    let len = match wire::frame_len(&len_buf) {
        Ok(Some(len)) => len,
        Ok(None) => return Ok(None),
        Err(_) => return Err(broken()),
    };
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    wire::Frame::decode(&payload)
        .map(Some)
        .map_err(|_| broken())
}

fn broken() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed IDBus conduit frame")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kennel_lib_dbus::message::reconstruct_call;
    use kennel_lib_dbus::wire::{Call, Frame, Reply};
    use std::net::Shutdown;

    /// Build the D-Bus bytes a workload would send for one method call.
    fn call_bytes(dest: &str, path: &str, iface: &str, member: &str, serial: u32) -> Vec<u8> {
        let call = Call {
            bus: Bus::Session,
            serial,
            no_reply: false,
            destination: dest.to_owned(),
            path: path.to_owned(),
            interface: iface.to_owned(),
            member: member.to_owned(),
            signature: String::new(),
            body_endian: b'l',
            body: Vec::new(),
        };
        reconstruct_call(&call, serial).expect("encode call")
    }

    /// Drive the whole relay over socketpairs: a workload on one end, a fake delegate on the
    /// conduit. Proves SASL completes, `Hello` is answered locally, a normal call is forwarded
    /// as a typed frame, a delegate reply is reconstructed back, and teardown joins cleanly.
    #[test]
    fn relay_round_trip_through_the_engine() {
        let (mut wl_test, wl_relay) = UnixStream::pair().expect("workload pair");
        let (mut cd_test, cd_relay) = UnixStream::pair().expect("conduit pair");

        let relay = thread::spawn(move || mediate(wl_relay, cd_relay, Bus::Session));

        // The fake delegate: read the forwarded call, reply once, then close (ending inbound).
        let delegate = thread::spawn(move || {
            while let Ok(Some(frame)) = read_frame(&mut cd_test) {
                if let Frame::Call(call) = frame {
                    let reply = Frame::Reply(Reply {
                        reply_serial: call.serial,
                        signature: String::new(),
                        body_endian: b'l',
                        body: Vec::new(),
                    });
                    cd_test.write_all(&reply.encode()).expect("delegate reply");
                    break;
                }
            }
            // Returning drops cd_test, which EOFs the facade's inbound reader.
        });

        // The workload: SASL, then Hello (answered locally), then a normal call (forwarded).
        let mut sasl = vec![0u8];
        sasl.extend_from_slice(b"AUTH EXTERNAL\r\nBEGIN\r\n");
        wl_test.write_all(&sasl).expect("sasl");
        wl_test
            .write_all(&call_bytes(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "Hello",
                1,
            ))
            .expect("hello");
        wl_test
            .write_all(&call_bytes(
                "org.freedesktop.Notifications",
                "/org/freedesktop/Notifications",
                "org.freedesktop.Notifications",
                "GetCapabilities",
                2,
            ))
            .expect("call");
        wl_test.shutdown(Shutdown::Write).expect("half-close");

        let mut got = Vec::new();
        wl_test.read_to_end(&mut got).expect("read replies");

        // The SASL OK was delivered, plus two D-Bus messages (Hello return + the forwarded
        // call's reconstructed reply) — well more than the 37-byte OK line alone.
        assert!(
            got.windows(3).any(|w| w == b"OK "),
            "SASL OK not delivered"
        );
        assert!(got.len() > 37, "expected OK + two D-Bus replies, got {} bytes", got.len());

        delegate.join().expect("delegate");
        relay.join().expect("relay");
    }
}
