//! In-kennel D-Bus facade: present a D-Bus server endpoint on the kennel's bus address and
//! mediate each connection through the binder gateway (§7.7.2).
//!
//! # Purpose
//!
//! D-Bus is never granted as a direct socket (§7.7.1). The kennel's `DBUS_SESSION_BUS_ADDRESS`
//! points here; this process terminates the workload's bus connection in the kennel, parses the
//! adversarial D-Bus wire (the sole such parser, [`kennel_lib_dbus::server::Facade`]), and emits
//! **typed** transactions. Those transactions ride the binder gateway: kenneld is the membrane
//! (§7.7.2a), so the facade reaches `host-dbus` only by transacting node 0 — never a raw conduit.
//! Per accepted connection it `DBUS_OPEN`s a connection id, fires each typed call as a oneway
//! `DBUS_SEND`, and keeps one `DBUS_RECV` outstanding to receive replies/signals; `DBUS_CLOSE` on
//! teardown. `Hello` is answered locally and the refuse-to-broker set (§7.7.5) is refused at the
//! facade; everything else is decided by the delegate against the compiled `[dbus]` table.
//!
//! # Invocation
//!
//! `facade-dbus <binder-device> <listen-path>=<session|system> [...]`, spawned by `kenneld`
//! into the kennel's view.
//!
//! # Non-goals
//!
//! No policy, no bus socket: kenneld relays and the delegate decides. This process only
//! terminates the workload's connection and frames typed transactions onto binder.

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::service::{dbus, status, verb};
use kennel_lib_dbus::server::{Action, Facade};
use kennel_lib_dbus::wire::{self, Bus, Frame};

/// The binder buffer mapping size for the facade's client.
const MAP_SIZE: usize = 128 * 1024;
/// The read chunk for the workload connection.
const CHUNK: usize = 16 * 1024;

/// Per-process connection-id allocator (the facade serves one kennel; ids are unique within it).
static NEXT_CONN_ID: AtomicU32 = AtomicU32::new(1);

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
    let _ = std::fs::remove_file(path);
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(path)?;
    for incoming in listener.incoming() {
        let workload = incoming?;
        let device = device.to_owned();
        thread::spawn(move || {
            if let Err(e) = mediate(&device, workload, bus) {
                eprintln!("facade-dbus: connection: {e}");
            }
        });
    }
    Ok(())
}

/// Mediate one workload bus connection over the binder gateway.
fn mediate(device: &str, workload: UnixStream, bus: Bus) -> io::Result<()> {
    let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
    // One binder client shared by both directions (the kernel routes per-thread; transactions
    // are `&self`). Register the connection with kenneld first.
    let binder = Arc::new(open_binder(device)?);
    let bus_byte = match bus {
        Bus::Session => dbus::SESSION,
        Bus::System => dbus::SYSTEM,
    };
    let reply = binder.transact(CONTEXT_MANAGER_HANDLE, verb::DBUS_OPEN, &dbus::encode_open(conn_id, bus_byte))?;
    if reply.first() != Some(&status::OK) {
        // The bus is not enabled (or refused): drop, the client sees "cannot connect to bus".
        return Ok(());
    }

    let facade = Arc::new(Mutex::new(Facade::new(bus)));
    let Ok(writer) = workload.try_clone() else {
        return Ok(());
    };
    let workload_w = Arc::new(Mutex::new(writer));

    // Inbound: one DBUS_RECV outstanding; each reply is a frame (or AGAIN to re-arm).
    let inbound = {
        let binder = Arc::clone(&binder);
        let facade = Arc::clone(&facade);
        let workload_w = Arc::clone(&workload_w);
        thread::spawn(move || recv_loop(&binder, conn_id, &facade, &workload_w))
    };

    // Outbound: read the workload, drive the engine, fire ToDelegate frames as oneway sends.
    workload_to_binder(&binder, conn_id, workload, &facade, &workload_w);

    // Teardown: close the connection at kenneld (also unblocks the parked DBUS_RECV).
    let _ = binder.transact(CONTEXT_MANAGER_HANDLE, verb::DBUS_CLOSE, &dbus::encode_conn(conn_id));
    let _ = inbound.join();
    Ok(())
}

/// Drive the engine over workload bytes; fire each `ToDelegate` frame as a oneway `DBUS_SEND`.
fn workload_to_binder(
    binder: &Connection,
    conn_id: u32,
    mut workload: UnixStream,
    facade: &Mutex<Facade>,
    workload_w: &Mutex<UnixStream>,
) {
    let mut buf = [0u8; CHUNK];
    while let Ok(n) = workload.read(&mut buf) {
        if n == 0 {
            break;
        }
        let actions = {
            let Ok(mut f) = facade.lock() else { break };
            match f.on_workload_bytes(buf.get(..n).unwrap_or(&[])) {
                Ok(actions) => actions,
                Err(e) => {
                    eprintln!("facade-dbus: {e}");
                    break;
                }
            }
        };
        for action in &actions {
            match action {
                Action::ToWorkload(bytes) => {
                    let Ok(mut w) = workload_w.lock() else { return };
                    if w.write_all(bytes).is_err() {
                        return;
                    }
                }
                Action::ToDelegate(frame) => {
                    // Synchronous send: kenneld writes the frame to the host-dbus pipe and acks
                    // immediately (it does NOT wait for the bus round-trip — the reply returns on
                    // DBUS_RECV), so no kenneld thread is held per call. The ack also carries the
                    // membrane's rate-limit verdict; a non-OK status means shed/over-rate, drop.
                    let req = dbus::encode_send(conn_id, &frame.encode());
                    match binder.transact(CONTEXT_MANAGER_HANDLE, verb::DBUS_SEND, &req) {
                        Ok(reply) if reply.first() == Some(&status::OK) => {}
                        _ => return,
                    }
                }
            }
        }
    }
}

/// Keep one `DBUS_RECV` outstanding; reconstruct each inbound frame to the workload.
fn recv_loop(
    binder: &Connection,
    conn_id: u32,
    facade: &Mutex<Facade>,
    workload_w: &Mutex<UnixStream>,
) {
    loop {
        let Ok(reply) =
            binder.transact(CONTEXT_MANAGER_HANDLE, verb::DBUS_RECV, &dbus::encode_conn(conn_id))
        else {
            return; // kenneld closed the connection (or a fatal error): stop.
        };
        match parse_recv(&reply) {
            RecvReply::Again => {}                 // nothing pending; re-arm.
            RecvReply::Closed => return,           // kenneld tore the connection down.
            RecvReply::Frame(frame) => {
                let actions = {
                    let Ok(mut f) = facade.lock() else { return };
                    match f.on_delegate_frame(frame) {
                        Ok(actions) => actions,
                        Err(_) => return,
                    }
                };
                for action in &actions {
                    if let Action::ToWorkload(bytes) = action {
                        let Ok(mut w) = workload_w.lock() else { return };
                        if w.write_all(bytes).is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// The outcome of a `DBUS_RECV`: a frame to deliver, re-arm, or a clean close.
enum RecvReply {
    Frame(Frame),
    Again,
    Closed,
}

/// Parse a `DBUS_RECV` reply: `[status]` then, on `OK`, the length-prefixed frame relayed
/// verbatim by kenneld. An empty reply is a clean close.
fn parse_recv(reply: &[u8]) -> RecvReply {
    match reply.first() {
        Some(&status::AGAIN) => RecvReply::Again,
        Some(&status::OK) => {
            let rest = reply.get(1..).unwrap_or(&[]);
            match wire::frame_len(rest) {
                Ok(Some(len)) => {
                    let payload = rest.get(4..4usize.saturating_add(len)).unwrap_or(&[]);
                    Frame::decode(payload).map_or(RecvReply::Closed, RecvReply::Frame)
                }
                _ => RecvReply::Closed,
            }
        }
        // An empty reply or any other status is a clean close.
        _ => RecvReply::Closed,
    }
}

/// Open the binder device and map the client buffer.
fn open_binder(device: &str) -> io::Result<Connection> {
    let fd = OpenOptions::new().read(true).write(true).open(device)?;
    Connection::open(fd.into(), MAP_SIZE)
}
