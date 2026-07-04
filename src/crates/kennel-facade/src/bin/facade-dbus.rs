//! In-kennel D-Bus facade: present a D-Bus server endpoint on the kennel's bus address and
//! mediate each connection through the binder gateway (§7.7.2).
//!
//! # Purpose
//!
//! D-Bus is never granted as a direct socket (§7.7.1). The kennel's `DBUS_SESSION_BUS_ADDRESS`
//! points here; this process terminates the workload's bus connection in the kennel, parses the
//! adversarial D-Bus wire (the sole such parser, [`kennel_lib_dbus::server::Facade`]), and emits
//! **typed** transactions. Mediation is the standing dbus-broker's (§7.7): the per-kennel
//! `SVC_CONNECT` is the locator (kenneld replies the mesh device path), the facade connects the
//! broker's per-session node there, then fires each typed call as a `DBUS_SEND` and keeps one
//! `DBUS_RECV` outstanding for replies/signals; `DBUS_CLOSE` on teardown. `Hello` is answered
//! locally and the refuse-to-broker set (§7.7.5) is refused at the facade; everything else is
//! decided by the broker against this kennel's compiled `[dbus]` table (pulled over the mesh).
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
use std::sync::{Arc, Mutex};
use std::thread;

use kennel_lib_binder::client::{Connection, CONTEXT_MANAGER_HANDLE};
use kennel_lib_binder::service::{dbus, status, svc_connect, verb};
use kennel_lib_dbus::server::{Action, Facade};
use kennel_lib_dbus::wire::{self, Bus, Frame};

/// The binder buffer mapping size for the facade's client.
const MAP_SIZE: usize = 128 * 1024;
/// The read chunk for the workload connection.
const CHUNK: usize = 16 * 1024;

/// Bounded retry for the mesh-bus session connect, covering the brief window between the broker
/// being reported Ready and its control node being registered (§7.7).
const MESH_CONNECT_ATTEMPTS: u32 = 20;
const MESH_CONNECT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

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
///
/// First `SVC_CONNECT` the bus-qualified D-Bus capability on the **per-kennel** bus. That is the
/// service-mesh trigger (§7.13.4): kenneld resolves the broker in the catalogue, socket-activates
/// it if it is `ondemand`, and consume-waits until it is Ready — then replies with the mesh device
/// path (the brokered locator). The facade opens *that* bus and `SVC_CONNECT`s the same capability
/// for a per-session node; kenneld resolves this facade's identity there by its cgroup and mints
/// the session via the broker, after which consumer↔broker is direct (kenneld out of the byte
/// path). With no enabled broker the locator refuses and the bus goes unserved (fail-closed).
/// The per-kennel bus is the mesh *trigger* and *locator*, never the identity mechanism —
/// identity is the cgroup the mesh reads.
fn mediate(device: &str, workload: UnixStream, bus: Bus) -> io::Result<()> {
    let binder = Arc::new(open_binder(device)?);
    // The bus-qualified capability name: kenneld's mesh handler reads it to pick this bus's filter.
    let capability = dbus::capability_for_bus(match bus {
        Bus::Session => dbus::SESSION,
        Bus::System => dbus::SYSTEM,
    });
    let Some(mesh_device) = locate_mesh_bus(&binder, capability)? else {
        // No enabled broker: fail closed — the client sees "cannot connect to bus". The standing
        // dbus-broker is the one mediation home; there is no legacy delegate to fall back to.
        eprintln!("facade-dbus: no dbus-broker provider is enabled; bus unserved");
        return Ok(());
    };
    mediate_brokered(&mesh_device, capability, workload, bus)
}

/// Ask kenneld, on the per-kennel bus, where the dbus mesh bus is — the service-mesh trigger.
/// `Ok(Some(path))` means the broker was resolved/activated and is Ready: open that bus and
/// `SVC_CONNECT` there. `Ok(None)` means no enabled broker — the bus goes unserved (fail-closed).
/// The reply is `[OK][mesh-device-path]`, or a refusal status. No identity rides back: the mesh
/// handler resolves this facade afresh by its cgroup.
fn locate_mesh_bus(binder: &Connection, capability: &str) -> io::Result<Option<String>> {
    let reply = binder.transact(
        CONTEXT_MANAGER_HANDLE,
        verb::SVC_CONNECT,
        &svc_connect::encode_request(capability),
    )?;
    if reply.first() != Some(&status::OK) {
        return Ok(None);
    }
    let path = reply.get(1..).unwrap_or(&[]);
    if path.is_empty() {
        return Ok(None);
    }
    Ok(std::str::from_utf8(path).ok().map(str::to_owned))
}

/// Mediate over the **mesh bus**: `SVC_CONNECT` for the dbus capability there. kenneld matches
/// this facade by its kernel-attested cgroup (→ ctx → filter), pushes `ACCEPT_SESSION` to the
/// broker, and hands back the per-session node; the engine then runs against that node directly.
/// The broker keys the session by the target node, so no `conn_id` rides the verbs.
fn mediate_brokered(
    mesh_device: &str,
    capability: &str,
    workload: UnixStream,
    bus: Bus,
) -> io::Result<()> {
    let binder = Arc::new(open_binder(mesh_device)?);
    // kenneld reports the broker Ready when its kennel constructs, which can be a hair before the
    // broker workload has registered its control node. Retry the session connect briefly so that
    // window does not surface as a spurious "cannot connect to bus".
    let request = svc_connect::encode_request(capability);
    let mut session = None;
    for attempt in 0..MESH_CONNECT_ATTEMPTS {
        match binder.transact_handle(CONTEXT_MANAGER_HANDLE, verb::SVC_CONNECT, &request) {
            Ok(handle) => {
                session = Some(handle);
                break;
            }
            Err(_) if attempt.saturating_add(1) < MESH_CONNECT_ATTEMPTS => {
                thread::sleep(MESH_CONNECT_BACKOFF);
            }
            Err(e) => return Err(e),
        }
    }
    let Some(session) = session else {
        return Ok(()); // broker never became reachable; the client sees "cannot connect to bus"
    };

    let facade = Arc::new(Mutex::new(Facade::new(bus)));
    let Ok(writer) = workload.try_clone() else {
        return Ok(());
    };
    let workload_w = Arc::new(Mutex::new(writer));

    let inbound = {
        let binder = Arc::clone(&binder);
        let facade = Arc::clone(&facade);
        let workload_w = Arc::clone(&workload_w);
        thread::spawn(move || recv_loop(&binder, session, &facade, &workload_w))
    };
    workload_to_binder(&binder, session, workload, &facade, &workload_w);
    let _ = binder.transact(session, verb::DBUS_CLOSE, &[]);
    let _ = inbound.join();
    Ok(())
}

/// Drive the engine over workload bytes; fire each `ToDelegate` frame as a oneway `DBUS_SEND`.
///
/// `handle` is the broker's per-session node — the session *is* the connection, so each frame
/// rides alone (no `conn_id`).
fn workload_to_binder(
    binder: &Connection,
    handle: u32,
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
                    // Synchronous send: the gateway (kenneld delegate, or the broker session node)
                    // writes the frame onward and acks immediately — the bus reply returns on
                    // DBUS_RECV, so no thread is held per call. The ack carries the rate-limit
                    // verdict; a non-OK status means shed/over-rate, drop.
                    match binder.transact(handle, verb::DBUS_SEND, &frame.encode()) {
                        Ok(reply) if reply.first() == Some(&status::OK) => {}
                        _ => return,
                    }
                }
            }
        }
    }
}

/// Keep one `DBUS_RECV` outstanding; reconstruct each inbound frame to the workload. `handle` is
/// the broker's per-session node, which identifies the connection.
fn recv_loop(
    binder: &Connection,
    handle: u32,
    facade: &Mutex<Facade>,
    workload_w: &Mutex<UnixStream>,
) {
    loop {
        let Ok(reply) = binder.transact(handle, verb::DBUS_RECV, &[]) else {
            return; // the gateway closed the connection (or a fatal error): stop.
        };
        match parse_recv(&reply) {
            RecvReply::Again => {}       // nothing pending; re-arm.
            RecvReply::Closed => return, // kenneld tore the connection down.
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
