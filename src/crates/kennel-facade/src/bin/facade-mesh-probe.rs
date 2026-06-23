//! `facade-mesh-probe` — the in-kennel mesh provide/consume round-trip probe (`07-13` §7.13.4).
//!
//! The test workload for the `mesh-roundtrip` and `gui-mesh` policy-suite cases, in three modes:
//! - `serve <path>` — bind an `AF_UNIX` socket at `<path>` (a provider's `[[provides]]` endpoint) and
//!   echo `ping`→`pong` for each connection, forever. The **provider** kennel's workload.
//! - `connect <path>` — connect to `<path>` (a consumer's `[[consumes]]` `at` socket), send `ping`,
//!   and exit 0 iff `pong` comes back. The **consumer** kennel's workload — its exit IS the verdict.
//! - `serve-display` — bind `$XDG_RUNTIME_DIR/wayland-0` and echo, the headless stand-in for a nested
//!   compositor: the `compositor-broker` spawns it per connection (`gui-mesh` case), with no GPU or
//!   display, so the broker's spawn-relay-kill path is exercised on real kennels.
//!
//! No binder, no node 0 from the probe's view: the consumer connects to an ordinary socket and the
//! provider serves an ordinary socket. kenneld's facade + broker bridge the two behind the scenes
//! (the consumer's `at` is a facade listener; on connect kenneld resolves the capability, reaches the
//! running provider's endpoint through `/proc/<pid>/root`, and splices). So a successful round-trip
//! proves the brokered connector actually reaches a *running provider across the kennel boundary*.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

/// Consumer-side round-trip attempts: the provider may be socket-activated on first consume (W6) or
/// still binding its endpoint, so the broker can briefly return `UNAVAILABLE`. Retry a bounded while.
const CONNECT_ATTEMPTS: u32 = 50;
/// Delay between consumer attempts.
const ATTEMPT_DELAY: Duration = Duration::from_millis(100);

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_default();
    // `serve-display` derives its path from `XDG_RUNTIME_DIR` (the private dir the compositor-broker
    // hands each spawned compositor), so it takes no path argument.
    if mode == "serve-display" {
        return serve_display();
    }
    let Some(path) = args.next() else {
        eprintln!("facade-mesh-probe: usage: <serve|connect> <path> | serve-display");
        return ExitCode::FAILURE;
    };
    match mode.as_str() {
        "serve" => serve(&path),
        "connect" => connect(&path),
        other => {
            eprintln!("facade-mesh-probe: unknown mode `{other}` (serve|connect|serve-display)");
            ExitCode::FAILURE
        }
    }
}

/// Bind `$XDG_RUNTIME_DIR/wayland-0` and echo — the headless stand-in for a nested compositor.
///
/// The `compositor-broker` gives each spawned compositor a private `XDG_RUNTIME_DIR` and waits for it
/// to bind `wayland-N` there before relaying the app into it. This binds exactly that socket and echoes
/// `ping`→`pong`, so the broker's spawn-relay-kill path is exercised on real kennels with no GPU or
/// display (the `gui-mesh` case).
fn serve_display() -> ExitCode {
    let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") else {
        eprintln!("facade-mesh-probe: serve-display: XDG_RUNTIME_DIR not set");
        return ExitCode::FAILURE;
    };
    let path = Path::new(&runtime).join("wayland-0");
    serve(&path.to_string_lossy())
}

/// Bind `path` and echo `ping`→`pong` for each connection, forever. The provider workload.
fn serve(path: &str) -> ExitCode {
    let _ = std::fs::remove_file(path); // clear a stale socket from a prior run
    if let Some(parent) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("facade-mesh-probe: bind {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("facade-mesh-probe: serving {path}");
    for incoming in listener.incoming() {
        let Ok(mut conn) = incoming else { continue };
        std::thread::spawn(move || {
            let mut buf = [0u8; 4];
            if conn.read_exact(&mut buf).is_ok() && &buf == b"ping" {
                let _ = conn.write_all(b"pong");
            }
        });
    }
    ExitCode::SUCCESS
}

/// Connect to `path`, send `ping`, and exit 0 iff `pong` comes back. The consumer workload.
fn connect(path: &str) -> ExitCode {
    for attempt in 1..=CONNECT_ATTEMPTS {
        match round_trip(path) {
            Ok(()) => {
                println!("facade-mesh-probe: mesh round-trip OK ({path})");
                return ExitCode::SUCCESS;
            }
            Err(e) if attempt == CONNECT_ATTEMPTS => {
                eprintln!("facade-mesh-probe: {path}: {e} (after {attempt} attempts)");
                return ExitCode::FAILURE;
            }
            Err(_) => std::thread::sleep(ATTEMPT_DELAY),
        }
    }
    ExitCode::FAILURE
}

/// One consumer round-trip: connect, send `ping`, read exactly `pong`.
fn round_trip(path: &str) -> std::io::Result<()> {
    let mut conn = UnixStream::connect(path)?;
    conn.write_all(b"ping")?;
    let mut buf = [0u8; 4];
    conn.read_exact(&mut buf)?;
    if &buf == b"pong" {
        Ok(())
    } else {
        Err(std::io::Error::other(format!("unexpected reply {buf:?}")))
    }
}
