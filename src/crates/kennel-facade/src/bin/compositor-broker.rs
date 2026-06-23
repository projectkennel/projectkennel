//! Per-connection nested-compositor orchestrator — the GUI service kennel's workload.
//!
//! The GUI service kennel holds the rights (the host Wayland leg and `/dev/dri`) but runs *no*
//! standing compositor. Instead it runs this broker, which listens on the kennel-to-kennel socket
//! and, for **each** accepted connection, spawns a fresh nested compositor and relays the remote app
//! into it. The compositor renders to the host desktop through the kennel's Wayland leg, so each
//! consuming app gets its own isolated compositor window.
//!
//! The compositor is whatever command is passed on the argv (`cage`, `weston`, `sway`, …); the
//! broker is compositor-agnostic. Its only requirement is the wlroots/libwayland convention of
//! naming the display socket `wayland-N` inside `XDG_RUNTIME_DIR`, which the broker overrides
//! per-instance so each compositor's socket sits at a known, unique path. Backend selection
//! (e.g. `WLR_BACKENDS=wayland` for wlroots compositors) is the policy's job, inherited via the env.
//!
//! # Lifecycle
//!
//! The broker owns the window's lifetime explicitly: it `relay_fds`-splices the accepted connection
//! into the new compositor's display socket, and the relay returns the moment the app disconnects
//! (the compositor drops the client and closes that socket). The broker then kills the compositor,
//! folding its window. The compositor is run as-is — its own exit behaviour is irrelevant, because
//! the broker is the one that ends it — so the window's life is exactly the connection's life.
//!
//! # Invocation
//!
//! `compositor-broker <listen-socket> <compositor> [compositor-args...]`, as the kennel's workload.
//! `WAYLAND_DISPLAY` (the host leg, set by the kennel's `[[unix.allow]]`) is inherited by each
//! spawned compositor as its upstream.

#![forbid(unsafe_code)]

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// How long to wait for a freshly-spawned compositor to bind its display socket before giving up.
const DISPLAY_WAIT: Duration = Duration::from_secs(8);

/// Poll interval while waiting for that display socket to appear.
const POLL: Duration = Duration::from_millis(50);

/// The private runtime-dir root under which each compositor gets its own `XDG_RUNTIME_DIR`.
const RUNTIME_ROOT: &str = "/tmp/compositor-broker";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(listen) = args.next() else {
        eprintln!("compositor-broker: usage: <listen-socket> <compositor> [compositor-args...]");
        return ExitCode::FAILURE;
    };
    let compositor: Vec<String> = args.collect();
    if compositor.is_empty() {
        eprintln!("compositor-broker: no compositor command given");
        return ExitCode::FAILURE;
    }
    // The host compositor leg each nested compositor renders to (set by the kennel's [[unix.allow]]
    // env). We fail early rather than spawn compositors that cannot reach a display.
    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        eprintln!("compositor-broker: WAYLAND_DISPLAY (the host Wayland leg) is not set");
        return ExitCode::FAILURE;
    }

    let _ = std::fs::remove_file(&listen); // a stale socket from a prior run
    if let Some(parent) = Path::new(&listen).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let listener = match UnixListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("compositor-broker: bind {listen}: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!("compositor-broker: listening at {listen}, compositor {compositor:?}");

    let compositor = Arc::new(compositor);
    let mut id: u64 = 0;
    for incoming in listener.incoming() {
        let Ok(conn) = incoming else { continue };
        id = id.wrapping_add(1);
        let compositor = Arc::clone(&compositor);
        thread::spawn(move || serve(conn, id, &compositor));
    }
    ExitCode::SUCCESS
}

/// Spawn a fresh compositor for one accepted connection, relay the app into it, and fold it (kill
/// the compositor) the moment the connection closes.
fn serve(conn: UnixStream, id: u64, compositor: &[String]) {
    // A private runtime dir so this compositor's auto-named display socket is at a known, unique
    // path — concurrent connections each get their own compositor and socket.
    let runtime = PathBuf::from(format!("{RUNTIME_ROOT}/{id}"));
    if let Err(e) = std::fs::create_dir_all(&runtime) {
        eprintln!("compositor-broker: [{id}] runtime dir: {e}");
        return;
    }
    let mut child = match spawn_compositor(&runtime, compositor) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "compositor-broker: [{id}] spawn {}: {e}",
                compositor.join(" ")
            );
            let _ = std::fs::remove_dir_all(&runtime);
            return;
        }
    };
    match wait_for_display(&runtime) {
        Some(display) => match UnixStream::connect(&display) {
            // Relay the remote app into this compositor, forwarding SCM_RIGHTS fds. Returns when the
            // app disconnects (the compositor drops the client and closes the socket) — then we fold
            // the window.
            Ok(upstream) => kennel_lib_scm::splice::splice_with_fds(conn, upstream),
            Err(e) => eprintln!(
                "compositor-broker: [{id}] connect {}: {e}",
                display.display()
            ),
        },
        None => eprintln!("compositor-broker: [{id}] compositor display never appeared"),
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&runtime);
}

/// Spawn the configured compositor with a private runtime dir for its display socket.
///
/// The env is inherited (so the host-leg `WAYLAND_DISPLAY`, the backend selection, `HOME`, and
/// `PATH` carry through); only the per-instance runtime dir is overridden.
fn spawn_compositor(runtime: &Path, compositor: &[String]) -> std::io::Result<Child> {
    let (program, rest) = compositor
        .split_first()
        .ok_or(std::io::ErrorKind::InvalidInput)?;
    Command::new(program)
        .args(rest)
        .env("XDG_RUNTIME_DIR", runtime)
        .spawn()
}

/// Poll the compositor's runtime dir until its `wayland-*` display socket appears (or the deadline
/// lapses).
fn wait_for_display(runtime: &Path) -> Option<PathBuf> {
    let start = Instant::now();
    while start.elapsed() < DISPLAY_WAIT {
        if let Some(display) = find_display(runtime) {
            return Some(display);
        }
        thread::sleep(POLL);
    }
    None
}

/// The first `wayland-*` socket in `runtime` (the compositor's auto-named display), excluding its
/// `.lock`.
fn find_display(runtime: &Path) -> Option<PathBuf> {
    for entry in std::fs::read_dir(runtime).ok()?.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("wayland-") && !name.ends_with(".lock") {
            return Some(entry.path());
        }
    }
    None
}
