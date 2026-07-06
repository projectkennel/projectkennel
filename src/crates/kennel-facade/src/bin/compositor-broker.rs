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

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// How long to wait for a freshly-spawned compositor to bind its display socket before giving up.
const DISPLAY_WAIT: Duration = Duration::from_secs(8);

/// Poll interval while waiting for that display socket to appear.
const POLL: Duration = Duration::from_millis(50);

/// The private runtime-dir root under which each compositor gets its own `XDG_RUNTIME_DIR`.
const RUNTIME_ROOT: &str = "/tmp/compositor-broker";

/// Ceiling on concurrently-live nested compositors.
///
/// Each accepted connection spawns a thread and a compositor process; without a bound, a consumer
/// can fork-bomb the GUI kennel by spamming connect/disconnect. The kennel's own cgroup caps the
/// total damage, so this is the in-budget-churn backstop, not the only bound — generous for real
/// use (this many simultaneous GUI windows is already a lot) while refusing a flood.
const MAX_LIVE_COMPOSITORS: usize = 64;

/// Token-bucket rate limit on *new* compositors: the sustained connects/sec a consumer may drive,
/// after an initial burst. The concurrency cap bounds how many compositors run at once; this bounds
/// how fast they can be cycled — a connect/disconnect flood (spawn-then-kill churn) thrashes process
/// creation in the GUI kennel even while staying under the live ceiling. Generous for real use
/// (open a handful of GUI apps in a burst); a flood is throttled, not served.
const RATE_BURST: f64 = 32.0;
const RATE_REFILL_PER_SEC: f64 = 8.0;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(listen_arg) = args.next() else {
        eprintln!(
            "compositor-broker: usage: <listen-socket[,socket...]> <compositor> [compositor-args...]"
        );
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

    // One or more comma-separated listen sockets. A single broker serves several capabilities —
    // each an in-view rendezvous socket in its OWN directory (the mesh binds a provide's rendezvous
    // at `dirname(endpoint)`, so co-located capabilities must differ there) — spawning a fresh
    // compositor per accepted connection on any of them.
    let listens: Vec<&str> = listen_arg.split(',').filter(|s| !s.is_empty()).collect();
    if listens.is_empty() {
        eprintln!("compositor-broker: no listen socket given");
        return ExitCode::FAILURE;
    }

    let compositor = Arc::new(compositor);
    let live = Arc::new(AtomicUsize::new(0));
    let ids = Arc::new(AtomicU64::new(0)); // globally-unique connection ids across all listeners

    let mut handles = Vec::new();
    for listen in listens {
        let _ = std::fs::remove_file(listen); // a stale socket from a prior run
        if let Some(parent) = Path::new(listen).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let listener = match UnixListener::bind(listen) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("compositor-broker: bind {listen}: {e}");
                return ExitCode::FAILURE;
            }
        };
        eprintln!("compositor-broker: listening at {listen}, compositor {compositor:?}");
        let compositor = Arc::clone(&compositor);
        let live = Arc::clone(&live);
        let ids = Arc::clone(&ids);
        handles.push(thread::spawn(move || {
            accept_loop(&listener, &compositor, &live, &ids);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    ExitCode::SUCCESS
}

/// Accept connections on one listen socket, spawning a compositor per connection. Run one per
/// listener; `live` (the global concurrency cap) and `ids` (globally-unique connection ids, so two
/// listeners never share a compositor runtime dir) are shared, the token-bucket rate limit is
/// per-listener.
fn accept_loop(
    listener: &UnixListener,
    compositor: &Arc<Vec<String>>,
    live: &Arc<AtomicUsize>,
    ids: &Arc<AtomicU64>,
) {
    let mut tokens = RATE_BURST;
    let mut last_refill = Instant::now();
    for incoming in listener.incoming() {
        let Ok(conn) = incoming else { continue };
        let id = ids.fetch_add(1, Ordering::SeqCst);
        // Rate-limit new compositors (token bucket): refill by elapsed time, capped at the burst,
        // then require a whole token. A flood that outruns the refill is dropped (the consumer
        // retries) before it can spawn — this caps connect/disconnect *churn* the live ceiling
        // alone would let through.
        let now = Instant::now();
        tokens = now
            .duration_since(last_refill)
            .as_secs_f64()
            .mul_add(RATE_REFILL_PER_SEC, tokens)
            .min(RATE_BURST);
        last_refill = now;
        if tokens < 1.0 {
            eprintln!("compositor-broker: [{id}] connect rate exceeded — connection refused");
            continue; // `conn` drops here, closing it
        }
        tokens -= 1.0;
        // Bound concurrent compositors so a consumer cannot fork-bomb the GUI kennel by spamming
        // connections. `fetch_add` reserves a slot; if we were already at the ceiling we give it
        // back and drop the connection (the consumer retries) rather than queue it — a wedged
        // compositor must not back up the accept loop. Soft cap: a brief over-count under a burst
        // of simultaneous accepts is harmless.
        if live.fetch_add(1, Ordering::SeqCst) >= MAX_LIVE_COMPOSITORS {
            live.fetch_sub(1, Ordering::SeqCst);
            eprintln!(
                "compositor-broker: [{id}] at capacity ({MAX_LIVE_COMPOSITORS} live) — connection refused"
            );
            continue; // `conn` drops here, closing it
        }
        let compositor = Arc::clone(compositor);
        let live = Arc::clone(live);
        thread::spawn(move || {
            serve(conn, id, &compositor);
            live.fetch_sub(1, Ordering::SeqCst); // release the slot when the window folds
        });
    }
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
        // `_keepalive` is the readiness-probe connection, HELD open until this scope ends so the
        // compositor never sees zero clients between "ready" and the app connecting (a kiosk shell
        // folds on a zero-client gap, which reset the app's connection). Dropped after the splice
        // returns — by then the app has long been the client.
        Some((display, _keepalive)) => match UnixStream::connect(&display) {
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

/// Poll the compositor's runtime dir until its `wayland-*` display socket appears **and the
/// compositor is ready** (advertises `wl_compositor`), or the deadline lapses.
///
/// The socket file appears before the compositor finishes registering its globals, so returning on
/// socket-exists alone races: a nested compositor client (sway, for a full session) that queries the
/// registry before `wl_compositor` is advertised fails to create its backend and dies (`wlroots:
/// Remote Wayland compositor does not support wl_compositor`). A single app tolerates it (it retries
/// its own connection), which is why the race only bit sessions and only on a cold broker. Gating on
/// [`probe_ready`] closes it; the returned socket is the probe connection, kept open for the caller
/// to hold across the app hand-off (see [`serve`]).
fn wait_for_display(runtime: &Path) -> Option<(PathBuf, UnixStream)> {
    let start = Instant::now();
    while start.elapsed() < DISPLAY_WAIT {
        if let Some(display) = find_display(runtime) {
            if let Some(keepalive) = probe_ready(&display) {
                return Some((display, keepalive));
            }
        }
        thread::sleep(POLL);
    }
    None
}

/// A probe connection to the compositor at `display`, **kept open**, once it advertises the
/// `wl_compositor` global — else `None`.
///
/// Does the minimal Wayland handshake — `wl_display.get_registry` then `wl_display.sync` — and, if
/// `wl_compositor` appears in the registry dump before the sync callback, returns the live socket so
/// the caller can HOLD it through the app hand-off. That matters because a kiosk compositor (weston
/// `kiosk-shell`, cage) tears down when it briefly sees zero clients: a throwaway probe that
/// connected and closed would leave a zero-client gap between readiness and the real app connecting,
/// and the app would then hit `Connection reset`. Keeping this connection alive across the hand-off
/// closes that gap. Native-endian, 32-bit-aligned wire (libwayland's ABI); no client library. A
/// connect failure, short read, or timeout reads as "not ready yet" so the caller keeps polling.
fn probe_ready(display: &Path) -> Option<UnixStream> {
    let mut sock = UnixStream::connect(display).ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .ok()?;
    // wl_display is object 1. get_registry(new_id=2), then sync(new_id=3); each message is
    // `object_id`, `(size<<16)|opcode`, args — get_registry is opcode 1, sync opcode 0, both
    // carrying one 4-byte new-id, so size = 12.
    let mut req = Vec::with_capacity(24);
    for (opcode, new_id) in [(1u32, 2u32), (0u32, 3u32)] {
        req.extend_from_slice(&1u32.to_ne_bytes());
        req.extend_from_slice(&((12u32 << 16) | opcode).to_ne_bytes());
        req.extend_from_slice(&new_id.to_ne_bytes());
    }
    sock.write_all(&req).ok()?;
    // Read events until wl_compositor appears (registry object 2, global opcode 0, whose interface
    // string is `wl_compositor`) or the sync callback fires (object 3, opcode 0 — registry dump
    // done without it).
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    let start = Instant::now();
    loop {
        let (verdict, consumed) = scan_registry(&buf);
        match verdict {
            Some(true) => return Some(sock), // ready — hand the LIVE connection back to hold
            Some(false) => return None,
            None => {}
        }
        buf.drain(..consumed.min(buf.len()));
        // Fallback: the socket is open and accepting but did not introspect as a Wayland
        // compositor within the window — a server we cannot probe this way (or a non-Wayland
        // stand-in, e.g. the headless echo the gui-mesh test uses). Hand the connection off rather
        // than stall; a real compositor advertises `wl_compositor` well within this window, so the
        // cold-start race it guards against is still closed.
        if start.elapsed() > Duration::from_secs(2) {
            return Some(sock);
        }
        match sock.read(&mut chunk) {
            Ok(n) if n > 0 => buf.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            // The read TIMED OUT (500 ms) with no verdict yet — a real compositor still coming up.
            // Loop and re-check the 2 s deadline; do not give up on the first quiet read.
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            // EOF or a hard error AFTER a successful connect: the peer is up but not talking the
            // Wayland handshake (it read our bytes and closed — the echo stand-in does exactly
            // this). Hand off; only a failed *connect* means "not up yet, keep polling".
            Ok(_) | Err(_) => return Some(sock),
        }
    }
}

/// Take `n` bytes off the front of `cur`, advancing it; `None` (leaving `cur` untouched) if fewer
/// than `n` remain. The cursor idiom the codebase's wire parsers use — bounds-checked, no indexing.
fn take<'a>(cur: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, tail) = cur.split_at_checked(n)?;
    *cur = tail;
    Some(head)
}

/// A native-endian `u32` from a 4-byte slice (as returned by `take(.., 4)`).
fn u32_ne(b: &[u8]) -> u32 {
    u32::from_ne_bytes(b.try_into().unwrap_or([0; 4]))
}

/// Scan `buf` for the Wayland registry verdict: `Some(true)` if `wl_compositor` was advertised,
/// `Some(false)` if the sync callback fired first (dump complete, not present) or a message is
/// malformed, `None` if more bytes are needed. The second element is how many bytes were consumed
/// (complete messages) so the caller can drain them and keep any partial trailing message.
fn scan_registry(buf: &[u8]) -> (Option<bool>, usize) {
    let mut cur: &[u8] = buf;
    loop {
        let msg_start = cur;
        let (Some(obj_b), Some(w1_b)) = (take(&mut cur, 4), take(&mut cur, 4)) else {
            // No full 8-byte header — rewind to the message start and ask for more.
            return (None, buf.len().saturating_sub(msg_start.len()));
        };
        let (obj, word1) = (u32_ne(obj_b), u32_ne(w1_b));
        let size = (word1 >> 16) as usize;
        let opcode = word1 & 0xffff;
        if size < 8 {
            return (Some(false), buf.len()); // malformed framing — give up, not-ready
        }
        let Some(body) = take(&mut cur, size.saturating_sub(8)) else {
            return (None, buf.len().saturating_sub(msg_start.len())); // incomplete body
        };
        // wl_registry.global: name(u32), interface(u32 len incl NUL + padded bytes), version(u32).
        if obj == 2 && opcode == 0 {
            let mut bc: &[u8] = body;
            let _name = take(&mut bc, 4);
            if let Some(slen_b) = take(&mut bc, 4) {
                let slen = u32_ne(slen_b) as usize;
                if bc.get(..slen.saturating_sub(1)) == Some(b"wl_compositor".as_slice()) {
                    return (Some(true), buf.len());
                }
            }
        }
        // wl_callback.done on our sync object: the registry dump is complete, no wl_compositor.
        if obj == 3 && opcode == 0 {
            return (Some(false), buf.len());
        }
    }
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
