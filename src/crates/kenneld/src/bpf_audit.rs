//! Draining the per-kennel BPF audit ring buffer into the unified writer.
//!
//! The cgroup BPF programs (`bpf/*.bpf.c`) reserve-and-commit packed audit events
//! into a per-kennel `audit_ringbuf` (`bpf/audit_events.h`). The privhelper pins
//! that buffer under `/run/user/<uid>/kennel/bpf/<id>/audit_ringbuf` (`kennel-privhelper::exec`);
//! kenneld — unprivileged — reopens it with `BPF_OBJ_GET` and drains it on a
//! per-kennel thread, parsing each event, resolving the kennel from the event's
//! `ctx_byte`, and emitting a canonical `02-3` event with `source: bpf` through the
//! same [`Writer`] the lifecycle and proxy events use.
//!
//! The drain is the consumer half of `02-7-bpf-abi.md` §The audit ring buffer.
//! Events whose `ctx_byte` does not match this kennel (a corrupt or foreign
//! sample on a per-kennel buffer) are dropped — defence in depth atop the
//! one-buffer-per-kennel pinning.

use std::ffi::CString;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use kennel_lib_audit::{Event, Outcome, Resource, Source, Value, Writer};

/// `KENNEL_AUDIT_MAGIC` ("AEVN"), the first word of every event (`audit_events.h`).
const AUDIT_MAGIC: u32 = 0x4145_564E;

/// Header field offsets within an event sample (`struct audit_hdr`, native order).
mod hdr {
    pub const MAGIC: usize = 0;
    pub const KIND: usize = 6;
    pub const CTX_BYTE: usize = 16;
    pub const PID: usize = 20;
    pub const COMM: usize = 24;
    /// Header length; payloads begin here.
    pub const LEN: usize = 40;
}

/// `enum audit_kind` (`audit_events.h`).
mod kind {
    pub const CONNECT_DENY: u16 = 1;
    pub const CONNECT_ALLOW: u16 = 2;
    pub const BIND_REWRITE: u16 = 3;
    pub const BIND_DENY: u16 = 4;
    pub const SOCK_DENY: u16 = 5;
    pub const SETSOCKOPT_FORCED: u16 = 6;
    pub const SENDMSG_DENY: u16 = 7;
}

/// A running drain: the worker thread plus its stop flag, wake eventfd, and pin dir.
///
/// Dropping it without [`stop`](Self::stop) detaches the thread (it exits on its
/// own next poll once the process tears down), but leaves the pins; callers should
/// `stop()` at kennel teardown.
pub struct Drain {
    stop: Arc<AtomicBool>,
    wake: Arc<OwnedFd>,
    join: Option<JoinHandle<()>>,
    pin_dir: PathBuf,
}

impl Drain {
    /// Signal the worker to finish, join it (a final drain runs first), then remove
    /// the per-kennel pin dir and its pinned maps. Best-effort cleanup.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        // Break the drain out of its poll now, so this join does not wait out a whole
        // POLL_INTERVAL cycle: it runs on the kennel-teardown critical path, before the
        // requester's exit status is sent (`server.rs` `run_kennel`). Mirrors the binder
        // looper pool's wake.
        let _ = kennel_lib_syscall::wake::signal_wake(self.wake.as_fd());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        clear_pin_dir(&self.pin_dir);
    }
}

/// The audit-ringbuf byte capacity (`KENNEL_MAPS`' `audit_ringbuf.max_entries`).
fn ringbuf_capacity() -> Option<usize> {
    kennel_lib_bpf::KENNEL_MAPS
        .iter()
        .find(|m| m.name == "audit_ringbuf")
        .and_then(|m| usize::try_from(m.max_entries).ok())
}

/// Reopen the pinned `audit_ringbuf` under `pin_dir` and spawn a thread draining it
/// into `writer`, attributing events to the kennel whose context byte is `ctx`.
///
/// Returns `None` (no drain) if pinning is disabled, the pin is absent (an older
/// privhelper, or pinning failed — egress still works, just no BPF audit), or the
/// buffer cannot be reopened/mapped. A `None` is logged by the caller, not fatal.
#[must_use]
pub fn spawn(pin_dir: PathBuf, ctx: u16, writer: Arc<Writer>) -> Option<Drain> {
    let capacity = ringbuf_capacity()?;
    let ringbuf = pin_dir.join("audit_ringbuf");
    let cpath = CString::new(ringbuf.as_os_str().as_encoded_bytes()).ok()?;
    // Unprivileged BPF_OBJ_GET of the group/owner-accessible pin (the pin dir is
    // chowned to us, the caller). Absent pin ⇒ no drain.
    let fd = kennel_lib_bpf::sys::obj_get(&cpath).ok()?;

    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    // A wake eventfd the drain polls alongside the ringbuf, so `Drain::stop` breaks it out of its
    // poll at once instead of after a POLL_INTERVAL cycle (mirrors the binder looper waker). If the
    // eventfd cannot be made, there is no drain (the audit ringbuf is best-effort — as above).
    let wake = Arc::new(kennel_lib_syscall::wake::make_wake_eventfd().ok()?);
    let worker_wake = Arc::clone(&wake);
    let join = std::thread::Builder::new()
        .name(format!("kennel-lib-bpf-drain-{ctx}"))
        .spawn(move || {
            drain_loop(
                &fd,
                capacity,
                ctx,
                &writer,
                &worker_stop,
                worker_wake.as_fd(),
            );
        })
        .ok()?;
    Some(Drain {
        stop,
        wake,
        join: Some(join),
        pin_dir,
    })
}

/// The worker loop: poll the ringbuf and emit each event until stopped, then drain
/// once more so events committed just before the stop are not lost.
fn drain_loop(
    fd: &OwnedFd,
    capacity: usize,
    ctx: u16,
    writer: &Writer,
    stop: &AtomicBool,
    wake: BorrowedFd<'_>,
) {
    let Ok(mut rb) = kennel_lib_bpf::RingBuffer::new(fd.as_fd(), capacity) else {
        return;
    };
    let poll_ms = i32::try_from(POLL_INTERVAL.as_millis()).unwrap_or(200);
    while !stop.load(Ordering::Acquire) {
        match rb.poll_or_wake(wake, poll_ms) {
            Ok(true) => drain_available(&mut rb, ctx, writer),
            Ok(false) => {}
            Err(_) => break,
        }
    }
    // Final sweep: anything committed between the last poll and the stop.
    drain_available(&mut rb, ctx, writer);
}

/// How often the drain wakes to check for events and the stop flag.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Consume every committed record, emitting the ones that parse for this kennel.
fn drain_available(rb: &mut kennel_lib_bpf::RingBuffer<'_>, ctx: u16, writer: &Writer) {
    let _ = rb.consume(|sample| {
        if let Some(event) = parse_event(sample, ctx) {
            writer.emit(&event);
        }
    });
}

/// Parse one ringbuf sample into a canonical `02-3` network event, or `None` if it
/// is not one of our events or belongs to another kennel (`ctx` mismatch).
fn parse_event(sample: &[u8], ctx: u16) -> Option<Event> {
    if u32_at(sample, hdr::MAGIC)? != AUDIT_MAGIC {
        return None;
    }
    if u16_at(sample, hdr::CTX_BYTE)? != ctx {
        return None; // foreign/corrupt sample on a per-kennel buffer — drop it
    }
    let event_kind = u16_at(sample, hdr::KIND)?;
    let pid = u32_at(sample, hdr::PID)?;
    let comm = read_comm(sample.get(hdr::COMM..hdr::LEN)?);
    let (action, outcome) = action_for(event_kind)?;

    let event = Event::new(action, Resource::Net, outcome, Source::Bpf)
        .pid(pid)
        .comm(comm);

    match event_kind {
        kind::CONNECT_DENY | kind::CONNECT_ALLOW | kind::SENDMSG_DENY => {
            connect_fields(event, sample)
        }
        kind::BIND_REWRITE | kind::BIND_DENY => bind_fields(event, sample),
        kind::SOCK_DENY => Some(sock_fields(event, sample)),
        kind::SETSOCKOPT_FORCED => Some(sockopt_fields(event, sample)),
        _ => None,
    }
}

/// The canonical event name and envelope outcome for an `audit_kind`.
const fn action_for(event_kind: u16) -> Option<(&'static str, Outcome)> {
    let mapped = match event_kind {
        kind::CONNECT_DENY => ("net.connect-deny", Outcome::Deny),
        kind::CONNECT_ALLOW => ("net.connect-allow", Outcome::Allow),
        kind::BIND_REWRITE => ("net.bind-rewrite", Outcome::Allow),
        kind::BIND_DENY => ("net.bind-deny", Outcome::Deny),
        kind::SOCK_DENY => ("net.sock-create-deny", Outcome::Deny),
        kind::SETSOCKOPT_FORCED => ("net.setsockopt-forced", Outcome::Info),
        kind::SENDMSG_DENY => ("net.sendmsg-deny", Outcome::Deny),
        _ => return None,
    };
    Some(mapped)
}

/// `struct audit_payload_connect`: family @0, protocol @1, port @2 (net order),
/// addr @4 (v4 `u32` / v6 `[16]`). Adds `addr_family`, `addr`, `port`.
fn connect_fields(event: Event, sample: &[u8]) -> Option<Event> {
    let body = sample.get(hdr::LEN..)?;
    let family = *body.first()?;
    let port = port_at(body, 2)?;
    let (addr_family, addr) = read_addr(body, family, 4)?;
    Some(
        event
            .field("addr_family", Value::str(addr_family))
            .field("addr", Value::str(addr))
            .field("port", Value::Uint(u64::from(port))),
    )
}

/// `struct audit_payload_bind`: family @0, _pad @1, port @2 (net order),
/// requested @4 `[16]`, rewritten @20 `[16]`. Adds `addr_requested`,
/// `addr_rewritten`, `port`.
fn bind_fields(event: Event, sample: &[u8]) -> Option<Event> {
    let body = sample.get(hdr::LEN..)?;
    let family = *body.first()?;
    let port = port_at(body, 2)?;
    let requested = read_raw_addr(body, family, 4)?;
    let rewritten = read_raw_addr(body, family, 20)?;
    Some(
        event
            .field("addr_requested", Value::str(requested))
            .field("addr_rewritten", Value::str(rewritten))
            .field("port", Value::Uint(u64::from(port))),
    )
}

/// `struct audit_payload_sock`: family `u16` @0, type `u16` @2. Adds
/// `socket_family`, `socket_type`.
fn sock_fields(event: Event, sample: &[u8]) -> Event {
    let body = sample.get(hdr::LEN..).unwrap_or(&[]);
    let family = u16_at(body, 0).unwrap_or(0);
    let sock_type = u16_at(body, 2).unwrap_or(0);
    event
        .field("socket_family", Value::Uint(u64::from(family)))
        .field("socket_type", Value::Uint(u64::from(sock_type)))
}

/// `struct audit_payload_sockopt`: level `i32` @0, optname `i32` @4. Adds
/// `level`, `optname`.
fn sockopt_fields(event: Event, sample: &[u8]) -> Event {
    let body = sample.get(hdr::LEN..).unwrap_or(&[]);
    let level = i32_at(body, 0).unwrap_or(0);
    let optname = i32_at(body, 4).unwrap_or(0);
    event
        .field("level", Value::Int(i64::from(level)))
        .field("optname", Value::Int(i64::from(optname)))
}

/// Render the address at `off` for `family` as `(addr_family token, rendered IP)`.
fn read_addr(body: &[u8], family: u8, off: usize) -> Option<(&'static str, String)> {
    match family {
        f if f == AF_INET => Some(("ipv4", read_v4(body, off)?)),
        f if f == AF_INET6 => Some(("ipv6", read_v6(body, off)?)),
        _ => None,
    }
}

/// Render just the IP at `off` for `family` (for the bind requested/rewritten
/// pair, which share one `addr_family` implicitly). Unknown family ⇒ `None`.
fn read_raw_addr(body: &[u8], family: u8, off: usize) -> Option<String> {
    match family {
        f if f == AF_INET => read_v4(body, off),
        f if f == AF_INET6 => read_v6(body, off),
        _ => None,
    }
}

/// `AF_INET` / `AF_INET6` (Linux).
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

fn read_v4(body: &[u8], off: usize) -> Option<String> {
    let bytes: [u8; 4] = body.get(off..off.checked_add(4)?)?.try_into().ok()?;
    Some(Ipv4Addr::from(bytes).to_string())
}

fn read_v6(body: &[u8], off: usize) -> Option<String> {
    let bytes: [u8; 16] = body.get(off..off.checked_add(16)?)?.try_into().ok()?;
    Some(Ipv6Addr::from(bytes).to_string())
}

/// Read a network-order (big-endian) `u16` port at `off`.
fn port_at(body: &[u8], off: usize) -> Option<u16> {
    body.get(off..off.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_be_bytes)
}

/// Trim `comm` at the first NUL and decode it lossily (untrusted, workload-set).
fn read_comm(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(field.get(..end).unwrap_or(&[])).into_owned()
}

/// Read a native-endian `u16` at `off`.
fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    b.get(off..off.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_ne_bytes)
}

/// Read a native-endian `u32` at `off`.
fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_ne_bytes)
}

/// Read a native-endian `i32` at `off`.
fn i32_at(b: &[u8], off: usize) -> Option<i32> {
    b.get(off..off.checked_add(4)?)?
        .try_into()
        .ok()
        .map(i32::from_ne_bytes)
}

/// Remove a per-kennel pin dir and its pinned-map files (unlinking a pin drops that
/// reference). Missing is success; best-effort.
fn clear_pin_dir(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    let _ = std::fs::remove_dir(dir);
}

/// The per-kennel BPF pin dir for `id`: `/run/user/<uid>/kennel/bpf/<id>/`.
///
/// In the owning user's `$XDG_RUNTIME_DIR` (resolved from the uid, matching the
/// privhelper's `pin_root`, so the two agree without passing a path over the wire).
/// `/run/user/<uid>/` is systemd's per-user `0700` runtime tree, so the pins are
/// private structurally — no shared directory, no group, no permission tricks.
#[must_use]
pub fn pin_dir_for(id: &str) -> PathBuf {
    let uid = kennel_lib_syscall::unistd::real_uid();
    PathBuf::from(format!("/run/user/{uid}/kennel/bpf")).join(id)
}

/// Remove a kennel's BPF pin dir without a running drain (e.g. after a bring-up
/// failure that left pins behind). Best-effort; missing is success.
pub fn cleanup_pins(id: &str) {
    clear_pin_dir(&pin_dir_for(id));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a connect-deny sample: 40-byte header + connect body, assembled in
    /// field order (no slice-indexing). Header ints native order, port network
    /// order, v4 network-order octets. `comm` is NUL-padded to 16 bytes.
    fn connect_deny_sample(ctx: u16, pid: u32, comm: &str, addr: [u8; 4], port: u16) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&AUDIT_MAGIC.to_ne_bytes()); // magic   @0
        s.extend_from_slice(&1u16.to_ne_bytes()); // version @4
        s.extend_from_slice(&kind::CONNECT_DENY.to_ne_bytes()); // kind    @6
        s.extend_from_slice(&0u64.to_ne_bytes()); // ts_ns   @8
        s.extend_from_slice(&ctx.to_ne_bytes()); // ctx     @16
        s.extend_from_slice(&0u16.to_ne_bytes()); // length  @18
        s.extend_from_slice(&pid.to_ne_bytes()); // pid     @20
        let mut comm16 = [0u8; 16]; // comm    @24
        for (slot, byte) in comm16.iter_mut().zip(comm.bytes()) {
            *slot = byte;
        }
        s.extend_from_slice(&comm16);
        // body @40: family, protocol, port (net), addr (net octets)
        s.push(AF_INET);
        s.push(6); // IPPROTO_TCP
        s.extend_from_slice(&port.to_be_bytes());
        s.extend_from_slice(&addr);
        s
    }

    #[test]
    fn parses_a_connect_deny_event() {
        let s = connect_deny_sample(7, 4242, "curl", [169, 254, 169, 254], 80);
        let ev = parse_event(&s, 7).expect("parse");
        assert_eq!(ev.event, "net.connect-deny");
        assert_eq!(ev.outcome, Outcome::Deny);
        assert_eq!(ev.source, Source::Bpf);
        assert_eq!(ev.pid, Some(4242));
        assert_eq!(ev.comm.as_deref(), Some("curl"));
        // addr_family / addr / port land as fields.
        let has = |k: &str, want: &Value| ev.fields.iter().any(|(fk, fv)| *fk == k && fv == want);
        assert!(has("addr_family", &Value::str("ipv4")));
        assert!(has("addr", &Value::str("169.254.169.254")));
        assert!(has("port", &Value::Uint(80)));
    }

    #[test]
    fn drops_a_foreign_ctx_and_a_non_event() {
        let s = connect_deny_sample(7, 1, "x", [127, 0, 0, 1], 9);
        // Wrong ctx ⇒ dropped.
        assert!(parse_event(&s, 9).is_none());
        // Corrupt magic ⇒ dropped.
        let mut bad = s.clone();
        if let Some(b) = bad.first_mut() {
            *b ^= 0xff;
        }
        assert!(parse_event(&bad, 7).is_none());
        // Too short ⇒ dropped, not a panic.
        assert!(parse_event(s.get(..10).expect("len"), 7).is_none());
    }

    #[test]
    fn pin_dir_is_in_the_users_xdg_runtime_dir() {
        let uid = kennel_lib_syscall::unistd::real_uid();
        assert_eq!(
            pin_dir_for("ai-coding"),
            PathBuf::from(format!("/run/user/{uid}/kennel/bpf/ai-coding"))
        );
    }
}
