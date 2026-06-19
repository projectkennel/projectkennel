//! The node-0 service protocol: transaction verb codes and reply status bytes.
//!
//! Shared by `kenneld`'s context manager and the in-kennel clients (the af-unix
//! proxy, future facades). Internal-stable (`02-4-binder.md` §Node 0): both ends ship
//! from one release, so this module is the single source of the convention.

/// Node-0 transaction verbs (the `code` field). `IServiceManager`-style semantics;
/// the numeric codes are Project Kennel's own (not Android-wire-compatible).
pub mod verb {
    /// Register a service the caller provides.
    pub const ADD_SERVICE: u32 = 1;
    /// Resolve a service name.
    pub const GET_SERVICE: u32 = 2;
    /// Whether a service is declared for the caller.
    pub const IS_DECLARED: u32 = 3;
    /// The service names the caller is granted to look up.
    pub const LIST_SERVICES: u32 = 4;
    /// Connect a granted `AF_UNIX` socket and return the connected fd (the af-unix
    /// facade; sent with `transact_fd`, the reply carries the socket fd).
    pub const CONNECT_AFUNIX: u32 = 5;
    /// Request an outbound network connection (the `INet` egress facade, §7.5.2).
    ///
    /// `facade-socks5` transacts the request payload `[transport: u8 | port: u16
    /// big-endian | host: UTF-8]` (see [`crate::service::transport`]) to kenneld, which decides under
    /// `[net.proxy]`, resolves the name, pins the vetted address, and (with the conduit
    /// built) returns the connection fd.
    pub const CONNECT_INET: u32 = 6;
    /// Collect a pending inbound connection for a policy-mirrored bind port (§7.5.7).
    ///
    /// The reverse of [`CONNECT_INET`]: `facade-client` transacts the request `[transport: u8 |
    /// port: u16 big-endian]` (see [`crate::service::inet::encode_bind_request`]) to kenneld; if a
    /// host-side connection to that mirrored port is waiting, the reply carries the conduit fd
    /// ([`crate::ctxmgr::Reply::Fd`]); otherwise the reply is the [`crate::service::status::AGAIN`]
    /// status byte and `facade-client` re-arms. kenneld makes NO policy decision here — the
    /// `[net.bpf].bind` cgroup ACL already gated the bind; this is a pure socketpair handoff. The
    /// handler never parks a looper (it bounded-polls then returns).
    pub const BIND_INET: u32 = 7;
    /// Register a workload bus connection for D-Bus mediation (the `IDBus` facade, §7.7.2).
    ///
    /// `facade-dbus` transacts `[conn-id: u32 | bus: u8]` (see [`crate::service::dbus`]) once
    /// per accepted workload connection. kenneld binds the `conn-id` to the `host-dbus` delegate
    /// for that bus and replies [`crate::service::status::OK`], or
    /// [`crate::service::status::DENIED`] if the policy did not enable the bus. kenneld is the
    /// **membrane**: the kennel reaches `host-dbus` only by transacting these verbs to node 0
    /// (§7.7.2a) — never a raw conduit fd.
    pub const DBUS_OPEN: u32 = 8;
    /// Send one mediated D-Bus message (the `IDBus` facade, §7.7.2). **`oneway`.**
    ///
    /// `facade-dbus` transacts `[conn-id: u32 | frame: IDBus TLV]` (see [`crate::dbus`]); kenneld
    /// rate-limits it at the membrane (§7.7.2c), then relays the frame to the bound `host-dbus`
    /// over the owner-only pipe. No reply — the bus reply returns asynchronously via
    /// [`DBUS_RECV`], so no kenneld thread is held per call.
    pub const DBUS_SEND: u32 = 9;
    /// Long-poll for the next inbound D-Bus frame on a connection (the `IDBus` facade, §7.7.2).
    ///
    /// `facade-dbus` keeps one `[conn-id: u32]` transaction outstanding; kenneld parks it and
    /// replies with the next inbound TLV frame `host-dbus` pushes for that connection — a reply
    /// or error to a prior [`DBUS_SEND`], or an allowlisted signal (§7.7.4) — or the
    /// [`crate::service::status::AGAIN`] byte to re-arm. The facade demultiplexes replies to
    /// calls by `reply_serial` itself.
    pub const DBUS_RECV: u32 = 10;
    /// Tear down a workload bus connection (the `IDBus` facade, §7.7.2). **`oneway`.**
    ///
    /// `facade-dbus` transacts `[conn-id: u32]` when the workload's connection closes; kenneld
    /// drops the connection state and tells `host-dbus` to release its serial map for it.
    pub const DBUS_CLOSE: u32 = 11;
}

/// The transport byte in a [`verb::CONNECT_INET`] request (the wire is internal-stable;
/// both ends ship from one release). Mirrors `host_netproxy::allow::Transport`.
pub mod transport {
    /// TCP (SOCKS5 `CONNECT`).
    pub const TCP: u8 = 0;
    /// UDP (SOCKS5 `UDP ASSOCIATE`; reserved — not yet served).
    pub const UDP: u8 = 1;
}

/// The [`verb::CONNECT_INET`] request wire: `[transport: u8 | port: u16 big-endian | host: UTF-8]`.
///
/// The single source of the layout: `facade-socks5` [`inet::encode_request`]s, kenneld
/// [`inet::decode_request`]s (then maps the transport byte and the host to its policy types). The
/// transport byte's validity is the decoder's caller's concern — this layer only frames bytes.
pub mod inet {
    /// Encode a `CONNECT_INET` request.
    #[must_use]
    pub fn encode_request(transport: u8, port: u16, host: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(host.len().saturating_add(3));
        out.push(transport);
        out.extend_from_slice(&port.to_be_bytes());
        out.extend_from_slice(host.as_bytes());
        out
    }

    /// Decode a `CONNECT_INET` request into `(transport byte, port, host)`. `None` for a short,
    /// empty/oversized-host, or non-UTF-8 payload (all untrusted).
    #[must_use]
    pub fn decode_request(data: &[u8], max_host: usize) -> Option<(u8, u16, &str)> {
        let [transport, hi, lo, host @ ..] = data else {
            return None;
        };
        if host.is_empty() || host.len() > max_host {
            return None;
        }
        let host = core::str::from_utf8(host).ok()?;
        Some((*transport, u16::from_be_bytes([*hi, *lo]), host))
    }

    /// Encode a [`crate::service::verb::BIND_INET`] request: `[transport: u8 | port: u16 big-endian]`.
    ///
    /// No host: the in-kennel target is the kennel's own loopback at `port`, which kenneld already
    /// knows. The reverse of [`encode_request`].
    #[must_use]
    pub fn encode_bind_request(transport: u8, port: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(3);
        out.push(transport);
        out.extend_from_slice(&port.to_be_bytes());
        out
    }

    /// Decode a `BIND_INET` request into `(transport byte, port)`. `None` for a payload that is not
    /// exactly 3 bytes (untrusted input; the transport byte's validity is the caller's concern).
    #[must_use]
    pub fn decode_bind_request(data: &[u8]) -> Option<(u8, u16)> {
        let [transport, hi, lo] = data else {
            return None;
        };
        Some((*transport, u16::from_be_bytes([*hi, *lo])))
    }

    #[cfg(test)]
    mod tests {
        use super::{decode_bind_request, decode_request, encode_bind_request, encode_request};

        #[test]
        fn round_trips() {
            let bytes = encode_request(0, 443, "api.openai.com");
            assert_eq!(
                decode_request(&bytes, 255),
                Some((0, 443, "api.openai.com"))
            );
        }

        #[test]
        fn rejects_short_empty_oversized_and_non_utf8() {
            assert!(decode_request(&[0, 0x01], 255).is_none()); // short
            assert!(decode_request(&[0, 0x01, 0xBB], 255).is_none()); // empty host
            assert!(decode_request(&[0, 0x01, 0xBB, b'a', b'b'], 1).is_none()); // oversized
            assert!(decode_request(&[0, 0x01, 0xBB, 0xFF, 0xFE], 255).is_none());
            // !utf8
        }

        #[test]
        fn bind_request_round_trips() {
            let bytes = encode_bind_request(0, 3000);
            assert_eq!(bytes, vec![0, 0x0B, 0xB8]); // transport=0, 3000 = 0x0BB8 big-endian
            assert_eq!(decode_bind_request(&bytes), Some((0, 3000)));
        }

        #[test]
        fn bind_request_rejects_wrong_length() {
            assert!(decode_bind_request(&[0, 0x0B]).is_none()); // short (2 bytes)
            assert!(decode_bind_request(&[0, 0x0B, 0xB8, 0x00]).is_none()); // long (4 bytes)
            assert!(decode_bind_request(&[]).is_none()); // empty
        }
    }
}

/// The request wire for the D-Bus mediation verbs ([`verb::DBUS_OPEN`]/[`verb::DBUS_SEND`]/
/// [`verb::DBUS_RECV`]/[`verb::DBUS_CLOSE`]).
///
/// Every request leads with a 4-byte big-endian **connection id** the facade allocates per
/// workload bus connection; kenneld routes by it and never interprets it. `DBUS_OPEN` adds a
/// bus selector byte; `DBUS_SEND` appends the [`crate::dbus`] TLV frame; `DBUS_RECV`/`DBUS_CLOSE`
/// are the id alone. The wire is internal-stable (both ends ship from one release).
pub mod dbus {
    /// The session bus selector byte (mirrors `crate::dbus::Bus::Session`).
    pub const SESSION: u8 = 0;
    /// The system bus selector byte.
    pub const SYSTEM: u8 = 1;

    /// Encode a [`super::verb::DBUS_OPEN`] request: `[conn_id: u32 be | bus: u8]`.
    #[must_use]
    pub fn encode_open(conn_id: u32, bus: u8) -> Vec<u8> {
        let mut out = Vec::with_capacity(5);
        out.extend_from_slice(&conn_id.to_be_bytes());
        out.push(bus);
        out
    }

    /// Decode a `DBUS_OPEN` request into `(conn_id, bus)`. `None` for any payload that is not
    /// exactly 5 bytes (untrusted; the bus byte's validity is the caller's concern).
    #[must_use]
    pub fn decode_open(data: &[u8]) -> Option<(u32, u8)> {
        let [a, b, c, d, bus] = data else {
            return None;
        };
        Some((u32::from_be_bytes([*a, *b, *c, *d]), *bus))
    }

    /// Encode a [`super::verb::DBUS_SEND`] request: `[conn_id: u32 be | frame bytes]`.
    #[must_use]
    pub fn encode_send(conn_id: u32, frame: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(frame.len().saturating_add(4));
        out.extend_from_slice(&conn_id.to_be_bytes());
        out.extend_from_slice(frame);
        out
    }

    /// Decode a `DBUS_SEND` request into `(conn_id, frame bytes)`. `None` for a payload shorter
    /// than the 4-byte id.
    #[must_use]
    pub fn decode_send(data: &[u8]) -> Option<(u32, &[u8])> {
        let [a, b, c, d, frame @ ..] = data else {
            return None;
        };
        Some((u32::from_be_bytes([*a, *b, *c, *d]), frame))
    }

    /// Encode a bare `[conn_id: u32 be]` request ([`super::verb::DBUS_RECV`]/[`super::verb::DBUS_CLOSE`]).
    #[must_use]
    pub fn encode_conn(conn_id: u32) -> Vec<u8> {
        conn_id.to_be_bytes().to_vec()
    }

    /// Decode a bare connection-id request. `None` unless the payload is exactly 4 bytes.
    #[must_use]
    pub fn decode_conn(data: &[u8]) -> Option<u32> {
        let [a, b, c, d] = data else { return None };
        Some(u32::from_be_bytes([*a, *b, *c, *d]))
    }

    #[cfg(test)]
    mod tests {
        use super::{decode_conn, decode_open, decode_send, encode_conn, encode_open, encode_send, SESSION};

        #[test]
        fn open_round_trips() {
            assert_eq!(decode_open(&encode_open(7, SESSION)), Some((7, SESSION)));
            assert!(decode_open(&[0, 0, 0, 1]).is_none()); // too short
        }

        #[test]
        fn send_round_trips_with_frame() {
            let bytes = encode_send(42, &[0xAA, 0xBB]);
            let (id, frame) = decode_send(&bytes).expect("decode");
            assert_eq!(id, 42);
            assert_eq!(frame, &[0xAA, 0xBB]);
            assert!(decode_send(&[0, 0, 1]).is_none()); // shorter than the id
        }

        #[test]
        fn conn_round_trips() {
            assert_eq!(decode_conn(&encode_conn(0xDEAD_BEEF)), Some(0xDEAD_BEEF));
            assert!(decode_conn(&[0, 0, 0]).is_none());
            assert!(decode_conn(&[0, 0, 0, 0, 0]).is_none());
        }
    }
}

/// Node-0 **lifecycle/config verbs** spoken only by `kennel-bin-init`, the kennel's uid-0
/// PID 1 (`docs/design/07-2-kennel-bin-init.md` §7.2.4).
///
/// A distinct high code range, disjoint from the [`verb`] registry codes (1–5), so the
/// two protocols never collide and `kenneld` can gate the lifecycle branch separately:
/// it serves these **only** when the kernel-stamped
/// `sender_pid == init_host_pid && sender_euid == 0` (the privhelper reports
/// `init_host_pid`; a host-side context manager sees host pids, not the kennel-internal
/// `1`).
pub mod lifecycle {
    /// `kennel-bin-init` pulls its supervision-half.
    ///
    /// The reply carries the `kennel-lib-spawn::wire::encode_supervision` bytes as a plain data
    /// reply. (The interactive pty does NOT ride binder: the privhelper factory passes the
    /// return socket on the construction channel and `kennel-bin-init` inherits it at
    /// `kennel_lib_syscall::pty::PTY_RETURN_FD` — `07-2`, decoupled from the bus.)
    pub const GET_SANDBOX_PLAN: u32 = 0x100;
    /// `kennel-bin-init` reports the facades are up (the facade→pid map), before it execs
    /// the workload.
    pub const NOTIFY_BOOT_SYNC: u32 = 0x101;
    /// `kennel-bin-init` reports a facade died (so `kenneld` can audit / tear down).
    pub const NOTIFY_FACADE_CRASH: u32 = 0x102;
    /// `kennel-bin-init` reports it is about to `execve` the workload.
    pub const NOTIFY_WORKLOAD_EXEC: u32 = 0x103;
    /// `kennel-bin-init` reports it re-forked a crashed facade (payload: the new host pid).
    pub const NOTIFY_FACADE_RESTART: u32 = 0x104;
    /// `kennel-bin-init`'s TTL timer fired (§9.7) — a **blocking** request.
    ///
    /// kenneld freezes the kennel's cgroup (atomic suspend — kennel-bin-init is mid-call, so it just
    /// blocks), audits, and decides per the policy's expiry action. The **reply** byte is
    /// [`crate::service::ttl::RESUME`] (kenneld thawed; the call returns and the kennel picks up where it left
    /// off) or [`crate::service::ttl::TERMINATE`] (kennel-bin-init should exit; kenneld may also kill the frozen
    /// cgroup outright). No payload.
    pub const NOTIFY_TTL_EXPIRED: u32 = 0x105;
}

/// The reply byte to a [`lifecycle::NOTIFY_TTL_EXPIRED`] call.
pub mod ttl {
    /// Resume: kenneld thawed the cgroup; the workload continues (`warn`, or `renew`
    /// when no operator was available to prompt). The one-shot alarm is *not* re-armed.
    pub const RESUME: u8 = 0;
    /// Terminate: the kennel should stop (`exit`, or a `renew` the operator declined);
    /// kenneld has frozen and will kill the cgroup.
    pub const TERMINATE: u8 = 1;
    /// Renew: kenneld thawed the cgroup and the operator approved another lifetime.
    ///
    /// `kennel-bin-init` re-arms its one-shot TTL alarm for a further period (§9.7). The
    /// re-arm is the one cooperative step — benign (it only sets a new future deadline, never
    /// evades one), so a compromised init that ignores it merely forgoes its own extension.
    pub const RENEW: u8 = 2;
}

/// Reply status byte (the first byte of a data reply).
pub mod status {
    /// Success (registered / found / true).
    pub const OK: u8 = 0;
    /// Refused by policy (not declared for this caller).
    pub const DENIED: u8 = 1;
    /// Permitted but no such registered service.
    pub const NOT_FOUND: u8 = 2;
    /// Refused: the name is in the reserved `org.projectkennel.*` namespace.
    pub const REFUSED_RESERVED: u8 = 3;
    /// The request was malformed (bad verb, oversized/!UTF-8 name).
    pub const BAD_REQUEST: u8 = 4;
    /// No work is ready yet — retry.
    ///
    /// The reply to a [`crate::service::verb::BIND_INET`] when no host-side connection is pending
    /// for the port; `facade-client` re-arms after a short backoff. Lets the inbound handler return
    /// promptly instead of parking a binder looper (§7.5.7).
    pub const AGAIN: u8 = 5;
}
