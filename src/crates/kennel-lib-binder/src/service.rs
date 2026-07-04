//! The node-0 service protocol: transaction verb codes and reply status bytes.
//!
//! Shared by `kenneld`'s context manager and the in-kennel clients (the af-unix
//! proxy, future facades). Internal-stable (`02-4-binder.md` §Node 0): both ends ship
//! from one release, so this module is the single source of the convention.

/// Node-0 transaction verbs (the `code` field). `IServiceManager`-style semantics;
/// the numeric codes are Project Kennel's own (not Android-wire-compatible).
pub mod verb {
    /// Register a service the caller provides — on a mesh bus, the cross-kennel service
    /// registration (codes 2–4 are retired `[binder]`-registry verbs).
    pub const ADD_SERVICE: u32 = 1;
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
    /// Register a callback node for a policy-mirrored bind port (the inbound mirror, §7.5.7).
    ///
    /// The push counterpart of [`BIND_INET`]: instead of `facade-client` polling, it transacts
    /// `REGISTER_MIRROR` once per mirrored port with [`crate::client::Connection::transact_node`],
    /// the payload `[transport: u8 | port: u16 be]` (see [`crate::service::inet::encode_bind_request`])
    /// plus its own binder node (flagged `FLAT_BINDER_FLAG_ACCEPTS_FDS`). kenneld acquires the
    /// translated handle, watches its death, and maps `port → handle`, replying
    /// [`crate::service::status::OK`] (or [`crate::service::status::DENIED`] if the port is not in
    /// the policy mirror set — registration is port-gated). The facade then blocks in a binder
    /// server loop. kenneld makes no per-connection policy decision — the `[net.bpf].bind` ACL
    /// already gated the bind.
    pub const REGISTER_MIRROR: u32 = 12;
    /// Deliver one inbound conduit to a registered mirror node (the inbound mirror, §7.5.7). **`oneway`.**
    ///
    /// kenneld pushes `DELIVER_INET` to the facade's registered node on each host-side accept, the
    /// payload `[transport: u8 | port: u16 be]` (decode with [`crate::service::inet::decode_port_prefix`],
    /// tolerant of the trailing fd object) carrying the conduit fd as a `BINDER_TYPE_FD` object via
    /// [`crate::client::Connection::transact_oneway_fd`]. One-way for backpressure: kenneld never
    /// blocks on the facade. The facade `connect`s its native listener at `<kennel-ip>:<port>` and
    /// splices.
    pub const DELIVER_INET: u32 = 13;
    /// Instantiate an ephemeral sibling kennel from an operator-signed template (dynamic spawn).
    ///
    /// `02-10` §7.12. A facade-class verb (no registry lock): the **requester workload** transacts
    /// `[template name@version | manifest-field patch]` (see [`crate::service::spawn`]) with
    /// `TF_ACCEPT_FDS` and carries **no** fds inbound. kenneld validates the grant, the content-pin,
    /// spawn-eligibility, and the patch (all verify-half), mints the stdio channel, and returns the
    /// requester's two ends ([`crate::ctxmgr::Reply::DataAndFds`]: the socketpair local end and the
    /// stderr pipe read end) with the `spawn-<uuid>`; construction proceeds asynchronously. Node 0
    /// keeps `accepts_fds` unset, so the only fd movement is this outbound reply
    /// (`binder-fd-passing-safety-verdict`).
    pub const SPAWN: u32 = 14;

    /// `kenneld` ← requester: **interrogate this kennel's `[spawn]` grant** (`02-10` §7.12).
    ///
    /// A read-only, fd-free facade-class verb carrying no request payload: the grant identifies the
    /// caller. `kenneld` replies (`[status | UTF-8 listing]`, the [`crate::service::spawn::encode_reply`]
    /// shape) with the allowed `name@version` templates, each with its per-requester-narrowed
    /// mutable-field manifest and the `max_instances`/live counts — so a workload can discover *what it
    /// may ask `SPAWN` for* rather than probe by trial. It exposes only the caller's own granted
    /// authority (nothing it could not learn by trying every `SPAWN`), and spawns nothing.
    pub const SPAWN_QUERY: u32 = 15;

    /// Resolve a mesh capability `name` and broker a connector to its provider (the cross-kennel
    /// capability mesh, `07-13-service-catalog.md` §7.13.4a).
    ///
    /// The standing-service sibling of [`SPAWN`]: where `SPAWN` mints a fresh kennel and injects its
    /// stdio fds, `SVC_CONNECT` *resolves* a named capability against the catalogue (§7.13.4) and
    /// brokers a connector to the already-declared provider — socket-activating it on first consume if
    /// it is enabled lazily (§7.13.6). A facade-class verb the consumer's facade transacts on the
    /// workload's behalf when the workload acts against its `at` endpoint, never the workload directly
    /// (request-don't-author, §7.12.1). The request carries only the capability
    /// [`name`](crate::service::svc_connect) (see that module for why the optional private `key` is
    /// matched broker-side and never on the wire); the reply is a [`crate::service::status`] byte, and
    /// on [`crate::service::status::OK`] the connector rides the binder object table per shape (a
    /// connected `af-unix` fd, a `binder-connector` node handle, or — for `dbus-name` — no object, the
    /// `IDBus` allow-set widened). A **consume-with-wait** blocks until the provider is
    /// declared-and-ready or the broker's deadline fires, returning
    /// [`crate::service::status::UNAVAILABLE`] on timeout (§7.13.4a).
    pub const SVC_CONNECT: u32 = 16;

    /// A mediation broker → kenneld (mesh node 0): **pull** the policy artifact for a session.
    ///
    /// The broker echoes the session's `(ctx, capability name)` (which kenneld handed it at
    /// [`crate::service::session::NEW_SESSION`]); kenneld selects the artifact by the consume's *shape
    /// from policy* from the running kennel's retained settled struct (the `dbus-name` `IDBus`
    /// filter). This is how a broker learns *what to allow* without kenneld holding a filter table.
    pub const GET_SESSION_POLICY: u32 = 17;

    /// The tun-broker → kenneld (its own **per-kennel bus**): register the sink node kenneld pushes
    /// egress sessions to.
    ///
    /// The `REGISTER_MIRROR` move for L3 egress: the standing tun-broker hands kenneld its callback
    /// node once at startup; kenneld acquires it, watches its death, and records it against the
    /// broker's ctx. Every `[net.udp]` consumer's session is then delivered to this one node
    /// ([`DELIVER_TUN_SESSION`]). The reply is a status byte.
    pub const REGISTER_TUN_SINK: u32 = 18;

    /// kenneld → the tun-broker (its per-kennel bus, the registered [`REGISTER_TUN_SINK`] node):
    /// mint one egress session for a `[net.udp]` consumer.
    ///
    /// The `DELIVER_INET` move: kenneld resolves the consumer's grants + tun `/64` in its own
    /// namespace and pushes them here (the [`tun_broker::encode_accept`](super::tun_broker::encode_accept)
    /// payload). The broker mints a
    /// fresh connected `SOCK_DGRAM` socketpair (frame boundaries preserved — no length prefix), spawns
    /// a per-session flow-mediator process on one end with those grants, and replies with the **other
    /// end's fd** — which kenneld hands to the consumer's `facade-tun` as its af-unix `[[consumes]]`
    /// connection. One socketpair + one mediator per consumer: separation, never a shared listener.
    pub const DELIVER_TUN_SESSION: u32 = 19;
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

    /// Decode the leading `[transport: u8 | port: u16 be]` prefix, **ignoring** any trailing bytes.
    ///
    /// Used for [`crate::service::verb::REGISTER_MIRROR`] and [`crate::service::verb::DELIVER_INET`],
    /// whose received payload carries the 3-byte prefix followed by alignment padding and a
    /// `flat_binder_object` (the node / the conduit fd). `None` if fewer than 3 bytes are present
    /// (untrusted input).
    #[must_use]
    pub fn decode_port_prefix(data: &[u8]) -> Option<(u8, u16)> {
        let [transport, hi, lo, ..] = data else {
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

        #[test]
        fn port_prefix_tolerates_trailing_object_bytes() {
            use super::decode_port_prefix;
            // Exactly the 3-byte prefix.
            assert_eq!(decode_port_prefix(&[0, 0x0B, 0xB8]), Some((0, 3000)));
            // Prefix followed by padding + a 24-byte flat_binder_object (the DELIVER_INET wire).
            let mut wire = vec![0, 0x0B, 0xB8, 0, 0, 0, 0, 0];
            wire.extend_from_slice(&[0xCC; 24]);
            assert_eq!(decode_port_prefix(&wire), Some((0, 3000)));
            // Fewer than 3 bytes is rejected.
            assert!(decode_port_prefix(&[0, 0x0B]).is_none());
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

    /// The mesh capability name a D-Bus consumer's `SVC_CONNECT` carries for the **session** bus.
    ///
    /// Distinct names per bus are how the consumer tells the mesh handler which filter to apply
    /// (the shared `svc_connect` codec carries only a name). Matches the `[[consumes]]` capability
    /// and the facade's request.
    pub const CAPABILITY_SESSION: &str = "org.projectkennel.dbus";

    /// The mesh capability name a D-Bus consumer's `SVC_CONNECT` carries for the **system** bus.
    pub const CAPABILITY_SYSTEM: &str = "org.projectkennel.dbus-system";

    /// Map a mesh capability `name` to the D-Bus bus byte it selects, or `None` if it is not a
    /// D-Bus capability. The mesh resolver uses this to pick the consumer's per-bus filter.
    #[must_use]
    pub fn capability_bus(name: &str) -> Option<u8> {
        match name {
            CAPABILITY_SESSION => Some(SESSION),
            CAPABILITY_SYSTEM => Some(SYSTEM),
            _ => None,
        }
    }

    /// The capability name for `bus` (the inverse of [`capability_bus`]).
    #[must_use]
    pub const fn capability_for_bus(bus: u8) -> &'static str {
        if bus == SYSTEM {
            CAPABILITY_SYSTEM
        } else {
            CAPABILITY_SESSION
        }
    }

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
        use super::{
            decode_conn, decode_open, decode_send, encode_conn, encode_open, encode_send, SESSION,
        };

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
/// PID 1 (Kennel book Vol 2 ch.2 (Process and Privilege Model)).
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
    /// A [`crate::service::verb::SPAWN`] was refused because the requester's `max_instances`
    /// concurrent-spawn ceiling is full (§7.12.7).
    ///
    /// Distinct from [`DENIED`] (a grant/pin/eligibility refusal) so a requester can tell "try again
    /// later" from "never".
    pub const CEILING_FULL: u8 = 6;
    /// A [`crate::service::verb::SVC_CONNECT`] resolved a capability whose provider is **not serving**.
    ///
    /// Either declared-but-failed (§7.13.7), or pending and the consume-with-wait deadline fired
    /// before it became ready (§7.13.4a, the cycle-safe timeout).
    ///
    /// Distinct from [`NOT_FOUND`] (nothing in the catalogue offers the `name`) precisely because
    /// §7.13.7 requires a consumer to tell "the capability exists but is down" from "no such
    /// capability" — a failed provider stays catalogued, so its consume is denied-and-audited as
    /// `UNAVAILABLE`, never a silent resolve-miss.
    pub const UNAVAILABLE: u8 = 7;
}

/// The [`verb::SPAWN`] request and reply wire (`02-10` §7.12).
///
/// **Request** (the requester is an untrusted workload, so kenneld decodes defensively): a
/// length-prefixed template `name@version`, then a count-prefixed list of `(field-path, value)`
/// manifest-patch pairs — `[tlen:u16be | template | n:u16be | (flen:u16be | field | vlen:u16be |
/// value) × n]`. Every length is `u16` big-endian; the whole patch is bounded to
/// `SPAWN_PATCH_MAX_BYTES` (64 KiB) at the spawner's compile, well under one `u16` per leaf.
///
/// **Reply**: a [`status`] byte, then — on [`status::OK`] — the `spawn-<uuid>` name. The two channel
/// fds ride the binder object table ([`crate::ctxmgr::Reply::DataAndFds`]), not these bytes.
pub mod spawn {
    /// The hard upper bound on a decoded `SPAWN` request (template + manifest patch).
    ///
    /// Enforced at [`decode_request`]. 64 KiB is far above any legitimate patch (the manifest is a
    /// handful of fields) while bounding an untrusted requester's transaction; the binder transaction
    /// buffer caps it further upstream, but the decoder asserts it directly so the stated invariant is
    /// real, not incidental.
    pub const SPAWN_PATCH_MAX_BYTES: usize = 64 * 1024;

    /// Frame a `u16`-big-endian length-prefixed string.
    fn put_str(out: &mut Vec<u8>, s: &str) {
        let len = u16::try_from(s.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(s.as_bytes().get(..usize::from(len)).unwrap_or(s.as_bytes()));
    }

    /// Advance `data` past `n` bytes, returning the consumed head (or `None` if short).
    fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        let (head, tail) = data.split_at_checked(n)?;
        *data = tail;
        Some(head)
    }

    /// Read one length-prefixed UTF-8 string off the cursor.
    fn take_str<'a>(data: &mut &'a [u8]) -> Option<&'a str> {
        let len = u16::from_be_bytes(take(data, 2)?.try_into().ok()?);
        core::str::from_utf8(take(data, usize::from(len))?).ok()
    }

    /// Encode a `SPAWN` request: the template ref and the manifest-field patch.
    #[must_use]
    pub fn encode_request(template: &str, patch: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        put_str(&mut out, template);
        out.extend_from_slice(&u16::try_from(patch.len()).unwrap_or(u16::MAX).to_be_bytes());
        for (field, value) in patch {
            put_str(&mut out, field);
            put_str(&mut out, value);
        }
        out
    }

    /// Decode a `SPAWN` request into `(template, patch)`.
    ///
    /// `None` for any malformed input — a short buffer, a non-UTF-8 or empty template/field, or
    /// trailing bytes after a well-formed request (all untrusted, all fail closed).
    #[must_use]
    pub fn decode_request(data: &[u8]) -> Option<(&str, Vec<(&str, &str)>)> {
        if data.len() > SPAWN_PATCH_MAX_BYTES {
            return None; // over the stated bound — fail closed before allocating the patch
        }
        let mut cur = data;
        let template = take_str(&mut cur)?;
        if template.is_empty() {
            return None;
        }
        let count = u16::from_be_bytes(take(&mut cur, 2)?.try_into().ok()?);
        let mut patch = Vec::new();
        for _ in 0..count {
            let field = take_str(&mut cur)?;
            let value = take_str(&mut cur)?;
            if field.is_empty() {
                return None;
            }
            patch.push((field, value));
        }
        // A well-formed request is fully consumed; trailing bytes are malformed.
        cur.is_empty().then_some((template, patch))
    }

    /// Encode a `SPAWN` reply body: a [`super::status`] byte, then (on [`super::status::OK`]) the
    /// `spawn-<uuid>` name. The channel fds are carried as binder objects, not in this payload.
    #[must_use]
    pub fn encode_reply(status: u8, uuid: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(uuid.len().saturating_add(1));
        out.push(status);
        out.extend_from_slice(uuid.as_bytes());
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn request_round_trips() {
            let patch = [("net.proxy.allow", "example.com:443"), ("fs.write", "/w")];
            let bytes = encode_request("net-fetch", &patch);
            let (template, got) = decode_request(&bytes).expect("decode");
            assert_eq!(template, "net-fetch");
            assert_eq!(
                got,
                vec![("net.proxy.allow", "example.com:443"), ("fs.write", "/w")]
            );
        }

        #[test]
        fn an_empty_patch_round_trips() {
            let bytes = encode_request("pure-compute", &[]);
            let (template, got) = decode_request(&bytes).expect("decode");
            assert_eq!(template, "pure-compute");
            assert!(got.is_empty());
        }

        #[test]
        fn trailing_garbage_is_rejected() {
            let mut bytes = encode_request("net-fetch", &[]);
            bytes.push(0xff);
            assert!(decode_request(&bytes).is_none());
        }

        #[test]
        fn a_short_buffer_and_empty_template_are_rejected() {
            assert!(decode_request(&[]).is_none());
            assert!(decode_request(&[0, 1]).is_none()); // claims 1 byte, none follows
            assert!(decode_request(&encode_request("", &[])).is_none()); // empty template
        }

        #[test]
        fn an_oversized_request_is_rejected_at_the_stated_bound() {
            // A request over SPAWN_PATCH_MAX_BYTES fails closed before the patch is walked — the
            // decoder enforces the bound the doc asserts, not merely the upstream buffer size.
            let big = vec![0u8; super::SPAWN_PATCH_MAX_BYTES + 1];
            assert!(decode_request(&big).is_none());
        }
    }
}

/// The [`verb::SVC_CONNECT`] request and reply wire (`07-13-service-catalog.md` §7.13.4a).
///
/// **Request**: the capability `name` to resolve, as bare bounded UTF-8 (`[name: UTF-8]`) — the
/// single-field idiom of [`inet::decode_request`]'s host, not the length-prefixed multi-field
/// [`spawn`] shape, because a `SVC_CONNECT` carries exactly one field. The name is the *public*
/// identifier (§7.13.1); the optional private **`key`** is deliberately **not** on the wire. kenneld
/// matches the key broker-side, reading the consumer's from its signed `[[consumes]]` (keyed by the
/// kernel-stamped caller identity and this `name`) and the provider's from its signed `[[provides]]`,
/// so the private token never transits the in-kennel facade boundary where a workload could observe
/// or forge it (§7.13.4 step 3). The facade names the capability; everything else — identity, key,
/// expected shape — is the signed grant the broker enforces.
///
/// **Reply**: a [`status`] byte. On [`status::OK`] the connector itself rides the binder object
/// table, not these bytes — a connected `af-unix` fd, a `binder-connector` node handle, or (for
/// `dbus-name`) no object at all — so [`svc_connect::decode_reply`] reads the leading status and
/// tolerates the trailing object, exactly as [`inet::decode_port_prefix`] does for the conduit fd. A
/// non-`OK`
/// status carries no object: [`status::DENIED`] (no signed `[[consumes]]`), [`status::NOT_FOUND`]
/// (nothing in the catalogue offers the name), [`status::UNAVAILABLE`] (resolved but the provider is
/// failed, or pending past the consume-with-wait deadline — §7.13.4a), or [`status::BAD_REQUEST`] (a
/// malformed name).
pub mod svc_connect {
    /// The hard upper bound on a `SVC_CONNECT` capability name.
    ///
    /// Matches the binderfs service-name cap (`02-4-binder.md` §Node 0, ≤ 255 bytes); a mesh name is
    /// a short dotted identifier (`org.projectkennel.wayland`), far under it.
    pub const SVC_NAME_MAX_BYTES: usize = 255;

    /// Encode a `SVC_CONNECT` request: the bare capability name.
    #[must_use]
    pub fn encode_request(name: &str) -> Vec<u8> {
        name.as_bytes().to_vec()
    }

    /// Decode a `SVC_CONNECT` request into the capability name. `None` for an empty, oversized
    /// (> [`SVC_NAME_MAX_BYTES`]), or non-UTF-8 payload — all untrusted, all fail closed.
    #[must_use]
    pub fn decode_request(data: &[u8]) -> Option<&str> {
        if data.is_empty() || data.len() > SVC_NAME_MAX_BYTES {
            return None;
        }
        core::str::from_utf8(data).ok()
    }

    /// Encode a `SVC_CONNECT` reply body: a [`super::status`] byte. On [`super::status::OK`] the
    /// connector (fd / node handle / nothing) is attached as a binder object, not in this payload.
    #[must_use]
    pub fn encode_reply(status: u8) -> Vec<u8> {
        vec![status]
    }

    /// Decode a `SVC_CONNECT` reply into its [`super::status`] byte, **ignoring** any trailing
    /// connector object the OK reply carries in the binder buffer. `None` only for an empty buffer
    /// (malformed).
    #[must_use]
    pub const fn decode_reply(data: &[u8]) -> Option<u8> {
        data.first().copied()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::service::status;

        #[test]
        fn request_round_trips() {
            let bytes = encode_request("org.projectkennel.wayland");
            assert_eq!(decode_request(&bytes), Some("org.projectkennel.wayland"));
        }

        #[test]
        fn request_rejects_empty_oversized_and_non_utf8() {
            assert!(decode_request(&[]).is_none()); // empty name
            assert!(decode_request(&vec![b'a'; SVC_NAME_MAX_BYTES + 1]).is_none()); // oversized
            assert!(decode_request(&[0xFF, 0xFE]).is_none()); // not UTF-8
        }

        #[test]
        fn request_accepts_the_name_at_the_exact_bound() {
            // The bound is inclusive: a name of exactly SVC_NAME_MAX_BYTES is valid.
            let name = "a".repeat(SVC_NAME_MAX_BYTES);
            assert_eq!(decode_request(name.as_bytes()), Some(name.as_str()));
        }

        #[test]
        fn reply_round_trips_each_status() {
            for s in [
                status::OK,
                status::DENIED,
                status::NOT_FOUND,
                status::UNAVAILABLE,
                status::BAD_REQUEST,
            ] {
                assert_eq!(decode_reply(&encode_reply(s)), Some(s));
            }
        }

        #[test]
        fn reply_reads_status_past_a_trailing_connector_object() {
            // The OK reply's data buffer is `[status | padding | flat_binder_object]` (the connector
            // fd/handle); decode_reply reads the leading status and tolerates the object bytes.
            let mut wire = encode_reply(status::OK);
            wire.extend_from_slice(&[0u8; 7]); // alignment padding
            wire.extend_from_slice(&[0xCC; 24]); // a 24-byte flat_binder_object
            assert_eq!(decode_reply(&wire), Some(status::OK));
        }

        #[test]
        fn reply_rejects_an_empty_buffer() {
            assert!(decode_reply(&[]).is_none());
        }
    }
}

/// The mesh bus wire protocol: the `ADD_SERVICE` and `SVC_CONNECT` verbs spoken on a **mesh
/// binderfs instance** (the binder analogue of the `af-unix` rendezvous directory, §7.13.4a).
///
/// The mesh bus reuses the per-kennel [`verb::ADD_SERVICE`] and [`verb::SVC_CONNECT`] codes but
/// with a different data layout: on the mesh, `ADD_SERVICE` carries a binder node alongside the
/// name (sent via [`crate::client::Connection::transact_node`]; the node arrives as a translated
/// `BINDER_TYPE_HANDLE` for the context manager), and `SVC_CONNECT`'s `OK` reply carries the
/// provider's handle as a `BINDER_TYPE_HANDLE` object (via [`crate::ctxmgr::Reply::Handle`]).
///
/// The name is the `endpoint` from the provider's `[[provides]]` (the public capability
/// identifier, e.g. `org.projectkennel.dbus-broker`).
pub mod mesh {
    /// The hard upper bound on a mesh service name, same as [`super::svc_connect::SVC_NAME_MAX_BYTES`].
    pub const MESH_NAME_MAX_BYTES: usize = 255;

    /// Encode a mesh `ADD_SERVICE` request data prefix: the bare service name.
    ///
    /// The caller sends this via [`crate::client::Connection::transact_node`], which appends the
    /// binder node object after the name bytes; the handler extracts both with
    /// [`decode_add_service`].
    #[must_use]
    pub fn encode_add_service(name: &str) -> Vec<u8> {
        name.as_bytes().to_vec()
    }

    /// Decode a mesh `ADD_SERVICE` request: extract the service name and the trailing binder
    /// handle (the provider's node, translated by the driver from `BINDER_TYPE_BINDER` to
    /// `BINDER_TYPE_HANDLE`).
    ///
    /// The data layout is `[name: UTF-8 | padding | flat_binder_object(24)]`. The name is
    /// everything before the last `FLAT_BINDER_OBJECT_SIZE` bytes (minus alignment padding).
    /// `None` for a short, empty, oversized, or non-UTF-8 name, or a missing/invalid handle
    /// object (all untrusted, all fail closed).
    #[must_use]
    pub fn decode_add_service(data: &[u8]) -> Option<(&str, u32)> {
        use crate::proto::{flat_binder_object_handle_value, FLAT_BINDER_OBJECT_SIZE};

        // The object sits at the end; everything before it (minus padding) is the name.
        let obj_start = data.len().checked_sub(FLAT_BINDER_OBJECT_SIZE)?;
        let handle = flat_binder_object_handle_value(data.get(obj_start..)?)?;

        // The name ends where alignment padding begins (round up to 8-byte boundary).
        // Walk backwards from obj_start to find the last non-zero byte before the object,
        // or use the fact that transact_node pads the name to 8-byte alignment.
        // The name bytes are everything before the padding; find the padding start.
        let name_end = (0..obj_start)
            .rev()
            .find(|&i| data.get(i).copied() != Some(0))
            .map_or(0, |i| i.saturating_add(1));
        if name_end == 0 || name_end > MESH_NAME_MAX_BYTES {
            return None;
        }
        let name = core::str::from_utf8(data.get(..name_end)?).ok()?;
        Some((name, handle))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::proto::{
            flat_binder_object_binder, BINDER_TYPE_HANDLE, FLAT_BINDER_OBJECT_SIZE,
        };

        /// Build a mock `ADD_SERVICE` payload as `transact_node` would lay it out:
        /// `[name bytes | padding to 8-byte alignment | flat_binder_object]`.
        /// The driver translates the `BINDER_TYPE_BINDER` to `BINDER_TYPE_HANDLE` for the
        /// context manager, so we hand-build the translated version.
        fn mock_add_service_data(name: &str, handle: u32) -> Vec<u8> {
            let mut buf = name.as_bytes().to_vec();
            let obj_off = buf.len().next_multiple_of(8);
            buf.resize(obj_off, 0); // padding
                                    // Build a BINDER_TYPE_HANDLE object (the translated form).
            let mut obj = flat_binder_object_binder(0, 0, 0);
            // Overwrite the type tag to BINDER_TYPE_HANDLE (as the driver would).
            obj[..4].copy_from_slice(&BINDER_TYPE_HANDLE.to_ne_bytes());
            // Set the handle in the union low (offset 8 within the object).
            obj[8..12].copy_from_slice(&handle.to_ne_bytes());
            buf.extend_from_slice(&obj);
            buf
        }

        #[test]
        fn add_service_round_trips() {
            let data = mock_add_service_data("org.projectkennel.dbus-broker", 42);
            let (name, handle) = decode_add_service(&data).expect("decode");
            assert_eq!(name, "org.projectkennel.dbus-broker");
            assert_eq!(handle, 42);
        }

        #[test]
        fn add_service_short_name() {
            let data = mock_add_service_data("x", 7);
            let (name, handle) = decode_add_service(&data).expect("decode");
            assert_eq!(name, "x");
            assert_eq!(handle, 7);
        }

        #[test]
        fn add_service_rejects_too_short() {
            // Shorter than a flat_binder_object — no room for name + object.
            assert!(decode_add_service(&[0u8; FLAT_BINDER_OBJECT_SIZE - 1]).is_none());
        }

        #[test]
        fn add_service_rejects_no_name() {
            // Just a binder object, no name bytes at all.
            let obj = [0u8; FLAT_BINDER_OBJECT_SIZE];
            assert!(decode_add_service(&obj).is_none());
        }

        #[test]
        fn add_service_rejects_bad_handle_type() {
            let mut data = mock_add_service_data("test-svc", 1);
            // Corrupt the type tag of the trailing object.
            let obj_start = data.len() - FLAT_BINDER_OBJECT_SIZE;
            *data.get_mut(obj_start).expect("object byte in range") ^= 0xFF;
            assert!(decode_add_service(&data).is_none());
        }
    }
}

/// Shared big-endian byte-codec primitives for the mesh control-channel wire protocols.
///
/// A cursor `take`, fixed integers, and `u16`-length-prefixed strings / string-lists, shared by
/// [`broker`] and [`tun_broker`] so the two control verbs cannot drift on their framing.
mod codec {
    /// Split `n` bytes off the front of the cursor, advancing it; `None` if short.
    pub(super) fn take<'a>(cur: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        let (head, tail) = cur.split_at_checked(n)?;
        *cur = tail;
        Some(head)
    }

    pub(super) fn put_u8(out: &mut Vec<u8>, v: u8) {
        out.push(v);
    }

    pub(super) fn take_u8(cur: &mut &[u8]) -> Option<u8> {
        take(cur, 1)?.first().copied()
    }

    pub(super) fn put_u16(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_be_bytes());
    }

    pub(super) fn take_u16(cur: &mut &[u8]) -> Option<u16> {
        let b = take(cur, 2)?;
        Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
    }

    /// A `u16`-count for a list, saturating past `u16::MAX`.
    pub(super) fn put_count(out: &mut Vec<u8>, n: usize) {
        put_u16(out, u16::try_from(n).unwrap_or(u16::MAX));
    }

    /// A `u16`-length-prefixed UTF-8 string.
    pub(super) fn put_str(out: &mut Vec<u8>, s: &str) {
        let len = u16::try_from(s.len()).unwrap_or(u16::MAX);
        put_u16(out, len);
        out.extend_from_slice(s.as_bytes().get(..usize::from(len)).unwrap_or(s.as_bytes()));
    }

    pub(super) fn take_str(cur: &mut &[u8]) -> Option<String> {
        let len = take_u16(cur)?;
        let s = core::str::from_utf8(take(cur, usize::from(len))?).ok()?;
        Some(s.to_owned())
    }

    /// A `u16`-count-prefixed list of strings.
    pub(super) fn put_str_list(out: &mut Vec<u8>, list: &[String]) {
        put_count(out, list.len());
        for s in list {
            put_str(out, s);
        }
    }

    pub(super) fn take_str_list(cur: &mut &[u8]) -> Option<Vec<String>> {
        let n = take_u16(cur)?;
        let mut list = Vec::with_capacity(usize::from(n));
        for _ in 0..n {
            list.push(take_str(cur)?);
        }
        Some(list)
    }
}

/// The generic mediation-session verbs — the shape-agnostic mesh handshake every mediation broker
/// (dbus, tun, …) shares (§7.13.4c).
///
/// A consumer's `SVC_CONNECT` to a mediated capability drives two generic transactions and no
/// shape-specific payload: kenneld sends [`NEW_SESSION`](session::NEW_SESSION) (ctx + capability
/// name, *no policy*) to the broker's control node, which mints a per-session node and replies with
/// it; kenneld forwards the
/// node to the consumer. The broker then **pulls** its policy lazily — on the session's first use it
/// transacts [`crate::service::verb::GET_SESSION_POLICY`] (the same ctx + name) to kenneld's node 0,
/// which selects the artifact by the consume's *shape from policy*. The artifact bytes are
/// shape-specific (a [`crate::service::broker`] filter, a [`crate::service::tun_broker`] grant set)
/// but the handshake is not.
pub mod session {
    use super::codec::{put_str, put_u16, take_str, take_u16};

    /// kenneld → a mediation broker (control node): mint a session for a consumer.
    ///
    /// Carries the consumer kennel's `ctx` and the `capability name` it connected — no policy. The
    /// broker mints a fresh per-session node, records `(ctx, name)` against it, replies with the node,
    /// and pulls the session's policy lazily ([`super::verb::GET_SESSION_POLICY`]) on first use.
    pub const NEW_SESSION: u32 = 1;

    /// Encode a session reference `[ctx: u16 be | name]`.
    ///
    /// The body of both [`NEW_SESSION`] (kenneld→broker) and [`super::verb::GET_SESSION_POLICY`]
    /// (broker→kenneld): the same `(ctx, name)` names the session on the way out and identifies it on
    /// the pull back.
    #[must_use]
    pub fn encode_ref(ctx: u16, name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        put_u16(&mut out, ctx);
        put_str(&mut out, name);
        out
    }

    /// Decode a session reference `[ctx: u16 be | name]`. `None` for malformed or trailing input.
    #[must_use]
    pub fn decode_ref(data: &[u8]) -> Option<(u16, String)> {
        let mut cur = data;
        let ctx = take_u16(&mut cur)?;
        let name = take_str(&mut cur)?;
        if !cur.is_empty() {
            return None;
        }
        Some((ctx, name))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn ref_round_trips() {
            let bytes = encode_ref(0x0042, "org.projectkennel.dbus");
            assert_eq!(
                decode_ref(&bytes),
                Some((0x0042, "org.projectkennel.dbus".to_owned()))
            );
        }

        #[test]
        fn ref_rejects_trailing_and_short() {
            let mut bytes = encode_ref(1, "x");
            bytes.push(0);
            assert!(decode_ref(&bytes).is_none(), "trailing garbage");
            assert!(decode_ref(&[]).is_none(), "short (no ctx)");
        }
    }
}

/// The D-Bus session-policy artifact: the compiled `IDBus` filter a `dbus-name` session is policed by.
///
/// Not a verb — the bytes kenneld returns from a broker's [`crate::service::verb::GET_SESSION_POLICY`] pull
/// (encoded from the consumer's retained `[dbus]` runtime) and the dbus-broker decodes to police the
/// session's traffic. The wire layout is unchanged from when kenneld pushed it; only the direction
/// (pull, not push) and the trigger (first use, not setup) moved.
pub mod broker {
    use super::codec::{put_str_list, put_u8, take, take_str_list};

    /// Encode an `ACCEPT_SESSION` request:
    /// `[bus: u8 | talk | call | broadcast | own | deny_talk]`.
    #[must_use]
    pub fn encode_accept(
        bus: u8,
        talk: &[String],
        call: &[String],
        broadcast: &[String],
        own: &[String],
        deny_talk: &[String],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        put_u8(&mut out, bus);
        put_str_list(&mut out, talk);
        put_str_list(&mut out, call);
        put_str_list(&mut out, broadcast);
        put_str_list(&mut out, own);
        put_str_list(&mut out, deny_talk);
        out
    }

    /// A decoded `ACCEPT_SESSION` request.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AcceptSession {
        /// The target bus: session (`0`) or system (`1`).
        pub bus: u8,
        /// Bus names the consumer may send method calls/signals to (talk).
        pub talk: Vec<String>,
        /// Allowed method calls, as `interface=member` filters.
        pub call: Vec<String>,
        /// Broadcast (signal) names the consumer may receive.
        pub broadcast: Vec<String>,
        /// Bus names the consumer may own.
        pub own: Vec<String>,
        /// Bus names explicitly denied for talk, overriding the talk set.
        pub deny_talk: Vec<String>,
    }

    /// Decode an `ACCEPT_SESSION` request. `None` for malformed input.
    #[must_use]
    pub fn decode_accept(data: &[u8]) -> Option<AcceptSession> {
        let mut cur = data;
        let &bus = take(&mut cur, 1)?.first()?;
        let talk = take_str_list(&mut cur)?;
        let call = take_str_list(&mut cur)?;
        let broadcast = take_str_list(&mut cur)?;
        let own = take_str_list(&mut cur)?;
        let deny_talk = take_str_list(&mut cur)?;
        if !cur.is_empty() {
            return None; // trailing garbage
        }
        Some(AcceptSession {
            bus,
            talk,
            call,
            broadcast,
            own,
            deny_talk,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn accept_round_trips() {
            let talk = vec!["org.freedesktop.portal.Desktop".to_owned()];
            let call = vec!["org.freedesktop.portal.FileChooser=OpenFile".to_owned()];
            let deny_talk = vec!["org.freedesktop.secrets".to_owned()];
            let bytes = encode_accept(1, &talk, &call, &[], &[], &deny_talk);
            let got = decode_accept(&bytes).expect("decode");
            assert_eq!(got.bus, 1);
            assert_eq!(got.talk, talk);
            assert_eq!(got.call, call);
            assert!(got.broadcast.is_empty());
            assert!(got.own.is_empty());
            assert_eq!(got.deny_talk, deny_talk);
        }

        #[test]
        fn accept_rejects_malformed() {
            let mut bad = encode_accept(0, &[], &[], &[], &[], &[]);
            bad.push(0xFF);
            assert!(decode_accept(&bad).is_none()); // trailing garbage
            assert!(decode_accept(&[]).is_none()); // short (no bus byte)
        }
    }
}

/// The UDP-egress session artifact (§8 / W2 Part D): the tun `/64` + compiled UDP grants for one
/// egress session.
///
/// The payload of [`crate::service::verb::DELIVER_TUN_SESSION`] — kenneld resolves a `[net.udp]`
/// consumer's grants + tun `/64` in its own namespace and pushes them to the tun-broker over the
/// broker's per-kennel bus. The broker decodes them, spawns a per-session flow mediator with them,
/// and never relays through kenneld on the data path. The categorical deny-CIDR floor is the broker's
/// own cgroup BPF filter, not on this wire.
///
/// **Wire layout (all big-endian):** see [`tun_broker::encode_accept`].
pub mod tun_broker {
    use super::codec::{put_count, put_str, put_u16, put_u8, take, take_str, take_u16, take_u8};

    /// The af-unix capability a `[net.udp]` consumer `[[consumes]]` (shape `af-unix`).
    ///
    /// The tun-broker's egress service: `facade-tun` `CONNECT_AFUNIX`es this on its per-kennel bus,
    /// and kenneld special-cases the name to the [`DELIVER_TUN_SESSION`](super::verb::DELIVER_TUN_SESSION)
    /// dance (resolve grants, deliver to the sink, hand back the minted session fd) rather than the
    /// generic rendezvous connect. The single source both `facade-tun` and kenneld reference, so the
    /// consume name cannot drift.
    pub const CAPABILITY: &str = "org.projectkennel.tun-udp";

    /// One name grant: a host pattern, its permitted ports (empty = any), and its transport.
    ///
    /// Mirrors the settled `NameRule`. `protocol` is carried on the wire (not implied) so a TCP
    /// grant rides this same `ACCEPT_SESSION` unchanged when the tun broker gains TCP mediation — the
    /// mechanism is transport-agnostic; UDP is only the first transport over it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Grant {
        /// The host pattern (dot-convention: `example.com` exact, `.example.com` apex+subdomains).
        pub name: String,
        /// Permitted ports; empty means any port.
        pub ports: Vec<u16>,
        /// Protocol ordinal (`0` any, `1` tcp, `2` udp) — the settled `Protocol` order.
        pub protocol: u8,
    }

    /// A decoded UDP `ACCEPT_SESSION`: the consumer's tun `/64` address and its grants.
    ///
    /// There is no deny set on the wire: the categorical deny-CIDR floor is the broker's cgroup BPF
    /// filter (`net.bpf`, on its `net.mode = host` cgroup), not a userspace re-check.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AcceptTunSession {
        /// The consumer's tun interface address (`::1` in its `/64`); its low 64 bits' prefix is the
        /// synthetic pool. Sixteen octets.
        pub tun_addr: [u8; 16],
        /// The UDP name grants (`udp_allow_names`).
        pub grants: Vec<Grant>,
    }

    /// Encode an `ACCEPT_SESSION` request:
    /// `[tun_addr: 16 | grants: count·(name, u16 nports·u16, u8 proto)]`.
    #[must_use]
    pub fn encode_accept(tun_addr: [u8; 16], grants: &[Grant]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&tun_addr);
        put_count(&mut out, grants.len());
        for g in grants {
            put_str(&mut out, &g.name);
            put_count(&mut out, g.ports.len());
            for &p in &g.ports {
                put_u16(&mut out, p);
            }
            put_u8(&mut out, g.protocol);
        }
        out
    }

    /// Decode an `ACCEPT_SESSION` request. `None` for malformed input.
    #[must_use]
    pub fn decode_accept(data: &[u8]) -> Option<AcceptTunSession> {
        let mut cur = data;
        let tun_addr = <[u8; 16]>::try_from(take(&mut cur, 16)?).ok()?;
        let n_grants = take_u16(&mut cur)?;
        let mut grants = Vec::with_capacity(usize::from(n_grants));
        for _ in 0..n_grants {
            let name = take_str(&mut cur)?;
            let n_ports = take_u16(&mut cur)?;
            let mut ports = Vec::with_capacity(usize::from(n_ports));
            for _ in 0..n_ports {
                ports.push(take_u16(&mut cur)?);
            }
            let protocol = take_u8(&mut cur)?;
            grants.push(Grant {
                name,
                ports,
                protocol,
            });
        }
        if !cur.is_empty() {
            return None; // trailing garbage
        }
        Some(AcceptTunSession { tun_addr, grants })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn accept_round_trips() {
            let tun = [
                0xfd, 0x6b, 0x6e, 0x9c, 0x69, 0x1c, 0x80, 0x01, 0, 0, 0, 0, 0, 0, 0, 1,
            ];
            let grants = vec![
                Grant {
                    name: "example.com".to_owned(),
                    ports: vec![443, 53],
                    protocol: 2,
                },
                Grant {
                    name: ".internal.example".to_owned(),
                    ports: Vec::new(),
                    protocol: 2,
                },
            ];
            let bytes = encode_accept(tun, &grants);
            let got = decode_accept(&bytes).expect("decode");
            assert_eq!(got.tun_addr, tun);
            assert_eq!(got.grants, grants);
        }

        #[test]
        fn accept_rejects_malformed() {
            let tun = [0u8; 16];
            let mut bad = encode_accept(tun, &[]);
            bad.push(0x00);
            assert!(decode_accept(&bad).is_none(), "trailing garbage");
            assert!(decode_accept(&[]).is_none(), "short (no tun addr)");
            assert!(decode_accept(&[0u8; 15]).is_none(), "truncated tun addr");
        }
    }
}
