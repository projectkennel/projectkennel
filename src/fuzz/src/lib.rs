//! Fuzz / property harnesses for Project Kennel's untrusted-input parsers.
//!
//! # Purpose
//!
//! CODING-STANDARDS.md §10.6: every parser of untrusted input carries a fuzz
//! target. The boundaries (§10.1) covered here are the egress front-door — both
//! the workload-facing SOCKS5/HTTP-proxy parse (the facade's protocol classifier
//! and HTTP request head) and the `CONNECT_INET` request wire the facade frames on
//! to kenneld — the binder driver-return command stream, the IPC wire formats (the
//! kenneld control protocol, the privhelper packed-struct request, and the enforcement-plan
//! wire a privileged process decodes), the D-Bus facade's incoming-message decoder
//! (the workload's bus client speaks raw D-Bus wire to `facade-dbus`, 07-7 §7.7),
//! and the signed-policy reader. Each must, for *any* input, return `Ok`/`Err`/`None`
//! — never panic, never hang, never read out of bounds.
//!
//! # Approach (Path C)
//!
//! [`arbitrary`] turns a flat fuzzer seed into a sequence of byte chunks, each
//! fed to every parser ([`run`]). [`run`] is the entry a cargo-fuzz
//! `fuzz_target!` would call if/when coverage-guided fuzzing is adopted; until
//! then the `#[cfg(test)]` runner below drives it over a deterministic
//! pseudo-random corpus, so `cargo test -p kennel-fuzz` exercises every parser.
//! No `libfuzzer-sys`, no C++ runtime, no proc-macro — `arbitrary` is the only
//! dependency, and only its byte-carving (`Unstructured`) is used.
//!
//! # Non-goals
//!
//! This is a *robustness* harness (no panics on adversarial bytes), not a
//! correctness oracle. Round-trip/differential properties live in each crate's
//! own unit tests.

use arbitrary::Unstructured;

/// Feed `data` to every untrusted-input parser. The parser results are
/// intentionally discarded: the property under test is "does not panic / hang /
/// misbehave", and a returned `Err` is a *correct* outcome for junk input.
pub fn fuzz_parsers(data: &[u8]) {
    // The egress front-door has two untrusted hops. (1) The workload speaks SOCKS5/HTTP-proxy to the
    // in-kennel facade (facade-socks5): the leading byte classifies the protocol, and an HTTP client
    // sends a `CONNECT host:port` / absolute-form request head — both fully workload-controlled bytes.
    let _ = kennel_facade::socks5::protocol::detect(data);
    let _ = kennel_facade::socks5::http::parse_request(data);
    // (2) The facade then frames the connect as a CONNECT_INET request `[transport | port | host]`
    // and transacts it to kenneld over binder; the host (a DNS name) is workload-controlled (07-5).
    let _ = kennel_lib_binder::service::inet::decode_request(data, 255);
    // (3) The UDP-egress front-door (facade-tun, W2 Part C): facade-tun copies whole IPv6 L3 frames
    // both ways behind a shape predicate, and the EGRESS direction parses fully workload-controlled
    // frames straight off the tun. Fixed endpoints (a kennel tun addr + its /64) stand in for the
    // per-kennel values; `data` is the raw frame. Must never panic/over-read on any bytes.
    {
        let kennel_addr = std::net::Ipv6Addr::new(0xfd6b, 0x6e9c, 0x691c, 0x8001, 0, 0, 0, 1);
        let prefix = [0xfd, 0x6b, 0x6e, 0x9c, 0x69, 0x1c, 0x80, 0x01];
        let _ = kennel_facade::tun::egress_ok(data, kennel_addr, prefix);
        let _ = kennel_facade::tun::ingress_ok(data, kennel_addr, prefix);
    }

    // The UDP-egress broker's DNS naming shim (W2 Part D): `respond` parses the workload's DNS
    // query via simple-dns and builds the AAAA/NODATA reply; `query_question` reads the question.
    // `data` is the raw query — fully workload-controlled. Must never panic on any bytes.
    {
        let grant = |name: &str| kennel_lib_policy::settled::NameRule {
            name: name.to_owned(),
            ports: Vec::new(),
            protocol: kennel_lib_policy::settled::Protocol::Udp,
        };
        let allow = kennel_tun_broker::shim::Allowlist::new([grant("example.com"), grant(".test")]);
        let mut pool =
            kennel_tun_broker::shim::Pool::new([0xfd, 0x6b, 0x6e, 0x9c, 0x69, 0x1c, 0x80, 0x01]);
        let _ = kennel_tun_broker::shim::respond(
            data,
            &allow,
            &mut pool,
            &std::collections::HashSet::new(),
        );
        let _ = kennel_tun_broker::query_question(data);
        // The flow forwarder reads an L3 frame facade-tun handed it (workload-derived bytes) to
        // extract the routed name/ports/payload; it must never panic on any frame.
        let _ = kennel_tun_broker::forward::route(data, &pool);
    }

    // IPC wire formats: the kenneld control protocol and the privhelper request.
    let _ = kenneld::control::Request::decode(data);
    let _ = kenneld::control::Response::decode(data);
    let _ = kennel_privhelper::wire::Request::decode(data);

    // The enforcement-plan wire (07-2): kenneld builds these bytes, but a *privileged* process
    // decodes them — the privhelper factory the construction-half, root `kennel-bin-init` the
    // supervision-half. A compromised kenneld supplying a malformed plan must hit a clean
    // `PlanWireError`, never a panic or over-read in the root decoder.
    let _ = kennel_lib_spawn::wire::decode_plan(data);
    let _ = kennel_lib_spawn::wire::decode_construction(data);
    let _ = kennel_lib_spawn::wire::decode_supervision(data);

    // The binder driver-return command stream: the read buffer the kernel fills
    // carries sender-controlled transaction payloads (07-1/02-4). The decoder must
    // bounds-check any junk; a single parse plus the transaction-data decode.
    let _ = kennel_lib_binder::proto::parse(data);
    let _ = kennel_lib_binder::proto::TransactionData::from_bytes(data);
    let _ = kennel_lib_binder::proto::flat_binder_object_fd_value(data);

    // The signed-policy reader: an empty trust store means the signature check
    // fails, but the TOML parse + schema-version gate run on the untrusted bytes
    // first, which is the surface we are fuzzing.
    let keys = kennel_lib_policy::KeySet::new();
    let _ = kennel_lib_policy::verify_settled(data, &keys);

    // The TOML parser itself (#228), directly: `verify_settled` stops at the first schema mismatch,
    // so deserialising into `IgnoredAny` drives every parser path on any document shape.
    let _ = kennel_lib_toml::from_slice::<serde::de::IgnoredAny>(data);

    // The terminal-escape filter: `data` stands in for workload PTY output (fully
    // attacker-controlled). The filter runs the vte ANSI state machine over it; the
    // robustness property is "no panic / hang on any bytes". The *security* invariant
    // (no OSC-52 introducer survives) is asserted in the dedicated test below.
    let _ = kennel_lib_term::filter(data, kennel_lib_term::FilterPolicy::default());

    // The D-Bus facade's incoming-message decoder (07-7 §7.7). The workload's bus
    // client speaks raw D-Bus wire to `facade-dbus`; the facade decodes the header
    // (destination/path/interface/member/signature — the entire allowlist surface)
    // and walks the body, all from fully workload-controlled bytes.
    fuzz_dbus_incoming(data);

    // The facade's SASL handshake (07-7 §7.7.2): the workload's bus client speaks the
    // line-based auth exchange before any message; `data` stands in for those bytes,
    // fed in one push. Bounded line parser — must never panic/hang on any input.
    let mut sasl = kennel_lib_dbus::sasl::SaslServer::new();
    let _ = sasl.push(data);

    // The typed IDBus conduit frame (07-7 §7.7.2): the dbus-broker (trusted) decodes frames
    // the in-kennel (untrusted) facade produced, so the small flat frame decoder reads
    // untrusted input. `data` is the frame payload after the length prefix.
    let _ = kennel_lib_dbus::wire::Frame::decode(data);
    let _ = kennel_lib_dbus::wire::frame_len(data);

    // The facade's whole connection driver (07-7 §7.7.2): `data` stands in for the bytes
    // a workload's bus client sends — SASL handshake then the binary message stream. This
    // exercises the SASL state machine, the mini-sansio decode loop, body extraction, and
    // the Hello/refuse-to-broker handling end to end. Must never panic/hang on any input.
    let mut facade = kennel_lib_dbus::server::Facade::new(kennel_lib_dbus::wire::Bus::Session);
    let _ = facade.on_workload_bytes(data);
}

/// Drive `data` through `mini-sansio-dbus`'s public sans-IO read loop exactly as
/// `facade-dbus` drives it off the conduit socket: `wants` reports the next slice the
/// decoder needs, we fill it from `data`, `satisfy_read` reframes and — once a whole
/// message has arrived — yields an [`IncomingMessage`] we then walk in full. The
/// `readbuf` is bounded; a header claiming a longer message than fits is a clean
/// `ReadBufIsTooShort`, the same refusal the facade gives an over-large frame.
fn fuzz_dbus_incoming(data: &[u8]) {
    use mini_sansio_dbus::{DBusConnection, OutgoingQueue};

    // The read path never enqueues; `wants` only takes a queue to also report
    // write-readiness, and `peek() == None` keeps the writer idle.
    struct NoQueue;
    impl OutgoingQueue for NoQueue {
        fn push_raw(&mut self, _buf: &[u8]) -> u32 {
            0
        }
        fn peek(&self) -> Option<&[u8]> {
            None
        }
        fn pop(&mut self) {}
    }

    let mut conn = DBusConnection::new(0);
    let queue = NoQueue;
    let mut readbuf = [0u8; 16 * 1024];
    let mut pos = 0usize;

    loop {
        let avail = data.len() - pos;
        if avail == 0 {
            return; // no more wire to feed — a truncated message is a non-event
        }
        let n;
        {
            let Ok((read, _write)) = conn.wants(&queue, &mut readbuf) else {
                return; // ReadBufIsTooShort etc. — a clean refusal, not a panic
            };
            let want = read.buf.len();
            if want == 0 {
                return;
            }
            n = want.min(avail);
            read.buf[..n].copy_from_slice(&data[pos..pos + n]);
        }
        pos += n;
        match conn.satisfy_read(n, &readbuf) {
            Ok(Some(msg)) => walk_dbus_message(&msg),
            Ok(None) => {}
            Err(_) => return,
        }
    }
}

/// Touch every header field the facade's allowlist reads, then walk the lazily
/// parsed body — each value is decoded from the same untrusted wire on demand.
fn walk_dbus_message(msg: &mini_sansio_dbus::IncomingMessage<'_>) {
    let _ = (
        msg.message_type,
        msg.serial,
        msg.path,
        msg.interface,
        msg.member,
        msg.error_name,
        msg.reply_serial,
        msg.destination,
        msg.sender,
        msg.signature,
        msg.unix_fds,
    );
    if let Some(mut body) = msg.body {
        // Bound the field count: an array of millions of items must not be a hang.
        for _ in 0..4096 {
            match body.try_next() {
                Ok(Some(v)) => walk_dbus_value(&v, 0),
                Ok(None) | Err(_) => break,
            }
        }
    }
}

/// Recursively decode a body value. Container types (struct/array/dict/variant)
/// re-enter the wire decoder for their elements; `depth` caps adversarial nesting
/// so a deeply nested signature cannot blow the stack.
fn walk_dbus_value(v: &mini_sansio_dbus::IncomingValue<'_>, depth: u8) {
    use mini_sansio_dbus::IncomingValue;
    if depth > 16 {
        return;
    }
    match v {
        IncomingValue::Struct(s) => {
            if let Ok(mut it) = s.fields_iter() {
                for _ in 0..4096 {
                    match it.try_next() {
                        Ok(Some(inner)) => walk_dbus_value(&inner, depth + 1),
                        _ => break,
                    }
                }
            }
        }
        IncomingValue::Array(a) => {
            let mut it = a.items_iter();
            for _ in 0..4096 {
                match it.try_next() {
                    Ok(Some(inner)) => walk_dbus_value(&inner, depth + 1),
                    _ => break,
                }
            }
        }
        IncomingValue::DictEntry(d) => {
            if let Ok((k, val)) = d.key_value() {
                walk_dbus_value(&k, depth + 1);
                walk_dbus_value(&val, depth + 1);
            }
        }
        IncomingValue::Variant(var) => {
            if let Ok(inner) = var.materialize() {
                walk_dbus_value(&inner, depth + 1);
            }
        }
        // Scalars and borrowed strings: already fully decoded by `cut`.
        _ => {}
    }
}

/// Drive the parsers from one fuzzer `seed`: feed the whole seed once, then use
/// [`arbitrary`] to carve the seed into a sequence of byte chunks and feed each.
/// Carving lets a single seed exercise length-prefixed and fixed-size parsers
/// with many boundary lengths.
pub fn run(seed: &[u8]) {
    fuzz_parsers(seed);
    let mut u = Unstructured::new(seed);
    while !u.is_empty() {
        // `arbitrary::<&[u8]>` reads a length then that many bytes from the
        // remaining buffer — a varied sub-slice per step.
        match <&[u8] as arbitrary::Arbitrary>::arbitrary(&mut u) {
            Ok(chunk) => fuzz_parsers(chunk),
            Err(_) => break,
        }
    }
}

/// Feed `f` a valid input and everything one step away from it: `seed` itself, every
/// truncation, and every single-byte change against a spread of bit patterns.
///
/// Random bytes almost never get past a decoder's first length or tag check, so they exercise
/// its first branch and little else. Starting from a frame the decoder accepts puts each
/// mutation deep inside it: a count that is now too large, a length that runs past the end, a
/// tag that no longer exists, a string that is no longer UTF-8.
pub fn mutations(seed: &[u8], mut f: impl FnMut(&[u8])) {
    f(seed);
    for cut in 0..seed.len() {
        f(&seed[..cut]);
    }
    let mut m = seed.to_vec();
    for i in 0..seed.len() {
        for pat in [0x01u8, 0x08, 0x40, 0x7f, 0x80, 0xff] {
            m[i] = seed[i] ^ pat;
            f(&m);
        }
        m[i] = seed[i];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift64* — a deterministic, dependency-free PRNG for the corpus.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    #[test]
    fn parsers_never_panic_on_adversarial_bytes() {
        // Boundary inputs: empty, single bytes, the SOCKS5/HTTP front-door bytes,
        // and a long run — the off-by-one and truncation cases.
        let boundaries: &[&[u8]] = &[
            b"",
            &[0x00],
            &[0xff],
            &[0x05, 0x01, 0x00],         // SOCKS5 greeting head
            b"CONNECT x:1 HTTP/1.1\r\n", // HTTP CONNECT head
            &[0xff; 1024],
        ];
        for d in boundaries {
            run(d);
        }

        // A deterministic pseudo-random corpus: many varied byte strings, lengths
        // spanning the small/medium/boundary range the parsers slice on.
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut buf = Vec::with_capacity(600);
        for _ in 0..20_000 {
            let len = (rng.next() % 600) as usize;
            buf.clear();
            for _ in 0..len {
                buf.push((rng.next() & 0xff) as u8);
            }
            run(&buf);
        }
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The binder service decoders, from frames their own encoders produce. Each is read by a
    /// privileged or trusted process from a payload its sender controls.
    #[test]
    fn binder_service_decoders_never_panic_on_mutated_frames() {
        use kennel_lib_binder::service::{
            broker, inet, mesh, session, spawn, svc_connect, tun_broker,
        };

        let seed = inet::encode_request(1, 443, "example.com");
        assert!(inet::decode_request(&seed, 255).is_some());
        mutations(&seed, |d| {
            let _ = inet::decode_request(d, 255);
        });

        let seed = inet::encode_bind_request(1, 8080);
        assert!(inet::decode_bind_request(&seed).is_some());
        mutations(&seed, |d| {
            let _ = inet::decode_bind_request(d);
            let _ = inet::decode_port_prefix(d);
        });

        let seed = spawn::encode_request("compute", &[("workload.argv", "a b"), ("ttl", "60")]);
        assert!(spawn::decode_request(&seed).is_some());
        mutations(&seed, |d| {
            let _ = spawn::decode_request(d);
        });

        let seed = svc_connect::encode_request("git-ssh");
        assert!(svc_connect::decode_request(&seed).is_some());
        mutations(&seed, |d| {
            let _ = svc_connect::decode_request(d);
        });

        // As `transact_node` lays it out: the name, zero padding to 8 bytes, then the handle
        // object the driver translated.
        let mut seed = mesh::encode_add_service("org.example.Service");
        seed.resize(seed.len().next_multiple_of(8), 0);
        seed.extend_from_slice(&kennel_lib_binder::proto::flat_binder_object_handle(3));
        assert!(mesh::decode_add_service(&seed).is_some());
        mutations(&seed, |d| {
            let _ = mesh::decode_add_service(d);
        });

        let seed = session::encode_ref(7, "consumer");
        assert!(session::decode_ref(&seed).is_some());
        mutations(&seed, |d| {
            let _ = session::decode_ref(d);
        });

        let seed = broker::encode_accept(
            0,
            &strings(&["org.example.A"]),
            &strings(&["org.example.A.Iface=Method"]),
            &strings(&["org.example.B"]),
            &strings(&["org.example.C"]),
            &strings(&["org.example.D"]),
        );
        assert!(broker::decode_accept(&seed).is_some());
        mutations(&seed, |d| {
            let _ = broker::decode_accept(d);
        });

        let grants = [tun_broker::Grant {
            name: "example.com".to_owned(),
            ports: vec![53, 443],
            protocol: 2,
        }];
        let seed = tun_broker::encode_accept([0xfd; 16], &grants);
        assert!(tun_broker::decode_accept(&seed).is_some());
        mutations(&seed, |d| {
            let _ = tun_broker::decode_accept(d);
        });
    }

    /// The typed D-Bus conduit frame: the broker decodes what the in-kennel facade produced.
    #[test]
    fn dbus_conduit_frames_never_panic_when_mutated() {
        use kennel_lib_dbus::wire::{Bus, Call, ErrorReply, Frame, Reply, Signal};
        let frames = [
            Frame::Call(Call {
                bus: Bus::Session,
                serial: 9,
                no_reply: false,
                destination: "org.example.Service".to_owned(),
                path: "/org/example/Object".to_owned(),
                interface: "org.example.Interface".to_owned(),
                member: "Method".to_owned(),
                signature: "su".to_owned(),
                body_endian: b'l',
                body: vec![1, 2, 3, 4, 5, 6, 7, 8],
            }),
            Frame::Reply(Reply {
                reply_serial: 9,
                signature: "s".to_owned(),
                body_endian: b'l',
                body: vec![0; 12],
            }),
            Frame::Error(ErrorReply {
                reply_serial: 9,
                name: "org.example.Error.Failed".to_owned(),
                message: "no".to_owned(),
            }),
            Frame::Signal(Signal {
                bus: Bus::System,
                path: "/org/example/Object".to_owned(),
                interface: "org.example.Interface".to_owned(),
                member: "Changed".to_owned(),
                signature: "u".to_owned(),
                body_endian: b'l',
                body: vec![7, 0, 0, 0],
            }),
        ];
        for frame in frames {
            let wire = frame.encode();
            // `encode` includes the conduit's length prefix; `decode` takes what follows it.
            let payload = &wire[4..];
            assert_eq!(Frame::decode(payload).as_ref(), Ok(&frame));
            mutations(payload, |d| {
                let _ = Frame::decode(d);
            });
            mutations(&wire, |d| {
                let _ = kennel_lib_dbus::wire::frame_len(d);
            });
        }
    }

    /// The control protocol (CLI to daemon, any local process can connect) and the helper's
    /// request, response and egress payload (anyone can run the helper).
    #[test]
    fn control_and_helper_messages_never_panic_when_mutated() {
        use kenneld::control::{Request, Response, StartRequest};
        let requests = [
            Request::Start(StartRequest {
                policy: "/home/u/.config/kennel/policies/a.toml".into(),
                kennel: "a".to_owned(),
                argv: strings(&["/bin/sh", "-c", "true"]),
                cwd: "/home/u".into(),
                term: "xterm-256color".to_owned(),
                interactive: true,
                force: false,
                watch_paths: vec!["/home/u/src".into()],
                oci_config: Some("/home/u/.local/share/kennel/oci/a/config.json".into()),
            }),
            Request::Stop {
                kennel: "a".to_owned(),
            },
            Request::List,
            Request::AuthorizedKeys {
                key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA".to_owned(),
            },
            Request::Attach {
                kennel: "a".to_owned(),
            },
            Request::Resize {
                kennel: "a".to_owned(),
                rows: 50,
                cols: 132,
            },
        ];
        for request in requests {
            let seed = request.encode();
            assert_eq!(Request::decode(&seed).as_ref(), Ok(&request));
            mutations(&seed, |d| {
                let _ = Request::decode(d);
            });
        }
        let responses = [
            Response::Started {
                ctx: 7,
                pid: 4242,
                filter_escapes: true,
            },
            Response::Stopped,
            Response::Exited { code: 137 },
        ];
        for response in responses {
            let seed = response.encode();
            assert_eq!(Response::decode(&seed).as_ref(), Ok(&response));
            mutations(&seed, |d| {
                let _ = Response::decode(d);
            });
        }

        use kennel_privhelper::wire::{self, EgressPayload, Op};
        let request = wire::Request {
            op: Op::DelAddr,
            ctx: 7,
            addr: "fd6b:6e9c:691c:8007::1".parse().expect("address"),
            prefix: 128,
            interface: "lo".to_owned(),
        };
        let seed = request.encode();
        assert_eq!(wire::Request::decode(&seed).as_ref(), Ok(&request));
        mutations(&seed, |d| {
            let _ = wire::Request::decode(d);
        });
        mutations(&wire::Response::refused(3).encode(), |d| {
            let _ = wire::Response::decode(d);
        });
        let payload = EgressPayload {
            meta: [1u8; wire::META_LEN],
            allow_v4: Vec::new(),
            deny_v4: Vec::new(),
            allow_v6: Vec::new(),
            deny_v6: Vec::new(),
            bind_allow_v4: Vec::new(),
            bind_deny_v4: Vec::new(),
            bind_allow_v6: Vec::new(),
            bind_deny_v6: Vec::new(),
            bind_allowed_ports: vec![443, 8443],
            pin_id: "kennel-9f3a".to_owned(),
        };
        let seed = payload.encode();
        assert_eq!(EgressPayload::decode(&seed).as_ref(), Ok(&payload));
        mutations(&seed, |d| {
            let _ = EgressPayload::decode(d);
        });
    }

    /// The mesh rendezvous datagram: `kennel-bin-init`, root in the kennel, decodes it.
    #[test]
    fn mesh_rendezvous_never_panics_when_mutated() {
        use kennel_lib_spawn::mesh_rendezvous::{decode, encode};
        use std::os::fd::OwnedFd;
        let null = || -> OwnedFd {
            std::fs::File::open("/dev/null")
                .expect("open /dev/null")
                .into()
        };
        let mounts = vec![
            (null(), std::path::PathBuf::from("/run/kennel/mesh/a")),
            (null(), std::path::PathBuf::from("/run/kennel/mesh/b")),
        ];
        let (seed, _) = encode(&mounts);
        assert_eq!(
            decode(&seed, vec![null(), null()]).expect("decode").len(),
            2
        );
        mutations(&seed, |d| {
            let _ = decode(d, vec![null(), null()]);
            let _ = decode(d, Vec::new());
        });
    }

    /// The signed policy, end to end: TOML, schema, SSHSIG armor and blob, signature check.
    ///
    /// Stronger than no-panic. A changed document must either fail to verify or verify as the
    /// very policy that was signed — a mutation in a part the signature does not cover (the
    /// envelope's own layout) may still verify, but it must not change what the policy says.
    #[test]
    fn a_mutated_signed_policy_never_verifies_as_a_different_policy() {
        use kennel_lib_policy::{settled::sample_settled, sign_settled, to_bytes, SigningKey};
        let key = SigningKey::from_seed("fuzz", &[7u8; 32]).expect("key");
        let mut keys = kennel_lib_policy::KeySet::new();
        keys.insert("fuzz", &key.public_key_bytes()).expect("trust");
        let policy = sample_settled();
        let doc = to_bytes(&sign_settled(&policy, &key).expect("sign")).expect("serialise");
        assert_eq!(
            kennel_lib_policy::verify_settled(&doc, &keys).ok().as_ref(),
            Some(&policy)
        );

        let check = |d: &[u8]| {
            if let Ok(verified) = kennel_lib_policy::verify_settled(d, &keys) {
                assert_eq!(
                    verified, policy,
                    "a changed document verified as another policy"
                );
            }
        };
        // Every byte, with two patterns: one keeps the byte ASCII (the document stays text and
        // reaches the parser), one does not (UTF-8 validation). Truncations on a stride.
        let mut m = doc.clone();
        for i in 0..doc.len() {
            for pat in [0x01u8, 0x80] {
                m[i] = doc[i] ^ pat;
                check(&m);
            }
            m[i] = doc[i];
        }
        for cut in (0..doc.len()).step_by(7) {
            check(&doc[..cut]);
        }
    }

    /// The SSHSIG armor and binary blob on their own, and the OpenSSH public-key line.
    #[test]
    fn sshsig_and_public_key_parsers_never_panic_when_mutated() {
        use kennel_lib_policy::sshsig::{sign_ed25519, SshSig};
        use kennel_lib_policy::SigningKey;
        let key = SigningKey::from_seed("fuzz", &[9u8; 32]).expect("key");
        let armor = sign_ed25519(&key, b"message");
        assert!(SshSig::parse_armored(&armor).is_ok());
        mutations(armor.as_bytes(), |d| {
            if let Ok(text) = std::str::from_utf8(d) {
                let _ = SshSig::parse_armored(text);
            }
        });

        // `ssh-ed25519 <base64 of: string "ssh-ed25519", string key>` — the trusted-key file line.
        let mut blob = Vec::new();
        for field in [b"ssh-ed25519".as_slice(), &key.public_key_bytes()] {
            blob.extend_from_slice(&u32::try_from(field.len()).expect("len").to_be_bytes());
            blob.extend_from_slice(field);
        }
        let line = format!(
            "ssh-ed25519 {} fuzz@example",
            kennel_lib_policy::b64::encode(&blob)
        );
        assert!(kennel_lib_policy::openssh::parse_public_key(&line).is_ok());
        mutations(line.as_bytes(), |d| {
            if let Ok(text) = std::str::from_utf8(d) {
                let _ = kennel_lib_policy::openssh::parse_public_key(text);
                let _ = kennel_lib_policy::openssh::parse_private_key(text);
            }
        });
    }

    /// Mint one valid D-Bus method-call whose body carries every value kind —
    /// scalars, string-likes, a struct, an array, a dict entry, and a variant — so
    /// decoding it drives [`walk_dbus_value`] down every container arm. Returns the
    /// wire bytes; the encoder lays them out exactly as a real bus peer would.
    fn valid_dbus_message() -> Result<Vec<u8>, mini_sansio_dbus::EncodeError> {
        use mini_sansio_dbus::{dbus_body, MessageType, SliceMessageEncoder};
        let mut buf = [0u8; 512];
        let mut encoder = SliceMessageEncoder::new(&mut buf, MessageType::MethodCall)?;
        encoder.set_path("/org/example/Object")?;
        encoder.set_interface("org.example.Interface")?;
        encoder.set_member("AllTypes")?;
        encoder.set_destination("org.example.Service")?;
        dbus_body!(encoder, {
            u8(0x2a),
            bool(true),
            i32(-123_456),
            u64(123_456_789),
            f64(12.5),
            str("hello"),
            object_path("/org/example/Value"),
            signature("su"),
            struct_ { str("inside-struct"), u32(77), },
            array<u16> [7, 8],
            dict_entry { str("dict-key"), u32(99), },
            variant<i32>(-9),
        });
        let len = encoder.finish()?;
        Ok(buf[..len].to_vec())
    }

    /// The D-Bus incoming decoder over a **structural** corpus. The random-byte
    /// sweep in [`parsers_never_panic_on_adversarial_bytes`] almost never forms a
    /// valid 16-byte header, so it rarely reaches the body. Here we start from a
    /// real message — proving the full descent runs once — then feed every
    /// single-byte mutation of it, so the decoder repeatedly enters real
    /// header/body-parse states and then meets adversarial bytes. None may panic,
    /// hang, or over-read; an `Err` is the correct outcome.
    #[test]
    fn dbus_incoming_never_panics_on_mutated_messages() {
        let base = valid_dbus_message().expect("encode the seed message");
        // The pristine message: the body walker descends through every arm.
        fuzz_dbus_incoming(&base);
        // Single-byte mutations: each offset XORed against a spread of bit patterns.
        let mut m = base.clone();
        for i in 0..base.len() {
            for pat in [0x01u8, 0x08, 0x40, 0x7f, 0x80, 0xff] {
                m[i] = base[i] ^ pat;
                fuzz_dbus_incoming(&m);
            }
            m[i] = base[i];
        }
        // Every truncation: a short read mid-header and mid-body.
        for cut in 0..=base.len() {
            fuzz_dbus_incoming(&base[..cut]);
        }
    }

    /// The terminal-escape filter's **security invariant**: for ANY input, the
    /// default-policy filtered output contains no OSC-52 (clipboard) introducer.
    /// This is stronger than no-panic — it asserts the dangerous sequence cannot
    /// survive, including across the adversarial corpus and OSC-52 payloads with
    /// junk spliced in (the desync attempts).
    #[test]
    fn osc52_never_survives_the_filter() {
        use kennel_lib_term::{filter, FilterPolicy};
        let contains_osc52 = |out: &[u8]| {
            // The introducer the filter must never emit: ESC ] 5 2 ;
            out.windows(4).any(|w| w == b"]52;")
        };

        // Seeded payloads: a clean OSC-52, and OSC-52 with adversarial splices that
        // try to confuse a naive matcher into passing the sequence through.
        let seeds: &[&[u8]] = &[
            b"\x1b]52;c;cHduCg==\x07",
            b"\x1b]52;c;cHduCg==\x1b\\", // ST-terminated
            b"text\x1b]52;c;AAAA\x07more",
            b"\x1b]\x1b]52;c;AAAA\x07",            // nested introducer
            b"\x1b]52;\x1b]0;title\x07c;AAAA\x07", // title spliced mid-OSC52
            b"\x1b]052;c;AAAA\x07",                // leading-zero param
        ];
        for s in seeds {
            assert!(
                !contains_osc52(&filter(s, FilterPolicy::default())),
                "OSC52 survived for seed {s:?}"
            );
        }

        // The adversarial corpus: random bytes with an OSC-52 head prepended, so the
        // parser frequently enters the OSC-52 state then sees junk. The filtered
        // output must never carry the introducer.
        let mut rng = Rng(0xD1B5_4A32_D192_ED03);
        let mut buf = Vec::with_capacity(640);
        for _ in 0..20_000 {
            buf.clear();
            buf.extend_from_slice(b"\x1b]52;c;");
            let len = (rng.next() % 600) as usize;
            for _ in 0..len {
                buf.push((rng.next() & 0xff) as u8);
            }
            assert!(
                !contains_osc52(&filter(&buf, FilterPolicy::default())),
                "OSC52 introducer survived filtering"
            );
        }
    }
}
