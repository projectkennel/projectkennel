//! Fuzz / property harnesses for Project Kennel's untrusted-input parsers.
//!
//! # Purpose
//!
//! CODING-STANDARDS.md §10.6: every parser of untrusted input carries a fuzz
//! target. The boundaries (§10.1) covered here are the egress front-door
//! (the `CONNECT_INET` request wire the in-kennel facade frames), the binder
//! driver-return command stream, the two IPC wire formats (the kenneld control
//! protocol and the privhelper packed-struct request), and the signed-policy
//! reader. Each must, for *any* input, return `Ok`/`Err`/`None` — never panic,
//! never hang, never read out of bounds.
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
    // The egress front-door: the in-kennel facade (facade-socks5) frames each workload connect as a
    // CONNECT_INET request `[transport | port | host]` and transacts it to kenneld over binder. The
    // host (a DNS name) is fully workload-controlled, so the decoder is the untrusted parse (07-5).
    let _ = kennel_lib_binder::service::inet::decode_request(data, 255);

    // IPC wire formats: the kenneld control protocol and the privhelper request.
    let _ = kenneld::control::Request::decode(data);
    let _ = kenneld::control::Response::decode(data);
    let _ = kennel_privhelper::wire::Request::decode(data);

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
            &[0x05, 0x01, 0x00],       // SOCKS5 greeting head
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
}
