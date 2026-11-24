# kennel-fuzz

Fuzz / property harnesses for Project Kennel's untrusted-input parsers
(CODING-STANDARDS.md §10.6, §10.1). One harness function feeds every parser; a
deterministic corpus runner asserts none of them panic on adversarial bytes.

## Why this shape ("Path C")

The maintainer chose the lightest approach: the `arbitrary` crate plus a
hand-rolled runner, **not** `cargo-fuzz` / `libfuzzer-sys`. Rationale (the
"dependency damage" review):

- `arbitrary` with `default-features = false` (no `derive`) has **zero transitive
  dependencies** — adopting it is exactly one new vendored crate, no proc-macro,
  no `build.rs`, no bundled C++/LLVM runtime, no CI C++ toolchain.
- `cargo-fuzz` + `libfuzzer-sys` (the coverage-guided alternative) would add ~5
  crates including a `build.rs` that compiles a bundled libFuzzer C++ runtime —
  the heaviest §5.3/§5.5 burden. It can be layered on later: [`run`] is exactly
  the body a `fuzz_target!` would call, so the harnesses are reused unchanged.

This is a **separate Cargo workspace** (`[workspace]` in its `Cargo.toml`): it is
not a member of the main workspace, so it does not enter the shipped crates'
`Cargo.lock` or `CHECKSUMS.toml`, and the offline `cargo build --frozen --locked`
gate is unaffected.

## Status

`arbitrary` 1.4.1 is vendored (`src/vendor/`), so the harness builds offline like every other
crate. CI runs it in the `fuzz (smoke)` job: clippy with `-D warnings`, then `cargo test`.

## What runs

```sh
cd src/fuzz && cargo test --offline --locked
```

- **Random bytes.** 20,000 pseudo-random byte strings from a fixed seed, fed to every parser
  (`parsers_never_panic_on_adversarial_bytes`). These mostly exercise each parser's first
  length or tag check.
- **Seeded corpora.** For the decoders random bytes rarely get into, a valid input is built
  with the decoder's own encoder and then every truncation and every single-byte change of it
  is fed back ([`mutations`]): the binder service requests, the D-Bus conduit frame, the
  control protocol, the helper's request, response and egress payload, the mesh rendezvous
  datagram, the SSHSIG armor and the OpenSSH public-key line. The same is done for raw D-Bus
  messages. The plan wire's three decoders have the equivalent test in `kennel-lib-spawn`,
  where the fully populated fixtures live.
- **Properties.** Two tests assert more than "no panic": no OSC-52 introducer survives the
  terminal filter, and a signed policy with any one byte changed either fails verification or
  verifies as exactly the policy that was signed.

When a decoder gains a field, add it to the seed for that decoder.

To add coverage-guided fuzzing later, install `cargo-fuzz`, add `libfuzzer-sys`
(its own §5.5 pass), and wrap [`run`] in `fuzz_targets/*.rs` — the parser-feeding
logic does not change.

[`run`]: ./src/lib.rs
[`mutations`]: ./src/lib.rs
