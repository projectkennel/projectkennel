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

## Status: staged — needs `arbitrary` vendored (§5.5) before it builds

The harness does not compile until `arbitrary` is vendored. The shipped build
does not reference it, so this is inert until a reviewer crosses the dep gate:

1. `cd` to the repo root (the `.cargo/config.toml` local-registry source applies
   to this crate too).
2. `tools/audit-helper.sh fetch arbitrary 1.4.1` (confirm the latest pin first),
   then `tools/audit-helper.sh confirm arbitrary 1.4.1`.
3. Read the source, add the `CHECKSUMS.toml` entry (reviewer name, ISO date,
   `verified-against`) and the `DEPENDENCIES.md` entry (draft below), per §5.5.
4. Two maintainer approvals on the checksum addition.

### DEPENDENCIES.md draft entry (fill in after verifying)

> **`arbitrary` =1.4.1** — turns a flat fuzzer seed into typed/byte inputs for
> the fuzz harnesses (`fuzz/`). Used with `default-features = false` (no `derive`
> feature), so it pulls **no transitive dependencies**. License: MIT OR
> Apache-2.0. Used only by `kennel-fuzz`, which is a non-shipped, separate-
> workspace test crate (not in any release artefact). Reviewer: TBD.

## Running (after vendoring)

```sh
cd fuzz && cargo test            # the deterministic-corpus runner (20k iterations)
```

To add coverage-guided fuzzing later, install `cargo-fuzz`, add `libfuzzer-sys`
(its own §5.5 pass), and wrap [`run`] in `fuzz_targets/*.rs` — the parser-feeding
logic does not change.

[`run`]: ./src/lib.rs
