# Audit — dynamic-spawn surface red-team (2026-06-22)

**Scope.** The dynamic-spawn surface introduced for 0.3.0: caller-chosen
`workload.argv`, the manifest-patch applicator (`patch.rs` / `variant.rs`), fragment
composition of exec floors (`compile.rs` / `leaf.rs`), and the read-only `SPAWN_QUERY`
verb. A *focused* pass on the new surface; the structural surface (fd-passing, the
looper threadpool, the reapers, `max_instances` accounting, the depth-1 bound) was
adversarially reviewed [2026-06-10/06-18](../../architecture/02-10-dynamic-spawn.md) and
is leaned on here, not re-verified.

**Method.** Four attackers, one per surface dimension, each grounded in the code and
asked for concrete, cited findings. Every finding then faced a three-skeptic panel that
could mark it refuted *only* by citing a specific control (a Landlock/seccomp gate, a
frozen field, a wire bound, a signature verify) with `file:line`; a finding with no
cited control survives. 20 findings → 10 confirmed, 10 refuted.

**Verdict — safe-with-fixes (now landed).** The cage holds: the strong claim — *a
caller cannot reach any filesystem path, host, or syscall the frozen cage forbids* —
survived intact. No escape was found. What did not survive is the weaker *advertised*
claim "only `exec.allow` binaries execute": the confirmed findings are
contract-vs-enforcement gaps, not escapes. All actionable findings are remedied in
[#76](https://github.com/projectkennel/projectkennel/pull/76); the rest are bounded by
existing controls and recorded as no-code with the reasoning.

## Confirmed findings and remedies

| # | Sev | Finding | Remedy |
|---|---|---|---|
| 1 | HIGH | Writable `$HOME`/`/tmp` tmpfs is `NOSUID|NODEV` but not `NOEXEC`, so an in-cage process can `/usr/bin/env LD_PRELOAD=$HOME/x.so <allowlisted-bin>` and run native code via a file-backed `PROT_EXEC` mmap — which Landlock's `FS_EXECUTE` gate has no hook for. In-cage code injection, **not** escape. | **Fixed.** `mount_tmpfs` gains a `noexec` flag, set for the workload-writable home/tmp/dev; extends `deny_writable` from execve to mmap. Anonymous `PROT_EXEC` (JITs) unaffected. |
| 2 | HIGH | `relpath` constraint's `under` root is dropped at apply — `patch.rs` never used it, so the constraint collapsed to "no `..`" and the agent wrote any relative path: a widening past the signed manifest. | **Fixed.** `instantiate` joins the traversal-free value under the signed root. (Symlink-following within the root is the runtime bind's `RESOLVE_IN_ROOT` concern, tracked separately.) |
| 3 | HIGH | `is_additive_only()` inspects only `.remove` vectors, so a signed fragment carrying `[lifecycle.override]` / `[net.audit.override]` passes the additive-only gate and silently replaces the inherited TTL/audit — acute for spawn, whose eligibility re-check trusts that TTL. | **Fixed.** Scalar overrides are rejected from an include; overrides belong in the inheritance chain (§5.10). |
| 4 | MED | Fragment `exec.allow` additions have no conflict check (only `net` does) and no writable-path screen — a signed-but-incautious fragment could land an interpreter the includer never reviewed. | **No code.** Exec unions without ambiguity (unlike net's same-host/different-port); fragments are maintainer-signed + catalogue-gated; the include closure is in the lockfile provenance; runtime `deny_writable` refuses exec of a writable path. A per-path warning (`core-coreutils` alone is 48) would be ignored noise. |
| 5 | MED | A spawn target composes its own fragment closure at compile, so fragments can widen the child's cage (`fs.write` / egress) with no re-check against the spawner's grant. | **No code.** The target is a signed settled artefact whose full resolved cage is reviewable (`kennel policy show`) when the operator adds it to `[spawn.allow]`; the cloud-metadata invariant deny holds union-add-only. |
| 6 | LOW | `SPAWN_QUERY` re-reads + ed25519-re-verifies every allowed template on every call, no rate limit — CPU amplification on the shared looper pool. | **Fixed.** The caps body is immutable for the grant's lifetime, so it is memoised (`OnceLock`); the live-count header is rendered fresh. |
| 7 | LOW | `workload.argv` is exempt from the per-field entry cap, and `SPAWN_PATCH_MAX_BYTES` (64 KiB) was a doc comment, not an enforced decode check (the binder buffer bounded it incidentally). | **Fixed.** `decode_request` enforces the 64 KiB bound, fail-closed before allocating the patch. |
| 8 | LOW | `argv[0]` has no verify-half re-check against `exec.allow`; the sole gate is Landlock `FS_EXECUTE` at execve. | **No code.** Landlock is the authoritative, correct exec gate (init-is-dumb-executor); a verify-half check would false-positive on PATH-resolved bare names. The real residual (indirect loader via `env`/`sh`) is closed by finding #1. |

## What held (verified controls)

The panel confirmed, by code citation, that these hold:

- **Membership double-gating.** A patch field-path outside the (per-requester-narrowed)
  manifest is rejected at both compile and apply — key-membership, not a set-difference,
  so a value that equals a frozen field's is still refused for naming an out-of-manifest field.
- **Verify→apply pin, no TOCTOU.** The content-pin (ed25519 signature commitment) is
  re-verified at `SPAWN` against the resolved bytes; a re-signed-in-place target resolves
  to a different signature and is caught.
- **The frozen `sha256` workload-pin re-validates the caller-replaced `argv[0]`.** A
  template that both pins `sha256` and opens `workload.argv` refuses any `argv[0]` whose
  bytes are not in the accepted set (the pin hashes the program, so interpreter chaining
  must itself name a pinned interpreter).
- **The cloud-metadata invariant deny is union-add-only on every compose path** — a
  fragment cannot remove or shadow it.
- **`net.proxy.allow` is inert under a frozen `net.mode = none`** — the allowlist grants
  nothing when there is no network.
- **The `DestPattern` wildcard matcher is label-boundary anchored** — `*.x`/`x.*` cannot
  be abused (`evilpypi.org`, `pypi.org.evil.com`, `10.0.0.5.6` are all refused).

## Notes

Two of the three HIGH findings were introduced by 0.3.0's own work — the
`workload.argv` + `/usr/bin/env`-in-`core-shell` combination made the latent `NOEXEC`
gap reachable, and the fragment catalogue introduced the override-gate hole — which is
the point of red-teaming fresh surface before a security headline ships.

The focused pass did not exercise one structural detail it flagged: the `max_instances`
slot live-counter under a concurrent `SPAWN` + `SPAWN_QUERY` interleave (assessed likely
sound — `SPAWN_QUERY` does not touch the slot counter). A full-surface pass re-verifying
fd-passing / reapers / `max_instances` / depth-1 against the argv+fragment changes
remains an option; the verdict assessed none of those is overturned.
