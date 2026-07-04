# Seccomp layer — mediation audit (2026-07)

**Verdict.** The seccomp layer is **defence-in-depth, not a fail-open**: every gap between what
`base-confined` denies and what a workload could in principle issue is independently closed by
another control. The hypothesised io_uring egress bypass is **refuted**. Three pieces of debt
(not holes) are addressed by W14; this note is the durable record of the negative result, so a
future kernel bump or uid-model change re-opens exactly the questions it answers rather than
re-deriving them.

## The io_uring egress-bypass hypothesis — refuted

The concern: a workload could issue a `connect()` through io_uring's async submission ring,
sidestepping the `cgroup/connect4`/`connect6` BPF egress gate, since the syscall entry point is
`io_uring_enter`, not `connect`.

It does not bypass. The cgroup connect hook fires from the kernel's `__sys_connect` →
`security_socket_connect` / the proto-op `->pre_connect` path, which is the **same proto-op layer**
io_uring's `io_connect` traverses to perform the connection — io_uring is a submission transport,
not an alternate connect implementation. The egress fence is placed below the syscall boundary, so
the ring and the syscall reach it identically. Egress enforcement is confirmed; the fence is not
syscall-shaped and io_uring does not route around it.

**Out of scope, explicitly:** io_uring egress *audit-record parity* — whether an io_uring-issued
connect emits the same `net.connect` audit event as the syscall path. Enforcement is confirmed;
whether the audit ring observes the io_uring path identically was not investigated. If a future
need for byte-exact audit parity arises, that is the open question.

## The cap-gated set — closed by uid-0-unreachability, not by a syscall floor

The syscalls a seccomp floor would most obviously want (`mount` and the new mount API, `bpf`,
`kexec_*`, `*_module`) are all **cap-gated**: they require a capability the workload does not hold.
The workload does not hold it because `kennel-bin-init` drops it to the **masked, non-zero operator
uid** before `execve`, and `no_new_privs` + the `deny_setuid`/`deny_setgid`/`deny_setcap` exec
invariants (already hard invariants in `kennel-lib-policy::invariant`) prevent re-acquisition. A
non-zero in-ns uid is not the user-namespace root, so it carries no capabilities in that namespace,
so the cap-gated set is unreachable **structurally** — a seccomp deny over those numbers would be
redundant with a property that already holds.

That is why W14 introduces **no code-level seccomp syscall invariant**. It instead makes the
load-bearing property — the drop actually happened — **checked** rather than merely enforced:
`fork_drop_exec_confined` now asserts `effective_uid() != 0` after the identity drop and before the
seal, failing the child closed (`_exit(126)`) if it is zero. This is defensive: no policy can
request a uid-0 drop today (`drop_uid` is unconditionally the operator's real uid, and kenneld is a
per-user daemon), so the check has no policy-reachable trigger — it guards against a future
uid-map or hook-placement regression, at the one point the property is established.

## The one real defect — non-additive `[seccomp] deny` composition (fixed)

`[seccomp] deny` folded with the scalar `or` rule: a child's `deny` list **replaced** the parent's.
A leaf writing a bare `deny = [...]` therefore silently dropped `base-confined`'s entire seccomp
hardening — the composition inconsistent with the additive `net.*.add` / `exec.*.add` increment
model everywhere else. W14 makes the deny fold **additive** (union of base and child), so a leaf can
only strengthen the denylist, never weaken it. There is no remove form, by design — the base's deny
is a floor, not a leaf's to narrow. (Observed in passing, not fixed here: the source `[seccomp]
allow` field is never translated into the settled policy — it is a dead no-op. Removing it is a
schema change, out of scope for this debt item; noted for the schema-consistency pass.)

## Denylist completeness (done)

`base-confined`'s denylist is **declared hardening**, not a framework floor — and now that (2) makes
it non-narrowable, completing it is worthwhile. W14 adds the families the audit found absent, all
cap-gated or otherwise closed today, so the deny makes *intent match enforcement* and defends the
belt-and-suspenders layer against a future regression:

- `io_uring_setup` / `io_uring_enter` / `io_uring_register` — a large async-submission surface;
  enforced anyway (cap-gated features unreachable at non-zero uid), the deny removes complex
  unaudited surface.
- the new mount API — `fsopen`, `fsconfig`, `fsmount`, `move_mount`, `open_tree`, `mount_setattr`:
  the modern path to what `mount` (already denied) does.
- `open_by_handle_at` / `name_to_handle_at` — handle-based open, which resolves a file handle
  bypassing path-based access checks.

The existing entries are kept. A name that fails to resolve is silently skipped at plan time
(`filter_map` over `syscall_number`), so each new name is both added to the resolver and covered by
a resolution test — a typo would otherwise make the deny a no-op.

## Scope note

The completion targets `base-confined` per the workstream. The two alternative base templates
(`base-flatpak`, `base-bwrap`) carry their own, older denylists and are **not** updated here; a leaf
on one of those does not inherit these families. That is a known consistency gap, left for a
follow-up (or the schema-consistency backlog pass) rather than widened speculatively — the three
bases may carry deliberately different intent, and the additive-fold fix (2) is what makes any base
denylist trustworthy in the first place.
