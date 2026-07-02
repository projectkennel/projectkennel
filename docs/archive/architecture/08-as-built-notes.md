# §8 Implementation notes: lessons and gotchas

The design and architecture chapters describe the system as built. This chapter
collects what does not belong in a surface description: the implementation lessons
that shaped the build, and the build/test gotchas that bite.

## 8.1 What is not here: roadmap and backlog

This chapter is **as-built only** — it carries no roadmap. The design and architecture
chapters are the source of truth for what each shipped feature does; designed-but-unbuilt
work lives in the [backlog](../governance/BACKLOG.md) (parked or declined) and, while a
release is in flight, in that release's `ROADMAP-<version>.md` under `docs/governance/`
(retired into the corpus once the release ships) — never here.

## 8.2 Implementation lessons (apply these to the rest)

- **A read-only bind remount must preserve the source's locked flags inside a userns.**
  `mount(MS_BIND|MS_REMOUNT|MS_RDONLY)` that *clears* a flag locked on the source
  superblock (`nosuid`/`nodev`/`noexec`) is `EPERM` in an unprivileged user namespace —
  the kernel permits clearing locked flags only with real privilege. So
  `mount::remount_readonly` `statvfs`es the target and carries the locked flags into the
  remount (this matters when binding a file from a `nosuid,nodev` mount — e.g. the
  `AF_UNIX` socket on the `$XDG_RUNTIME_DIR` tmpfs). It is also strictly more restrictive
  (a read-only grant never wants `suid`/`dev`), and a source without those flags (the root
  fs under `/usr`) is unaffected, so an executable bind stays executable. The lesson
  generalises: under a userns, a remount may only *add* restrictions.
- **The kenneld `AppArmor` profile is `flags=(unconfined)`; its only job is to grant
  `userns`.** kenneld execs the setuid privhelper, which *inherits* this profile across exec
  and needs `userns`/`mount`/`pivot_root`/`sys_admin` to build the sandbox — the `userns` grant
  in particular because it clones the namespace **as the operator** (so the userns is
  operator-owned), which is an unprivileged-userns creation as far as
  `apparmor_restrict_unprivileged_userns` is concerned, despite the setuid bit (the setuid bit
  buys the map-write/mount caps; the grant buys the userns creation — both are required, removing
  the profile breaks construction). An *enforcing* profile cannot work: the privhelper fexecve's
  `kennel-bin-init`, which sets `PR_SET_NO_NEW_PRIVS` (seccomp requires it) and execs the arbitrary
  workload — and under no-new-privs the kernel denies *every* AppArmor exec transition (`Ux`→unconfined
  and even `Cx`/`Px`→stricter both give `apparmor="DENIED" … info="no new privs"`). That leaves only
  `ix` for the workload, which would inherit kenneld's `mount`/`userns`/`sys_admin` — worse than
  unconfined. The workload is confined by Landlock + seccomp + namespaces, not AppArmor; confining it
  via AppArmor would need runtime `aa_change_onexec` (a v2 question). See `dist/apparmor/kenneld`.
- **Userns-dependent proofs must report their precise skip cause, and be confirmed with
  `--nocapture`.** `cargo test` captures a passing test's output, so a test that skips
  (e.g. where the host lacks the `AppArmor` `userns` grant) still reads as a green `ok`
  unless its skip cause is surfaced. The spawn proofs `eprintln!` the exact reason; the
  production proof is the off-sudo runner `src/tools/unprivileged-e2e.sh`, which loads the
  `userns` profile. Relaxing the host sysctl is not the remedy (security-weakening).
- **The Landlock ruleset must be built *after* `pivot_root`, in the child.** A rule
  opens an `O_PATH` fd at build time and is keyed to that inode. Bind mounts preserve
  inodes (so system/home/dev rules match a parent-built ruleset), but the constructed
  `/etc` has fresh tmpfs inodes a host-opened fd would never match — libc would be
  denied `/etc`. So the seal builds the ruleset post-pivot with a *skip-missing* pass
  (a grant for a path the view doesn't contain is vacuous). See `kennel-lib-spawn::spawn`.
- **The process is ephemeral; the work is not.** The new root is a throwaway tmpfs,
  but every *writable* bind resolves to a persistent host inode (the agent's real
  project tree), so work survives teardown. Any new writable surface must keep this
  property — never let something the workload means to keep live only on the tmpfs.
- **Fail closed, and prove it adversarially.** Every BPF decision path defaults to
  `KENNEL_DENY`; every new scope/right ships with a test that shows the *denied*
  case actually denies on the running kernel (the IPv4-mapped-IPv6 connect, the
  abstract-socket scope, the device ioctl). A test that only shows the allow path
  is half a test.
- **Landlock denial errnos differ by class.** Filesystem/network rules deny with
  `EACCES`; scoping (`SCOPE_*`) denies with `EPERM`. Accept both when asserting "the
  scope bit fired".
- **The daemon's TCB is bounded by crate boundary, not vigilance — and it only
  shrinks.** The runtime trusted computing base is the dependency closure of the
  privileged binaries (`kenneld`, `kennel-privhelper`, `kennel-bin-init`); a compromise
  of anything in it breaks confinement. The structural rule is that anything the daemon
  does **not** need to *verify-and-load and supervise* lives in its own crate, outside
  that closure: the operator CLI is `kennel-cli` (its `serde_json`/`lexopt` deps stay
  there), the policy **compiler** is `kennel-lib-compile` (the daemon links only the
  verify-and-load `kennel-lib-policy` half), the control wire is `kennel-lib-control`,
  and the trust-manifest reader is `kennel-lib-manifest`. `cargo tree -p kenneld` must
  show **none** of those. The inventory and the TCB-closure total live in
  `03-crate-decomposition.md` § "Crate inventory and TCB". When adding a dependency or a
  feature, ask first whether it lands in the TCB closure; if the daemon does not strictly
  need it, put it behind a crate boundary the daemon does not cross. The TCB is a budget
  that goes down, not up — a heavyweight dep (a JSON/serialisation stack, an async
  runtime, a parser the daemon does not run) reaching `kenneld`'s closure is a regression
  to be refused, not absorbed.

## 8.3 Build and test gotchas

- **Rebuild the BPF privhelper before root tests.** A workspace `cargo test` /
  `cargo clippy --all-targets` rebuilds `kennel-privhelper` with default features,
  clobbering the `--features bpf-egress` binary; the `kenneld` e2e then fails with
  `ENOSYS`. Always `cargo build -p kennel-privhelper --features bpf-egress` (and
  `host-netproxy`) immediately before running the gated binaries.
- **Run the gated test *binaries* directly under sudo**, not `sudo cargo` (which
  leaves root-owned files in `target/`). Compile with `--features e2e
  --no-run`, then `sudo ./target/debug/deps/<name>-<hash>`. Use `pkill -x kenneld`,
  never `pkill -f` (which matches the harness wrapper and kills the shell).
- **Stage shim / `/etc` / new-root dirs outside `/tmp`.** The seal mounts a fresh
  tmpfs over `/tmp` before the shadow binds; a `/tmp`-staged source vanishes.
  Production stages under `$XDG_RUNTIME_DIR`; tests under `/run`.
- **`cargo fmt --all` is a gate — run it before committing.** Default rustfmt (no
  `rustfmt.toml`); `cargo fmt --all -- --check` runs in CI and the pre-commit/pre-push
  hooks, so the corpus is rustfmt-clean and new code must be too. (This reverses the
  earlier hand-formatting convention; the corpus was reflowed when the gate was added.)
- **A required new settled-schema field touches every fixture.** Adding a
  non-defaulted field to a policy struct forces every `FsPolicy`/`Plan` literal
  across crates into the same commit.
- **`src/fuzz` is a separate workspace with its own `Cargo.lock`; CI runs it
  `--offline --locked`.** Any change to the *transitive* dep graph of its path-deps
  (it links `kenneld`, so a change to kenneld's deps counts) staleness the fuzz lock,
  and the `fuzz` CI job fails to resolve even though the shipped build is fine — the
  main `--frozen --locked` gate never reaches it. After a crate restructuring,
  regenerate it: `cd src/fuzz && cargo update --offline` (it inherits the repo-root
  `.cargo` vendor config), then commit `src/fuzz/Cargo.lock`. It does not enter the
  main Cargo.lock or `CHECKSUMS.toml`, so its only failure mode is the stale lock.
