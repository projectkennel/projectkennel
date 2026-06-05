# Decisions register — high-severity doc↔code reconciliation

> **STATUS (branch `feat/config-layer`, 6 commits, local — not pushed):** all rulings implemented.
> - **Code:** D11 config layer (+D4/H37/H35/H38, install G2/G5) · D1 exec.allow Landlock allowlist · D2 SO_PEERCRED · D9 bind_subnet_map populated. Full workspace build + clippy + unit/integration tests green.
> - **Docs:** D3/D5/D6/D7/D8/D10 + the staleness bulk (crate counts, CI jobs, socket name, netproxy TCP, ssh-agent mechanism, audit catalogue, privhelper cgroup ops) + a 02-6-internal-api rewrite.
> - **Owed (flagged, not done):** `exec.deny` compilation (H21, a compiler item) · bind **port** policy (H16, needs BPF program changes) · a privileged `bpf-egress` e2e to runtime-verify D1's allowlist and D9's bind attach. The kernel mechanics for both are proven by unit/probe tests.
>
> The choices only you can make. Once ruled, I fix top-down from D1. ★ = my recommendation.
> Pure defects (no decision needed) are listed at the bottom for confirmation.
> Source: `TRIAGE-HIGHSEV.md` / `AS-BUILT.md`. Fill the **Ruling:** line (or just say "your recs except …").

---

## D0 — Default policy for documented-but-unbuilt features  *(sets the default for D5–D10)*
Several `design/07-*` chapters describe features that aren't built. Pick the default treatment:
- **(a) Roadmap banner ★** — keep the chapter, add a clear "NOT YET BUILT — design intent" banner so no one trusts it as as-built.
- (b) Delete the claim — remove the unbuilt prose entirely.
- (c) Decide per-item below.

**Ruling:** ☑ (a) roadmap — *"walk before we run"; unbuilt features keep a NOT-BUILT banner.*

---

## Priority 1 — Security / correctness

### D1 — `exec.allow` / `exec.deny` enforcement  *(H20/H21)*
Today they enforce nothing; execution is gated only by `fs.read` EXECUTE, so `inspect-only` can run all of `/usr/bin`. This is the one finding with a real security consequence.
- **(a) Build ★** — wire `exec.allow` into Landlock EXECUTE; compose `exec.deny` up the template chain.
- (b) Fix-doc — drop the allowlist-is-an-exec-control claim, document that `fs.read` is the exec boundary.

**Ruling:** ☐ (a) build ☐ (b) fix-doc ☐ defer — ____

### D2 — SO_PEERCRED on the control socket  *(H10/H19, boundary 7)*
Documented peer-UID check is absent; only the `0600` socket mode protects the daemon.
- **(a) Build ★** — add `getsockopt(SO_PEERCRED)` UID check in the accept loop (~15 lines, real defence-in-depth).
- (b) Delete-claim — rely on socket mode, remove boundary 7 from the docs.

**Ruling:** ☐ (a) build ☐ (b) delete-claim ☐ defer — ____

### D3 — `deny_setuid` / `deny_setgid` / `deny_setcap` flags  *(H22)*
Flags are never read, BUT `MS_NOSUID` mounts + `no_new_privs` already block setuid/setgid exec — effect holds; only the per-file-capability case is unchecked.
- **(a) Fix-doc ★** — document that it's enforced structurally via nosuid.
- (b) Build — add an explicit setcap-bit check too.

**Ruling:** ☐ (a) fix-doc ☐ (b) build ☐ defer — ____

---

## Priority 2 — Layout / install coherence

### D11 — Configuration layer  *(NEW — supersedes D4 + H37, reframes H35/H38)*
**No install-specific hardcoded paths in binaries.** Express them in a layered config, per the design's never-built `kennel.conf` (`07-paths.md:138`).
- **Cascade (high→low), per-key deep merge:** `$XDG_CONFIG_HOME/kennel/config.toml` → `/etc/kennel/config.toml` → `/usr/lib/kennel/config.toml` (vendor baseline) → compiled-in fallback defaults. Binary hardcodes only the *search cascade* + fallbacks, never install paths.
- **Goes in config:** privhelper path, netproxy path, bastion bins (ssh-reorigin/socks-connect/akc), libexec dir, daemon trust dir, CLI template/trust *search* dirs, feature-detection overrides. **Stays out:** per-user tag/gid (kernel-trusted, `/etc/kennel/subkennel`); XDG runtime-derived paths.
- **Vendor defaults:** binaries → `/usr/libexec/kennel` (this is where D4's ruling lands); trust dir → `/etc/kennel/keys`.
- **Security split (needs your nod):** security-sensitive keys (daemon **trust-store dir**, **privhelper/binary paths**) resolve from **`/etc` + `/usr/lib` only** — NOT user config, else a user trusts their own signing key (policy-signing bypass) or redirects the privhelper. User config overrides only convenience keys.

**Ruling:** ☑ BUILT (security-split as above) — `kennel-config` crate; daemon + CLI wired; `/opt` constants deleted; vendor `system.toml`/`config.toml` shipped; install.sh → `/usr/libexec/kennel` + installs AppArmor (G2) + the 3 missing bins (G5).

> Effect: **D4 ☑ /usr/libexec** is the vendor-config default (not a constant). **H37 ☑ fixed** — daemon reads `trust_dir` from config (system+vendor), default `/etc/kennel/keys`; the `/etc/kennel/trust` constant is deleted. **H35/H38 ☑ absorbed**. **G2** (AppArmor now installed at the matching path) and **G5** (all bins installed) closed by the new install.sh.

### D4 — Install prefix: `/opt/kennel` vs `/usr/libexec/kennel`  *(H35)* — ☑ RESOLVED via D11 (vendor default `/usr/libexec/kennel`)
All code + `install.sh` + systemd say `/opt/kennel`; only `07-paths.md` + the AppArmor profile say `/usr/libexec/kennel`. One ruling makes five places agree.
- **(a) `/usr/libexec/kennel` ★** — the documented intent; FHS-correct for non-PATH helpers; the security-critical AppArmor profile already targets it. Cost: update ~6 code constants + install.sh + systemd `ExecStart` (mechanical).
- (b) `/opt/kennel` — least churn; fix the doc + the one profile path line instead.

**Ruling:** ☑ (a) /usr/libexec — *align all five places to the documented path.*

### D5 — Single-instance enforcement  *(H11/H12)*
No flock; `bind()` removes a stale socket rather than failing, so a second daemon silently takes over. systemd socket-activation already guarantees one instance.
- **(a) Fix-doc ★** — rely on socket activation; drop the flock/EADDRINUSE prose.
- (b) Build — add the `kenneld.lock` flock as belt-and-braces.

**Ruling:** ☐ (a) fix-doc ☐ (b) build ☐ defer — ____

---

## Priority 3 — Feature build-or-shelve  *(default from D0 unless you override)*

### D6 — D-Bus proxy & X11 isolation  *(H29–H32)*
No `xdg-dbus-proxy`, no Xephyr/Xwayland; schema is just `enabled`/`*_isolated` toggles. Large unbuilt subsystems.
**Ruling:** ☑ D0-default (roadmap) — *future work; walk before run.*

### D7 — `fs.scrub` / `fs.home.sanitise`  *(H23/H24)*
Parsed in source policy, deliberately dropped at translate; no shim step.
**Ruling:** ☐ D0-default ☐ build ☐ delete — ____

### D8 — Runtime TTL enforcement  *(H27/H28)*
`ttl_*` parsed/signed into settled policy but nothing arms a timer. (Also: enum is `stop`/`warn`; doc says `exit`/`warn`/`renew`.)
- **(a) Fix-doc ★** — document TTL as carried-but-not-yet-enforced; align doc enum to `stop`/`warn`.
- (b) Build — add the TTL reaper (SIGTERM→SIGKILL) + reconcile the enum.

**Ruling:** ☐ (a) fix-doc ☐ (b) build ☐ defer — ____

### D9 — Bind port policy + bind-rewrite  *(H15/H16/H39)*
BPF bind programs look up `bind_subnet_map` that nothing populates → in-subnet binds fail closed; port policy (`min_port`) never checked. Decides whether H15/H39 is a code-fix or a doc-fix.
- (a) Build — populate `bind_subnet_map` end-to-end + add port checks (makes in-kennel servers work as documented).
- (b) Shelve ★? — fix-doc to say bind-rewrite/port policy isn't wired yet. *(Need your read on whether workloads are expected to bind listening sockets.)*

**Ruling:** ☑ (a) build — *workloads DO bind listening sockets (Claude Code runs inside a kennel); wire `bind_subnet_map` end-to-end + port checks. H15/H39 become code-fixes.*

### D10 — Auto-compile-on-run & AF_UNIX abi<6 fallback  *(H26, H25)*
H26: `kennel run` of a *source* policy doesn't compile-in-memory (requires pre-settled). H25: no seccomp fallback for abstract-socket denial below Landlock ABI 6 (moot on modern kernels).
- **(a) Fix-doc ★** for both — document run requires a settled artefact; drop the abi<6 fallback claim.
- (b) Build either if you want them.

**Ruling:** ☐ (a) fix-doc both ☐ build H26 ☐ build H25 ☐ defer — ____

---

## Pure defects — confirm you want these fixed (not really decisions)
- **H37 — trust-store split-brain.** ☑ folded into **D11** — daemon reads the trust dir from config (system+vendor), default `/etc/kennel/keys`.
- **02-6-internal-api.md** is stale top-to-bottom (wrong crates, invented types). → rewrite, not patch. **Confirm:** ☐ rewrite
- **Doc-staleness bulk** (crate counts, CI job count, cgroup ops ✅, socket name, netproxy TCP-not-unix, ssh-agent mechanism, audit catalogue) → straight doc edits once D4 is set. **Confirm:** ☐ proceed

---

### Fix order once ruled
D1 → D2/D3 → H37 → D4 (unblocks all path edits) → D5 → D6–D10 per your rulings → doc-staleness bulk → 02-6 rewrite.
