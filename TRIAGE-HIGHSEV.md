# High-severity triage worksheet (40 findings)

> Companion to `AS-BUILT.md`. Each item is classified by **resolution direction**, not blame.
> Prior (from your rulings on addressing + cgroup ops): **the code is the as-built truth; the doc is usually what moved.** So most items are doc-fixes. The ones that need *you* are grouped first.
> Ruling slots: `☐ fix-doc ☐ build ☐ delete-claim ☐ fix-code ☐ defer`. H-numbers match the AS-BUILT extract.

**Classes:** 🤔 DECIDE (your call) ·  🔧 FIX-CODE (genuine defect) ·  📕 FIX-DOC (code right, doc stale) ·  ✅ pre-ruled

Counts: 13 DECIDE · 3 FIX-CODE · 24 FIX-DOC (3 of them pre-ruled by you).

---

## 🤔 DECIDE — build the control, or delete the doc claim

These describe controls/features the doc promises but the code does not implement. Not bugs — product decisions. My recommendation in **bold**.

### Security controls (defence-in-depth that's documented but absent)
- **H20 / H21 — `exec.allow` / `exec.deny` are not execution controls.** `design/07-1-exec.md` says Landlock `EXECUTE` gates `exec.allow`; in reality execution is governed by `fs.read` EXECUTE grants and `exec.allow`/`deny` are never wired in. This breaks `inspect-only`'s core promise. → **BUILD** (wire `exec.allow` into Landlock EXECUTE, compose `exec.deny`). Highest-value code fix in the set.
  **Ruling:** ☐ build ☐ delete-claim ☐ defer — ____
- **H10 / H19 — no SO_PEERCRED check** (boundary 7, 02-4-ipc). Daemon serves every connection; only the `0600` socket mode protects it. → **BUILD** (a `getsockopt(SO_PEERCRED)` UID check is ~15 lines, real defence-in-depth).
  **Ruling:** ☐ build ☐ delete-claim ☐ defer — ____
- **H22 — `deny_setuid/setgid/setcap` flags never read.** *Mitigated:* `MS_NOSUID` mounts + `no_new_privs` already block setuid/setgid exec, so the effect holds; only the per-file-capability case is unchecked. → **FIX-DOC** (state it's enforced structurally via nosuid) unless you want the explicit setcap check.
  **Ruling:** ☐ fix-doc ☐ build ☐ defer — ____

### Unbuilt subsystems (design docs describe rich features; code has only toggles/stubs)
- **H29–H32 — D-Bus proxy & X11 isolation.** No `xdg-dbus-proxy`, no Xephyr/Xwayland; schema is reduced to `enabled`/`*_isolated` bools. The `07-5/07-6` design chapters describe a whole feature set that isn't built. → **FIX-DOC (mark roadmap)** unless these are on the near-term build list.
  **Ruling:** ☐ fix-doc/roadmap ☐ build ☐ defer — ____
- **H23 / H24 — `fs.scrub` / `fs.home.sanitise`.** Parsed in the source policy, deliberately dropped at `translate` (source-only); no shim implementation. → **DECIDE** (build the shim step, or mark the design sections roadmap).
  **Ruling:** ☐ fix-doc/roadmap ☐ build ☐ defer — ____
- **H28 (+H27) — runtime TTL enforcement.** `ttl_seconds`/`ttl_action` are parsed, translated, signed into the settled policy, but nothing arms a timer. → **DECIDE** (build the TTL reaper, or mark not-yet-enforced). H27 also: enum is `stop`/`warn`, doc says `exit`/`warn`/`renew` — fold into the same ruling.
  **Ruling:** ☐ build ☐ fix-doc ☐ defer — ____
- **H16 — bind port policy (`min_port`/`allowed_ports`).** Doc says privileged-port binds are refused; BPF only checks address, never port. → **DECIDE** (build, or delete the claim). Tied to H15/H39 below.
  **Ruling:** ☐ build ☐ delete-claim ☐ defer — ____
- **H26 — auto-compile-on-run.** Doc says `kennel run` of a *source* policy compiles+signs in memory; code requires a pre-settled artefact. → **FIX-DOC** unless you want the convenience path.
  **Ruling:** ☐ fix-doc ☐ build ☐ defer — ____
- **H25 — AF_UNIX abstract-socket seccomp fallback below ABI 6.** No fallback; empty scope below ABI 6. On modern kernels (ABI ≥ 6) moot. → **FIX-DOC (delete fallback claim)** likely.
  **Ruling:** ☐ fix-doc ☐ build ☐ defer — ____
- **H11 / H12 — single-instance enforcement.** No flock, and `socket::bind()` *removes* a stale socket rather than failing on EADDRINUSE — so a second daemon silently takes over. With systemd socket-activation only one ever runs. → **FIX-DOC** (rely on socket activation) unless you want belt-and-braces.
  **Ruling:** ☐ fix-doc ☐ build-flock ☐ defer — ____
- **H35 — install prefix `/opt/kennel` vs documented `/usr/libexec/kennel`.** All code+install+systemd say `/opt/kennel`; only `07-paths.md` + the AppArmor profile say `/usr/libexec`. This is the one we hit first. → **DECIDE the canonical prefix**, then make all five places agree. (If code wins → fix-doc+profile; if doc wins → fix the constants+install.)
  **Ruling:** ☐ /opt (fix-doc) ☐ /usr/libexec (fix-code) ☐ defer — ____

---

## 🔧 FIX-CODE — genuine defects / inconsistencies

- **H37 — trust-store split brain.** CLI + `install.sh` use `/etc/kennel/keys`; the **daemon** reads `/etc/kennel/trust` ([policy.rs:21](src/crates/kenneld/src/policy.rs#L21)). Out of the box the daemon trusts nothing the installer placed. → align the daemon constant to `/etc/kennel/keys`.
  **Ruling:** ☐ fix-code ☐ defer — ____
- **H15 / H39 — bind-rewrite fails closed because `bind_subnet_map` is never populated.** The bind4/bind6 BPF programs look up a map that nothing fills end-to-end, so in-subnet binds return `KENNEL_DENY`. If bind-rewrite is a shipped feature this is a real break; if deferred, it's a doc-fix. → **FIX-CODE** (wire the map population) **or DECIDE** to defer.
  **Ruling:** ☐ fix-code ☐ defer/fix-doc — ____

---

## 📕 FIX-DOC — code is the as-built truth; correct the doc

*(✅ = you already ruled the code correct.)*

**02-6-internal-api.md is wholesale stale — rewrite, don't patch:**
- H1/H2 — `kennel-audit` IS a real unified crate (doc says it doesn't exist; netproxy now uses it).
- H3/H4/H5/H6 — 11 crates not 8; real spawn API is `Plan`+`prepare`/`spawn` (not `Spawn`/`Workload`); no `BpfRuntime`/`Policy`/`RawPolicy`/`TemplateChain`/`InstallConstants` (last one removed in `2db5eff`).
  **Ruling (whole doc):** ☐ rewrite-02-6 ☐ defer — ____

**Crate count / build docs:**
- H7/H8 (03-crate-decomposition) — 11 crates, audit is first-class; privhelper deps are syscall + optional bpf only.
- H33/H34 (06-build-and-test) — 11 crates not 8; CI is 5 jobs not 16.
  **Ruling:** ☐ fix-doc ☐ defer — ____

**Privhelper op set / cgroup (✅ pre-ruled — code right):**
- ✅ H9/H13/H14 — privhelper has no cgroup create/delete; ops are add/del-addr + setup-egress + set-gid-map; cgroup is made higher up in kenneld's delegated subtree. Docs 01-process-model + 04-boundary-1 stale.
  **Ruling:** ☑ fix-doc (confirmed) — update 01-process-model.md & 04-trust-boundaries.md

**Paths (the non-prefix ones):**
- H36 — socket is `control.sock`, not `kenneld.sock`. (cosmetic doc-fix)
- H38 — netproxy listens on **TCP loopback** (the bit-packed `/28` address), not a `proxy.sock` unix socket. Code is by-design.
  **Ruling:** ☐ fix-doc ☐ defer — ____

**Misc code-is-right:**
- H17 (05-templates) — ssh-agent is NOT declared via `[[unix.allow]]`; the validator hard-refuses that and routes ssh-agent through the dedicated `[ssh]` path. Doc describes the wrong mechanism.
- H18 (02-3-audit-schema) — the event catalogue lists exec/unix/dbus/scrub events that nothing emits (because those subsystems aren't built). Mark catalogue aspirational / trim to lifecycle.* + egress.
  **Ruling:** ☐ fix-doc ☐ defer — ____

---

## 📌 Open question for you (drives ~15 of the above)
For the unbuilt subsystems (D-Bus, X11, fs.scrub/sanitise, TTL, bind-port): do the `design/07-*` chapters stay as **design intent** (a roadmap we'll build to) — in which case they need a clear "NOT YET BUILT" banner, not deletion — or are some descoped for good (delete)? Your answer flips most DECIDE items between *roadmap-banner* and *delete-claim*.
