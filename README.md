# Project Kennel

**Kernel-enforced confinement for unsigned code — at per-task granularity, cheap enough to be disposable.**

The user level of a modern developer workstation has become a complete software runtime — package managers, container runtimes, AI coding agents, MCP servers, IDE extensions — all running as the user, none arriving through the operating system's validated install path. The host level has decades of enforcement vocabulary for code like this (AppArmor, SELinux, systemd hardening, capability sets, audit), but none of it operates at user-level workload granularity. Project Kennel provides the enforcement vocabulary the user level should have acquired as it grew into a runtime.

It started as confinement for a single unsigned workload. Two things changed the scope. Construction got cheap: a fully isolated kennel — fresh user, PID, mount, IPC, and network namespaces, a constructed view, a private IPC bus, cgroup limits, the seal — stands up to workload `execve` in **≈ 3.7 ms median** (≈ 4.4 ms p90, workload-independent) and tears down in **≈ 0.7 ms** (measured by [`spawn-spinup.sh`](src/tools/spawn-spinup.sh) on kernel 6.17), which makes per-task, throwaway isolation practical rather than aspirational. And composition got first-class: a confined workload can spawn its own scoped, ephemeral sub-kennels, and confined kennels can provide capabilities to one another through a brokered, operator-declared mesh. The result is a substrate for confining not just a workload but an *agent* — something that runs untrusted code, reaches the network, touches a workspace, and wants to do all three at once.

The model is an Anderson reference monitor: complete mediation, tamperproof, verifiable. Its defining discipline is **construction by absence** — a workload is constrained by what its constructed world does not contain, not by a list of denials layered over a permissive one. Non-granted paths are *absent*, not merely unreadable. The trusted computing base only shrinks.

Policy describes kernel-level constraints (which files, which network destinations, which sockets, which services), not workload behaviour. The same policy confines an AI coding agent, a Postgres container, an `npm install`, or an MCP server. Enforcement is via Landlock, cgroup BPF, user/mount/PID/IPC/network namespaces, seccomp, and `PR_SET_NO_NEW_PRIVS` — kernel mechanisms the workload's userspace cannot reach.

**The daemon runs unprivileged; one small setuid-root helper does the rest.** `kenneld` is an ordinary user process — it runs as you, holds no standing privilege, and is the unprivileged orchestrator that schedules, brokers, resolves, and verifies the signed policy. The sandbox — user, mount, PID, IPC, and network namespaces, `mount`, `pivot_root`, the constructed view — is built by a single small **setuid-root privhelper** that is deliberately frugal with the bit: it drops its effective uid to the operator *across* the `clone`, so the workload's **user namespace is owned by the operator, not root** (the bubblewrap-equivalent mechanism — `CAP_SYS_ADMIN` only *inside* that namespace), and re-escalates to root only for the handful of host-global operations a user namespace genuinely cannot reach — add/remove the per-kennel loopback addresses, attach the egress BPF (`host` mode only), write a policy-granted supplementary group into the workload's `gid_map`, and the one-time `binder` module load — then drops back. There is no `sudo` anywhere in the spawn; privilege is concentrated in that one small, audited binary, and the namespaces it builds are operator-owned.

## Status

**0.4.0 — the service-mesh release.** The reference runtime, the threat catalogue ([THREATS.md](docs/design/THREATS.md)), and the design corpus are all implemented and published — the runtime is the reference, not a sketch. Versioned on a stable-surface cadence, with a [CHANGELOG](CHANGELOG.md) recording every change.

The full vertical runs **unprivileged**, proven end-to-end as the ordinary operator with no `sudo` (kernel 6.17, Landlock ABI ≥ 6; see [BUILD-ENV.md](docs/design/BUILD-ENV.md) for the kernel floor), each slice exercised by the real installed toolchain in the policy-suite e2e:

- **The spawn.** An identity-mapped user namespace; the workload as PID 1 of its own PID namespace; the constructed-`$HOME` view via `pivot_root` (non-granted paths *absent*, not denied); a synthetic `/etc`; an allowlisted `/dev` with host-device passthrough; a fresh `/proc` and private `/tmp`; Landlock filesystem and network rules with abstract-unix/signal scoping; a seccomp denylist; `PR_SET_NO_NEW_PRIVS`; and a cgroup the kennel is *born in* (`clone3(CLONE_INTO_CGROUP)`, no post-hoc migration). Construction is per-task and **cheap enough to be disposable** — the ≈ 3.7 ms floor above is what lets confinement be per-task rather than per-session.

- **Four network modes.** `none` (an own net namespace with no interfaces — no egress); `constrained` (an own net namespace, egress via a per-kennel SOCKS/HTTP proxy, **default-deny** — only `net.allow` passes; **the default posture**); `unconstrained` (the same, default-allow minus the invariant floor and any `net.deny`); and `host` (shares the host net namespace, **direct** egress with the `net.allow` allowlist enforced via cgroup-BPF + Landlock, requires a stated `net.reason`, and reinstates the host-reconnaissance residual T1.6). The net namespace is the boundary in every mode but `host`; the egress BPF is attached **only** in `host`, where it is the sole gate (§7.5).

- **Dynamic spawn.** A confined workload can ask `kenneld`, over the binder IPC bus, to instantiate a scoped, ephemeral **sibling** kennel from an operator-signed, `@`-pinned template it holds a `[spawn]` grant for — no host privilege, no second capability of its own. The workload *names* a signed template and writes only the fields the template's mutable-field manifest opens (`kennel run <template@version> [field=value]… -- <argv>`); it cannot author policy at runtime. `kenneld` validates, mints the channel, and brokers it, staying control-plane only — it never parses the protocol that rides the channel (MCP travels as opaque JSON-RPC the daemon does not frame). Spawning is bounded — **depth-1 by hard rule** (a spawned kennel cannot itself spawn), an atomic `max_instances` fork-bomb ceiling, and a triple reaper that guarantees a spawned tool dies with the agent that spawned it.

- **The service mesh.** Confined kennels `[provides]` capabilities to one another and `[consumes]` them by name, with every cross-kennel connection operator-declared, `kenneld`-brokered, and **deny-by-default**. The catalogue is *derived* from the signed `[provides]` blocks of enabled kennels — a projection of signed policy, never authored central state, so it cannot drift from reality — and the reserved `org.projectkennel.*` namespace is gated to maintainer-signed templates (a self-signed reserved claim is dropped *and* its policy refused). `kenneld` brokers an af-unix connector through a host-owned rendezvous point, socket-activates an `ondemand` provider on first consume and idle-reaps it when no consumer runs; `autorun` sidecars start with the daemon under a signed restart policy. This is the standing-service complement to dynamic spawn: spawn provisions per-use; the mesh provisions once and is consumed many times.

- **Confined GUI.** X11 is **cut**, not deferred. A GUI app reaches a real desktop through a per-kennel **nested compositor** run as a service kennel — bring-your-own `cage`/Weston/sway, unpatched and host-independent (proven on stock GNOME) — brokered over the mesh behind a single tagged host-compositor leg. The app's `wl_registry` is the *inner* compositor's; the host's other clients are absent by construction, so the app draws and gets its own window without holding a raw host-compositor socket or any filesystem grant. The render/display leg is built; the interactive file broker is fenced post-0.4.0.

- **OCI substrate.** A bring-your-own-rootfs model (`kennel oci`) boots a **digest-pinned**, unpacked OCI image as the kennel root, under the same Landlock/seccomp/egress confinement, with a loud `[rootfs]` grant and a Landlock closure-lock that restores the executable-surface boundary after uid-persona flattening. The image is fetched and unpacked by stock `skopeo`/`umoci` inside a confined `oci-fetch` kennel, at workload authority — never in the daemon.

- **Workspace trust (T2.8).** A masked `.trust-manifest.json` at each writable root pins the SHA-256 of host-side execution triggers (`Makefile`, `.git/hooks/*`, `.vscode/tasks.json`, …). The CLI maintains it host-side; the spawn view **masks it invisible** to the workload (an empty over-mount inside the writable bind), so a confined agent can rewrite a trigger but cannot forge the pin — host tooling reads the real manifest and refuses a trigger whose hash diverged. `kennel review` is the operator re-pin. Two terminal-facing hardenings join it: the PTY escape filter (`[tty]`, dropping OSC 52 clipboard / 9;777 notifications / DCS-APC-PM-SOS, T2.6) and an egress refusal of literal special-use destinations.

- **Identity, IPC, audit.** The workload's account and groups are masked to `kennel`; inherited supplementary groups drop to the overflow gid unless a policy-granted group is re-granted through the privhelper's `gid_map` write. Binder is the central IPC primitive — a private per-kennel instance mounted before entry, with `kenneld` as each kennel's node-0 context manager and a reserved `org.projectkennel.*` service namespace (D-Bus, Wayland, AF_UNIX, spawn, policy). A unified `kennel-lib-audit` writer (one canonical event schema, one sanitisation pass, per-class levels) fans out to file, stdout, syslog, and opt-in journald, selected by the signed `[audit]` policy section over a config cascade (built-in < `/etc/kennel` < `~/.config` < policy). All three userspace sources route through it — `kenneld`'s lifecycle, the egress proxy's per-request `net.egress`, and the privhelper's `priv.invoke`/`priv.refuse` (recorded by `kenneld` at the IPC boundary). The egress proxy also keeps a per-kennel JSONL audit log; a mediated **D-Bus facade** (`org.projectkennel.IDBus`, §7.7) does per-message method filtering so no raw bus reaches the kennel.

- **The `kennel` CLI.** `run` / `attach` / `stop` / `list` (the listing carries the cross-kennel mesh view); `oci` (build/run an image substrate); `review` (re-pin the trust manifest); `keygen` / `subkennel` / `audit` / `daemon-reload`; and a `kennel policy` group — `compile` (resolve a source policy + its templates into a signed, byte-pinned settled policy), `validate`, `sign`, `list` / `show` / `edit` / `generate`, `lint`, `risks`, `diff`, `upgrade`. One name, two contexts: host-side it is the operator command; inside a spawn-capable kennel the same `kennel` dispatches `run` / `caps` over the binder. An interactive `run` is **detachable** — `kenneld` owns the controlling pty and brokers it, so `Ctrl-\ d` detaches without ending the workload and `kennel attach <name>` reconnects (the tmux / `docker attach` model, no `setns`). End-to-end **ed25519** trust across templates, fragments, and the settled artefact, a `kennel.lock` byte-pin, and a control-plane version handshake that refuses a CLI/daemon schema skew at the boundary. The shipped [templates](templates/) and composable [fragments](fragments/) are signed under the maintainer key `kennel-maint-2026` (verify with `kennel policy validate --require-signed` against [keys/](keys/)).

On distributions that restrict unprivileged user namespaces (Ubuntu's `kernel.apparmor_restrict_unprivileged_userns=1`), a shipped AppArmor profile grants `userns` to the `kenneld` binary ([dist/apparmor/kenneld](dist/apparmor/kenneld)) — which the privhelper it `exec`s inherits to build the **operator-owned** user namespace (it clones as the operator, so it needs the grant even though it is setuid-root). A one-time install step `install.sh` applies.

### A principle worth stating: authentication, never attestation

The mesh provides capabilities a confined kennel may *use* — render, transport, session-bus access, a key to authenticate ("may I do this"). It never provides *attestation* — vouching, signing, secret-issuance ("trust that this is so"). An attestation's worth derives from the trust of its origin, and the mesh's origins are confined-and-untrusted by definition, so a peer kennel making a trust claim others rely on is incoherent. This is why there is no secrets broker and no signing service in the mesh: a kennel whose job is to be trusted is a trust root misplaced inside the boundary the project exists to confine. Trust material arrives as a signed construction parameter from the operator, never from a peer at runtime.

## SSH egress: double-blind re-origination

The hardest part of confining a workload that does real work — an agent or a build needs to `git push`/`pull` or `ssh` to a few hosts, with selected keys.

The obvious grant is to forward an `ssh-agent` socket into the sandbox. It is a **destination-blind signing oracle**: the agent protocol signs an opaque blob, *not* a hostname, so a workload holding the socket can have an allowlisted key sign a challenge it crafted for an *attacker-chosen* host and authenticate as the user anywhere that key is accepted. A curated `~/.ssh/config` constrains only the client the workload is free to bypass.

Project Kennel routes SSH through a per-user **re-origination bastion** (a stock OpenSSH `sshd` running forced commands only) so that **both ends of the dangerous (key × destination) pairing are blinded**:

- **The workload is blind to the credential.** Its constructed `~/.ssh` holds only a *disposable synthetic* ed25519 key — never a real key, never an agent socket. The real key stays in the user's host-side store.
- **The credential cannot be aimed by the workload.** Which synthetic key authenticates is the destination selector: the bastion's forced command bakes in the `(host, real-key-fingerprint)` edge, re-originating a fresh, host-key-verified `ssh` with `IdentitiesOnly` to exactly that host and no other. The workload cannot redirect it, and a non-synthetic key is refused.

A synthetic key is thus a capability for exactly one `(host, key)` edge: `git push` to a granted host works, with zero key material in the sandbox and no signing oracle to abuse. Validated against stock OpenSSH 9.6 (design [§7.10](docs/design/07-10-ssh.md)).

## What is deliberately not here

Three things are declined on principle, not deferred for capacity — recorded so they are not re-proposed:

- **No secrets broker, no signing service** — attestation does not belong inside the confinement boundary (above).
- **No first-party OCI unpacker** — the security argument (unpacking is adversarial-input parsing) is already met by running the unpack confined; a bespoke parser would be cost and risk for marginal gain.
- **No daemon-side protocol mediation** — `kenneld` brokers and resolves; it never parses MCP frames or portal bodies. (The D-Bus facade's per-method filtering is the one mediated exception, and it runs in an out-of-TCB facade, not the daemon.) Application-semantic mediation, if ever wanted, is a confined interposer, never the daemon.

Genuinely deferred, designed but not built: a macOS port (Mach ports, Seatbelt SBPL — the mechanism mapping exists, the runtime does not); per-method policy on *mesh* service grants (mesh grants are service-name-level today; the D-Bus facade aside, there is no per-method filtering on a mesh capability); and the OCI integrity ladder above the digest-pinned floor. See [docs/architecture/](docs/architecture/) for the as-built boundary.

## Residuals, named

Confinement is honest about what it does not close. The standing residuals: **T1.6** (host-network reconnaissance, present only in `net.mode = host`, behind a required reason); the **GUI host-compositor leg** (one scoped `AF_UNIX` passthrough to the host compositor, the GUI analogue of T1.6); and **R2 delegated composition** (an agent permitted to spawn a network-capable tool and a filesystem-capable tool can bridge their channels — mitigated by single-leg template scoping, not eliminated, because closing it would put cross-kennel information-flow reasoning in the daemon). These are tagged in the threat catalogue, not hidden.

## Size

A rough sense of scale — more specification than code, and the code that exists is small and mostly safe. (Rust SLOC excludes `#[cfg(test)]`; prose via `wc -w`; a snapshot that drifts.)

| Artefact | Size |
|---|---|
| Design docs (`docs/design/`) | ≈ 111,000 words |
| Architecture docs (`docs/architecture/`) | ≈ 79,500 words |
| Implementation — Rust (26 crates) | ≈ 33,800 SLOC |
| Implementation — BPF (C, host-mode egress) | ≈ 600 SLOC |
| `unsafe` Rust | quarantined to 5 small crates (below) |

Almost every crate carries `#![forbid(unsafe_code)]`. The entire `unsafe` surface is quarantined to five small, single-purpose crates — `kennel-lib-syscall`, `kennel-lib-landlock`, `kennel-lib-bpf`, `kennel-lib-binder`, and `kennel-lib-scm` — each block held to a `SAFETY:`/`INVARIANTS:`/`FAILURE MODE:` template ([supply-chain/UNSAFE-CRATES.md](supply-chain/UNSAFE-CRATES.md) is authoritative).

## What is here

| Path | What |
|---|---|
| [EXEC-SUMMARY.md](docs/design/EXEC-SUMMARY.md) | Why the project exists; the one-page case. |
| [THREATS.md](docs/design/THREATS.md) | The threat catalogue: stable IDs, incident citations, MITRE/compliance mappings. The durable contribution. |
| [docs/design/](docs/design/) | The design corpus — threat model, policy surface, template system, the spawn and mesh models, enforcement architecture. An implementation-independent specification. |
| [docs/architecture/](docs/architecture/) | The reference implementation's architecture — process model, IPC, API surfaces, crate decomposition, trust boundaries, supervision, latency. |
| [CODING-STANDARDS.md](docs/governance/CODING-STANDARDS.md) | Normative engineering rules (the bar is OpenSSH / libpam). |
| [CONTRIBUTING.md](.github/CONTRIBUTING.md) | How to contribute, and what gets closed without review. |

## Reading order

Using it: [INSTALL.md](INSTALL.md) → [HOWTO.md](HOWTO.md) → [HOWTO-admin.md](HOWTO-admin.md). The installed man pages are the reference (`man kennel`, `man policy.toml`, `man kenneld`).

New readers (design): [EXEC-SUMMARY.md](docs/design/EXEC-SUMMARY.md) → [THREATS.md](docs/design/THREATS.md) → the design corpus (start at §1) → a worked policy template. Implementers and auditors then read the architecture corpus and CODING-STANDARDS.

## Reporting a vulnerability

See [SECURITY.md](.github/SECURITY.md). Do not file a public issue for a specific exploitable vulnerability in Project Kennel itself.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). The threat catalogue, design corpus, and reference runtime are all Apache-2.0. One exception: the BPF programs under [src/bpf/](src/bpf/) (host-mode egress only) are GPL-2.0, as required by the kernel for programs declaring a GPL license section; the user-space loader and everything else are Apache-2.0.

## Contact and links

- **Website:** <https://projectkennel.org>
- **Repository:** <https://github.com/projectkennel/projectkennel>
- **Security contact:** security@projectkennel.org
- **Canonical THREATS.md:** <https://github.com/projectkennel/projectkennel/blob/main/docs/design/THREATS.md>
