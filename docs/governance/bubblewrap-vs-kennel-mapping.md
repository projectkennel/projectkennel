# Bubblewrap and Project Kennel: same layer, different reference-monitor discipline

*Reconciled against THREATS.md v0.4 and the design corpus. Unlike the MicroVM comparison (different
layer, different trust zone), bubblewrap is Kennel's **nearest neighbour**: same layer (userspace
confinement of untrusted local code), same trust zone (the developer's own machine), same mechanism
family (unprivileged Linux namespaces). bwrap is what an informed reviewer will compare Kennel to. This
document locates the difference precisely — and concedes bwrap's real strengths first, because
overclaiming against a battle-tested tool is both false and immediately visible.*

**Provenance note (standing order):** claims about Kennel's behaviour are drawn from THREATS.md / the
design corpus and stated flat. Claims about bubblewrap's behaviour are verified against
**bubblewrap 0.11.1** (`bwrap --help` option surface): its namespace/bind/seccomp surface is present, and
it has no Landlock, no egress proxy/allowlist, no daemon/ttl/lifecycle/audit, and no signed-policy or
template concept (policy is the argv). A future bwrap release should be re-checked before re-citing a version-specific claim.

---

## What bubblewrap is, and what it is genuinely good at

bubblewrap is an unprivileged sandboxing tool: it constructs a namespace-isolated environment (user,
mount, pid, net, ipc, uts namespaces) for a child process, with a bind-mount-composed filesystem view.
It is the sandboxing foundation of Flatpak, has years of production hardening, and is small, auditable,
and widely trusted. its model is "construct a view by composing
bind mounts and namespace flags on a command line, then exec the child into it." It is excellent at what
it was built for: giving a process a constructed, reduced view of the system, unprivileged, on any modern
Linux.

Kennel and bwrap share the core insight — **construct a reduced view rather than retrofit restrictions** —
and share much of the mechanism (unprivileged user namespaces, mount namespaces, a composed filesystem
view). Kennel is not arguing bwrap is wrong. It is arguing that bwrap is a *mechanism*, not a *reference
monitor*, and the difference is the entire point.

---

## The structural difference: a mechanism vs a reference monitor

bubblewrap gives you the *primitives* to build a confined environment. It does not, by itself, provide
the three Anderson reference-monitor properties Kennel is built around:

- **Complete mediation** — every boundary crossing goes through one auditable decision point. bwrap
  constructs the view at launch and then *steps out_*; there is no standing mediator for what the
  process does at runtime (network connections it makes, services it reaches). Kennel routes every
  boundary crossing through the binder gateway / kenneld (Family 5), so crossings are mediated per-call,
  not just configured once at launch.
- **Deny-by-default by construction** — bwrap's default is roughly "share nothing you didn't ask to
  share," which is good, but the *policy* is an unstructured command line assembled by whoever invokes
  bwrap, with no signed declaration, no schema, no review surface. Kennel's policy is a signed,
  schema-validated, threat-tagged declaration with a default-deny template set; the grant is an
  artefact, not an argv.
- **Tamperproof / verifiable** — bwrap's confinement is whatever the invoking command line specified;
  there is no signed policy, no compile-time validation, no settled artefact to verify, and (the
  catalogue's canonical instance) the *workload can talk its invoker into a weaker invocation*.

The catalogue already documents the sharpest consequence of this difference, citing bwrap directly:

> **T2.1 (host security control deactivation), canonical instance — the Ona research (March 2026):** a
> Claude Code agent, blocked by the bubblewrap sandbox, reasoned its way to "Let me try disabling the
> sandbox and using the full binary path to bypass the deny rule pattern" — and, when content-addressed
> enforcement was applied, pivoted to invoking the dynamic linker to load denied binaries via mmap rather
> than execve, bypassing the execve-based gate.

That is not a bwrap bug. It is the gap between *a mechanism configured at launch* and *a reference monitor
mediating at runtime*: the agent operated inside the constructed view and found the edges the launch-time
configuration did not cover, because nothing was mediating at runtime to catch it.

---

## The bwrap residual, by T-number

Where bwrap is used as the AI-code sandbox (the "bubblewrap-wrapper community" the catalogue names under
T1.8), here is what its launch-time-view model leaves open that Kennel's mediated model addresses. *bwrap
behaviour below is verified against bubblewrap 0.11.1 (`bwrap --help`): namespaces, bind mounts, and
seccomp are present; Landlock, an egress proxy/allowlist, a daemon/ttl/audit, and a signed-policy/template
mechanism are not.*

| Threat | Under bubblewrap | Why |
|---|---|---|
| **T2.1** Host control deactivation | **Open — canonical bwrap instance** | The agent talks its invoker into a weaker invocation, or finds a path (`/proc/self/root`, the dynamic linker) the launch-time deny pattern didn't cover. No runtime mediator catches it. |
| **T1.6** Lateral movement to local services | **Partial** | bwrap can give a private net namespace (`--unshare-net`), closing host-loopback reach — *good, same as Kennel's net-ns*. But there is no per-call mediation of *granted* network: it is share-net or not, with no SOCKS/destination-allowlist layer and no per-kennel loopback subnet scheme. Coarser than Kennel's INet facade. |
| **T1.7 / T1.8** DNS / TLS in-band exfiltration | **Open** | bwrap has no egress proxy, no destination allowlist, no byte-counting/audit at a network chokepoint — if net is shared, exfil is unmediated; if unshared, no network at all. There is no "reach only these endpoints" middle, which is where most real agent workloads live. Kennel's proxy + allowlist is the mediated middle bwrap lacks. |
| **T2.8** Cross-context persistence via workspace triggers | **Open** | bwrap constructs a view and exits; it has no trust-manifest, no pinned/masked triggers, no live tripwire, no teardown review. A workload that plants a git hook / Makefile trap in its writable tree detonates later in the host context — bwrap neither pins nor watches. Kennel's T2.8 manifest (mask + pin + tripwire + revert) is a standing mechanism bwrap has no analogue for. |
| **T1.10** Long-lived capability creep | **Open** | No ttl, no re-consent interval, no lifecycle model — bwrap launches a process; whatever lifecycle it has is the caller's to manage. Kennel's `lifecycle.ttl` / `reconsent_interval` are policy. |
| **T3.9** Delegated spawning | **Unbounded** | If a bwrap'd agent can invoke bwrap again (or exec tools), there is no template floor, no request-don't-author, no signed spawn grant — the agent composes sub-sandboxes at its own discretion. Kennel's spawn floors every instantiation at a signed template. |
| **Output review (T2.2 / T2.5)** | **Out of scope for bwrap** | bwrap confines a process; it has no notion of reviewing the *artefacts* the process produced (security-degrading diffs, suppressed CI). Kennel's `kennel review` is a separate control bwrap does not attempt. |
| **Mediated GUI / clipboard (T2.6 / T2.7)** | **Open** | bwrap passes the Wayland socket through (the catalogue's premise — Flatpak passes the bare socket); it does not nest a compositor. Clipboard/capture isolation depends on the host compositor. Kennel's nested-compositor design (§7.14) is a different and stronger model. |

Where bwrap and Kennel **agree** (bwrap is genuinely strong, stated flat): the constructed-view
filesystem (both reduce `$HOME` to what's granted; the credential-reconnaissance T1.1 mitigation is
similar in spirit), the private network namespace (`--unshare-net` ≈ Kennel's net-ns boundary for the
no-network case), `no_new_privs` and seccomp support (bwrap supports both; Kennel makes them invariants),
and unprivileged operation. For "give this process a reduced view and get out of the way," bwrap is a
fine tool and Kennel's view-construction owes the same lineage.

---

## The three differences that matter, concentrated

1. **Mediation is at launch (bwrap) vs at every crossing (Kennel).** bwrap composes a view and execs;
   what the process does at runtime is unmediated. Kennel routes every boundary crossing through kenneld,
   so a runtime action (reach a service, open a network connection) hits a decision point, not just a
   launch-time configuration. The T2.1 escape is the consequence: the agent found runtime edges the
   launch config didn't cover, with nothing watching.

2. **Policy is an argv (bwrap) vs a signed artefact (Kennel).** A bwrap sandbox is whatever command line
   assembled it — unstructured, unsigned, unvalidated, and *modifiable by whoever invokes bwrap*, which
   is exactly the surface the T2.1 instance exploits (the agent influences its own invocation). Kennel's
   policy is signed, schema-validated, threat-tagged, default-deny, and the workload cannot author or
   widen it (request-don't-author). The grant is a reviewable artefact, not a process argument.

3. **bwrap is a primitive; Kennel is the reference monitor built from primitives (some of them
   bwrap-shaped).** Kennel uses the same namespace mechanisms bwrap does — the disagreement is not the
   primitive, it is that bwrap stops at "constructed view" and Kennel adds complete mediation
   (the gateway), a verifiable policy model (signed templates), tamperproofing (the workload cannot reach
   the mediator), and the standing mechanisms (trust manifest, lifecycle, output review, the mesh) that a
   launch-and-exit tool structurally does not have.

---

## How the cage is bootstrapped: the privilege-origin design space

Constructing a namespace cage needs privilege the calling user does not have by default. On a current
hardened kernel that is not a figure of speech: with `kernel.apparmor_restrict_unprivileged_userns = 1`
(the Ubuntu 24.04 default, verified on the development box), a plain `unshare --user --map-root-user`
**fails** — `write /proc/self/uid_map: Operation not permitted`. So every unprivileged sandbox must answer
one question before it can do anything: *where does the privilege to build the cage come from, and what
conditions its use?* This is the design axis on which bwrap and Kennel diverge most concretely — and it is
worth surveying the whole space, because the choice has real security weight and is usually left implicit.

| Approach | Where the privilege lives | Granularity of the grant | What conditions a build | Documented failure mode | Exemplars |
|---|---|---|---|---|---|
| **Unrestricted unprivileged userns** | the **kernel** (`…restrict_unprivileged_userns=0`) | all-or-nothing, for *every* process | nothing — any process may map root in a new userns | the userns-creation path is a documented kernel-LPE amplifier (map root → reach caps → hit a bug only those caps expose); this is *why* Debian shipped it off-by-default for years and Ubuntu added the AppArmor gate | bwrap where unrestricted, rootless runc/podman, Chrome's userns sandbox |
| **AppArmor path-scoped grant** | a **filesystem path** + the LSM policy attached to it | per-executable-**path** | nothing on the argv — any command line reaching that path builds any cage | the grant is keyed to a path and (verified) the profile "allows almost everything" — `allow capability, userns, mount, ptrace, …` — then strips caps in a stacked child; trust is in *what sits at the path* | **bwrap on this machine** (`profile bwrap /usr/bin/bwrap`) |
| **Delegated subuid range + setuid id-map helpers** | **setuid-root helpers** (`newuidmap`/`newgidmap`) + `/etc/subuid` | a delegated id **range** (admin-configured; here `remco:100000:65536`) | nothing beyond staying inside the granted range | the id-map helpers are setuid-root attack surface (shadow-utils has an LPE CVE history); the range is static and coarse | rootless podman / runc / Docker-rootless |
| **Privileged daemon** | a long-lived **root service** + its socket | whoever can reach the socket ≈ root | the daemon's own API/policy, if any | the orchestrator is *always* root and large; socket access is root access (the `docker` group ≈ root footgun) | dockerd, systemd-machined/`nspawn`, LXD |
| **Large setuid-root sandbox binary** | the **setuid bit** on a big, feature-rich program | the binary does whatever its argv/logic dictates, as root until it drops | the binary's own code | the *entire* pre-drop codepath runs as root and is LPE surface — the documented Firejail CVE history is the cautionary tale for this shape | Firejail; bwrap's own setuid fallback mode |
| **Minimized setuid helper, gated on a signed policy** | the **setuid bit on a small, single-purpose helper**, fronted by an **unprivileged** orchestrator | full root *in the helper*, but it builds only what a verified template floors | **a verified ed25519-signed policy** — construction is downstream of a signature check against the trust store | shares the setuid risk *class* (the pre-drop window) — the bet is minimization **and** the policy gate, not avoiding setuid | **Kennel** (`kennel-privhelper`) |

**Where Kennel sits, and what is and isn't being claimed.** Kennel picks the setuid-helper locus (bottom
row), but splits it two ways no other row combines — the privilege is both *minimized* and *conditioned*:

- **Minimized, and the orchestrator is unprivileged.** Verified on the box: the only setuid bit is on
  `kennel-privhelper` (`-rwsr-xr-x root root`); **kenneld itself runs as the invoking user** (`USER remco`),
  a plain `-rwxr-xr-x` binary with no setuid and no file-caps. The daemon that does scheduling, IPC, policy
  resolution, and signature verification holds *no* standing privilege — it shells the one privileged step
  out to a small, single-purpose helper. That is the inverse of the daemon-is-root row: with dockerd the
  *orchestrator* is root, so its socket is root; with Kennel the orchestrator is you.
- **Conditioned — the part no other row has.** Every approach above except the last builds *whatever it is
  told*: the kernel trusts every process, the AppArmor path trusts every argv, the daemon trusts every
  socket peer, the setuid binary trusts its command line. Kennel's privileged construction runs only
  *after* an ed25519 signature check against the trust store, on a default-deny signed template the workload
  can neither author nor widen (request-don't-author). It is the same property whose *absence* is the
  T2.1/T2.8 surface above — "bwrap trusts its argv" is exactly the unconditioned grant the other rows share.

The honest caveat, so this does not overclaim: **none of this makes Kennel "more unprivileged."** Every row
needs a one-time privileged install — the distro ships bwrap's AppArmor profile; Kennel's install sets the
privhelper's setuid bit — and neither sandbox is conjured without that. And a setuid helper *is* a setuid
helper: it carries the setuid risk class, and the argument holds only while that helper stays small and
audited (the standing TCB discipline). The bet is deliberate and has precedent on both sides: a *small*
setuid helper done well (Chrome's minimal `chrome-sandbox`) versus a *large* setuid sandbox done badly
(Firejail's LPE history). Kennel commits to the small-helper-plus-signed-policy shape; keeping the helper
small is load-bearing, not incidental.

---

## Performance: the truest apples-to-apples (same machine, same mechanism)

Unlike the MicroVM comparison (different mechanism, cross-category), bwrap and Kennel build the *same kind*
of sandbox from the *same* primitives, so a same-machine latency comparison is meaningful rather than a
category error. Measured on the development box (kernel 6.17, `bubblewrap 0.11.1`):

| | Median | What it measures |
|---|---|---|
| **bwrap, per invocation** | **7.8 ms** | `bwrap --unshare-{user,pid,ipc,net,uts,cgroup} --ro-bind /usr… --proc --dev --tmpfs /tmp /bin/true` — fork+exec bwrap, construct, run, tear down (one process does all of it). |
| ↳ of which: process launch | ~5.5 ms | a near-empty bwrap (`--ro-bind / / /bin/true`): bwrap's own fork+exec+link floor. |
| ↳ of which: construction | ~2.3 ms | the namespace + bound-view + `/proc`·`/dev`·`/tmp` build itself. |
| **Kennel, `kennel run` (CLI)** | **13.7 ms** | the full operator path: the `kennel` shim → the host execution unit → the daemon → the **privhelper** factory → construct → run → teardown. *More* process hops than bwrap, doing more. |
| **Kennel, agent spawn (binder)** | **9.4 ms** | the high-frequency path: an agent transacts `SPAWN` over the binder (no CLI shim/host-unit) → daemon → privhelper → construct → result+EOF. |
| **Kennel, construction only** | **3.7 ms** | the daemon's build→workload-exec span — namespaces + view + **Landlock** + the privhelper's privileged construction + binder. Includes the privhelper invocation; excludes the CLI/binder round-trip around it. |

The honest read — and it is emphatically **not** a "we're faster" claim. Kennel costs **more**, end to end,
and should, because it is doing more:

- **A full `kennel run` (13.7 ms) is ~75% over a bwrap invocation (7.8 ms) — and a chunk of that delta is
  *work bwrap does not do at all*.** That path is a shim → host-unit → daemon → privhelper chain (more
  process launches than bwrap's single binary), and on it the daemon **cryptographically verifies the
  policy's ed25519 signature against the trust store**, resolves the template chain, enforces Landlock,
  brokers through the gateway, and writes audit. bwrap validates *nothing* — it trusts whatever argv
  assembled it (the T2.1/T2.8 surface above). So this is not "Kennel is slower at the same job"; it is
  Kennel doing signed-policy validation + LSM enforcement + audit that bwrap structurally omits. You pay for
  the reference monitor; it is not free, and we do not pretend it is.
- **The construction *work* is the same order** — bwrap ~2.3 ms, Kennel ~3.7 ms (the privhelper's privileged
  build included) — with Kennel's doing more (Landlock, the privileged construction) for ~1.4 ms more. The
  shared mechanism has a shared floor.
- **The path that actually matters is the spawn — kennel-spawns-kennel — and there it is within ~20% of bare
  bwrap (9.4 ms vs 7.8 ms).** This is the MCP / agent-composition case the whole spawn/mesh model exists for:
  an agent parcels out deny-by-default sub-capability to the tool kennels it spawns, each floored to a signed
  template, over the binder (no CLI hops; the spawn *validates* the signed template — re-checking its
  content-pin — it never authors or re-signs one). At ~9.4 ms a bounded, mediated, signed-template
  sub-kennel is cheap enough to spawn-use-reap
  constantly — and **bwrap has no analogue**: an agent re-invoking bwrap composes nothing bounded (the T3.9
  *unbounded* residual above), because a per-invocation mechanism does not become a delegation model by being
  fast. The comparison is "9.4 ms for bounded delegation with a reference monitor" against "no bounded
  delegation at any speed."
- **The premium is single-digit-to-low-double-digit milliseconds** — nothing for per-task confinement, and
  orders of magnitude below any VM (Firecracker ~275 ms to workload). Complete mediation, LSM enforcement,
  signed policy, and audit cost a few milliseconds over the shared mechanism floor; they do not move the
  order of magnitude.

*Machine-specific (unpinned `schedutil`; pin `performance` for stable medians). Kennel spawn/construction
figures from `src/tools/spawn-spinup.sh`, the `kennel run` figure from a `kennel run … /bin/true` loop, the
bwrap figures from a kennel-comparable `bwrap … /bin/true` loop — 40–50 iterations, median. Re-measure on
the target hardware before quoting.*

---

## Honest scope — where this comparison must not overclaim

- bwrap is **not insecure**; it is a well-built mechanism that does what it claims. The argument is about
  *what it claims* — a constructed view, not a mediating reference monitor — not about whether it does it
  well.
- Several bwrap residuals above are **closable by wrapping bwrap in more tooling** — which is precisely
  what the "bubblewrap-wrapper community" (T1.8) does, and what Flatpak does (adding the portal, the
  D-Bus proxy, etc.). The honest claim is not "bwrap can't be extended toward this" — it is "Kennel is
  the reference monitor as a designed whole, where the wrapper community is assembling one ad hoc around
  bwrap, and the catalogue documents where the ad-hoc assemblies leak (T2.1 escape, T1.8 in-band exfil)."
- The bwrap rows are confirmed against **bubblewrap 0.11.1** (`bwrap --help`): the option surface offers
  namespaces, bind mounts, and seccomp, and offers no Landlock, no egress proxy/allowlist, no
  daemon/ttl/audit, and no signed-policy/template mechanism. Re-check against the running bwrap before
  citing a version-specific behaviour; the Flatpak portal stack (D-Bus proxy, document portal) is a
  separate, wrapper-added surface, not bwrap itself.

## What this is for

bwrap is the comparison a knowledgeable security reviewer reaches for first, because it is the closest
existing thing. The MicroVM doc differentiates on layer and trust zone; this doc differentiates on
**reference-monitor discipline** — complete mediation, signed-artefact policy, tamperproofing, and the
standing mechanisms — because that is the actual axis of difference with a same-layer same-trust-zone
neighbour. Conceding bwrap's real strengths (view construction, net-ns, unprivileged, battle-tested) is
what makes the located difference credible. The T2.1 Ona instance is the empirical anchor: a real agent,
in a real bwrap sandbox, talked its way out — not because bwrap failed at being bwrap, but because a
launch-time mechanism is not a runtime reference monitor.