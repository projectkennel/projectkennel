# AWS Lambda MicroVMs and Project Kennel: different layers, different trust zones

*Reconciled against THREATS.md v0.4. AWS Lambda MicroVMs (announced 2026-06-22) isolate user- and
AI-generated code per user/session using Firecracker VM-level isolation. This document maps what that
boundary closes and what it does not, by T-number — the same closed/bounded/out-of-scope discipline as
the openclaw mapping — and states plainly where the two systems sit relative to each other. MicroVMs are
not a competitor to Kennel; they are the **coarse tenant-isolation layer above** the **fine
capability-confinement layer** Kennel occupies. The launch is the strongest market validation to date
that the problem is present-tense — and it leaves the within-environment residual exactly where Kennel's
shape is.*

**The one-line distinction:** a MicroVM is the **box** (isolate this whole untrusted environment from the
next tenant's). Kennel is **what the code may do inside the box** (deny-by-default capability confinement
within one environment). A VM boundary says nothing about what the workload reaches on its *own* assigned
environment — and that is where the openclaw threat class lives.

---

## What MicroVMs close — and Kennel agrees they close

VM-level isolation via a hypervisor is a genuinely strong boundary **between** environments. Stated
honestly, because the credibility of the rest depends on it:

- **Tenant-to-tenant isolation — CLOSED by the VM boundary.** One user's MicroVM cannot reach another's:
  separate guest kernel, hardware-virtualization separation. This is the same property Kennel provides
  laterally between kennels (§4.5 per-kennel isolation, T5.2 cross-kennel) but enforced at a *stronger,
  coarser* boundary — a hypervisor rather than namespaces + a reference monitor. For pure "blob A must not
  touch blob B," a MicroVM is a heavier and arguably stronger boundary than a kennel.
- **Host-kernel attack surface from the guest — reduced.** A guest-kernel compromise is contained by the
  hypervisor; the analogue of T5.1–T5.4 (framework gateway surface) is replaced by the Firecracker/KVM
  boundary, a different and well-studied surface. Kennel's TCB is its userspace reference monitor; a
  MicroVM's TCB is the VMM + host kernel.

Where the problem is "give each tenant a sealed environment," MicroVMs are a strong answer and Kennel does
not dispute it. The catalogue's lateral-isolation claims and the MicroVM's tenant-isolation claims point at
the same property from two mechanisms.

---

## What MicroVMs do NOT close — the within-environment residual, by T-number

A MicroVM isolates the environment; it does nothing about what the workload does **inside** its own
environment. Every threat below happens inside a MicroVM unchanged, because each is a within-environment
capability question a VM boundary does not address. This is the openclaw threat class, and it is precisely
Kennel's shape.

| Threat | Inside a MicroVM? | Why the VM boundary doesn't help |
|---|---|---|
| **T1.1** Credential / history / config reconnaissance | **Unaddressed** | The AI code inside the VM still reads `~/.aws`, `.ssh`, `.env`, tokens mounted or present in *its own* environment. A VM around it changes nothing about what it reads within. |
| **T1.6** Lateral movement to local services | **Partly** | Cross-*tenant* is closed by the VM; but services *inside* the same MicroVM (a sidecar DB, an agent socket) are fully reachable — there is no per-capability gate within the box. |
| **T1.7 / T1.8 / X9** DNS + TLS in-band exfiltration | **Unaddressed** | The MicroVM has a dedicated HTTPS URL and egress; AI code exfiltrates within legitimate traffic exactly as before. VM isolation is not an egress allowlist or a proxy. |
| **T2.1 / T2.2 / T2.5** Posture degradation in produced code/config | **Unaddressed** | The code the workload *writes* — disabled TLS verify, `chmod 777`, suppressed CI checks — is produced inside the VM and shipped out. The VM boundary is around the process, not its output. |
| **T2.3** Secrets in unintended locations | **Unaddressed** | A within-environment data-handling threat. No VM property prevents the workload embedding a secret it holds. |
| **T2.8** Cross-context persistence via workspace triggers | **Unaddressed** | The workload plants a git hook / Makefile trap in its *own* writable tree; the VM doesn't pin or mask triggers. If that tree persists (MicroVMs suspend/resume up to 8h and retain state), the trap persists with it. |
| **T3.6** MCP / skill capability creep | **Unaddressed** | A skill inside the MicroVM runs with the environment's full capability — the 800-malicious-ClawHub-skills problem is a *within-box* problem the VM doesn't touch. |
| **T3.7** AI agent prompt injection from project content | **Unaddressed** | Injection redirects the agent *inside* its environment; the VM bounds the blast radius to the whole environment, not to a deny-by-default policy. A tricked agent reaches everything its box grants — which, without capability confinement, is everything in the box. |
| **T3.9** Delegated spawning / cross-tool composition | **Unaddressed within** | If the agent spawns tools inside its MicroVM, there is no template floor, no request-don't-author, no per-spawn capability bound — the agent composes freely within its environment. |

The pattern is exact: **MicroVMs make the box; the openclaw threat class operates inside the box.** A
MicroVM running openclaw still has openclaw doing everything openclaw does to its own environment — reading
its credentials, being prompt-injected, exfiltrating in-band, planting persistence — it simply cannot reach
the *next tenant's* box. Tenant isolation is real and valuable; it is not capability confinement, and the
catalogue's within-environment families are untouched by it.

**They compose.** Kennel inside a MicroVM is coherent and arguably ideal: the VM bounds tenant-to-tenant,
Kennel bounds what-the-code-reaches within. AWS validated the coarse layer enormously; the fine layer is
the residual their own launch leaves, and the catalogue already enumerates it — dated before this launch.

---

## The shape mismatch: Lambda is the wrong trust zone and the wrong billing model

Beyond the threat mapping, there is a structural reason MicroVMs do not address the developer/enterprise
case Kennel targets — they are the wrong *shape*, independent of what they isolate:

- **Outside the trust zone.** Lambda MicroVMs run the code in **AWS's environment**, not the developer's.
  For the workstation case — an AI coding agent on a developer's laptop, a package post-install on a build
  box, an MCP server in a dev environment — the code that needs confining is *already inside the
  developer's trust zone, on the developer's machine, touching the developer's credentials and source.*
  Shipping it to a MicroVM in `us-east-1` to isolate it is the wrong topology: it moves the workload out of
  the environment whose resources are the actual target (T1.1 credentials, T2.8 the local project tree,
  T1.6 local services), and those resources are not in AWS. The threat is *local*; the isolation is
  *remote*. You cannot confine an agent's access to `~/.aws` by running the agent in someone else's cloud —
  either the credentials go to the cloud too (worse), or the agent isn't doing the local work it was for.
- **Billed by the hour, metered, baseline-plus-usage.** MicroVMs bill for baseline compute while running
  plus active duration. That is a per-second cloud-spend model on every confined execution. The
  workstation confinement case — confine *every* agent run, *every* package install, *every* untrusted
  build, continuously, by default — is economically nonsensical as metered cloud compute. Kennel's ≈3.7ms (measured)
  local kennel construction costs effectively nothing per spawn; a per-second-billed MicroVM per
  package-install is a cost model that guarantees confinement gets *switched off* under budget pressure,
  which is the friction-routing-around behaviour the catalogue's whole Family-2 thesis (§1.2) warns about.
  Confinement that costs money per use is confinement that gets disabled; confinement that costs ~nothing
  and is the default is confinement that holds.
- **Enterprise data-residency and dependency.** Routing developer code and its data through AWS to confine
  it adds a third-party processor to every confined execution — a data-residency, compliance, and
  vendor-dependency surface (the catalogue's X8 "vetted system tools" boundary, now an entire cloud). The
  enterprise that wants AI-code confinement on its developers' machines does not want each confined run to
  be an AWS API call with its source as the payload.

So even where the threat overlaps, the *deployment shape* diverges: MicroVMs are **multi-tenant SaaS-backend
isolation** (a platform isolating its users' code from each other, in the platform's cloud, metered). Kennel
is **workstation / in-trust-zone confinement** (the operator confining untrusted code on the operator's own
machine, locally, free per use, by default). They are not the same product even where they touch the same
threats — different trust zone, different topology, different economics.

## Why MicroVMs structurally cannot host the delegated-spawn model

The sharpest consequence of the trust-zone difference: the spawn / mesh model (T3.9, §7.12–7.13) — an agent
holding real local capability that **delegates bounded sub-capability** to tools it spawns, each floored to
a signed template, the agent never holding the whole trifecta — **cannot exist in the Lambda topology, and
not because AWS hasn't built it yet. The trust zone forbids it.**

The spawn model's entire value is *bounded delegation of genuine local authority*: the agent parcels out
deny-by-default slices of the developer's **actual** `~/.aws`, SSH agent, project tree, and local services.
For MicroVMs to do this, that genuine local authority would have to be **inside the AWS MicroVM** — which
forces a dilemma with no good branch:

- Either the developer's real cloud credentials and source are **copied into a per-session VM in
  `us-east-1`** — which is a credential-exfiltration pattern the catalogue flags as a *threat* (T1.1, with
  the destination being AWS itself), not a feature; or
- the MicroVM holds **no real local credentials**, in which case there is nothing meaningful to delegate and
  the spawn model is pointless.

To delegate local authority you must hold local authority; the moment you move it to the cloud to isolate
it, you have either created the leak or removed the thing worth delegating. This is why MicroVMs are stuck
at the *coarse* layer: tenant-to-tenant isolation is trust-zone-portable (you isolate blobs that need no
real local credentials), but **capability confinement of an agent doing real local work is trust-zone-bound**
— it requires the real local capabilities to be in scope, which requires being in the local trust zone,
which Lambda definitionally is not.

A second, independent reason it cannot live there: the spawn model is **high-frequency by construction** — an
agent spawns many short-lived tool kennels, the mesh brings providers up and reaps them on demand, the whole
design rests on ≈3.7ms (measured) ephemeral construction *because* it happens constantly. A per-session-billed MicroVM
is the wrong granularity for that pattern even setting the trust zone aside: every spawned tool becomes a
metered cloud VM, and the spawn-use-reap-spawn loop that makes an agent useful becomes a per-step cloud cost.
High-frequency local ephemeral spawn and per-session billed remote VMs are incompatible on economics alone.

So the boundary is not "AWS built the layer above and may come down into Kennel's." They **cannot** come
down: coming down means hosting the developer's real credentials in their cloud and metering every spawn,
both non-starters. The delegated-spawn / mesh model is Kennel's defensibly *because* it lives in the local
trust zone — which is precisely where AWS, owning a remote surface, is not.

---

## Strategic reading (for the record, not the catalogue)

- **The "now" question is settled.** AWS shipping a new serverless primitive whose headline is "isolate AI-
  generated code per session" is the loudest external confirmation that the demand is present-tense, not
  anticipated. This is Virtu-shaped market timing (felt, now), not Asteroid-shaped (five years out). The
  desert does not exist for this problem.
- **The surface-owner has moved — at the coarse layer.** AWS owns the cloud surface and put VM isolation
  into it, the Cloudflare/Lynkstate dynamic. But MicroVMs are the *wrong granularity* for within-
  environment capability confinement and the *wrong trust zone* for the workstation case — so AWS built the
  layer above Kennel and the layer beside Kennel's market, not Kennel. Their launch makes the fine-grained,
  in-trust-zone layer *more* visible (everyone reaching for MicroVMs to isolate AI code discovers the box
  doesn't stop the code from exfiltrating its own grants), not less.
- **The defense is the one already prescribed:** the un-decomposable whole (capability confinement is not a
  feature bolted onto a VM), the public dated corpus (priority on the within-environment framing AWS
  conspicuously did not address), and the precise threat articulation showing *why VM isolation is not
  enough* — which the catalogue contained, dated, before the launch. AWS just created the audience that
  needs this gap analysis.

## For THREATS.md / positioning

A short, factual "isolation boundaries: VM-level vs capability-level" note is worth a place in the design
document's positioning section — not in the threat entries themselves. It should state, neutrally: VM-level
isolation (Firecracker, gVisor, MicroVMs) closes tenant-to-tenant and host-kernel-from-guest; it does not
address the within-environment capability families (T1.1, T1.6-within, T1.7/T1.8, T2.x, T3.6, T3.7, T3.9);
the two compose (capability confinement inside a VM); and the workstation/in-trust-zone case is a different
deployment shape (local, free-per-use, default-on) from multi-tenant cloud-backend isolation (remote,
metered, per-session). Keep it descriptive and honest — MicroVMs genuinely close the tenant-isolation
class, and saying so precisely is what makes the within-environment gap credible rather than competitive
positioning.