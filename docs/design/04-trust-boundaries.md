# §4 Trust boundaries and the reference monitor

A confinement system is a reference monitor or it is scenery. Anderson's 1972 study named the three properties such a monitor has to hold: it mediates every access to a protected resource (complete mediation; it cannot be bypassed), the code it constrains cannot alter it (tamperproof), and it is small enough to be analysed for correctness (verifiable). Project Kennel is built to those three, and this chapter follows them — §4.1–4.5 are complete mediation, §4.6 is tamperproofing, §4.8 is verifiability and what it costs.

The nearest familiar handle for what that produces is a mandatory access control layer that runs in user space — kind of, with two qualifications that carry the whole chapter. It is not label MAC: it does not gate edges between security contexts the way SELinux gates `httpd_t → postgresql_t`. And the thing it is mandatory *over* is the content of an interaction, not merely whether the interaction is reachable. The second qualification is the load-bearing one, because content is exactly where the kernel's own access control stops.

## 4.1 The reachability ceiling

Kernel access control, discretionary and mandatory alike, decides reachability and then stands down. Unix DAC asks whether a uid may open a file; once the descriptor is held, every read and write across it is ungoverned, because under DAC possession is authority. SELinux raises the same question to labels — may this domain connect to that socket — and it is genuinely mandatory, since the constrained process cannot relax it. But it still answers a reachability question and then stops. Neither model can see the bytes that cross the channel it permitted. SELinux cannot read the query on a connection it allowed; DAC cannot tell a benign write to a socket from one that carries `docker run -v /:/host`.

That channel granularity is insufficient is not a claim this document needs to argue, because the platform already conceded it. `dbus-daemon` enforces per-method policy in user space precisely because the kernel cannot see a method call. polkit exists for the same reason. ssh forced commands, sudo's command matching, and `git-shell` are each a userspace mediator bolted onto one protocol because kernel access control granted the channel and had nothing to say about its use. These mediators are per-protocol, separately configured, and tied to no shared threat model. Project Kennel is the generalisation of the move they each make once: a single reference monitor, every resource class, one policy vocabulary, one audit stream.

The gap is sharpest in a single object. A reachability-based sandbox confines by placement — it decides which sockets, devices, and paths appear in the workload's view, and that decision is the whole of its enforcement. Take how such a tool grants Docker: it binds `/var/run/docker.sock` into the view. Nothing further happens. Every `docker run`, every bind mount, every `docker exec` then crosses that socket, and the sandbox neither inspects nor judges any of it. Because the Docker socket is a root-equivalent control channel, "the socket is present" is operationally "the workload holds root on the host." The boundary decision was the security decision, taken at the coarsest available granularity. (ai-jail is the honest representative of this class — it documents Docker-socket passthrough as on by default, and is right that for its stated job, confining the operator's own agent, placement suffices. For a workload the operator does not trust, it does not.)

A reference monitor cannot leave the decision there. It has to mediate the use, not only the reach. Project Kennel does this two ways, and which one applies to a resource is a deliberate per-class choice: remove the channel so that no use exists to mediate (§4.2), or interpose so that every use is a transaction the monitor authorises (§4.3).

## 4.2 Complete mediation by construction — the absence path

The first way to mediate every access to a resource completely is to arrange that the resource is not present. If it is not in the workload's view, the count of accesses to mediate is zero, and complete mediation holds by construction. This is the *constructed-view* pattern: rather than enumerate what a kennel is denied against the host's real state, Project Kennel presents the kennel with a positively constructed view of each resource class, containing only what policy grants. What is not in the view is not present, not deniable, not enumerable.

The pattern is not novel in isolation — Flatpak's per-app filesystem views, container mount namespaces, and chroot share the structure. What matters here is applying it uniformly across every resource class as the structural answer to optimisation-driven reconnaissance (§1): a workload that cannot enumerate its environment cannot probe for what to route around.

The alternative most systems reach for is a denylist — enumerate the resources the kennel should not touch, configure the kernel to deny them. That works against a workload that fails closed: it hits a denial, gets an error, stops. It fails against a workload that optimises. An agent running `find ~ -name '.env'` against a real `$HOME` with read denials on credential paths still sees the *existence* of `~/.ssh/`, `~/.aws/`, `~/.gnupg/` — the directory entries, the file counts, the names, the mtimes, and the fact that some paths are deniable and others are not, which is itself a signal of importance. The agent does not need to read `~/.ssh/id_ed25519` to plan against it. Knowing it exists is enough to ask the user for SSH access, search shell history for past use, or generate code that requires a key and prompt for the grant. Denylists leak structural information, and they can be enumerated by trying things and watching which fail.

Under construction the kennel's `$HOME` is a fresh tmpfs holding only the paths policy bind-mounts in. `~/.ssh/` is not "present but denied"; it does not exist, and `find ~ -name '.env'` returns nothing because the `~` the kennel sees never contained those files. The same logic runs through every class where absence is the right answer:

- The network view holds one route, to the kennel's egress proxy. The host's real network is not in the namespace, not in any route, not in `ip route show`; the user's loopback services are absent from the kennel's `127.0.0.1`.
- The process view, under a PID namespace, holds the kennel's own descendants. The user's shell, browser, IDE, and password manager are not deniable to it; they are invisible.
- The environment view is *synthesised* from policy by the spawn wrapper: `execve` replaces the environment wholesale (`env_clear`), framework variables are forced, and a sensitive variable like `AWS_SECRET_ACCESS_KEY` is absent because nothing was inherited to begin with — not stripped after the fact. A pass-through from the parent is a discouraged, warned, per-variable opt-in, never the default.

Denial is structural, and the workload's probing has no surface to act against. Three consequences follow that a denylist cannot offer. Inspection is one-directional: the answer to "what does the kennel see for X" is "the constructed view for X," with no "everything not denied" to reason about. Policy edits are positive: a grant says "add this to the view," never "remove this from the deny list." And the view *is* the boundary, so authoring bugs are bugs in what was included — visible — rather than in what was forgotten.

## 4.3 Complete mediation by interposition — the transaction path

Construction handles resources the workload has no legitimate need to reach. The harder case is a resource the workload must reach, where each use has to be judged on its content. Removing the channel is not available; the monitor has to sit in it. Project Kennel interposes here, and splits the interposition three ways so that the only part the workload can reach holds no authority: a thin facade converts the protocol, kenneld decides, and a host-side delegate acts.

The facade is a converter and nothing more — it turns the workload's protocol (a SOCKS5 `CONNECT`, a D-Bus method call) into a typed binder transaction on the per-kennel bus, whose context manager is kenneld. The decision sits across that boundary, where binder hands kenneld one property a socket-in-view model cannot: every crossing is a synchronous transaction the kernel stamps with the caller's identity (`sender_pid`, `sender_euid`), which the caller cannot forge. kenneld authorises and audits each transaction against that unforgeable principal; where an action follows — an outbound connection, say — a host-side delegate performs it and returns only its result back through kenneld. Because binderfs is mounted inside the kennel's own user namespace, the bus confers no host-side privilege. Kernel enforcement stays simple ("you may reach only your facade"), the policy lives in kenneld, and the component the workload can actually reach and feed hostile bytes to decides nothing.

Three facades are built, and they show the range of the limb:

- **AF_UNIX brokered connect** (`facade-afunix`, §7.6). Granted endpoints are reached by a binder transaction that returns a connected socket fd; the socket path is absent from the constructed view. Construction removes the pathname, interposition governs the connect, and the workload cannot enumerate the host's other sockets to begin with.
- **Egress** (`facade-socks5` in the kennel, `host-netproxy` host-side, §7.5). The worked example of the split: `facade-socks5` converts a SOCKS5 `CONNECT` into a binder transaction; kenneld validates it against the egress policy — DNS resolution, per-destination allow and deny, audit, the user-space concerns a cgroup-BPF connect hook cannot express — on the stamped principal; `host-netproxy`, an unprivileged process in the user's host-side context (the kennel's own netns has no route to the real network, so the connection is originated where the network is), then opens the outbound TCP and passes the established fd back through kenneld to the facade, which hands it to the workload. BPF stays the in-kernel floor underneath. The facade never sees the policy and never opens a connection.
- **SSH re-origination** (`facade-ssh`, §7.10). The interposition is what makes the capability safe. Exposing a per-kennel `ssh-agent` would hand the workload a destination-blind signing oracle: the agent protocol carries an opaque blob to sign, not a destination, so a hostile workload could authenticate an allowlisted key against an attacker-chosen host. The bastion never exposes an agent; it binds the destination to a disposable synthetic key that is itself the destination selector, so the key cannot be aimed elsewhere.

The same analysis marks the limb's boundary, and gpg is where interposition is *refused* rather than built. A signing oracle is worse than the SSH case, because it stamps the user's verified identity permanently onto whatever artefact the workload presents — malware, a release, a forged commit — not just one live session. The SSH fix does not carry over: SSH is a transport, so the bastion can re-originate and bind a destination, but commit signing is a data-integrity protocol whose hash incorporates its own signature, leaving no host-verifiable property to bind a facade's decision to. This is settled by axiom, not deferred (§11.2): a kennel exists to contain code the operator does not trust, and an untrusted workload must never produce a cryptographic attestation *as* the operator. Authentication is a constrained, host-verifiable capability a facade can mediate; attestation is the operator vouching for data, which cannot be delegated. A `gpg-agent` grant is therefore a footgun, warned loudly and surfaced in `kennel policy risks`, never a sanctioned facade. The workload commits unsigned; the human signs on review before push.

Interposition is not free, and §4.8 accounts for the bill — but the bill is not the facade. The reachable converter holds no authority and parses hostile input on the untrusted side of the boundary, so its compromise is inert; the standing cost is the live decision point kenneld holds in the path. The limb is justified only where content governance is the requirement and construction cannot supply it.

## 4.4 The two limbs across resource classes

Which limb applies to a class is a design decision, not an accident of mechanism. Absence is chosen where the workload has no legitimate need to name the resource; interposition where it does, but each use must be judged; several classes use both.

| Resource class | Mediation | Mechanism |
|---|---|---|
| Filesystem (§7.4) | Construction | Constructed `$HOME` view, granted paths bind-mounted from real locations, private `/tmp` tmpfs, Landlock over the result |
| Binary execution (§7.3) | Construction | `execve` allowlist plus the resolved library closure; nothing outside the closure is present to run |
| Network (§7.5) | Both | Empty per-kennel netns removes every destination (construction); the egress facade governs the one that remains (interposition) |
| AF_UNIX, pathname (§7.6) | Both | Path absent from the view (construction); brokered connect per endpoint (interposition) |
| AF_UNIX, abstract (§7.6) | Construction | Landlock `SCOPE_ABSTRACT_UNIX_SOCKET` (ABI 6) scopes the abstract namespace to the kennel; seccomp/AppArmor fallback below 6.12 |
| D-Bus (§7.7) | Interposition | Per-method filtering needs the protocol parsed; xdg-dbus-proxy today, binder facade on the roadmap |
| Process visibility (§7.9) | Construction | PID namespace; only the kennel's own descendants |
| Environment (§7.9) | Construction | Synthesised spawn (`env_clear`); built from policy, framework variables forced, parent pass-through a warned per-variable opt-in |
| X11 (§7.8) | Construction | A separate X server per kennel (Xwayland- or Xephyr-isolated); there is no useful protocol-level filter to interpose, so the host display is simply not reachable |

The unifying property holds in both columns: what is not constructed is not there, and what is reachable is reached only through a transaction the monitor sees. Default-deny is structural, not the residue of an exhaustive deny-list.

## 4.5 The trust hierarchy

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          USER ACCOUNT (real uid)                          │
│                                                                           │
│   DEFAULT CONTEXT — the user's normal shell. Full authority of the uid.   │
│   The trust root. kenneld and the privhelper run here, at the user's      │
│   authority, and construct kennels as lateral peers beneath it:           │
│                                                                           │
│     ┌── kennel: ai-coding ──┐   ┌── kennel: ai-coding+npm ──┐             │
│     │  constructed views    │   │  policy refines ai-coding │             │
│     │  egress via facade    │   │  (intersection, narrower) │             │
│     └───────────────────────┘   │  net.mode = none          │             │
│                                  └───────────────────────────┘             │
│     ┌── kennel: untrusted-build ─┐                                        │
│     │  independent narrowing     │   siblings are mutually invisible      │
│     └────────────────────────────┘                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

Kennels are lateral. kenneld is always the constructor; one kennel does not run inside another, and the `ai-coding+npm` kennel above is a separately constructed sibling whose *policy* refines the `ai-coding` template, not a process nested within it. Relationships between kennels are relationships between policies, never containment.

The boundaries that must not weaken:

- **Default context ↔ kennel.** A kennel cannot influence default-context processes, files outside its grants, sockets, or environment. The default context owns its confined children and can inspect, signal, and kill them.
- **Sibling kennels.** Two kennels are mutually invisible unless a grant says otherwise. Their loopback subnets are disjoint, their AF_UNIX views are disjoint, their PID visibility is disjoint.
- **Kennel ↔ kernel.** Every syscall passes through the kennel's policy; there is no bypass via "I am still uid 1000." Same-uid is no longer the trust boundary. Cgroup membership, the mount namespace, and the Landlock ruleset are.
- **Refining policy ↔ base policy.** A kennel whose policy refines another's computes the intersection of its own declarations and the base; it may narrow, never widen.

## 4.6 Tamperproofing the monitor

The second reference-monitor property is that the constrained code cannot alter the monitor. Two surfaces carry the weight: the construction path that builds a kennel, and the host-side integrity witness for what a kennel writes.

Project Kennel runs primarily as the user's uid, with one privileged exception, the *privhelper*, which is the kennel constructor. To build a kennel it creates the namespaces, writes the identity map that gives the kennel a real uid 0 (host root mapped `0 0 1` plus the operator's line, in a single `write(2)`, with no subuid/subgid delegation), brings up the per-kennel loopback subnet, mounts the constructed view and the per-kennel binderfs instance, and `fexecve`s the root-owned `kennel-bin-init` supervisor as the kennel's uid-0 PID 1.

Because it builds from a compiled policy `Plan`, the privhelper is the largest new surface where root decodes operator-controlled bytes. The design contains it deliberately. The Plan is split: the privhelper parses only the construction half — the uid/gid maps, loopback config, binderfs parameters, the view bind list, the pivot target — and it parses them host-side, before any kennel namespace exists, so nothing it decodes has passed through a sandbox that could have shaped it, and the decoder is bounded and fuzzed. The supervision half — the workload argv and environment, the facade list, the Landlock ruleset, the seccomp filter, ulimits, the pty — is never pushed to root; the contained `kennel-bin-init` pulls it post-pivot over the binder bus. No operator or workload code runs as the mapped uid 0: `kennel-bin-init` is `fexecve`d only after `pivot_root` has detached the host root, it holds no ambient host capabilities, and it is trusted by provenance — root-owned, non-writable, opened by descriptor before the namespace exists. The escalation-window analysis for the mapped uid 0 is in §2.8.

The second surface is what a kennel leaves behind. A workload with `fs.write` to a project can plant a deferred trigger — a `Makefile` recipe, a `.git/hooks/` script, an IDE task — that fires later in the user's *unconfined* shell (T2.8). The witness is a host-readable marker the workload cannot forge: `.trust-manifest.json` at each writable workspace root pins the SHA-256 of the known execution triggers (schema `docs/schemas/trust-manifest-v1.json`). The same over-mount that masks credential files masks the manifest out of the constructed view, so the workload provably cannot read or forge it, while host tooling refuses a trigger whose hash has diverged. The honesty bound matters and is stated as such: the masking is structural and complete, but the defence is best-effort in *which* triggers it enumerates and in relying on host tooling to honour the marker — it informs the host, it does not enforce on it (see T2.8 for residuals).

Project Kennel's own trust position follows from this:

- **Higher than kennels.** It owns the policy decisions, the facades, the audit log, the cgroup hierarchy.
- **Equal to the default context.** It can do nothing the user could not do in their normal shell.
- **Bounded by consent.** The user installs it, configures it, and can disable it. It does not survive a user working actively against it, and does not try to — the threat model is confining same-uid processes the user has chosen to confine, not protecting the user from themselves. A determined adversary already in the default context can read Project Kennel's state directly; the default context is the trust root, and anyone there is, by assumption, the user.

## 4.7 What crosses each trust boundary

**Default context → kennel:** the invocation parameters (`kennel run <name> cmd`), the synthesised environment, the constructed filesystem view (read-only by default for most paths), standard input and output (the controlling terminal, where granted), and an initial working directory constrained to lie inside the granted filesystem.

**Kennel → default context:** exit status and signals to the parent, standard output and error, audit events via the log writer rather than directly, and files written to granted writable paths (which the default context reads normally).

Nothing else crosses. In particular: no D-Bus signals to the user's session bus (the proxy filters incoming as strictly as outgoing); no desktop notifications unless explicitly granted, which is itself a capability (§7.7); no clipboard bridge unless deliberately bridged; no input events to other windows; no `kill()` to processes outside the kennel.

**Kennel ↔ sibling kennel:** nothing by default. Two kennels are mutually invisible; a shared path or a shared loopback service is possible but requires deliberate policy on both sides.

## 4.8 Verifiability, and the cost of mediation

The third reference-monitor property is that the monitor is small enough to be analysed, and it is where the project's "how can I do less" stance stops being a temperament and becomes a requirement. Every component in the trusted base has to earn its size, because the base is what has to be audited; a facade earns its place only by closing a threat the construction limb cannot, and each one is justified against a threat ID rather than added for convenience.

The honest cost of the interposition limb belongs here, and it is smaller than the obvious objection assumes. The objection is that a facade parses adversary-supplied protocol — SOCKS5, D-Bus — on every message, putting a parser for hostile input in the loop for the life of the kennel. It does parse it, but the facade sits on the untrusted side of the binder boundary and holds no authority. It converts a request into a typed binder transaction and nothing more; the decision is kenneld's, on the stamped principal, and any privileged effect is `host-netproxy`'s, acting only on a kenneld-validated request and returning an established fd. Compromising a facade binary buys the workload nothing — it can already emit any binder transaction it likes, kenneld re-validates every one, and the converter it subverted was never trusted. The foreign-protocol parser is quarantined exactly where its compromise is inert.

What interposition genuinely costs is kenneld: a single live decision point standing in the path for the kennel's lifetime, ruling on every transaction. The entire runtime decision sits there and nowhere else. `host-netproxy` stands alongside it but decides nothing — it is a policy-free dialer that opens the connection kenneld already authorised and returns the fd. It runs host-side in the user's own context, an ordinary unprivileged process that is neither part of the kennel nor part of the privileged helper, so what it can reach is the user's own network and no more. Its integrity bounds where a connection lands, which makes it trusted, but at user authority and with no policy of its own: it adds the user's reach to the trusted base, not privilege and not judgement. A reachability-only sandbox has no standing mediator of either kind.

Crucially, kenneld stands in the *control* path, not the data path. It rules on the `CONNECT` and does not carry the bytes that follow: once it authorises a connection, the established socket is handed down as an fd the facade reads and writes directly, and data moves between the facade and the host-side connection without traversing kenneld at all. Mediation is paid once per connection, at setup; throughput is whatever the kernel sustains, independent of the mediator, so the decision point's load tracks the rate of decisions rather than the volume of data. This is not a gap in complete mediation — the mediated event is acquiring the connection, and bytes on an already-authorised connection are its sanctioned use, the way reads on a granted file descriptor are not fresh access decisions. Performance and scalability both follow from keeping the monitor on the control plane and vending a kernel handle for the data plane.

The cost is bounded by what the trusted code reads. kenneld rules on typed, length-prefixed binder transactions (§7.1) rather than raw foreign protocol, so the hostile-input parser stays outside the decision path, in the untrusted facade. netproxy reads less still — a validated dial request from kenneld over the host-side SCM_RIGHTS channel, never a byte of workload input. The privhelper's Plan decoder is cheapest of all: it runs once, host-side, before any sandbox exists, against bytes no workload has touched, and it is fuzzed. One locus of runtime policy, reading a format the project defines, is the verifiability win the limb is built to preserve.

Stated plainly against the alternative: a reachability-only sandbox carries a smaller trusted base because it attempts less. It accepts the ceiling of §4.1 — placement is the whole decision — in exchange for no standing mediator. Project Kennel buys content mediation with a standing decision point in kenneld. That is the trade, and naming it is part of being verifiable. The purchase is kept bounded by construction: foreign-protocol parsing is pushed to untrusted converters where a compromise is contained, the trusted path reads only typed transactions, and absence is preferred wherever it suffices because it costs nothing to audit.

## 4.9 Required kernel features

Each class needs specific mechanisms to construct or interpose its boundary safely. The binding floor is kernel 6.10, set by Landlock `FS_EXECUTE`; Project Kennel refuses to start on kernels lacking a required feature rather than degrade silently, and reports which feature is missing.

| Resource class | Required mechanism | Minimum kernel |
|---|---|---|
| Filesystem view + exec | Mount namespace + Landlock `FS_EXECUTE` | 6.10 (the project floor) |
| Network view | Network namespace + cgroup BPF (connect hooks) | 4.10 for the hooks; 6.10 effective |
| AF_UNIX, pathname | Mount namespace + binder brokered-connect facade | binderfs 5.0; 6.10 effective |
| AF_UNIX, abstract | Landlock `SCOPE_ABSTRACT_UNIX_SOCKET` (ABI 6); seccomp/AppArmor fallback below | 6.12 for native scoping |
| Construction + binder bus | User namespace + binderfs (`FS_USERNS_MOUNT`) | 3.8 user ns; 5.0 binderfs |
| Signal isolation | Landlock `SCOPE_SIGNAL` (ABI 6) + PID namespace; AppArmor fallback below | 6.12 for native scoping |
| D-Bus view | binder facade or xdg-dbus-proxy, over the AF_UNIX view above | user space |
| Process view | PID namespace + procfs `hidepid` | 3.8 (PID ns) |
| Environment view | Spawn wrapper | none |

Below Landlock ABI 6 (kernel 6.12) the abstract-AF_UNIX and signal classes fall back to the seccomp/AppArmor path; on ABI 6 and above they are enforced natively and Project Kennel does not rely on AppArmor for the workload. The full feature matrix and the AppArmor `userns`-grant arrangement are in §8.