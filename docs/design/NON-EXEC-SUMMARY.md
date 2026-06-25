# Project Kennel: Security Stance and Trust Boundaries

The user ID (`uid`) on a modern developer workstation has become a massive, mostly atomic trust zone. Today, AI coding agents, package manager post-install scripts, container runtimes, and IDE extensions all run as the user's `uid`, authored by parties the user has no formal trust relationship with. Under standard Discretionary Access Control (DAC), the operating system views all these distinct workloads simply as the user, granting them full reach to SSH keys, cloud credentials, source code, and network interfaces. For AI agents specifically, the threat is not inherent malice, but optimization pressure: an agent trained on task completion will systematically degrade security posture to remove friction.

While the host level has spent decades developing Mandatory Access Control (MAC) vocabularies—like SELinux and AppArmor—to constrain specific binaries regardless of who invokes them, the user level has historically relied on fragmented tooling. Foundational tools like `bubblewrap` successfully pioneered unprivileged namespace isolation at the user level, but they fundamentally act as launch-time mechanisms: they configure a view, launch the process, and step out of the way. A workload cannot be spawned against an unsigned or untrusted policy; the cryptographic gate is not a check that can be bypassed at runtime, because enforcement is built into construction.

Project Kennel builds upon these same namespace primitives to provide the standing runtime enforcement that a launch-and-exit tool structurally lacks. It is not merely a packaging sandbox; it is a user-space implementation of an Anderson reference monitor. It shifts the trust boundary away from the `uid` itself, using cgroup membership, mount namespaces, and Landlock rulesets to enforce a cryptographically signed, default-deny policy that the workload cannot bypass, tamper with, or author.

## Enforcement by Construction and Interposition

Kernel access control decides reachability and then stands down. A reachability-only sandbox confines by placement—if a socket or path is present, its subsequent use is ungoverned. A reference monitor must mediate the content of the interaction, not merely the channel. Project Kennel achieves complete mediation through two structural limbs.

**The Absence Path (Construction).** Where a workload has no legitimate need to reach a resource, the resource is structurally omitted from its view. Rather than deploying a denylist—which leaks structural information and can be enumerated by an optimizing agent—Kennel mounts a fresh tmpfs for `$HOME` containing only granted paths. The host loopback and the user's real network routes are placed outside the kennel's network namespace. A workload cannot probe or optimize against an edge that does not exist.

**The Transaction Path (Interposition).** Where a resource must be reached, the channel is replaced with a transaction the monitor authorizes. Rather than granting raw host sockets, Kennel interposes a brokered facade. A SOCKS5 or D-Bus request from the workload hits a thin converter, which translates the request into a typed transaction on a per-kennel `binderfs` bus. The `kenneld` orchestrator rules on the transaction against the caller's unforgeable identity. If allowed, an unprivileged host-side delegate performs the action and passes an established file descriptor back.

Crucially, the standing mediator (`kenneld`) sits in the control path, not the data path, making runtime mediation performant.

## The TCB and the Rule of 1

A confinement system is defined by where it holds privilege. The industry standard heuristic for vulnerability management is the "Rule of 2," which dictates that a system component must not combine more than two of three risk factors: untrusted input, an unsafe language, and high privilege. Project Kennel engineers its Trusted Computing Base (TCB) to compress this heuristic down to a strict **Rule of 1**. No component in the architecture holds more than a single risk vector.

The TCB is written in safe Rust and is small enough to be read and audited in full. To maintain the Rule of 1, the architecture rigorously separates privilege, language safety, and input handling:

* **The Orchestrator (`kenneld`):** Handles policy resolution, cryptographic verification, Landlock enforcement, and audit routing. It is written in safe Rust. It operates entirely unprivileged as the invoking user. It reads no untrusted input, accepting only cryptographically verified policy templates and typed binder transactions.
* **The Privileged Helper (`kennel-privhelper`):** The only component that holds elevated privilege, and the only component that runs as setuid root. It executes solely to write identity maps and mount the cage. It is written in safe Rust and operates only *after* an ed25519 signature check against the trust store verifies the policy template. It reads no untrusted input.
* **The Facades and Parsers:** Foreign protocol parsers for adversarial input (e.g., the `vte` terminal escape parser, or the `mini-sansio-dbus` decoder) are pushed entirely out of the TCB. They handle untrusted input, but are written in safe Rust and execute either as unprivileged client-side tooling or fully confined within the sandbox. If hostile bytes subvert a facade, the compromise remains inert because the component holds no authority.

To complete the model, `unsafe` Rust is quarantined to a small, bounded set of crates responsible solely for raw kernel ABI boundaries, ensuring that memory unsafety never intersects with untrusted data parsing or overarching logic.

## The Attestation Boundary

Not all capabilities can be brokered safely. Project Kennel draws a hard line between authentication-shaped capabilities, which are constrained and host-verifiable, and attestation-shaped capabilities, which rely on the trust of their origin.

A kennel is confined and untrusted by definition. Therefore, it cannot act as a trust root. The project explicitly refuses to broker `gpg-agent` or other signing oracles. Delegating signing authority to an untrusted workload creates an incoherent trust claim; an agent commits unsigned, and the operator signs on review.

## Residuals and Honest Limitations

Project Kennel makes specific claims about what it confines, but documents its limitations:

* **Kernel CVEs:** The system relies on the host kernel mechanisms. An escape via a kernel vulnerability, hardware attack, or side channel is outside the scope.
* **Within-Policy Abuse:** The monitor governs boundaries, not intent. If a policy grants a kennel network access to an API and read access to source code, the workload can exfiltrate that code to that API.
* **The Operator Context:** Project Kennel does not protect the user from themselves. A determined user in the unconfined default context can signal, trace, or read the state of their own kennels. The default context is the trust root.

Project Kennel accepts the standing cost of a runtime mediator to secure the user level against optimization-driven workloads. It pays this cost through unprivileged orchestration, cryptographic policy gates, and a structurally compartmentalized trusted computing base.
