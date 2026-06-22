# §5 Template system

## 5.1 Why templates

The §7 policy surface is rich. A complete policy for a kennel can reach several hundred lines across all the resource classes. Asking users to author such policies from scratch produces, predictably, subtly broken policies — the AppArmor experience writ small.

Templates are Project Kennel's answer to this. They are first-class artefacts: signed, versioned, threat-tagged, tested, documented. Users compose their policy as a *delta* from a chosen template. The delta is short (typically 5–15 lines for a leaf user policy), explicit, and reviewable.

A template carries:

- A complete policy for a recognisable workflow.
- Documentation describing the threats it defends against and its known limitations.
- A test suite verifying it enforces what it claims (`tests/allow.sh`, `tests/deny.sh`).
- Threat tags linking each rule to entries in `THREATS.md`.
- A version, advanced on every change, signed by the template maintainer.

The user's policy file is mostly metadata plus deltas. Adding a capability requires a `reason` field. Project Kennel's diff tool surfaces what each addition costs in terms of threat exposure.

This shifts Project Kennel's centre of gravity. The policy primitives in §7 are how templates are *expressed*. Templates are how users *consume* Project Kennel. The tool is the smaller part. The template set and the social contract around it are the larger part.

A complete, annotated example of a real template (`ai-coding-strict`) is provided in the companion document `TEMPLATE-ai-coding-strict.md`. This chapter introduces the concepts; that document shows them in concrete TOML. Readers who prefer concrete first should read the worked template before continuing here.

## 5.2 Template structure on disk

A template lives under `templates/<name>/` in Project Kennel repository:

```
templates/ai-coding-strict/
├── policy.toml          ← the template's policy
├── README.md            ← human-facing documentation
├── THREATS.md           ← threat tags and impact analysis
├── CHANGELOG.md         ← version history
├── tests/
│   ├── allow.sh         ← scripts verifying expected operations succeed
│   ├── deny.sh          ← scripts verifying expected denials happen
│   └── fixtures/        ← test data
└── meta.toml            ← name, version, author, signing key reference
```

The template's `policy.toml` declares its inheritance and identity at the top:

```toml
template_base = "base-confined"
template_version = "4"
template_name = "ai-coding-strict"
```

`template_version` is a quoted string by convention even though its values are integers; this allows future use of non-integer suffixes (e.g. `"4-rc1"`) without breaking the schema.

The two-field form shown here (a `template_base`/`template` name plus a separate version field) is the original form and remains accepted. The canonical form, and what `kennel` emits, is the combined version-pinned reference `template_base = "ai-coding-strict@v4"`; references carry their version inline and bind to signed content. See §5.10.

The remainder of `policy.toml` is the template's full policy, expressed as direct rules and as deltas from the base template (§5.3). Project Kennel's compiler resolves the inheritance chain at policy load time and produces a single flat effective policy.

A user's leaf policy lives outside the template directory, typically in `~/.config/kennel/kennels/<name>.toml`:

```toml
template = "ai-coding-strict"
template_version = "4"
name = "myproj-ai"

[[fs.read.add]]
path = "~/projects/myproj/**"
reason = "the project I am working on"

[[net.allow.add]]
name = "api.anthropic.com"
ports = [443]
reason = "Claude API"
threats.exposed = ["T1.8"]
```

The user policy is approximately 10 lines. Everything else — the credential denylist, the constructed view, the per-kennel loopback, the Landlock scoping — is inherited from the template.

## 5.3 Delta syntax

Templates and user policies compose by deltas. There are four delta operations, applied at policy-resolution time to the effective policy of the parent template:

- `[[<section>.add]]` — add a new entry to a list-valued section. The brackets are double, indicating TOML array-of-tables; each delta block is one entry.
- `[[<section>.remove]]` — remove a matching entry from a list-valued section. Matching is by the unique-key field for that section (typically `path` for filesystem, `name` for network, `real` for unix sockets).
- `[<section>.override]` — replace a scalar or single-key value. Single brackets, since this is one table.
- `[[<section>.deny.invariant]]` and similar — mark a rule in the parent as not removable by further downstream deltas (template invariants, §5.5).

Every delta block requires a `reason` field. The schema validator rejects deltas without one. Reasons appear in audit logs, diff output, and policy review tooling. The intent is to ensure deviations from defaults carry institutional knowledge — six months later, the developer (or a colleague) reading the policy can see *why* a specific allow exists.

Worked example, showing all four operations:

```toml
# Add a filesystem read grant — typical user delta.
[[fs.read.add]]
path = "~/projects/myproj/**"
reason = "the project I am working on"

# Add a network allow — typical user delta.
[[net.allow.add]]
name = "api.anthropic.com"
ports = [443]
reason = "Claude API"
threats.exposed = ["T1.8"]

# Remove a default deny — rare; surfaces strongly in the diff.
[[fs.deny.remove]]
path = "~/.config/git/**"
reason = "this workflow needs the user's git config; accepted T1.1 exposure"
threats.exposed = ["T1.1"]

# Override a scalar — moderately common, e.g., raising audit verbosity.
[net.audit.override]
level = "full"
reason = "this kennel handles sensitive data; full audit required"

# Mark a rule as a template invariant — only valid in templates,
# not in user policies. Downstream user deltas cannot remove it.
[[net.deny.invariant]]
cidr = "169.254.169.254/32"
reason = "cloud metadata; never permitted from kennels"
```

The `*.invariant` form is distinct from the others: it does not add or remove a rule, it *annotates* the rule with the property that further downstream policies cannot remove it. Invariants are template-author tools, not user-author tools (§5.5).

Some sections in §7 use single-bracket TOML tables rather than arrays (`[fs.tmp]`, `[fs.home]`, `[cap]`). These accept the `override` delta form only, not `add`/`remove`. The schema describes which sections accept which delta forms.

## 5.4 Template substitution variables

Template policies may reference variables that are expanded at kennel-lib-spawn time. Project Kennel substitutes these before applying the policy:

| Variable | Expands to |
|---|---|
| `<kennel>` | The kennel name (`name` field from the user policy) |
| `<uid>` | The user's real uid as a decimal integer |
| `<user>` | The user's login name |
| `<tag>` | Project Kennel's IPv4 loopback tag (default `42`, configurable per-install) |
| `<ctx>` | A small integer derived from the kennel's name hash, unique per concurrent kennel |
| `<home>` | The user's real `$HOME` |
| `<gid>` | Project Kennel's IPv6 ULA Global ID for loopback isolation |

Example usages from the worked template:

```toml
shim_root = "/run/kennel/<kennel>/home"
proxy_listen_v4 = true                  # the listener address is computed, not templated
proxy_listen_v4_address = "1:1080"      # host offset + port within the kennel's own /28
log_path = "~/.local/state/kennel/<kennel>/network.jsonl"
SSH_AUTH_SOCK = "/run/kennel/<kennel>/home/.ssh/agent.sock"
```

The proxy listener address cannot be assembled by lexical substitution: under the bit-packed address scheme (§7.5.2) the kennel's subnet is computed from `<tag>` and `<ctx>`, so the address is not octet-aligned. The config names only the host offset and port within the kennel's own subnet; Project Kennel computes the full address.

The substitution is purely lexical and happens before validation. Project Kennel refuses to spawn a kennel if any unsubstituted variable remains in the effective policy. User policies typically do not need to use these substitution variables directly; they appear in template-level rules where the template author knows that kennel-specific values are needed.

## 5.5 Framework invariants and template invariants

Project Kennel distinguishes two kinds of invariants. They have different scope and different enforcement.

### Framework invariants

Properties that hold across every policy, regardless of which template it derives from. Listed in `schema/invariants.toml` and enforced by the validator at policy-load time. The current set:

- `cap.no_new_privs = true` — non-negotiable. `PR_SET_NO_NEW_PRIVS` is always set.
- `exec.deny_setuid = true` — non-negotiable. Setuid binaries are always refused at execve.
- `exec.deny_setgid = true` — non-negotiable. Same logic for setgid.
- Granting `unix.allow` for `/tmp/.X11-unix/*` — forbidden. X11 is a non-goal (§7.8): it cannot be granted (no useful per-client confinement), and the view exposes no host X server socket.
- Granting `unix.allow` for `/var/run/docker.sock` or `/run/containerd/containerd.sock` at the *framework* level — permitted (some templates need it), but invariant-marked by templates that include it, so deltas in user policies can never silently grant it.
- `unix.default = "allow"` — forbidden. Default-deny on AF_UNIX sockets is structural to the constructed-view design.
- `dbus.session.enabled = true` without a corresponding `dbus.session.allow` block — forbidden. Enabling D-Bus session-bus access requires explicitly specifying what is allowed; the validator rejects "enable but allow nothing" because it is almost always a policy bug.
- Removing the cloud-metadata `[[net.deny]]` entries (169.254.169.254, fd00:ec2::254) — forbidden across all policies, regardless of template.
- The constructed-view shim for `$HOME` — present in every kennel; cannot be disabled by policy.
- The SOCKS5 proxy as the only network egress — cannot be disabled by policy when `net.mode != "open"`.
- The PID namespace for kennels — cannot be disabled by policy.

The list grows over time as Project Kennel matures. Adding a new Project Kennel invariant is a breaking change; existing policies that conflict must be updated. Removing an invariant is treated as a weakening of Project Kennel's guarantees and is rare.

Templates that genuinely need a property Project Kennel invariants prohibit are not confined; they should be honest about that and the workflow should run unconfined (`kennel run --bare cmd`), not under a contrived template that claims to confine without Project Kennel's structural guarantees.

### Template invariants

Properties that hold within policies derived from a specific template. A template marks a rule as an invariant; downstream user policies cannot remove the rule via a delta. The schema validator rejects the delta with a clear error message.

The syntax is `[[<section>.<form>.invariant]]`, typically `[[net.deny.invariant]]`, `[[net.allow.invariant]]`, `[[unix.deny.invariant]]`. The rule has the same fields as the non-invariant form; the `invariant` suffix is purely an annotation that propagates the rule's non-removability.

A template author uses invariants for rules that are *central to the template's threat model*. Removing them would mean the policy no longer corresponds to the template's documented properties. The `ai-coding-strict` template marks its cloud-metadata denies as invariant; the credential-path denies are not marked invariant (a user might legitimately need to grant access to a specific credential path for a corp workflow).

Different templates set different invariants. The `ai-coding-permissive` template has fewer invariants than `ai-coding-strict`, by design — it accepts that users will need to weaken more defaults. The `untrusted-build` template has more invariants than either, because its purpose is strong constraint regardless of user preference.

Templates that derive from a parent template inherit the parent's invariants. Adding more invariants is permitted; removing inherited invariants is permitted only if the deriving template documents the difference and bumps its version accordingly.

## 5.6 Threat tags

Every rule that grants a capability carries threat metadata:

```toml
[[net.allow]]
name = "api.anthropic.com"
ports = [443]
reason = "Claude API"
threats.exposed = ["T1.8"]
```

The tag values reference entries in `THREATS.md`. Tags are bare T-numbers (`"T1.8"`) or T-numbers with informative slugs (`"T1.8:exfil-via-allowed-host"`). The slug is purely for readability; the T-number is canonical.

Two threat-tag fields are defined:

- `threats.exposed` — threats this rule weakens defence against, or fails to defend against. Recommended for any rule that grants a capability the baseline template would have denied.
- `threats.mitigated` — threats this rule actively mitigates. Rare on individual rules; more commonly, the template documents mitigations at the template level (in its `THREATS.md` companion file). Use on individual rules only when the rule is the *primary* mitigation for a specific threat.

The diff command, audit reports, and `--explain` output all reference these tags. A user reviewing their policy can ask "for T1.2 (malicious post-install), what rules mitigate it and what rules expose it?" Project Kennel answers mechanically by scanning the effective policy.

When a user delta adds a rule with `threats.exposed`, the diff tool surfaces this:

```
+ unix.allow: /run/corp/vpn-agent.sock
    reason: corp-vpn-agent
    threats.exposed: T1.6 (privileged service surface)
    WARNING: granting access to a privileged service socket.
             Consider whether the kennel truly needs this.
```

The user sees not just "you added a grant" but "you added a grant that exposes you to T1.6". This is what makes the diff actionable.

## 5.7 The template set

The minimum viable set of templates, each maintained as a first-class artefact:

| Template | Purpose | Defends | Notable residuals |
|---|---|---|---|
| `base-confined` | The root of all confined templates. Deny-by-default across exec/fs/net: `no_new_privs`, deny setuid/setgid/setcap, empty `exec.allow` (runs nothing), no abstract unix sockets, the cloud-metadata + link-local invariant denies (RFC1918 stays reachable), a system read baseline covering the lib dirs (libraries load via READ — no `[lib]` execute-allowlist, §7.3.7). | T3.1, T2.7, baseline against T1.6 | Cannot be used directly (no exec/project scope) |
| `ai-coding-strict` | AI agent on a single project. Worked example in `TEMPLATE-ai-coding-strict.md`. | T1.1, T1.2, T1.3, T1.6, T2.1, T2.3, T3.7 | T1.8 (exfil via API); T2.2 (semantic regressions in code) |
| `ai-coding-permissive` | Same shape, broader fs scope and open-net audit mode. | T1.1 partial | T1.8; weaker T2.1; documented as weaker |
| `untrusted-build` | Build script from untrusted source. `net.mode = "none"` during install. | T1.2 strong, T1.5 strong | Needs offline mirrors for legitimate dependencies |
| `inspect-only` | Read-only fs on a directory; no exec beyond inspection tools. | T1.2, T1.4, T1.5 strong | Cannot build, run, or test |
| `package-install` | Install from specific registries. Time-bounded. | T1.2 partial, T1.9 partial | TTL is the primary defence against T1.10 |
| `dev-server` | Run a local dev server. Grants specific host loopback services. | T1.1, T1.3 | Explicit T1.6 exposures for granted services |
| `docs-and-research` | AI agent doing web research. `net.mode = "open"` with heavy audit. | T1.1 | T1.9, T1.8; weaker than strict |
| `containerised-service` | Long-lived local service (Postgres, Redis, etc) confined **directly by the kennel** — no container runtime; the kennel *is* the container. Per-kennel loopback for the service's port. | T3.3, T1.1 partial | Secrets via a run-time store; kernel/Landlock CVEs |
| `containerised-tool` | Short-lived build tools, linters, formatters under the same direct-kennel confinement. | T1.2, T3.3 | Strict outbound; no published ports by default |
| `ml-coding` | ML workflow with GPU. | T1.1 with GPU caveat | GPU driver surface in scope; documented |
| `mcp-server` | MCP server invoked by an agent in another kennel. | T3.6, T1.1 | Inherits parent kennel's policy by default |

Each ships in the Project Kennel repository, versioned. The repository is the canonical source; users typically reference templates by name and Project Kennel resolves to the local installed copy.

The set is not closed. Organisations write their own templates (§5.15). New templates are added when a workflow is sufficiently common to warrant a standard variant; templates are deprecated when they no longer have maintainers or are superseded by better alternatives.

## 5.8 Template inheritance

Templates can extend other templates. `ai-coding-strict` is defined as deltas from `base-confined`:

```
base-confined          ← minimal: no_new_privs, deny setuid, deny-by-default exec
                         (empty exec.allow), deny abstract unix sockets, the
                         cloud-metadata + link-local invariant denies (RFC1918
                         stays reachable), a read baseline covering the system
                         lib dirs (libraries load via READ; §7.3.7).
                         (Every confined template inherits from this.)
  ↓
ai-coding-strict       ← adds: project-tree fs scope (in user delta),
                         exec.allow for python/node/git/build tools,
                         net.allow for registries and LLM API (latter in user delta),
                         fs.scrub for .env-like patterns.
  ↓
your-ai-coding         ← user policy: the specific project path,
                         the specific LLM API endpoint, corp deltas if any.
```

The schema enforces single-line inheritance: a template extends one template, no diamonds. Composition is by override of named rules; the parent's effective policy is computed first, then the child's deltas are applied. Invariants from the parent propagate; the child can add invariants but not remove them.

User policies are leaf nodes in the inheritance tree. A user policy extends one template; the user policy is not itself a template that other user policies can extend. This restriction is deliberate — it prevents the failure mode where users accumulate ad-hoc "team templates" that nobody maintains and that drift from the official set.

If a team needs a shared baseline beyond what the official templates provide, the right answer is an organisation-managed template (§5.15) with its own signing, versioning, and review process, not a user policy that other developers extend.

Inheritance is the single-parent backbone. Cross-cutting policy fragments that several unrelated templates need to share (a corporate egress allowlist, a mandated audit configuration) are composed through *includes* rather than through a contrived inheritance hierarchy. Includes are version-pinned, signed, and additive-only; they are described in §5.10.

## 5.9 Template-level constructs

Three template-author tools deserve specific mention because they appear in the worked template but are not policy primitives in the §7 sense — they are template-level mechanisms that map onto multiple policy elements.

### `fs.home.sanitise`

Some host configuration files are needed inside the kennel but the host version contains sensitive content. A common case is `~/.gitconfig`: the agent needs git to know the user's email and signing preferences, but the host's `~/.gitconfig` often contains credential-helper URLs, embedded tokens, or `url.*.insteadOf` rewrites that point at internal hosts.

`fs.home.sanitise` constructs a sanitised copy at kennel-lib-spawn time:

```toml
[[fs.home.sanitise]]
real = "~/.gitconfig"
shim = "~/.gitconfig"
strip = ["credential.*", "github.user", "github.token", "url.*.insteadof"]
```

Project Kennel reads the real file, strips the matching keys, writes the sanitised result to a tmpfs location, and bind-mounts that location into the agent's view at the shim path. The agent sees a gitconfig that lets git operate but reveals nothing about the host's credential setup.

The pattern generalises to other config files (`~/.npmrc` minus `_authToken`, `~/.cargo/config.toml` minus `[registries.*]` credentials, etc.), but `.gitconfig` is the canonical example.

### `fs.scrub`

Some files within the project tree should not be visible to the agent even though the project tree is granted writable. `.env`, `terraform.tfstate`, and similar credential-shaped files are the typical examples.

```toml
[fs.scrub]
patterns = [".env", ".env.*", "*.pem", "*.key", "terraform.tfstate"]
mode = "empty"
```

For each pattern, Project Kennel overlays a tmpfs at any matching path during shim construction. The agent reading the file sees the `mode` content:

- `mode = "empty"` — the file appears as an empty file (zero bytes). Most tools tolerate this; build systems that read the file but use empty defaults proceed cleanly.
- `mode = "enoent"` — the file appears not to exist (open returns ENOENT). Stricter, but breaks tools that test for the file's existence before reading.

The default is `"empty"` for compatibility; templates that prioritise strictness over compatibility can override to `"enoent"`.

`fs.scrub` is a defence against T2.3 (introduction or preservation of secrets in unintended locations). It is a partial defence: the agent can recover scrubbed file contents through indirect paths (`git show HEAD:.env`, reading from the index, reading from build artefacts). Project Kennel cannot prevent semantic-level recovery without breaking legitimate tooling; `fs.scrub` is best-effort for direct reads, documented as such.

### Per-kennel service instances

Some services are inappropriate to share with the user's main session but are useful to the agent as a *per-kennel* instance scoped to that one kennel. Templates declare per-kennel service instances through `[[unix.allow]]`, binding a per-kennel socket rather than the user's shared one — for example a project-scoped tool daemon:

```toml
[[unix.allow]]
name = "tool-daemon"
real = "~/.cache/kennel/<kennel>/tool.sock"
shim = "/run/tool.sock"
reason = "a project-scoped helper daemon, per kennel"
```

Project Kennel binds the granted host socket into the kennel's constructed view at the `shim` path (and, where given, sets the named `env` var to that path); the socket at the `real` path is the per-kennel instance.

**ssh-agent is special: prefer the bastion, not a raw shim.** An exposed ssh-agent socket is a destination-blind signing oracle: anything that can reach the socket can sign with every key the agent holds, against any host (T1.6, §7.10.1). The intended path for SSH egress is therefore the dedicated `[ssh]` section and the §7.10 re-origination bastion, which binds each synthetic key to a forced command for one fixed destination, so a kennel can never use a key against a host it was not granted and never holds the real key.

A policy *may* still shim a real ssh-agent through `[[unix.allow]]` (with `env = "SSH_AUTH_SOCK"`); Project Kennel does not forbid the footgun. But because doing so re-creates the signing-oracle exposure the bastion exists to prevent, the framework flags it loudly — at validation, at compile, and at run time — so the author is choosing it with eyes open rather than by accident.

## 5.10 Signing, versioned references, and includes

Templates are signed, and references to them are version-pinned. These two properties are inseparable: a reference names a *specific signed version*, and resolving the reference verifies that the bytes about to be composed into the effective policy are exactly the bytes a trusted key signed for that version. A reference that names a version without binding to its signed content is not a supply-chain control — it is trust-on-first-use against whatever happens to sit at that name today.

### Versioned reference syntax

Every reference to a template or fragment carries its version inline, as `<name>@<version>`:

```toml
template_base = "ai-coding-strict@v4"
```

The `@v4` is part of the reference, not a separate field. A reference without a version is rejected by the validator (production mode) or resolved to the highest locally-installed version with a warning (development mode). The earlier two-field form (`template = "ai-coding-strict"` with a separate `template_version = "4"`, §5.2) remains accepted for backward compatibility, but the combined form is canonical and is what `kennel` emits when it writes policies.

Versions are semver-shaped: `v4`, `v4.2`, `v2.33.2`. The leading `v` is required. Ordering follows semver; `kennel policy upgrade` (§5.11) uses it to detect newer versions.

### The signature covers the content

A template version is a *signed artefact*. The signature envelope (the `[signature]` block, detailed in the architecture's config-schema chapter) covers the canonical-form serialisation of the template's substantive content — the policy rules, the invariants, the threat tags, the inheritance and include references. The "meat" is signed, not merely a filename or a version label.

This means a reference `ai-coding-strict@v4` resolves successfully only if:

1. An artefact named `ai-coding-strict` at version `v4` is found in the search path.
2. Its embedded signature verifies against a key in the trust store.
3. The signed content covers every substantive field (a template that signs only a subset of its fields is rejected — the rule is about the schema, not the instance).

A template whose signature does not verify is refused, regardless of whether the unverified fields are consulted.

### Byte-pinning: the lockfile

Version pinning constrains *which* version is referenced. It does not, on its own, constrain *what bytes* live under that version — a maintainer could re-tag `v4` to different content, or a compromised distribution channel could serve different bytes under the same version signed by a different still-trusted key. This is the same gap the project's dependency policy addresses for Rust crates (CODING-STANDARDS.md §5.5: "pinning a version constrains which crate Cargo resolves to; it does not constrain what bytes live under that name"). Templates get the same treatment.

Project Kennel maintains a lockfile, `kennel.lock`, recording for each resolved reference:

- The name and version.
- The signing key ID that the signature verified against.
- The artefact's ed25519 signature.

The signature *is* the content commitment. An ed25519 signature is deterministic (RFC 8032) and bound to the exact canonical bytes it covers, so a version re-tagged to different bytes — even re-signed by another trusted key — produces a different signature. There is no separate content hash: pinning the signature already pins the bytes, and the project takes no `sha2` dependency for a second commitment it does not need.

On every subsequent load, the resolver re-verifies each reference and checks its recorded signature against the lockfile. A mismatch — same version, different signature — is a hard error, not a warning. The lockfile is the transition from trust-on-first-use (the first time a reference is resolved and recorded) to trust-pinned (every load thereafter). `kennel policy upgrade` is the only sanctioned way to change a locked entry, and it surfaces the change for review.

The lockfile lives beside the leaf policy and is committed to source control by teams who keep their kennel policies in a repository. A policy plus its lockfile is a reproducible specification: anyone resolving the same policy against the same trust store gets byte-identical effective policy, or a hard failure.

### Includes

Inheritance (§5.8) is single-line: one parent, no diamonds. It is the backbone for "this template is a stricter/looser variant of that one." But organisations frequently have *cross-cutting* policy fragments they want to reuse across unrelated templates — a corporate egress allowlist, a mandated audit configuration, a set of denied credential paths specific to the organisation. Expressing these through single-line inheritance would force an artificial hierarchy.

Includes are the mechanism. A template (or a leaf policy) may pull in additional signed, version-pinned fragments:

```toml
template_base = "ai-coding-strict@v4"
include = [
    "corp-egress-allowlist@v2.33.2",
    "corp-audit-baseline@v1.4.0",
]
```

Each include is a versioned reference resolved and signature-verified exactly as `template_base` is, and byte-pinned in the lockfile exactly the same way. Included fragments are *additive*: they may add rules (`[[<section>.add]]`) and mark invariants (`[[<section>.*.invariant]]`), but they may not remove or override rules. This restriction is deliberate — additive-only composition is order-independent and free of diamond-resolution ambiguity. A fragment that needs to remove or override belongs in the inheritance chain, not in an include.

Resolution order is defined and strict:

1. Resolve the inheritance chain (single parent line) to a base effective policy.
2. Apply each include in listed order, additively.
3. Apply the including template's (or leaf policy's) own deltas.

If two includes contribute conflicting entries for the same unique key (e.g., two different `[[net.allow]]` blocks for the same host with different ports), resolution fails with an explicit conflict error. Conflicts are not resolved by last-wins; the policy author must reconcile them deliberately, by editing one fragment's scope or by moving the rule into the leaf policy where the intent is explicit.

### Trust store and enforcement

Signing keys live in the trust store: `~/.config/kennel/keys/` for user-installed keys, `/etc/kennel/keys/` for system-installed (organisation) keys. Public keys only; private signing keys are never in these trees.

- The project's maintainer keys ship with the package and verify the official template set.
- Organisations install their own keys and sign their own templates and fragments. Organisations can require, via system-wide configuration, that policies derive only from templates and includes signed by specific keys — an attacker who installs a malicious template signed by an untrusted key cannot have it loaded.

Project Kennel refuses to load any template or include whose signature is invalid. It warns but does not refuse on *missing* signatures in development mode (local unsigned templates are part of the authoring workflow); production deployments set a settings flag, pushed to managed workstations, that turns missing-signature into a hard refusal. CI verifies that every committed template and fragment version carries a valid signature and that its lockfile entry matches.

### The composable fragment catalogue

The include *mechanism* (resolution, signature verification, additive `[[*.add]]`/invariant deltas, lockfile byte-pinning) and a curated *catalogue* of à-la-carte fragments are both built. A fragment is a reusable capability bundle a leaf or template can `include` instead of hand-listing the same grants. The shipped set (`fragments/<name>/policy.toml`, signed; `fragments/README.md` is the catalogue) is two kinds — the **base userland** every template otherwise repeats, and the **capability bundles** for a language, toolchain, or workflow:

- **`core-shell`** — the POSIX shells (`sh`/`bash`/`dash`); base-confined denies exec and grants no shell, so every interactive or scripted kennel composes this.
- **`core-coreutils`** — the non-mutating read/compute/text userland (`cat`/`ls`/`grep`/`sed`/`awk`/`find`/… plus pagers); carries no filesystem-mutating tool.
- **`core-file-mutation`** — the write-side coreutils (`cp`/`mv`/`rm`/`mkdir`/`ln`/`chmod`/`mktemp`/`install`), kept separate so a read-only kennel that composes only `core-coreutils` cannot mutate.
- **`core-archive`** — tar and the common compressors (`gzip`/`xz`/`bzip2`/`zip`/`zstd`).
- **`net-clients`** — the fetch-client binaries `curl`/`wget` (distinct from `net-permissive`, which grants the egress *destinations* they reach).
- **`lang-python`** — `python3`/`pip` on `exec.allow`, `pip`'s cache dir writable, PyPI on the egress allowlist.
- **`lang-node`** — `node`/`npm`/`npx` on `exec.allow`, the npm cache writable, the registry on the egress allowlist.
- **`toolchain-c`** — `cc`/`gcc`/`g++`/`as`/`ld`/`ar`/`make` plus gcc's backend binaries.
- **`vcs-git`** — `git` + `git-core` helpers, the system git config bound read-only.
- **`net-permissive`** — broad egress to the common public package ecosystems and code forges for a human-driven workflow. *(Divergence from the original sketch: a fragment cannot "flip to `net.mode = open`" — a mode change is a scalar override, which §5.10 reserves for the inheritance chain, not an additive fragment. `net-permissive` is therefore a curated allowlist under the unchanged net-ns + proxy + invariant denies, not an off switch.)*

The shipped reference templates compose these rather than hand-listing: `ai-coding-strict`, `interactive`, `untrusted-build`, and `package-install` pull in the `core-*` userland plus the toolchains they need, and `inspect-only` is `core-shell` + `core-coreutils` and pointedly not `core-file-mutation` — it can look but not touch. The exec floor a template exposes is a *selection* of bundles; which bundles it composes never changes the cage (net mode, fs grants, ceilings), because `argv[0]` stays gated by the resolved `exec.allow` under Landlock. Each is signed and version-pinned, composed additively so unrelated bundles combine without ordering ambiguity (a leaf is then `template_base = "base-confined@v1"` + `include = ["lang-python@v1", "vcs-git@v1"]`); shared egress destinations are kept byte-identical across fragments so a leaf may include overlapping bundles without a conflict. `kennel policy sign` signs a fragment (the leaf-syntax form) as well as a template; `tools/install.sh` ships fragments into the runtime template search dir; `kennel policy list` labels each `(fragment)`. The catalogue is gated in CI by `kennel-lib-compile/tests/fragments_catalogue.rs` (signature, additive-only, and a real compile-and-assert per fragment).

## 5.11 Versioning and upgrade

Template versions are integers (encoded as quoted strings, see §5.2), incremented on every change to the template's policy or threat tags. The `template_version` field in a user policy references the version the policy was authored against.

When a user runs `kennel` with a policy referencing an old template version:

```
$ kennel run my-ai-coding bash

WARNING: template ai-coding-strict has a newer version (v5; you have v4).
Run `kennel policy upgrade my-ai-coding` to review changes and upgrade.

[kennel starts with the user's pinned v4 baseline]
```

Project Kennel does not silently auto-upgrade. The user reviews changes and consents:

```
$ kennel policy upgrade my-ai-coding

ai-coding-strict v4 → v5 changes:

  + Added [[net.deny.invariant]] for 100.64.0.0/10 (CGNAT)
    threats.mitigated: T1.6 (lateral via CGNAT)
    impact: small; almost no workflows hit this

  ~ Changed fs.scrub.patterns to include "*.p12" and "*.pfx"
    threats.mitigated: T2.3 (cert-key exfiltration)
    impact: workloads reading PKCS#12 files now see empty content

  - Removed [[exec.allow]] /usr/bin/python3.10 (EOL upstream)
    impact: kennels using python3.10 will fail; use python3.12

Your deltas:
  - Still apply: project path, Claude API allow
  - Conflict: your `fs.read.add: ~/projects/myproj/**/*.pem` overlaps with
    v5's new `fs.scrub` pattern. Review and decide.

Migrate? [y/N]
```

Conflicts are surfaced. The user resolves them deliberately. Migration is not automatic.

## 5.12 User workflow

```
$ kennel init my-ai-coding --template ai-coding-strict
Created ~/.config/kennel/kennels/my-ai-coding.toml
Based on: ai-coding-strict (v4)

This template defends against: T1.1, T1.2, T1.3, T1.6, T2.1, T2.3, T3.7
Known residuals: T1.8 (exfil via API), T2.2 (semantic code regressions)
See ai-coding-strict/README.md for the full threat-model summary.

Customize by editing the file. Run `kennel diff my-ai-coding` to review.

$ vim ~/.config/kennel/kennels/my-ai-coding.toml
# user adds rules with reasons

$ kennel diff my-ai-coding
# shows the diff, threat impact, warnings

$ kennel validate my-ai-coding
# schema check, invariant check, template version check

$ kennel run my-ai-coding bash
# starts the kennel
```

The `diff` and `validate` commands are run frequently. They are fast (no network, no kernel ops, just parse and compare).

## 5.13 What `kennel diff` produces

```
$ kennel diff ~/.config/kennel/kennels/my-ai-coding.toml

Template: ai-coding-strict (v4, last modified upstream 2026-04-10)
Inherited from: base-confined (v2)

Your deltas (3):

  + fs.read.add: ~/projects/myproj/**
      reason: the project I am working on
      threats.exposed: none catalogued
      threat impact: read access to one project tree

  + fs.write.add: ~/projects/myproj/**
      reason: the project I am working on
      threats.exposed: T2.2, T2.3, T2.4, T2.5
      threat impact: workload can write to the project tree. Output review
                     tooling (kennel review) flags security-degrading
                     diffs at commit time.

  + net.allow.add: api.anthropic.com:443 (TLS required)
      reason: Claude API
      threats.exposed: T1.8
      threat impact: outbound to one additional host. Audited via proxy.
                     T1.8 (in-band exfiltration via the API) is the
                     primary residual; documented and accepted.

Effective policy summary:
  Threats defended: T1.1, T1.2, T1.3, T1.7, T2.1, T2.3, T3.1
  Threats exposed: T1.8 (by Claude API grant); T2.2 (semantic regressions
                   in produced code)
  Threats unchanged from template: T2.7 (TIOCSTI prevented by kernel sysctl)

Audit-log location: ~/.local/state/kennel/my-ai-coding/
```

The user can read this and reason about the changes. The output is also useful in code review when an organisation reviews user policies against an organisational baseline.

## 5.14 Template invariants in practice

Section 5.5 introduced template invariants. Here is the concrete pattern, as used by `ai-coding-strict`:

```toml
# In ai-coding-strict/policy.toml

[[net.deny.invariant]]
cidr = "169.254.169.254/32"
reason = "cloud metadata IPv4 — never permitted from kennels"

[[net.deny.invariant]]
cidr = "fd00:ec2::254/128"
reason = "AWS IPv6 metadata — never permitted"
```

A user policy attempting to remove these via `[[net.deny.remove]]` is rejected at validation:

```
$ kennel validate ~/.config/kennel/kennels/my-ai-coding.toml
ERROR: cannot remove template invariant
  rule:     [[net.deny]] cidr = "169.254.169.254/32"
  declared: ai-coding-strict/policy.toml (template invariant)
  reason:   "cloud metadata IPv4 — never permitted from kennels"

Template invariants are rules central to the template's threat model.
Removing them would mean the policy no longer corresponds to the template's
documented properties. To override, switch to a different template or
write an organisation-specific template that does not declare this
invariant.
```

Templates that allow significant user override (`ai-coding-permissive`) have fewer invariants. Templates that defend strictly (`untrusted-build`, `inspect-only`) have more. The level of invariant-ness is itself a template-design decision and is documented in each template's README.

## 5.15 Out-of-tree templates

Users and organisations can write their own templates not committed to Project Kennel repo. Such templates live under `~/.config/kennel/templates/<name>/` (user-local) or `/etc/kennel/templates/<name>/` (system-wide, managed by IT) and are referenced the same way as in-tree templates.

Project Kennel's tools (validate, diff, upgrade) work identically on out-of-tree templates. The threat tags reference the same `THREATS.md` catalogue (or an org-specific extension thereof; the catalogue itself is versioned and can be forked).

CI for organisation templates is the organisation's responsibility. Project Kennel provides the testing primitives (`kennel test-template <name>`) that exercise the template's `tests/allow.sh` and `tests/deny.sh` against a configured kernel. Organisations integrate this into their template-repository CI to gate template publication.

Project Kennel supports a system-wide configuration that requires policies to derive from a specific organisation-controlled template. This is the mechanism by which an enterprise can mandate a corporate baseline: every developer's leaf policy must derive from `corp-confined`, which itself derives from one of the official templates and adds organisation-specific invariants (corp registry, corp VPN socket, etc.). User policies cannot derive directly from the official templates; they must go through `corp-confined`, which means the corporate invariants are non-removable.

## 5.16 Centre of gravity

Templates and their maintenance are Project Kennel's primary deliverable. The code is in service of the templates. A framework with great primitives and weak templates has weak security in practice; a framework with strong templates compensates substantially for primitives that have gaps.

This implies a maintenance commitment: the template set is not a one-time deliverable. Templates need to evolve as the kernel evolves (new Landlock features, new BPF hooks), as the threat landscape evolves (new AI agent behaviour patterns, new package-manager attack vectors), and as the user base provides feedback ("this template is unusable for workflow X"). Project Kennel needs a process for template maintenance, version-bump, deprecation, and replacement.

The threat catalogue (THREATS.md) is the foundation for all of that. Templates derive their security claims from the catalogue's threat IDs. The catalogue is versioned. Templates reference specific catalogue versions in their `meta.toml`. A change in the catalogue's threat definitions may require template updates.

This is the social contract Project Kennel needs to sustain to remain useful: keep the templates honest, keep the catalogue current, keep the diff tool's output meaningful. The technical work is well-defined; the sustained-attention work is harder, and Project Kennel's design should not pretend otherwise. See §9 (policy lifecycle) for the operational story of how templates evolve in deployed environments.
