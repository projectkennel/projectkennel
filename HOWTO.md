# Project Kennel — HOWTO (running and authoring)

A task-oriented guide for **using** Project Kennel: running a workload confined
by a policy, then authoring, signing, and tuning your own policies. For
installing and operating kennel on a host, see [HOWTO-admin.md](HOWTO-admin.md).
For the reference detail behind each step, see the man pages (`man kennel`,
`man policy.toml`) and `docs/`.

> **Prerequisites.** kennel is installed and your user is enabled
> (`systemctl --user enable --now kenneld.socket`). If `kennel list` errors that
> it cannot reach kenneld, ask your administrator — see
> [HOWTO-admin.md](HOWTO-admin.md).

---

## 1. Your first kennel

Run a shell confined by a shipped template:

```sh
kennel run interactive -- /bin/sh
```

You now have a shell inside a kennel. What just happened, and what you got:

- A **constructed `$HOME`**: a fresh view containing only what the policy grants.
  `ls ~` does not show your real home; `~/.ssh` does not exist inside the kennel
  (not "denied" — *absent*).
- A **masked identity**: `whoami` reports `kennel`, not your login name.
- **No ambient network**: the kennel has its own network namespace; egress only
  flows where the policy allows, through a proxy. With `interactive` there is no
  egress grant, so an outbound connection simply fails.
- A **synthesised environment**: `env` shows only what the policy put there —
  none of your shell's secrets (`AWS_*`, `GITHUB_TOKEN`, …) leak in.

Exit the shell and the kennel is gone: no leftover state, no reclaim.

List what is running and stop one by name:

```sh
kennel list
kennel stop <name>
```

`kennel run <policy> <name>` gives the kennel an explicit name; otherwise one is
derived. See `man kennel`.

---

## 2. Running Claude Code (or any agent) confined

The canonical use is running an AI coding agent against one project, with nothing
else reachable. The `ai-coding-strict` template is the starting point:

```sh
kennel run ai-coding-strict claude -- claude
```

This confines the agent to the constructed home and whatever the template grants
(typically: read/write within a project directory, an egress allowlist for the
model API, no credential paths). Everything outside the grant is absent or
denied, and every boundary crossing is audited (§6).

To confine the agent to **one project** and grant the egress it needs, write a
leaf policy that inherits the template (§3) rather than editing the template.

---

## 3. Writing a policy from a template

A *policy* is a TOML file that inherits a signed template chain. Scaffold one:

```sh
kennel policy generate myproject --from ai-coding-strict
```

This writes a leaf `policy.toml` whose `template_base` points at
`ai-coding-strict`. Edit it to grant exactly what your workload needs. The full
field reference is `man policy.toml` and
[docs/archive/architecture/02-2-config-schema.md](docs/archive/architecture/02-2-config-schema.md);
the common sections:

```toml
name = "myproject"
template_base = "ai-coding-strict@v1"

[fs]
# Read/write inside one project; write covers create/modify/delete.
read  = ["~/work/myproject/**"]
write = ["~/work/myproject/**"]

[workload]
argv = ["claude"]
cwd  = "~/work/myproject"
```

See what it actually resolves to (the *effective* policy, after inheritance and
includes):

```sh
kennel policy show myproject
```

Resolve and check it without producing an artefact:

```sh
kennel policy validate myproject
```

`validate` is the fast feedback loop while authoring — it reports schema errors,
missing required `reason`s, invariant violations, and inheritance problems with
an exit code your scripts can branch on (`man kennel`, EXIT STATUS).

> **Run a source policy directly.** `kennel run ./policy.toml` (or
> `kennel run myproject`) compiles and signs it in memory for the local-dev loop,
> so you do not have to compile-and-sign by hand every iteration.

---

## 4. Signing and the lockfile

For anything beyond local iteration, compile to a **signed settled artefact**.
First make a signing key (once):

```sh
kennel keygen my-key-2026
```

Then compile and sign:

```sh
kennel policy compile myproject --key my-key-2026
```

This resolves the inheritance chain and every included fragment, verifies each
referenced artefact's signature, records or checks each in `kennel.lock`, and
writes the settled artefact the daemon enforces at run time.

`kennel.lock` sits beside your policy and pins the exact bytes of every template
and fragment it resolved (by SHA-256). Commit it alongside the policy: resolving
the same policy against the same trust store then yields a byte-identical result
or a hard failure — never a silent substitution. The first resolution records
the lock (trust-on-first-use); a later mismatch is an error you resolve
deliberately. See
[docs/archive/architecture/02-2-config-schema.md](docs/archive/architecture/02-2-config-schema.md)
§The lockfile.

---

## 5. Granting capabilities (recipes)

Each grant is keyed to a `policy.toml` section (`man policy.toml` for every
field). Grant the **least** that makes the workload work; every grant is visible
in `kennel policy show` and audited at run time.

**Network egress (by name).** In the proxied modes, allow a destination the
per-kennel proxy resolves and pins:

```toml
[net]
mode = "constrained"            # own net-ns, default-deny, proxied

[[net.proxy.allow]]
name   = "api.anthropic.com"
ports  = [443]
reason = "the model API"
```

**SSH egress (no key in the kennel).** The kennel authenticates to a host-side
bastion that runs `ssh` *as you*; the kennel never holds a real key:

```toml
[[ssh.destinations]]
dest    = "git@github.com"
options = ["-i", "~/.ssh/id_ed25519"]
reason  = "push the project"
```

**A Unix socket.** Expose one host socket into the view under a shim path:

```toml
[[unix.allow]]
name   = "docker"
real   = "/run/docker.sock"
shim   = "/run/docker.sock"
reason = "build images"
```

**A host device.** Pass a specific device through (loud — `reason` + a threat
tag are required):

```toml
[[fs.dev.passthrough]]
path    = "/dev/ttyUSB0"
group   = "dialout"
reason  = "flash the board"
threats = { exposed = ["T-device"] }
```

After editing, re-run `kennel policy validate` (and `kennel policy lint` if you
maintain templates) before compiling.

**Review what you exposed.** Each grant moves the threat needle; to see the whole
picture for a policy — what it exposes, what it mitigates, and the documented
residual for each — evaluate it against the threat catalogue:

```sh
kennel policy risks myproject
```

It lists every threat the policy's grants expose (with the granting line and your
`reason`) and the catalogue's residual for each — including exposures *derived*
from a grant's shape (e.g. `mode = host` reinstates host-network reconnaissance,
T1.6). A `reason` you wrote on a grant is the answer to "why is this risk
acceptable?", and `risks` is where you confirm the open risks are the ones you
meant to accept. `--json` emits the report for CI. Full threat definitions live in
[docs/reference/THREATS.md](docs/reference/THREATS.md).

---

## 6. Reading the audit log

Every boundary crossing is recorded. Show a running (or finished) kennel's log:

```sh
kennel audit myproject
```

Useful filters (`man kennel`, COMMANDS → audit):

```sh
kennel audit myproject --resource network     # one class
kennel audit myproject --since 1h             # recent only
kennel audit myproject --follow               # stream live
kennel audit myproject --novel-only           # only events not seen before
```

The classes are `network`, `filesystem`, `exec`, and others; the schema is
[docs/archive/architecture/02-3-audit-schema.md](docs/archive/architecture/02-3-audit-schema.md).
A denied connect, a refused exec, a blocked bind — each lands here with the
attempted target, so the audit log is the first place to look when a workload
"can't reach" something.

---

## 7. Troubleshooting

**A workload can't reach the network.** Expected unless you granted egress
(§5). Check `kennel audit <name> --resource network` for the denied destination,
then add a `[[net.proxy.allow]]` (or a `[net.bpf]` CIDR rule in `host` mode).

**A policy won't parse / compile.** `kennel policy validate <policy>` prints the
exact field and reason. A common cause is a field name the parser does not
accept — the authoritative list is `man policy.toml` and
[docs/archive/architecture/02-2-config-schema.md](docs/archive/architecture/02-2-config-schema.md).
Some design-doc examples are marked roadmap (not yet built) and are rejected by
the parser; the schema reference is the source of truth for what is accepted
today.

**A signature or lock error (exit code 6).** A referenced template/fragment is
unsigned, signed by an untrusted key, or its bytes changed since the lock was
recorded. Check the key is in your trust store. If the template published a new
version, `kennel policy upgrade <name>` is the sanctioned path: it shows the source diff,
asks for consent, and re-pins the lock (§8). A mismatch you did not expect is a
supply-chain signal, not a nuisance — review before accepting. See `man kennel`.

**A kennel won't start at all.** Spawn failures are an admin/host concern (userns
support, the privhelper, an `/etc/kennel/subkennel` allocation). Capture detail
by setting `log_level = "debug"` in `system.toml` (admin) and reading both the
user journal (`journalctl --user -u kenneld.service`) and the system journal
(`sudo journalctl -t kenneld`) merged by time. See
[HOWTO-admin.md](HOWTO-admin.md).

**Pin what runs.** To stop a `kennel run -- <cmd>` from overriding the policy's
command, set `[workload].pinned = true`; an override then needs `--force`.

---

## 8. Upgrading a policy's template

When the template your policy inherits publishes a newer version, `kennel run`
warns you but keeps running your pinned version — it never auto-upgrades. To move
to the new version deliberately:

```sh
kennel policy upgrade myproject
```

This finds the newest available version of your `template_base`, shows the **source
diff** between your pinned version and the new one, and asks for consent. On `y` it
re-points `template_base` and recompiles so `kennel.lock` re-pins to the new bytes.
This is the only sanctioned way to change a locked entry — the lock is otherwise
immutable, and a mismatch is a hard error (exit 6).

Review the diff before accepting; a template change can widen or narrow what your
workload may do. (The richer semantic threat-impact view is `kennel diff`, which is
roadmap; today `upgrade` shows the honest source diff, and `kennel policy show`
prints the full effective policy after upgrading.) For scripts, `--yes` skips the
prompt. See `man kennel`.

---

## See also

- `man kennel`, `man kennel-policy`, `man policy.toml` — the reference.
- [HOWTO-admin.md](HOWTO-admin.md) — installing and operating kennel on a host.
- [docs/archive/architecture/02-2-config-schema.md](docs/archive/architecture/02-2-config-schema.md)
  — the complete policy schema.
- [docs/archive/design/](docs/archive/design/) — the design rationale (the §7.x policy chapters).
