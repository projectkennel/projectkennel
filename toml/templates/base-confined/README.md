# base-confined

The root of every confined template. **Not used directly** — it has no
filesystem or execution scope of its own, so a kennel run from it could not do
anything useful. Derive a workflow template (e.g. `ai-coding-strict`) from it.

## What it provides

The confined posture every other template inherits:

- **Capabilities:** `no_new_privs`, the whole bounding set dropped.
- **Execution:** setuid/setgid/setcap/writable-file execution refused; `sudo`,
  `su`, and admin binaries denied. No tool allowlist (templates add theirs).
- **Filesystem:** the constructed `$HOME` view (granted paths only — non-granted
  paths are *absent*, not just denied), a private `/tmp`, a minimal constructed
  `/dev`, `/proc` with `hidepid=2`, the system read baseline, and a categorical
  deny list over credentials, browser/messaging/wallet state, shell histories,
  and host-security config.
- **Network:** proxy-only egress (cgroup BPF denies everything else, fail-closed);
  invariant denies for cloud metadata, link-local, RFC1918, and CGNAT (no
  downstream policy may remove them); wildcard binds rewritten to the kennel's
  private loopback; `IPV6_V6ONLY` forced.
- **Sockets/IPC:** AF_UNIX default-deny; abstract sockets denied (Landlock
  scoping); D-Bus and X11 off; cross-boundary ptrace and signals denied.
- **Environment:** curated — secrets stripped, framework variables forced.
- **Seccomp:** a defence-in-depth deny list (CVE-historied / escape syscalls).

## Threats

Defends the baseline of T1.1 (reconnaissance), T1.6 (lateral movement), T2.1 (host
control deactivation), T3.1 (setuid escalation). Workflow-specific threats are the
deriving template's job.

## Status

This is a **source** template; see `templates/README.md` for what is
runtime-enforced today versus compiler-folded. The `[unix]`/`[dbus]`/`[x11]`/
`[env]`/`[ptrace]` sections are design-level except where noted (abstract-unix
deny and signal isolation are enforced natively via Landlock scoping, §8.1).
