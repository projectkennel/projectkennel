# §7.3 Policy surface: binary execution

## 7.3.1 What we gate

Which binaries the kennel may `execve()`, `execveat()`, or `fexecve()`. This includes the initial process the kennel launches and every child process spawned thereafter.

## 7.3.2 Threats addressed

A kennel should not be able to:

- Escalate via `sudo`, `su`, `pkexec`, `gpasswd`, `passwd`, `chsh`.
- Mount filesystems (`mount`, `umount`).
- Drop into an unrestricted shell when the policy only intended the kennel to run a specific tool.
- Execute setuid or setcap binaries to gain capabilities outside the policy.
- Run unrelated binaries that happen to be on `PATH` (`curl`, `nc`, `socat` for unintended network use; `gdb` for ptrace; `ssh` for arbitrary outbound).

Some of these have other mitigations elsewhere (network ACLs catch `curl`, `nc`; ptrace policy catches `gdb`), but the exec ACL is the first line: if a binary isn't on the list, it doesn't run, regardless of what it would have done.

## 7.3.3 Mechanism

Primary: Landlock with `LANDLOCK_ACCESS_FS_EXECUTE` on a path allowlist. Available in kernel 6.10+ with full semantics; earlier kernels have partial coverage and Project Kennel refuses to apply exec policies on kernels too old.

Belt and braces: `PR_SET_NO_NEW_PRIVS` is set unconditionally in every kennel. This is the kernel mechanism that prevents setuid binaries from gaining their uid even if they are executable; it is cheap, non-negotiable, and a precondition for several other framework guarantees.

For systems with AppArmor available and a system policy framework willing to load fragments: AppArmor `Px`/`Cx` rules give transition-on-exec semantics that Landlock does not (the executed binary gets a different profile applied automatically). Project Kennel can optionally emit AppArmor fragments for richer exec semantics on systems that support them; the core enforcement does not depend on this.

## 7.3.4 Policy primitives

```toml
[exec]
# Explicit path allowlist. Glob patterns supported. Execution is DENY-BY-DEFAULT,
# the same posture as fs and net: an EMPTY allow denies ALL execve (nothing can be
# launched as a new program), so a bare base template runs nothing and a derived
# template/leaf adds exactly the binaries it needs. (This gates execve, not in-process
# code loading — see §7.3.7.)
allow = [
    "/usr/bin/git",
    "/usr/lib/git-core/**",
    "/usr/bin/python3",
    "/usr/bin/python3.12",
    "/usr/bin/node",
    "/usr/bin/npm",
    "/usr/bin/ssh",
]

# Categorical refusals. Framework invariants — a leaf cannot weaken them.
deny_setuid = true         # refuse to execute any file with the setuid bit
deny_setgid = true         # refuse to execute any file with the setgid bit
deny_setcap = true         # refuse to execute any file with file capabilities

# Refuse execution of files in writable paths.
# This is the BSD `noexec` mount equivalent at the policy layer:
# a binary copied into a writable directory cannot be executed.
deny_writable = true
```

There is intentionally **no `exec.deny` list**. Under deny-by-default it would be
moot: `sudo`/`su`/`pkexec`/`mount`/… are simply not in any allowlist, so they never
run — and the `deny_setuid`/`setgid`/`setcap` invariants plus `no_new_privs`
(§7.3.8) neuter setuid escalation regardless of whether a binary was named. A deny
list that enforces nothing is reassurance theatre, so it is omitted rather than
shipped to look protective. (Where a policy must subtract a binary from a *glob*
allow it can still do so via the compiler's `-=` list delta, §5; that is policy
composition, not a runtime deny.)

The escape hatch for an open posture is an explicit **`permissive-exec`** opt-out: a
`**` (or `/**`) entry in `allow` opts into permissive-exec: anything readable becomes
executable (the inverse of the default-deny posture). It is the one case the compiler *warns* about — a deliberate, diff-visible
choice, never the default.

The `deny_writable` flag deserves attention. Without it, a kennel with `fs.write` access to `~/projects/foo/` and `exec.allow = ["/usr/bin/python3"]` could still write a static binary to `~/projects/foo/evil` and execute it via interpreter shenanigans, or could write a shell script and run it via the allowed `python3`. With `deny_writable`, the union of writable paths and executable paths is empty by enforcement, closing this hole.

There is a subtle interaction with interpreters that read scripts as arguments (`python3 script.py`). The interpreter is allowed to execute; the script file is *not* a binary being executed, it is a file being read by the interpreter. Whether the interpreter then runs malicious code from the script is an interpreter-level concern, not an exec-level concern. Project Kennel cannot meaningfully sandbox what Python does once it is running; that is what the other resource classes (fs, net, unix) are for.

## 7.3.5 Interpreter caveat

An exec policy gates which interpreters can run. It does not gate what those interpreters do. A kennel with `exec.allow = ["/usr/bin/python3"]` can execute arbitrary Python code that the interpreter reads from files the kennel can read, from stdin, from network sources, from anywhere.

This is the right design. The exec layer answers "what binaries may execute"; the fs, net, and unix layers answer "what those binaries may do". Trying to gate interpreter behaviour at the exec layer (by, say, restricting Python script paths) is brittle and circumventable. The proper containment for interpreter-based threats is in the other resource classes.

Document this prominently. Users sometimes expect "exec.allow = python3 only" to mean "the kennel can only run a specific Python program". It means "the kennel can run any Python program but cannot directly execute non-Python binaries". The distinction matters.

## 7.3.6 PATH handling

The kennel's `$PATH` is set by Project Kennel from policy, not inherited:

```toml
[exec]
path = ["/usr/bin", "/usr/local/bin"]
```

This becomes the kennel's `$PATH`. Combined with deny-by-default `exec.allow`, even if the kennel invokes `sudo` by name the `execve` fails — `sudo` is simply not on the allowlist, so Landlock denies `FS_EXECUTE` regardless of where it sits on `PATH`. The Landlock enforcement is independent of `$PATH`; setting `$PATH` explicitly is purely for user experience (clear errors when a tool isn't available, rather than mysterious lookups).

## 7.3.7 Dynamic linker: what `FS_EXECUTE` actually gates

What Landlock `FS_EXECUTE` gates is precise, and narrower than it first appears: the kernel checks it at **`execve(2)`** — on the opened-for-exec (`FMODE_EXEC`) file. That is *two* files for a dynamically-linked program: the binary itself, **and** its ELF interpreter (`PT_INTERP` / `ld.so`), which the kernel opens `FMODE_EXEC` to run it. So an allowlisted dynamic binary needs `FS_EXECUTE` on its loader as well as on itself.

It does **not** extend to the shared libraries the loader then pulls in. Those are loaded with `dlopen`-style `mmap`, and **Landlock has no `mmap`/`mprotect` hook** — a file mapped `PROT_EXEC` is never checked against `FS_EXECUTE`. A library therefore loads on `READ` alone, and *no* `FS_EXECUTE` grant on it changes that (verified directly; see the `kennel-lib-spawn` `exec_gating` test). The corollary is the important one for the threat model:

> **Execution control here means `execve`, default-deny — *which programs the kennel may launch*. It is not a control over in-process code loading.** A program the kennel is allowed to run can `dlopen` (or `mmap`+execute) any *readable* file; Landlock cannot prevent it. The honest boundary is "you cannot spawn a new program that is not on the allowlist," not "you cannot run code that isn't on the allowlist." (For an interpreter workload — Python, Node — the distinction is moot anyway: it evaluates code by design.)

Consequently the kennel resolves and grants **only the loaders**, never a "library set." At compile time it inspects each `exec.allow` binary's ELF with the vendored `object` crate (no `ldd`, which would *run* the loader) and reads its `PT_INTERP`; the distinct loader paths settle into `exec.loaders` in the signed policy, fixed and auditable. A statically-linked binary has no `PT_INTERP` and contributes none. The libraries themselves are simply *readable* via the ordinary `fs.read` grants that already cover `/usr`, `/lib`, `/lib64` — there is no `[lib]` section, and there is deliberately no execute-allowlist over libraries: it would be an unenforceable, blind policy target.

## 7.3.8 Interaction with `no_new_privs`

`PR_SET_NO_NEW_PRIVS` (set unconditionally, see §7.3.3) means:

- Setuid binaries do not gain their setuid uid.
- Setgid binaries do not gain their setgid gid.
- File capabilities do not apply on `execve`.
- AppArmor and SELinux transitions that would *gain* privilege are blocked (transitions to less-privileged profiles still work).

Combined with `deny_setuid` and `deny_setgid` in the exec policy, this is belt-and-braces: the policy refuses to execute setuid binaries, and even if a setuid binary somehow gets executed, it does not gain the uid. Either alone is sufficient; both together are defence in depth.

`no_new_privs` is set unconditionally and cannot be disabled via policy. Project Kennel's invariants prohibit any policy from setting `no_new_privs = false`. This is non-negotiable; a confinement framework that allowed disabling `no_new_privs` would be misnamed.

## 7.3.9 Summary

The combined effect of the exec policy:

- Only listed binaries may run.
- No setuid or setcap binaries may run.
- Binaries in writable paths may not run.
- Setuid behaviour is neutralised even if a setuid binary somehow runs.
- `PATH` lookups find only the policy-permitted directories.
- An allowlisted dynamic binary runs (its binary and its loader are execute-granted; its libraries load via `READ`, §7.3.7). Conversely, library/in-process code loading is *not* execute-gated — the boundary is `execve`, default-deny.

## 7.3.10 Test plan

For each invariant, a regression test in Project Kennel's `tests/exec/` directory:

1. Run `/usr/bin/sudo` from a kennel that does not list it in `exec.allow` (deny-by-default); expect EACCES (or ENOENT if PATH-scoped).
2. Run a setuid binary from a kennel with `deny_setuid = true`; expect EACCES.
3. Run a setuid binary from a kennel with `deny_setuid = false` but `no_new_privs` set; expect execve to succeed but the binary's effective uid to equal the calling uid (verify via `/proc/self/status`).
4. Copy a static binary to a writable path, attempt to execute it from a kennel with `deny_writable = true`; expect EACCES.
5. Run a *dynamic* binary in `exec.allow`; expect success — the compiler resolved its loader (`PT_INTERP`, §7.3.7) and granted `FS_EXECUTE` on the binary and that loader, while its libraries load via `READ`. Removing the loader's execute grant must make the `execve` fail; the libraries needing no execute grant is verified by `kennel-lib-spawn`'s `exec_gating` test.
5a. With an empty `exec.allow`, attempt to run any binary; expect EACCES (deny-by-default). Add a `**` `permissive-exec` entry; expect success and a compile-time warning.
6. Run an interpreter in `exec.allow`, pass it a script that attempts to `execve()` a denied binary; expect the script's execve to fail with EACCES. (Note the boundary: the interpreter `dlopen`ing a readable library is *not* prevented — Landlock does not gate `mmap`; only the `execve` of a new program is, §7.3.7.)
7. Attempt `setsockopt(IPV6_V6ONLY, 0)` after setting `no_new_privs`; the prctl should have prevented this from affecting privilege, verify the socket behaves as v6-only (this is a no_new_privs sanity test, not exec-specific, but lives in this section).
8. Confirm `no_new_privs` cannot be set false via policy: policy validator rejects the configuration.

The full test suite for the exec layer is roughly two dozen cases. The list above is the core; the full set lives in Project Kennel's test corpus and is exercised in CI on every kernel version Project Kennel supports.
