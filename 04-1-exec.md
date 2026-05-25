# §4.1 Policy surface: binary execution

## 4.1.1 What we gate

Which binaries the context may `execve()`, `execveat()`, or `fexecve()`. This includes the initial process the context launches and every child process spawned thereafter.

## 4.1.2 Why it matters

A confined context should not be able to:

- Escalate via `sudo`, `su`, `pkexec`, `gpasswd`, `passwd`, `chsh`.
- Mount filesystems (`mount`, `umount`).
- Drop into an unrestricted shell when the policy only intended the context to run a specific tool.
- Execute setuid or setcap binaries to gain capabilities outside the policy.
- Run unrelated binaries that happen to be on `PATH` (`curl`, `nc`, `socat` for unintended network use; `gdb` for ptrace; `ssh` for arbitrary outbound).

Some of these have other mitigations elsewhere (network ACLs catch `curl`, `nc`; ptrace policy catches `gdb`), but the exec ACL is the first line: if a binary isn't on the list, it doesn't run, regardless of what it would have done.

## 4.1.3 Mechanism

Primary: Landlock with `LANDLOCK_ACCESS_FS_EXECUTE` on a path allowlist. Available in kernel 6.10+ with full semantics; earlier kernels have partial coverage and the framework refuses to apply exec policies on kernels too old.

Belt and braces: `PR_SET_NO_NEW_PRIVS` is set unconditionally in every confined context. This is the kernel mechanism that prevents setuid binaries from gaining their uid even if they are executable; it is cheap, non-negotiable, and a precondition for several other framework guarantees.

For systems with AppArmor available and a system policy framework willing to load fragments: AppArmor `Px`/`Cx` rules give transition-on-exec semantics that Landlock does not (the executed binary gets a different profile applied automatically). The framework can optionally emit AppArmor fragments for richer exec semantics on systems that support them; the core enforcement does not depend on this.

## 4.1.4 Policy primitives

```toml
[exec]
# Explicit path allowlist. Glob patterns supported.
# Anything not in this list cannot be executed inside the context.
allow = [
    "/usr/bin/git",
    "/usr/lib/git-core/**",
    "/usr/bin/python3",
    "/usr/bin/python3.12",
    "/usr/bin/node",
    "/usr/bin/npm",
    "/usr/bin/ssh",
]

# Explicit denials, evaluated before allow. Useful for "allow /usr/bin/* but
# specifically not sudo" patterns.
deny = [
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/pkexec",
    "/usr/bin/doas",
    "/usr/bin/chsh",
    "/usr/bin/gpasswd",
    "/usr/bin/passwd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/newgrp",
]

# Categorical refusals. Evaluated before allow.
deny_setuid = true         # refuse to execute any file with the setuid bit
deny_setgid = true         # refuse to execute any file with the setgid bit
deny_setcap = true         # refuse to execute any file with file capabilities

# Refuse execution of files in writable paths.
# This is the BSD `noexec` mount equivalent at the policy layer:
# a binary copied into a writable directory cannot be executed.
deny_writable = true
```

The `deny_writable` flag deserves attention. Without it, a context with `fs.write` access to `~/projects/foo/` and `exec.allow = ["/usr/bin/python3"]` could still write a static binary to `~/projects/foo/evil` and execute it via interpreter shenanigans, or could write a shell script and run it via the allowed `python3`. With `deny_writable`, the union of writable paths and executable paths is empty by enforcement, closing this hole.

There is a subtle interaction with interpreters that read scripts as arguments (`python3 script.py`). The interpreter is allowed to execute; the script file is *not* a binary being executed, it is a file being read by the interpreter. Whether the interpreter then runs malicious code from the script is an interpreter-level concern, not an exec-level concern. The framework cannot meaningfully sandbox what Python does once it is running; that is what the other resource classes (fs, net, unix) are for.

## 4.1.5 Interpreter caveat

An exec policy gates which interpreters can run. It does not gate what those interpreters do. A context with `exec.allow = ["/usr/bin/python3"]` can execute arbitrary Python code that the interpreter reads from files the context can read, from stdin, from network sources, from anywhere.

This is the right design. The exec layer answers "what binaries may execute"; the fs, net, and unix layers answer "what those binaries may do". Trying to gate interpreter behaviour at the exec layer (by, say, restricting Python script paths) is brittle and circumventable. The proper containment for interpreter-based threats is in the other resource classes.

Document this prominently. Users sometimes expect "exec.allow = python3 only" to mean "the context can only run a specific Python program". It means "the context can run any Python program but cannot directly execute non-Python binaries". The distinction matters.

## 4.1.6 PATH handling

The context's `$PATH` is set by the framework from policy, not inherited:

```toml
[exec]
path = ["/usr/bin", "/usr/local/bin"]
```

This becomes the context's `$PATH`. Combined with `exec.allow`, the framework can ensure that even if the context tries to invoke `sudo` by name, the lookup fails (because `/usr/bin` is on PATH and `sudo` is in `exec.deny`). The Landlock enforcement is independent of `$PATH`; setting it explicitly is purely for user experience (clear errors when a tool isn't available, rather than mysterious lookups).

## 4.1.7 Dynamic linker and library considerations

Landlock's filesystem ACL also covers reads. The framework grants read access to `/usr/lib`, `/lib`, `/usr/lib64`, `/lib64`, and `/etc/ld.so.cache` by default in all templates, because every executable in `exec.allow` depends on these. Templates explicitly note this as a baseline grant.

Statically-linked binaries don't need lib reads, but the framework cannot inspect a binary's linkage at policy-load time without either parsing ELF or running ldd, both of which are out of scope. The unconditional lib-read grant is a small over-grant for static binaries; the framework accepts this rather than introduce ELF parsing.

## 4.1.8 Interaction with `no_new_privs`

`PR_SET_NO_NEW_PRIVS` (set unconditionally, see §4.1.3) means:

- Setuid binaries do not gain their setuid uid.
- Setgid binaries do not gain their setgid gid.
- File capabilities do not apply on `execve`.
- AppArmor and SELinux transitions that would *gain* privilege are blocked (transitions to less-privileged profiles still work).

Combined with `deny_setuid` and `deny_setgid` in the exec policy, this is belt-and-braces: the policy refuses to execute setuid binaries, and even if a setuid binary somehow gets executed, it does not gain the uid. Either alone is sufficient; both together are defence in depth.

`no_new_privs` is set unconditionally and cannot be disabled via policy. The framework's invariants prohibit any policy from setting `no_new_privs = false`. This is non-negotiable; a confinement framework that allowed disabling `no_new_privs` would be misnamed.

## 4.1.9 What's gated, summarised

The combined effect of the exec policy:

- Only listed binaries may run.
- No setuid or setcap binaries may run.
- Binaries in writable paths may not run.
- Setuid behaviour is neutralised even if a setuid binary somehow runs.
- `PATH` lookups find only the policy-permitted directories.
- The dynamic linker can find libraries (because libs are readable by baseline grant).

## 4.1.10 Test plan

For each invariant, a regression test in the framework's `tests/exec/` directory:

1. Run `/usr/bin/sudo` from a context with `sudo` in `exec.deny`; expect EACCES (or ENOENT if PATH-scoped).
2. Run a setuid binary from a context with `deny_setuid = true`; expect EACCES.
3. Run a setuid binary from a context with `deny_setuid = false` but `no_new_privs` set; expect execve to succeed but the binary's effective uid to equal the calling uid (verify via `/proc/self/status`).
4. Copy a static binary to a writable path, attempt to execute it from a context with `deny_writable = true`; expect EACCES.
5. Run a binary in `exec.allow` whose libraries are in the baseline-allowed lib paths; expect success.
6. Run an interpreter in `exec.allow`, pass it a script that attempts to `execve()` a denied binary; expect the script's execve to fail with EACCES.
7. Attempt `setsockopt(IPV6_V6ONLY, 0)` after setting `no_new_privs`; the prctl should have prevented this from affecting privilege, verify the socket behaves as v6-only (this is a no_new_privs sanity test, not exec-specific, but lives in this section).
8. Confirm `no_new_privs` cannot be set false via policy: policy validator rejects the configuration.

The full test suite for the exec layer is roughly two dozen cases. The list above is the core; the full set lives in the framework's test corpus and is exercised in CI on every kernel version the framework supports.
