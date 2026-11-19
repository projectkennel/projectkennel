# ai-coding-native

[`ai-coding-strict`](../ai-coding-strict/) for agents whose runtime loads native code it unpacks
at run time. The one difference: the kennel's private `/tmp` allows executable file mappings
(`[fs.tmp] mmap_exec = true`), so `dlopen` of a library written there works.

Use it when an agent fails with `failed to map segment from shared object` on a file under
`/tmp`. The common case is a Bun single-file executable such as `opencode`, which extracts
embedded `.so` files (its TUI render library) into `$TMPDIR` and loads them (#218).

```toml
name = "myproj-opencode"
template_base = "ai-coding-native"

[[fs.write.add]]
path = "~/projects/myproj/**"
reason = "the project I am working on"
```

## What changes, and what does not

- **Still refused:** `execve` of anything in `/tmp`. Landlock grants execute only to the exec
  allowlist, and writable paths never get it (`exec.deny_writable`).
- **Now allowed:** loading native code from `/tmp`, including running a whole program through
  the dynamic loader (`ld-linux… /tmp/prog`). The exec allowlist therefore no longer bounds
  *which* native code runs.
- **Unchanged:** the containment boundary. Landlock's filesystem rules, the BPF network ACLs,
  seccomp and the namespaces apply to the whole process, whatever code it runs. Interpreters
  in `ai-coding-strict` (`python3`, `node`) already run arbitrary code within the same bounds.
- **Not persistent:** `/tmp` is a fresh per-kennel tmpfs, so nothing planted there survives the
  session. Persistent writable paths, such as the project tree, are not affected by this
  template.

The compiler warns when `mmap_exec` is set; `kennel policy compile` shows it for every leaf
derived from this template.
