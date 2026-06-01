# inspect-only

For reading a directory to decide whether to trust it — `grep`, `cat`, `less`,
`tree` over a freshly cloned repo — **without letting its build system run**.
Network off, nothing writable, and the only executables are text-inspection
tools. There is no compiler, interpreter, build tool, or package manager in the
kennel, so the repo's code cannot execute.

## What the user adds

```toml
template = "inspect-only@v1"
name = "inspect-repo"

[[fs.read.add]]
path = "~/clones/suspect-repo/**"
reason = "the repo to read before trusting it"
```

That's the whole leaf — read the path, and nothing else.

## Defends / residuals

- **Defends:** T2 (no build/install can run), T4, T5 (strong — the source cannot
  execute).
- **Residual:** a CVE in an inspection tool processing crafted input (e.g. a
  hostile file that exploits `less`). Out of scope — assumes vetted system tools.

## Adds over base-confined

`net.mode = "none"` and an exec allowlist of text-inspection tools only. Adds
nothing writable (the user grants only read paths).
