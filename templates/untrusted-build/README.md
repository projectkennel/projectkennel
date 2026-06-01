# untrusted-build

For running a build from source you don't trust — a cloned repo's `make`, a
tarball's `./configure && make`. The defining property: **the network is off**.
A malicious build script (T2/T5) has the toolchain and the source tree and
nothing else: no egress for command-and-control, no exfiltration, no fetching a
second-stage payload.

## What the user adds

```toml
template = "untrusted-build@v1"
name = "build-foo"

[[fs.read.add]]
path = "~/build/foo/**"
reason = "the source tree to build"

[[fs.write.add]]
path = "~/build/foo/**"
reason = "build outputs go in-tree"
```

Because there is no network, **dependencies must be pre-populated** — a vendored
directory, a committed `node_modules`/`vendor`/`target`, or an offline mirror in
the project tree. That is the cost of the strong guarantee.

## Defends / residuals

- **Defends:** T2 (post-install/build scripts — no egress at all), T5 (build-time
  compromise — the build cannot reach out to alter itself or report back).
- **Residual:** legitimate builds that fetch at build time fail; you must supply
  dependencies offline. If a workflow genuinely needs network, it is not an
  untrusted build — use `package-install` (one registry) or accept a weaker
  template.

## Adds over base-confined

`net.mode = "none"`, the build toolchain (compilers, build drivers, autotools,
archivers — **no** fetching package managers), and a 2-hour `stop` TTL.
