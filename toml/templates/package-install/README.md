# package-install

For installing packages from a registry when you don't fully trust the package.
The threat is the **post-install / setup script** (T1.2): it runs as you, with the
package manager's reach. This template cuts that reach to one registry, a scratch
directory, and a short lifetime.

## What the user adds

```toml
template = "package-install"
name = "npm-try"

[[fs.write.add]]
path = "~/scratch/npm-try/**"
reason = "scratch dir for the trial install"

# Override the TTL if needed (default 1h, stop):
[lifecycle.override]
ttl = "30m"
reason = "quick trial; should be ephemeral"
```

For a pip or cargo install, add the registry the leaf needs:

```toml
[[net.allow.add]]
name = "pypi.org"
ports = [443]
reason = "Python package index"
threats.exposed = ["T1.9"]
```

## Defends / residuals

- **Defends:** T1.2 (post-install scripts — no curl/wget, egress limited to the
  registry, fs limited to scratch), T1.9 (partial), T1.10 (the TTL bounds persistence).
- **Residuals:** a compromise of the registry itself delivers the malicious
  package through legitimate channels (out of scope). In-band exfil to the
  registry is theoretical and low-realism.

## Adds over base-confined

The package managers + their build toolchain (for native modules), basic install
userland (**no** curl/wget), one registry by name, and a short `stop` TTL.
