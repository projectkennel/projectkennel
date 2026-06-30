# Composable fragments

A **fragment** is a signed, version-pinned, additive-only capability bundle a policy can
`include` instead of hand-listing the same grants every time (`docs/design/05-templates.md`
§5.10). Where a *template* (`../templates/`) is the single-parent backbone a leaf derives
from, a fragment is a cross-cutting à-la-carte add-on: pull in exactly the capabilities a
workload needs and nothing else.

```toml
name = "my-agent"
template_base = "ai-coding-strict@v1"
include = ["lang-python@v1", "vcs-git@v1"]   # ← compose what the workload needs
```

Fragments are **additive-only**: every entry is a `[[*.add]]` delta appended to the
effective policy. They can only widen — anything that must *remove* or *override* a grant
belongs in the inheritance chain, not a fragment, which keeps composition order-independent
and free of diamond ambiguity (§5.10). Two fragments that add conflicting rules for the same
destination fail to compile with an explicit conflict, never a silent last-wins.

## The catalogue

| Fragment | Grants |
|---|---|
| **`core-shell`** | the POSIX shells (`sh`/`bash`/`dash`) — base-confined denies exec and grants no shell, so every interactive or scripted kennel needs this |
| **`core-coreutils`** | the non-mutating read/compute/text userland (`cat`/`ls`/`grep`/`sed`/`awk`/`find`/`sort`/… + pagers) — carries **no** filesystem-mutating tool |
| **`core-file-mutation`** | the write-side coreutils (`cp`/`mv`/`rm`/`mkdir`/`ln`/`chmod`/`mktemp`/`install`) — kept separate so a read-only kennel cannot mutate |
| **`core-archive`** | tar and the common compressors (`gzip`/`xz`/`bzip2`/`zip`/`zstd`/…) |
| **`net-clients`** | the fetch-client **binaries** `curl`/`wget` (distinct from `net-permissive`, which grants the egress destinations they reach) |
| **`lang-python`** | `python3`/`pip` on `exec.allow`, the pip cache writable, PyPI on the egress allowlist |
| **`lang-node`** | `node`/`npm`/`npx` on `exec.allow`, the npm cache writable, the npm registry on egress |
| **`toolchain-c`** | `cc`/`gcc`/`g++`/`as`/`ld`/`ar`/`make` and gcc's backend binaries (`/usr/lib/gcc/**`) |
| **`vcs-git`** | `git` + its `git-core` helpers, the system git config read-only (no egress — that is the leaf's or `net-permissive`'s) |
| **`net-permissive`** | broad egress to the common public package ecosystems and code forges (PyPI, npm, crates.io, GitHub, ghcr.io) for a human-driven workflow |

The `core-*` bundles are the base userland a template would otherwise hand-list; the shipped reference
templates (`ai-coding-strict`, `interactive`, `inspect-only`, `untrusted-build`, `package-install`)
compose them. `inspect-only`, for instance, is `core-shell` + `core-coreutils` and pointedly **not**
`core-file-mutation`, so it can look but not touch. The exec floor a template exposes is a *selection* of
bundles; the cage (net mode, fs grants, ceilings) is unchanged by which bundles it composes, because
`argv[0]` stays gated by the resolved `exec.allow` under Landlock.

The shared egress destinations (PyPI, npm) are byte-identical across `lang-*` and
`net-permissive`, so a leaf may include both without a conflict (identical entries dedup).

`net-permissive` does **not** open the network: a fragment cannot flip the structural
`net.mode` (that is a scalar override, which belongs in the inheritance chain), so the
per-kennel net namespace, the SOCKS proxy, and the invariant denies (cloud-metadata,
link-local) all still apply. It is a curated allowlist, not an off switch.

## Authoring and signing

Each fragment is `fragments/<name>/policy.toml`, signed in place by a maintainer key whose
public half is in `../keys/`:

```sh
kennel policy sign fragments/<name>/policy.toml --key ~/.config/kennel/keys/<key>.key
```

`tools/install.sh` ships every fragment into the runtime template search dir
(`/etc/kennel/templates/`), alongside the templates, so a leaf's `include` resolves and
verifies out of the box. `kennel policy list` shows each one labelled `(fragment)`.

The catalogue is gated in CI by `kennel-lib-compile/tests/fragments_catalogue.rs`, which
verifies every committed fragment's signature against `keys/`, checks it is additive-only,
and compiles a real leaf that includes it to assert its grants land.
