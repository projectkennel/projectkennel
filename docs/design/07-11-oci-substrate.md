# §7.11 Policy surface: OCI substrate execution

> **An OCI image is run as the kennel's root filesystem — as inert content under Kennel's own
> namespaces, never via a container daemon.** `kenneld` boots an unpacked rootfs directly: no
> Docker daemon, no daemon socket, no in-daemon registry client or API parser. The model is split
> into two verbs — `kennel oci build` (fetch + unpack) and `kennel oci run` (boot under policy) —
> so every parser (registry, manifest, tar, the image's own config) executes inside a confined
> kennel at workload authority, and the substrate-replacement policy primitive (`[rootfs]`) is
> scoped to the OCI run model alone. Running a third-party image is a loud, operator-declared trust
> decision (T3.8); Kennel's contract over it is confinement, not content integrity. The concrete
> shape — store layout, schema, the launcher, the daemon spawn-path branch — is the implementation
> contract in [`02-9-oci.md`](../architecture/02-9-oci.md).

Developers package and run dependencies as OCI images. Kennel offers that as a deployment model or
it does not get adopted, independent of how the model rates against Kennel's own integrity
preferences. This chapter is why the two obvious bridges are wrong (§7.11.1), the model that
replaces them (§7.11.2–§7.11.5), and the trust the operator takes on when they use it
(§7.11.7–§7.11.9).

## 7.11.1 Why not a container daemon

The Docker daemon is a root-equivalent orchestration engine, and the two ways to bridge to it both
fail Kennel's premises. Exposing the daemon socket through an L7 proxy puts a large stateful parser
in the host TCB — the Docker HTTP API, chunked transfer, the hijacked `101 Switching Protocols`
upgrade for exec/attach — in front of a socket whose `container-create` verb is trivially
host-root. Running rootless Docker or Podman *inside* a kennel grants `unshare(CLONE_NEWUSER)` and
`mount()`, the two most-exploited container-escape surfaces, to the workload.

Kennel takes neither. `kenneld` boots an unpacked OCI rootfs directly under its own namespaces, as
inert filesystem content. The fetch and run phases are split so every parser — registry protocol,
manifest, tar extraction, and the image's own runtime config — executes inside a confined kennel at
workload authority, where a parser bug is contained like any other workload and never reaches the
daemon. The TCB does not grow.

## 7.11.2 Two verbs, and why the split is load-bearing

OCI execution is **not** a parameter on `kennel run`. It is its own pair of verbs:

```
kennel oci build <name> -- <image-ref>      # fetch + unpack into the named store
kennel oci run   <name>                      # boot the named image under policy
```

`build` is the fetch phase; `run` is the boot phase; the two are coupled only by a named entry in
an operator-owned store. The separation does three things a single overloaded `kennel run -- …`
could not:

- **It partitions the policy grammar by run model.** `[rootfs]` and the substrate-trust grant it
  carries are valid *only* in an OCI-model policy that `kennel oci run` consumes. `kennel run`
  rejects a policy containing `[rootfs]`; `kennel oci run` rejects one without it. The compiler
  enforces the split, so the universal policy grammar that most workloads use never grows a
  substrate-replacement primitive, and the substrate-trust risk derivation stays local to the OCI
  model.
- **It removes a per-policy "append argv" knob.** The only reason to append CLI tokens to a pinned
  `argv` would be a generic `kennel run build-oci -- …` shape; with a dedicated verb, "the trailing
  tokens are the image reference" is the meaning of `oci build`, baked into the verb rather than a
  `[workload]` field the daemon must validate against a signature.
- **It gives every awkward artifact a home** — the recorded image digest, the unpacked rootfs, the
  image's runtime config, and the scaffolded run policy all live under the named store entry, keyed
  by `<name>`.

## 7.11.3 Trust boundary: `[rootfs]` is a loud grant

Running a third-party image is a trust decision the operator makes, not one Kennel makes for them.
The operator declares an image as their execution substrate the way they declare a host directory
writable: an input the policy names and the signature covers.

`[rootfs]` is therefore a **loud grant**, in the class of `mode = host` and
`[[fs.dev.passthrough]]`. It carries a required `reason`, and the compiler derives a substrate-trust
exposure (T3.8) from its presence, surfaced by `kennel policy risks` with the grant as carrier —
the mechanism by which `mode = host` derives T1.6. The grant sits parallel to `[fs.write]`: a
declared trust extension, confined identically to every other once declared. Kennel does not vet
the image, launder its contents, or assert anything about bytes it did not pin.

## 7.11.4 Architecture: build and run

Execution is two kennels coupled only by a named, content-addressed store entry.

**The builder** (`kennel oci build`) runs a user-space OCI tool (`skopeo`, `umoci`) inside a
confined kennel to pull an image and unpack its rootfs into the operator-owned store. The broad
egress an image pull needs lives here and nowhere else — the egress high-water mark of the flow —
and it runs under a **Kennel-shipped, vetted** fetch policy (`constrained` egress, registry
allowlist, `fs.write` to the store entry), so the operator never authors or signs the broad-egress
step. The builder pulls **by digest**; when the reference is a tag it resolves the tag to a digest
*at build time* and records that digest, so even a tag-built image freezes to a pinned digest.

**The runner** (`kennel oci run`) resolves `<name>` to its store entry, verifies the signed run
policy, asserts the signed `[rootfs].image` equals the recorded `digest`, and hands `kenneld` the
unpacked rootfs. `kenneld` boots it under the standard view construction — constructed `/dev`, fresh
`/proc`, private `/tmp`, the T2.8 masks, the per-kennel netns boundary, the SOCKS proxy, seccomp,
Landlock — with two image-specific adaptations: a minimal targeted `/etc` overlay (not the host-mode
synthetic tree) and an in-kennel launcher as the entrypoint.

## 7.11.5 The in-kennel launcher

An OCI image carries its own runtime config — `Entrypoint`, `Cmd`, `Env`, `WorkingDir`, `User`.
Kennel does not parse that config in the daemon (a manifest parser in the TCB is exactly what
§7.11.1 refuses) and does not make the operator transcribe it by hand into policy. Instead a small
Kennel-shipped **launcher** becomes the workload's `argv[0]`, parses the config *inside the confined
kennel* at workload authority, applies `WorkingDir`/`Env`/`Entrypoint`+`Cmd`, and `execve`s the
real entrypoint. A bug in it is a bug in a confined, unprivileged process holding no capability, no
`mount`, no `unshare` — contained exactly like the builder's parsers.

The default is launcher-resolves-from-config; an operator who wants the standard run model's
stronger guarantee overrides with an explicit `[workload].argv` (with optional `sha256`), which
`kenneld` resolves and pins in-root. The override is **all-or-nothing**: explicit argv opts out of
the *entire* image config (the `Env` merge and `WorkingDir` included), so policy `[env]` becomes the
sole environment source. The half-way reading (operator argv but image env still merged) is a muddy
trust story; the launcher is simply not invoked in the override path.

## 7.11.6 Image `Env` is sanitised, not merged raw

Merging the image's `Env` "with policy on top" is not safe as a bare merge. An image is untrusted
substrate, and a handful of environment variables are arbitrary-code-injection vectors a dynamic
loader, language runtime, or shell entrypoint acts on at startup — `LD_PRELOAD`, `LD_LIBRARY_PATH`,
`NODE_OPTIONS`, `PYTHONPATH`, `BASH_ENV`. An unfiltered merge would hand an image free injection into
its own (waived) closure, and worse, those paths can point into an additive `[fs.read/write]` bind —
operator-writable host content. This is exactly the `AT_SECURE` case the kernel and loader handle by
stripping these variables under untrusted elevation; the launcher reproduces it because the image
`Env` is an input *no policy field reaches*.

So the launcher strips the injection-vector names from the image `Env` **before** the merge — prefix
`LD_*`/`GLIBC_*`, plus three exact-name tiers (the glibc loader floor of `unsecvars.h`, the language
runtimes, the shell-entrypoint sourced files). The strip is image-scoped: Kennel's synthesised
`[env]` is layered on top unfiltered, so an operator who deliberately wants a stripped name re-adds
it via `[env].set` and it wins. This is orthogonal to `[env].deny` (which filters the *caller→kennel*
pass-through, a different input) — which is why the strip must live in the launcher and cannot be
delegated to policy. The exact denylist is the implementation contract (`02-9-oci.md` §env-strip).

## 7.11.7 Security posture — what holds, what is waived

**What holds over an image root.** Every property the confinement limb provides is unchanged,
because none of it depends on the substrate's provenance: the per-kennel network namespace and its
egress boundary; brokered crossings over binder; the SOCKS proxy and `[net]` policy; the masked
identity and the targeted `/etc` overlay that overrides the image's `resolv.conf`/`nsswitch`/
`hostname`/`passwd`; the constructed `/dev` allowlist; seccomp; the absence of a daemon socket; the
absence of a nested user namespace. The workload acquires no kernel capability, no `mount`, no
`unshare`. The TCB is the size it was — the launcher and every image parser run at workload
authority, not in the daemon.

**What the operator waives.** The image supplies its own runtime closure — `ld.so`, libc, the NSS
modules, everything `argv[0]` loads after `execve`, and its own entrypoint, env, and config. This is
the substrate-trust residual catalogued as **T3.8**, derived from the `[rootfs]` grant the way T1.6
is derived from `mode = host` (no `threats.reinstated` field; the shape of the grant is the tag):

- **Provenance, not a per-binary pin.** In the default flow the launcher is `argv[0]`; the image
  entrypoint it execs is image-chosen and provenance-covered (it came from `image@sha256`) but not
  separately hashed. The `[workload].argv` + `sha256` override restores the per-binary pin; the
  dynamic closure stays unpinned regardless.
- **Image `Env` enters the workload, sanitised** (§7.11.6) — declared substrate beneath policy's
  final say.
- **Image `User` is not honored** — the userns maps the precise operator identity with no subuid
  range, so the workload runs as the persona uid; a uid-baked image fails on `EACCES`, not identity.
- **`fs.execute` is coarse** over a declared substrate — the operator granted execute across a
  userspace they chose to run.

The posture claim is confinement, not content integrity. The build/run split keeps all image parsing
out of the daemon, and the runner adds no registry, manifest, or tarball parser.

## 7.11.8 Integrity ladder

Content integrity is waived at the floor and available as opt-in hardening, each rung a
`threats.mitigated` the risk engine surfaces, per named store entry. The integrity unit at every
rung is the **whole entry** — `rootfs/`, `config.json`, and `digest` — because the launcher trusts
`config.json` for the entrypoint and env.

- **Floor — digest-pinned build.** The rootfs provably came from `image@sha256:…`: provenance,
  recorded and checked against the signed `[rootfs].image`, no runtime content verification. A build
  with no resolvable digest is rejected — a substrate with no provenance is indistinguishable from
  operator error.
- **Rung 1 — content-addressed entry.** The entry records the expected tree hash of its contents and
  `kennel oci run` verifies it before pivot (the entry keeps its `<name>` key — record-and-verify,
  not renamed-to-hash). Spawn-time tamper-evidence over the operator-owned, read-only entry, closing
  the gap between the build-time digest and the bytes (and config) the runner boots.
- **Rung 2 — fs-verity.** The builder enables fs-verity on the unpacked files and `config.json`; the
  runner requires it. Per-file Merkle verification at read time — tamper-evidence on every library
  load and on the config the launcher parses, the verifiable-monitor target for this surface.

The floor ships first; Rungs 1 and 2 are sequenced behind it, opt-in so the operator who needs them
pays for them and the one who does not is not blocked.

## 7.11.9 Where the residual is surfaced

There is no separate threat-tag field on the settled policy. The `[rootfs]` grant *is* the carrier:
the compiler derives the T3.8 substrate-trust exposure from its presence, and `kennel policy risks`
reports it with the grant and the operator's `reason`, the same derivation path `mode = host` uses
for T1.6 (§7.5). An operator reading the risk report sees the waiver they declared, named, with the
reason they gave for it.
