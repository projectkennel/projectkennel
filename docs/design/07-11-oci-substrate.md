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
  carries are valid *only* in an OCI-model policy that `kennel oci run` consumes. The two grammars
  are **mutually exclusive at the block level**: a normal policy has an optional `[workload]` and
  never `[rootfs]`; an OCI policy has a mandatory `[rootfs]` and never `[workload]`. The split lives
  in two places, and the distinction matters: the **compiler** validates *structure* — it enforces
  `[rootfs]` XOR `[workload]`, the required `reason`, and the persistence/closure-lock fields, and it
  compiles and signs **either** model (it must — an OCI policy has to become a signed artefact like
  any other), keying the run model off which block is present. The **run-model rejection** is the
  *verb router's*: `kennel run` refuses a settled policy that carries `[rootfs]`, and `kennel oci run`
  refuses one without it (and checks the digest). So `kennel policy compile` never rejects `[rootfs]`;
  the universal policy grammar that most workloads use never grows a substrate-replacement primitive,
  and the substrate-trust risk derivation stays local to the OCI model.
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

The unpack is **rootless**: the builder kennel is unprivileged and has no subuid range, so it cannot
`chown` extracted files to the image's uids — it discards the tarball ownership headers and writes
every inode as the operator (`umoci unpack --rootless`, or `skopeo` + a no-`chown` tar extraction).
This is not an incidental detail: it is the *cause* of the single-uid flatten that closure-lock
exists to repair (§7.11.4c). The builder must therefore never be granted (and cannot acquire) a uid
map that would let it preserve image ownership — the flatten is structural, and the lock, not DAC,
is what re-imposes the boundary.

**The runner** (`kennel oci run`) resolves `<name>` to its store entry, verifies the signed run
policy, asserts the signed `[rootfs].image` equals the recorded `digest`, and hands `kenneld` the
unpacked rootfs. `kenneld` boots it under the standard view construction — constructed `/dev`, fresh
`/proc`, private `/tmp`, the T2.8 masks, the per-kennel netns boundary, the SOCKS proxy, seccomp,
Landlock — with two image-specific adaptations: an **overlay** root that keeps the image read-only
while letting Kennel's `/etc` files and the mountpoints win (§7.11.4a), and an in-kennel launcher as
the entrypoint (§7.11.5).

## 7.11.4a View construction: the overlay, and rootfs persistence

When the root is an image, the view is an `overlayfs`, not a bind of the image directory. The image
is a **read-only lower** — never an upperdir, because an image upperdir would make the image
writable and land every workload write in the digest-pinned, ladder-covered store entry, destroying
the integrity unit. Above and below it sit two trusted layers the untrusted image cannot shadow
upward: a small **Kennel layer** holding only the invariant `/etc` files (`resolv.conf`, `hostname`,
`passwd`, `group`, `hosts`, `nsswitch.conf`), so Kennel's resolver and persona win by *layer
precedence* — a real Kennel file outranks an image symlink at the same path with no unlink-replace,
which is the §7.2 targeted-`/etc` intent expressed as ordering and which retires the seed-copy of
image `/etc` and its symlink-dereference hazard entirely; and a Kennel-shipped **scaffold** of empty
mountpoint directories so a distroless or scratch image that ships none of `/proc`, `/dev`, `/tmp`,
`/etc` still boots. The mechanism — the lower-stack order, the assembly, the unprivileged-userns
overlay floor — is the implementation contract (`02-9-oci.md`).

`/etc` is **writable-through**: the `kennel-etc` lower sets the defaults, a workload may copy-up a
file into its own upper, and that harms only its own view. Nothing in `/etc` is pinned, because the
criterion for what to defend is **enforcement is the netns, BPF, uid-map, Landlock, and seccomp —
never file content**: `resolv.conf`/`hosts`/`nsswitch` are not security-load-bearing (the proxied
modes have no DNS endpoint to redirect to; `host` mode gates the connect IP in BPF), and
`passwd`/`group` are persona coherence, self-affecting. A workload rewriting them disarms only
itself, so they stay writable-through (an image can `useradd` at runtime).

**Rootfs persistence is a single loud binary**, not an operator-chosen writable path. Kennel owns the
backing location; the operator chooses only *whether* the rootfs persists:

```toml
[rootfs]
persistence = "discard"   # "discard" (default) | "persist"
```

- **`discard`** (default) — an ephemeral upper makes the root writable for image compatibility and is
  gone at teardown. Nothing persists to shadow the pinned image, so the integrity story is untouched.
- **`persist`** — a Kennel-managed upper under the store entry. This is the **loud** value: it
  accumulates divergence *outside* the integrity ladder (which covers the image layer, not
  lower+upper), and `kennel policy risks` derives that exposure from `persistence = "persist"`,
  surfaced against the `[rootfs]` block's `reason`.

There is **always an upper** — whole-tree immutability is `[rootfs].readonly = ["/"]`, a Landlock
fact (§7.11.4c), not a no-upper mount mode (which dissolves a separate immutable assembly into one
uniform path). A `readonly = ["/"]` root plus a narrow additive `[fs.write]` bind for the workload's
writable `/data` is the recommended posture for a long-running workload: the image stays immutable
and ladder-covered, the writable surface is operator-named, path-scoped, and T2.8-masked. Additive
`[fs.write]` binds are orthogonal to the persistence axis *and* the closure-lock axis — a bind is
operator-named host content (different verb: `[fs]` binds a host path *in*; `[rootfs].readonly`/
`writable` lock/unlock an *existing rootfs* path), whereas the upper is a Kennel-managed whole-root
layer the operator does not name.

## 7.11.4c Closure-lock: re-imposing the boundary the build-flatten erased

The unprivileged `oci build` cannot `chown` to the image's uids — there is no subuid range, and the
builder kennel grants nothing that writes other-uid-owned files — so `umoci`/`skopeo` **flatten every
inode in the image to the single persona uid**. That does not merely drop root ownership; it erases
*every* intra-image DAC boundary at once (root/app, app/other), because there is now one owner. The
workload runs as that same uid, so DAC permits it to write anything it can reach — **its own
binaries included**. Absent re-imposition, the OCI substrate is *strictly more permissive than the
same image under Docker*, where the app uid cannot write root-owned `/usr`.

**Closure-lock** restores the one load-bearing boundary the flatten destroyed: the executable surface
is not self-writable. It is **Landlock**, not a DAC scheme, because after the flatten DAC has nothing
left to deny. The build collapses every inode to the single persona uid, so the workload is the sole
owner of the entire tree — and an owner may write its own files, or `chmod` them writable first, no
matter its uid or capabilities. Ownership-based permission is structurally vacuous here; it is not
that DAC is bypassed but that there is no longer a foreign owner for it to protect. Landlock denies
by path regardless of owner, so it re-imposes a boundary the uid model can no longer express. This is
map-independent — it holds whether the workload runs as in-namespace root or the persona uid — which
is why the lock does not rely on, and is not weakened by, the runtime uid choice (residual C). The
lock is expressed as two `[rootfs]` lists over existing rootfs paths, longest-prefix wins:

```toml
[rootfs]
readonly = ["/usr", "/lib"]            # Landlock deny-write (read + execute kept)
writable = ["/usr/lib/python3.12"]     # carve a hole back out; loud, derived risk
```

The **unlisted-path default is writable, and that is honest labelling, not a policy assertion** — the
flatten made DAC vacuous, so for any path the build did not lock there is no boundary to assert.
Boundaries come from the build-derived `readonly` set written into the signed policy, never from a
grammar default; there is no compiler-side default closure. `readonly = ["/"]` is whole-tree
immutable.

**The `readonly` set is derived at `oci build`, written into the scaffolded `policy.toml`, and
visible in the signed text** — the operator reviews and signs the resurrected boundary; the build
derives, the signature ratifies. Derivation is **best-effort and high-level**, gated on one signal:
does the image declare a non-root `config.User` (effective runtime uid ≠ 0)?

- **All-root image** (no non-root `USER`) — derive nothing; everything writable. *If everything is
  root, nothing is*: a flat image intends a writable substrate, and Kennel matches that intent rather
  than inventing a boundary the author did not. This is also the root-running compat tail — runtime
  `pip -g`/`npm -g`/`apt` work because root-running images get no lock. (A root image under Kennel is
  then at Docker parity — root in a container can write `/usr` too — not a regression.)
- **Non-root `USER` declared** — the author intended `/usr` off-limits to the app. Derive the coarse
  FHS closure (`/usr`, `/bin`, `/sbin`, `/lib*`, which the merged-usr symlinks resolve into). Not a
  per-inode ownership walk; an FHS-level estimate. The `writable` carve-out is the recourse when the
  estimate over-reaches.

`config.User` is read at build for this decision **even though it is ignored as a runtime uid** (the
workload runs as the persona uid — residual C). Same field, two consumers, no conflict.

Closure-lock is active wherever there is a writable upper — i.e. always, since there is always an
upper — and is **independent of `persist`**: the point is that the writable upper plus the uid-map
manufactures a write capability that does not exist on a normal filesystem, so the boundary is
re-imposed whenever that capability exists, not only when it persists.

**Two known gaps** (the derivation is a `config.User` gate, not a per-inode walk): an image that
**drops privilege in its entrypoint** (`gosu`/`su-exec` — common in official `postgres`/`redis`
images) keeps `config.User = 0` and reads as all-root, so it gets no lock despite a clear app/root
intent; and **app code installed outside `/usr|/lib`** (`/app`, `/opt`, `/srv` — most Node/Python/Go
images) stays writable, so for those the claim is "the FHS closure is locked," not "the executable
surface is locked." The `writable` carve-out handles over-reach; under-reach is the operator's to
lock by hand. A future per-inode build-time walk (over the still-unflattened layers) would close
both.

## 7.11.4b Layer lifecycle: `revert` and `update`

Because the image lower is never mutated and the upper is a known Kennel-owned path under the store
entry, two verbs act on the managed upper without reconstructing anything:

- **`kennel oci revert <name>`** obliterates the managed upper and recreates it empty; the next run's
  merged root is the lowers plus a clean layer. It is the *total* case of the persistence-safety
  revert (the blunt end of selective revert), a host-side operator act the workload cannot perform,
  refused while the entry runs. Its claim is narrow — it returns the mutable state to empty; it does
  not re-attest the image lower (the integrity ladder's job). A no-op for a `discard` entry (no
  managed upper exists).
- **`kennel oci update <name> -- <new-image-ref>`** replaces the assured layer: fetch and unpack the
  new image by digest through the vetted builder path, swap `rootfs/` + `config.json` + `digest`,
  bump `[rootfs].image`, and **re-derive the closure lock** from the new image (§7.11.4c). Because the
  run policy was signed against the old digest, update **clears the signature** and leaves the entry
  in the "operator reviews and re-signs" state a fresh build does — it never auto-signs, because a
  fetch silently changing what a signed policy authorises is exactly what the signature exists to
  prevent. The managed upper is **discarded by default** (an upper layered over the old image carries
  copy-ups that would shadow the new one's patched binaries); `--keep-state` preserves it with a
  derived rebase-hazard warning. Refused while running.

`build` creates and refuses an existing `<name>`; `update` replaces and refuses an absent one — the
same grammar discipline across the `oci` noun. Rollback is not a version stack: re-`update` to a
prior digest (recorded in the entry's audit line) is the supported path; keeping N old layers is a
non-goal.

## 7.11.5 The in-kennel launcher

An OCI image carries its own runtime config — `Entrypoint`, `Cmd`, `Env`, `WorkingDir`, `User`.
Kennel does not parse that config in the daemon (a manifest parser in the TCB is exactly what
§7.11.1 refuses) and does not make the operator transcribe it by hand into policy. Instead a small
Kennel-shipped **launcher** becomes the workload's `argv[0]`, parses the config *inside the confined
kennel* at workload authority, applies `WorkingDir`/`Env`/`Entrypoint`+`Cmd`, and `execve`s the
real entrypoint. A bug in it is a bug in a confined, unprivileged process holding no capability, no
`mount`, no `unshare` — contained exactly like the builder's parsers.

The launcher runs *inside the image's filesystem*, which may be musl, distroless, or `scratch` with
no host `ld.so`/`libc`, so it — like every Kennel binary the seal runs inside a kennel root
(`kennel-bin-init` and the in-kennel facades) — is **statically linked**; a dynamically-linked host
binary would fail to load against an alien substrate. The default launcher does a standard `execve`
of the image entrypoint *from within the root* (it holds nothing to drop and crosses no boundary —
the pivot already happened): there is no host-side `openat2(RESOLVE_IN_ROOT)` and no TOCTOU fd-pin
on the image entrypoint, because the OCI model's provenance anchor is the image digest, not a
per-binary hash (§7.11.7 residual A).

The launcher **always** resolves the entrypoint from the image config; there is no `[workload]` block
in an OCI policy (`[rootfs]` and `[workload]` are mutually exclusive, §7.11.2), so there is no
per-binary pin in the OCI model — provenance is anchored on the recorded image digest (§7.11.8), the
whole of the assertion. A `kennel oci run <name> -- <cmd>` supplies a **`Cmd` override**: the launcher
runs it in place of the image's `Cmd` while keeping the image `Entrypoint` and the sanitised `Env`
(the same shape as `docker run <image> <cmd>`). This is a runtime convenience with no policy impact —
it changes no grant and crosses no trust boundary, since the entrypoint, env, and substrate are all
still the image's — so it is allowed rather than friction the operator routes around.

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
identity; the constructed `/dev` allowlist; seccomp; the closure-lock executable boundary
(§7.11.4c); the absence of a daemon socket; the absence of a nested user namespace. The workload
acquires no kernel capability, no `mount`, no `unshare`. The TCB is the size it was — the launcher
and every image parser run at workload authority, not in the daemon.

The targeted `/etc` is **not** in this hard-invariant set: it is a *default*, not a boundary the
workload cannot touch. The `kennel-etc` lower sets Kennel's `resolv.conf`/`nsswitch`/`hostname`/
`passwd` over the image's, but `/etc` is writable-through (§7.11.4a) so a workload may copy-up-shadow
them in its own upper — harmlessly, since enforcement is the netns/BPF/uid-map/Landlock/seccomp
above, never the file content. It overrides the image; it is not an invariant.

**What the operator waives.** The image supplies its own runtime closure — `ld.so`, libc, the NSS
modules, everything `argv[0]` loads after `execve`, and its own entrypoint, env, and config. This is
the substrate-trust residual catalogued as **T3.8**, derived from the `[rootfs]` grant the way T1.6
is derived from `mode = host` (no `threats.reinstated` field; the shape of the grant is the tag):

- **Provenance, not a per-binary pin — and not a per-invocation one.** `argv[0]` is the Kennel-pinned
  launcher; the image entrypoint it execs is image-chosen and provenance-covered (it came from
  `image@sha256`) but not separately hashed. There is no per-binary pin in the OCI model — the
  standard run model's "this exact entrypoint binary" narrows to "this exact image, by digest," and
  the digest is the whole of the assertion. The dynamic closure stays unpinned. The signature pins the
  *substrate*, not the *invocation*: a `kennel oci run … -- <cmd>` override (§7.11.5) changes the
  command under an unchanged signature, where the standard model's `[workload].argv` *is* signed. So
  two operators sharing one signed OCI policy can run different commands under an identical signature —
  the OCI signature attests the image and the policy grants, not the exact command line.
- **Image `Env` enters the workload, sanitised** (§7.11.6) — declared substrate beneath policy's
  final say.
- **Image `User` is not honored as a runtime uid.** The userns maps a single entry — the host operator
  identity to one in-namespace uid — with no subuid range, so the workload runs as the persona uid and
  `config.User` is not applied. The failure this produces is **identity, not permission**: because the
  build already flattened every inode to the persona uid, the workload owns its whole tree and writes
  succeed where a real foreign-owned dir would have refused, so there is no ownership `EACCES`. What
  breaks instead is an image that *assumes* its uid — `gosu 1000`/`su-exec` dropping to a uid the map
  does not contain, or an `id -u` equality check — which is the same `config.User = 0` reading that
  costs such images their closure-lock (§7.11.4c). `config.User` is read at build, for the lock
  decision; the same field, a different consumer, no conflict.
- **Closure-tampering is closed for a non-root image, by build-derived closure-lock** (§7.11.4c): the
  executable surface (the FHS closure) equals the pinned image throughout the session, enforced by
  Landlock against in-namespace root. For an all-root image there is no lock — but that is the image's
  own posture (Docker parity), not a Kennel gap. Two derivation gaps remain (`gosu`/`su-exec`
  drop-privilege images read as all-root; app code outside `/usr|/lib` stays writable); a `persist`
  upper additionally diverges *data* outside the integrity ladder, and each `writable` carve-out is
  its own derived risk line. `fs.execute` coarseness is unchanged.

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
