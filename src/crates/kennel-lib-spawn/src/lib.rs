// SPDX-License-Identifier: Apache-2.0

//! Project Kennel spawn orchestration.
//!
//! # Purpose
//!
//! Turn a settled policy into a confined workload. The runtime pipeline is:
//! verify the settled-policy bytes (one signature, schema gate, framework
//! invariants — via [`kennel_lib_policy::verify_settled`]); substitute the
//! per-instance placeholders (`<ctx>`, `<uid>`, `<kennel>`, `<home>`, and the
//! masked `<user>`/`<group>`) and refuse any that remain;
//! translate the result into a [`Plan`] of kernel enforcement
//! objects; then apply the plan and exec.
//!
//! This crate holds **no `unsafe`** (`#![forbid(unsafe_code)]`): every syscall
//! routes through `kennel-lib-syscall` and `kennel-lib-bpf`.
//!
//! # Scope of this build
//!
//! Two halves live here. The first is pure: verify → substitute → translate the signed policy
//! into a [`Plan`] and a [`ConstructionHalf`]/[`Supervision`] pair, all testable off the spawn
//! path. The second is the view construction itself ([`build_view_and_pivot`]): mounts, binds
//! and the pivot, run by the privhelper **factory** in its construction child.
//! The factory clones the namespaces, writes the identity maps,
//! builds the constructed view, and `fexecve`s `kennel-bin-init` as the
//! kennel's uid-0 PID 1, which applies the irreversible seal (Landlock + seccomp + cgroup join)
//! before running the workload. The post-`fork` `unsafe` lives in `kennel-lib-syscall`; egress BPF
//! is attached in the same factory op. The root e2e exercises the whole vertical.

#![forbid(unsafe_code)]

mod image;
pub mod mesh_rendezvous;
pub mod plan;
pub mod procfs;
pub mod wire;

use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use kennel_lib_policy::{KeySet, PolicyError, SettledPolicy};
use kennel_lib_syscall::fd::{proc_path, NodeKind, RootDir};
use kennel_lib_syscall::landlock::{AccessFs, AccessNet, Ruleset};

pub use plan::{
    AuxProcess, BindMount, ConstructionHalf, ImageRoot, LoopbackAddr, Persistence, Plan, ProcView,
    ProxyEndpoint, ShimView, Supervision,
};

/// The per-instance values the runtime fills into a settled policy's deferred
/// placeholders.
#[derive(Debug, Clone)]
pub struct RuntimeSubstitutions {
    /// The kennel's context number (`<ctx>`), assigned at start. IPv4-enabled
    /// kennels are capped at 255; v6-only kennels may range higher.
    pub ctx: u16,
    /// The user's UID (`<uid>`).
    pub uid: u32,
    /// The kennel's runtime ID (`<kennel>`).
    pub kennel: String,
    /// The user's home directory (`<home>`).
    pub home: PathBuf,
    /// The caller's resource namespace (derived from the caller's uid), under
    /// which this kennel's cgroup lives (`/sys/fs/cgroup/<namespace>/<ctx>`).
    pub namespace: String,
}

/// Everything that can stop a spawn before exec.
#[derive(Debug)]
pub enum SpawnError {
    /// The settled policy failed verification (signature, schema, invariants).
    Policy(PolicyError),
    /// A placeholder remained after substitution — the policy referenced a
    /// variable the runtime does not provide.
    UnsubstitutedPlaceholder {
        /// The policy field the placeholder was found in.
        field: String,
        /// The offending value.
        value: String,
    },
    /// A syscall during confinement setup or the spawn itself failed.
    Syscall(io::Error),
    /// The settled policy could not be translated into an enforcement plan
    /// (e.g. a malformed CIDR).
    InvalidPolicy(String),
}

impl core::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Policy(e) => write!(f, "policy verification failed: {e}"),
            Self::UnsubstitutedPlaceholder { field, value } => {
                write!(f, "unsubstituted placeholder in {field}: `{value}`")
            }
            Self::Syscall(e) => write!(f, "confinement/spawn syscall failed: {e}"),
            Self::InvalidPolicy(m) => write!(f, "policy could not be translated: {m}"),
        }
    }
}

impl std::error::Error for SpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(e) => Some(e),
            Self::Syscall(e) => Some(e),
            Self::UnsubstitutedPlaceholder { .. } | Self::InvalidPolicy(_) => None,
        }
    }
}

impl From<PolicyError> for SpawnError {
    fn from(e: PolicyError) -> Self {
        Self::Policy(e)
    }
}

/// Replace the deferred placeholders in `s`. `user`/`group` are the policy's own
/// masked identity (`[identity].user`/`.group`, default `kennel`), not runtime
/// context — they are grammar-validated names (§7.4), so safe to splice into paths.
fn substitute_str(s: &str, subst: &RuntimeSubstitutions, user: &str, group: &str) -> String {
    s.replace("<ctx>", &subst.ctx.to_string())
        .replace("<uid>", &subst.uid.to_string())
        .replace("<kennel>", &subst.kennel)
        .replace("<home>", &subst.home.to_string_lossy())
        .replace("<user>", user)
        .replace("<group>", group)
}

/// Expand a leading home token (`~`, `$HOME`, or the `<home>` placeholder) in `s` to `home`.
/// No change if `s` has no home prefix.
fn expand_home_prefix(s: String, home: &str) -> String {
    for tok in ["~", "$HOME", "<home>"] {
        if s == tok {
            return home.to_owned();
        }
        if let Some(rest) = s.strip_prefix(tok).and_then(|r| r.strip_prefix('/')) {
            return format!("{home}/{rest}");
        }
    }
    s
}

/// Substitute a **bind-backed path** field (`fs.read`/`fs.write`/`exec.allow`): `substitute_str`
/// plus a leading `~`/`$HOME` → the operator's home.
///
/// A home-relative grant (`~/foo`) names a host path whose *data* lives there, but the kennel must
/// never see that location: `remap_target` relocates it beneath the persona `$HOME` (`/home/kennel/…`)
/// for the bind target, the Landlock rule, and the exec-allowlist match. So `~/foo/bin/tool` becomes
/// a grant on `/home/kennel/foo/bin/tool` inside the kennel, bound from the operator's real
/// `~/foo/bin/tool`. Expanding to the real home here is what lets the existing remap do the
/// relocation; `~` is the *only* way to name the home — the real path is never written in policy.
fn substitute_path(s: &str, subst: &RuntimeSubstitutions, user: &str, group: &str) -> String {
    let s = substitute_str(s, subst, user, group);
    expand_home_prefix(s, &subst.home.to_string_lossy())
}

/// Substitute a **persona-string** path field (`exec.path` search roots, `exec.shell`): a `~`/`$HOME`
/// prefix → the **persona** home (`/home/<user>`) directly.
///
/// Unlike the bind-backed fields, these are not bound — they are strings the workload reads (its
/// `$PATH`, its `$SHELL`/`pw_shell`). So `~` resolves straight to the in-kennel persona home, the
/// path that actually exists in the view: `exec.path = ["~/.local/bin"]` becomes
/// `/home/kennel/.local/bin` in `$PATH`, matching where a `~/.local/bin/...` `exec.allow` grant
/// landed (its remap target is the same persona path).
fn substitute_persona_path(
    s: &str,
    subst: &RuntimeSubstitutions,
    user: &str,
    group: &str,
) -> String {
    // Resolve the home prefix to the persona home FIRST — before `substitute_str` would expand a
    // `<home>` token to the *operator's* home (a leak in a string the workload reads). The remaining
    // `<…>` tokens (ctx/uid/…) are then substituted normally.
    let s = expand_home_prefix(s.to_owned(), &format!("/home/{user}"));
    substitute_str(&s, subst, user, group)
}

/// Error if `value` still contains an unresolved `<…>` placeholder.
fn reject_leftover(field: &str, value: &str) -> Result<(), SpawnError> {
    if value.contains('<') {
        return Err(SpawnError::UnsubstitutedPlaceholder {
            field: field.to_owned(),
            value: value.to_owned(),
        });
    }
    Ok(())
}

/// Apply the runtime substitutions to a verified settled policy, returning a copy
/// with placeholders filled. Refuses any placeholder that remains unresolved.
///
/// # Errors
///
/// Returns [`SpawnError::UnsubstitutedPlaceholder`] if a path field still
/// contains a `<…>` token after substitution.
pub fn substitute(
    policy: &SettledPolicy,
    subst: &RuntimeSubstitutions,
) -> Result<SettledPolicy, SpawnError> {
    let mut p = policy.clone();
    // The masked identity drives `<user>`/`<group>`; clone before borrowing `fs`.
    let user = p.identity.user.clone();
    let group = p.identity.group.clone();
    let fs = &mut p.effective_policy.fs;

    for path in &mut fs.read {
        *path = substitute_path(path, subst, &user, &group);
        reject_leftover("fs.read", path)?;
    }
    for path in &mut fs.write {
        *path = substitute_path(path, subst, &user, &group);
        reject_leftover("fs.write", path)?;
    }
    // Exclusive paths (§2.7) are a subset of write — substitute them identically so the plan
    // builder's source match holds (an unsubstituted `~` would never equal a substituted bind
    // source, silently dropping the over-mount).
    for path in &mut fs.exclusive {
        *path = substitute_path(path, subst, &user, &group);
        reject_leftover("fs.exclusive", path)?;
    }
    // The `mmap_exec` opt-outs (#229) name `write` paths: substitute them identically, or a `~/`
    // opt-out never matches its substituted bind and the bind silently stays noexec.
    for path in &mut fs.write_mmap_exec {
        *path = substitute_path(path, subst, &user, &group);
        reject_leftover("fs.write_mmap_exec", path)?;
    }
    // Redirects (W15): `path` must keep matching its (substituted) grant in `read`/`write`,
    // and `source` is a bind-backed host path like any grant — both substitute identically.
    for r in &mut fs.redirect {
        r.path = substitute_path(&r.path, subst, &user, &group);
        reject_leftover("fs.redirect.path", &r.path)?;
        r.source = substitute_path(&r.source, subst, &user, &group);
        reject_leftover("fs.redirect.source", &r.source)?;
    }
    for bin in &mut p.effective_policy.exec.allow {
        *bin = substitute_path(bin, subst, &user, &group);
        reject_leftover("exec.allow", bin)?;
    }
    for dir in &mut p.effective_policy.exec.path {
        *dir = substitute_persona_path(dir, subst, &user, &group);
        reject_leftover("exec.path", dir)?;
    }
    {
        let shell = &mut p.effective_policy.exec.shell;
        *shell = substitute_persona_path(shell, subst, &user, &group);
        reject_leftover("exec.shell", shell)?;
    }
    // The synthesised environment (§7.9.2): substitute placeholders in the values
    // (e.g. a HOME under `/home/<user>/…`); keys are fixed var names.
    for value in p.env.vars.values_mut() {
        *value = substitute_str(value, subst, &user, &group);
        reject_leftover("env.set", value)?;
    }

    Ok(p)
}

/// The runtime entry point: verify settled-policy `bytes`, substitute the
/// per-instance placeholders, and produce the enforcement [`Plan`].
///
/// # Errors
///
/// Returns [`SpawnError::Policy`] if verification fails, or
/// [`SpawnError::UnsubstitutedPlaceholder`] if a placeholder is unresolved.
pub fn prepare(
    bytes: &[u8],
    keys: &KeySet,
    subst: &RuntimeSubstitutions,
) -> Result<Plan, SpawnError> {
    let verified = kennel_lib_policy::verify_settled(bytes, keys)?;
    let substituted = substitute(&verified, subst)?;
    Plan::from_policy(&substituted, subst.ctx, &subst.namespace, &subst.home)
}

/// Build (but do not install) a Landlock ruleset from a plan's path and port rules.
///
/// With `skip_missing`, a path that cannot be opened — absent from the
/// constructed view — is skipped rather than failing the build; a grant for a
/// path the view does not contain is vacuous. The seal builds with `skip_missing`
/// after `pivot_root`; the fallback path builds in the parent without it.
///
/// Public so `kennel-bin-init` builds the workload's ruleset post-pivot from its
/// [`Supervision`] half with the identical logic (Kennel book Vol 2 ch.2 (Process and Privilege Model)); it is
/// `unsafe`-free, so sharing it keeps `kennel-bin-init` `#![forbid(unsafe_code)]`.
///
/// # Errors
///
/// Returns the OS error if the ruleset cannot be created or a path rule fails to apply
/// (other than a `skip_missing`-tolerated absent path).
pub fn build_ruleset(
    fs: &[(PathBuf, AccessFs)],
    net: &[(u16, AccessNet)],
    net_handled: AccessNet,
    skip_missing: bool,
) -> io::Result<Ruleset> {
    let mut ruleset = Ruleset::new()?;
    // TCP rights the BPF ACL alone gates (#218): Landlock must not handle them.
    ruleset.handle_net_only(net_handled);
    for (path, access) in fs {
        match ruleset.allow_path(path, *access) {
            Ok(()) => {}
            Err(e) if skip_missing && e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    for (port, access) in net {
        ruleset.allow_port(*port, *access);
    }
    Ok(ruleset)
}

/// Construct the kennel's filesystem view in a fresh tmpfs root and `pivot_root`
/// into it (§7.4.5), so non-granted path *names* are absent from the view, not
/// merely access-denied.
///
/// Runs in the forked child's mount-namespace seal, after [`make_root_private`].
/// In order: mount the new root (a tmpfs holding only scaffolding); bind the
/// granted system and `~/…` paths in (same-inode binds, so the post-pivot
/// Landlock rules match, and writable binds resolve to **persistent host
/// inodes** so the work survives teardown); copy the staged synthetic `/etc`
/// (the host `/etc` is never bound in); bind the allowlisted `/dev` nodes;
/// mount a fresh `/proc` and the private `/tmp`; then `pivot_root` and detach the
/// old root.
///
/// [`make_root_private`]: kennel_lib_syscall::mount::make_root_private
///
/// Public so the privhelper factory builds the view in its construction child with the
/// identical logic (`07-2` §7.2.1); it is `unsafe`-free (mounts go through
/// `kennel_lib_syscall::mount`), so sharing it keeps the factory `#![forbid(unsafe_code)]`.
///
/// # Errors
///
/// Returns the OS error if any mount, bind, `/proc`/`/tmp` setup, or the `pivot_root`
/// fails.
pub fn build_view_and_pivot(
    view: &ShimView,
    new_root: &Path,
    file_binds: &[(PathBuf, PathBuf)],
    operator: Option<FsIdentity>,
) -> io::Result<()> {
    use kennel_lib_syscall::mount;

    // From here to the pivot, every path this function touches is resolved with the OPERATOR's
    // filesystem identity (see [`FsIdentity`]). The caller is the kennel's uid 0 = host root, and
    // the host filesystem is still mounted.
    fs_as_operator(operator)?;
    // Scaffolding is created 0755 / 0644 regardless of the mask this process inherited: nothing
    // in the view's own skeleton should be writable by group or other. Landlock is what stops
    // the workload writing there, but the modes should not depend on it.
    kennel_lib_syscall::process::set_umask(0o022);

    // OCI substrate root (§7.11.4a / T3.8): boot the image as a layered overlay
    // (kennel-etc : image : scaffold) instead of a constructed tmpfs. Distinct head
    // (no host-closure mirror, /etc wins by layer precedence), shared seal tail.
    if let Some(img) = &view.image {
        return build_image_view_and_pivot(view, new_root, img, file_binds, operator);
    }

    // 1. The new root: a fresh tmpfs (scaffolding only; bound content is host-backed).
    // Mode 0755: a tmpfs defaults to 1777, which would make the view's `/` world-writable.
    mount::mount_tmpfs(new_root, None, Some("0755"), false, false).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("mount tmpfs new_root {}: {e}", new_root.display()),
        )
    })?;
    // Every destination below is resolved INSIDE the new root, by descriptor (see `RootDir`).
    let stage = RootDir::open(new_root)?;

    // 2. Bind the granted system + home paths in.
    materialize_binds(&view.binds, &stage, None)?;

    // 2b. Merged-usr compat symlinks (`/bin -> usr/bin`, `/lib64 -> usr/lib`, …).
    //    On modern systems these top-level dirs are symlinks into `/usr`; the view's
    //    bound content lives under `/usr`, so without replicating them `/bin/sh`,
    //    `#!/bin/sh` shebangs, and the `/lib64/ld-linux…` loader all `ENOENT`.
    //    Mirror exactly the host's links (only where the host has one and the view
    //    does not already provide the path), so both path resolution and the Landlock
    //    rules on `/bin/…` paths land on the bound `/usr` inodes.
    for link in ["bin", "sbin", "lib", "lib64", "lib32", "libx32"] {
        let host = Path::new("/").join(link);
        let Ok(target) = std::fs::read_link(&host) else {
            continue; // not a symlink on this host (non-merged-usr) — nothing to mirror
        };
        if stage.lookup(&host)?.is_some() {
            continue; // already present (e.g. bound in by a grant)
        }
        stage.symlink(&target, &host)?;
    }

    // 3. The synthetic /etc: a fresh dir in the root tmpfs populated with the
    //    staged vanilla files. The host /etc is never bound in (it carries host
    //    specifics). Writes are denied by the Landlock read grant on /etc.
    stage.ensure(Path::new("/etc"), NodeKind::Directory)?;
    for (source, target) in file_binds {
        stage
            .copy_into(source, target)
            .map_err(|e| io::Error::new(e.kind(), format!("stage {}: {e}", target.display())))?;
    }

    // 3b. `/etc` overlays: bind the granted real host `/etc` files read-only ON TOP of the
    //     synthetic floor just built (the resolver/hosts a `net.mode = host` service needs). The
    //     synthetic `/etc` is the floor; an explicit `fs.read` grant layers the real file over it.
    materialize_etc_overlays(&view.etc_overlays, &stage)?;

    // 4–7. The seal tail (constructed /dev, binderfs, /proc, /tmp, home, masks, pivot).
    seal_view_tail(view, new_root, &stage, operator, true)
}

/// Bind each granted host `/etc` file read-only over the synthetic `/etc` floor (the real resolver
/// config / hosts a `net.mode = host` service resolves real names against, §8 / W2).
///
/// The synthetic `/etc` is built first (a floor of scrubbed files); this layers the real host path
/// on top of the specific entries the policy granted — a **file** (`/etc/resolv.conf`) or a whole
/// **directory** (`/etc/fonts`, `/etc/ssl/certs` — fontconfig and the CA bundle a GUI or TLS client
/// needs). The `source` is the host path the content comes from and the `view_path` is where it
/// lands: equal for an ordinary grant, divergent for a W15 `source` redirect (`/etc/sway` served
/// from the kennel-shipped `/etc/kennel/config/sway`). A source that does not exist is skipped
/// (nothing to overlay). The overlay set is already restricted to safe entries ([`crate::plan`]
/// never emits a protected-floor path), so this trusts its input.
///
/// # Errors
/// The OS error if creating the target mountpoint, the bind, or the read-only remount fails.
fn materialize_etc_overlays(
    overlays: &[crate::plan::EtcOverlay],
    stage: &RootDir,
) -> io::Result<()> {
    use kennel_lib_syscall::mount;
    for overlay in overlays {
        let source = &overlay.source;
        // The host source (still reachable pre-pivot). Skip a grant whose host path is absent.
        if source.symlink_metadata().is_err() {
            continue;
        }
        let place = stage.ensure(&overlay.view_path, kind_of(source))?;
        mount::bind(source, &proc_path(&place), false).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("etc overlay bind {}: {e}", overlay.view_path.display()),
            )
        })?;
        let mounted = mounted_at(stage, &overlay.view_path)?;
        mount::remount_readonly(&proc_path(&mounted)).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "etc overlay remount_ro {}: {e}",
                    overlay.view_path.display()
                ),
            )
        })?;
    }
    Ok(())
}

/// The Kennel-shipped scaffold lower (§7.11.4a): empty mountpoint dirs the seal mounts over
/// and (for `readonly`) `pivot_root`'s `put_old`, plus empty `/etc` placeholders. Fixed
/// content, so it is built in the staging tmpfs per spawn rather than shipped as an artifact.
const SCAFFOLD_DIRS: &[&str] = &[
    "proc",
    "dev",
    "tmp",
    "sys",
    "run",
    "run/kennel",
    "etc",
    "home",
    ".kennel-oldroot",
];
/// The `/etc` files `kennel-etc` provides; the scaffold ships empty placeholders so the
/// `readonly` ro-bind has a target even on a scratch image, and `kennel-etc` outranks them.
const KENNEL_ETC_FILES: &[&str] = &[
    "resolv.conf",
    "hostname",
    "hosts",
    "passwd",
    "group",
    "nsswitch.conf",
];

/// Closure-lock (§7.11.4c): lock the executable closure as **read-only mounts** — Landlock
/// rights are additive (the `/` write grant cannot be subtracted at `/usr`), so the lock is a
/// mount, robust against the persona workload (no `CAP_SYS_ADMIN` to remount, `mount`
/// seccomp-blocked). The `writable` carve-outs bind FIRST (a fresh RW bind of the writable
/// overlay inode at the deeper mountpoint), so a later read-only remount of the enclosing
/// `readonly` path does not touch them — the deeper mount serves its own subtree. These
/// paths name image content, so a link (`/bin` → `usr/bin`) is followed, inside the root.
fn lock_closure(stage: &RootDir, img: &crate::plan::ImageRoot) -> io::Result<()> {
    use kennel_lib_syscall::mount;
    for w in &img.writable {
        if let Some(target) = stage.resolve(w)? {
            let target = proc_path(&target);
            mount::bind(&target, &target, false).map_err(|e| {
                io::Error::new(e.kind(), format!("writable carve-out {}: {e}", w.display()))
            })?;
        }
    }
    for ro in &img.readonly {
        // A locked path the image does not contain is created, empty, and locked like the rest.
        // Skipping it would leave the name free: the workload could create `/usr/local/bin`
        // later, in the writable layer, and have an executable location outside the lock.
        let resolved = if let Some(target) = stage.resolve(ro)? {
            Some(target)
        } else {
            stage.ensure(ro, NodeKind::Directory).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("closure-lock {} (absent in the image): {e}", ro.display()),
                )
            })?;
            stage.resolve(ro)?
        };
        if let Some(target) = resolved {
            let target = proc_path(&target);
            mount::bind(&target, &target, true).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("closure-lock ro mount {}: {e}", ro.display()),
                )
            })?;
            // Resolve again: the name now leads to the mount just made, which is what to seal.
            let mounted = stage.resolve(ro)?.ok_or_else(|| {
                io::Error::other(format!("closure-lock {} vanished", ro.display()))
            })?;
            kennel_lib_syscall::namespace::readonly_mount_tree(&proc_path(&mounted)).map_err(
                |e| {
                    io::Error::new(
                        e.kind(),
                        format!("closure-lock ro remount {}: {e}", ro.display()),
                    )
                },
            )?;
        }
    }
    Ok(())
}

/// The OCI substrate variant of [`build_view_and_pivot`] (§7.11.4a / T3.8): the view is a
/// three-lower `overlay` — `kennel-etc : image : scaffold` (leftmost wins) — with the
/// persistence tri-state choosing the upper. **Nothing is ever written to the image** (it is a
/// read-only lower, never an upper), so the integrity-ladder hash/verity is never invalidated by
/// the runner's writes and `<store>/<name>/rootfs/` is shared read-only across runs.
///
/// Departures from the constructed view: no merged-usr mirror (the image carries its own layout);
/// `/etc` is not synthesised — Kennel's `resolv.conf`/`hostname`/`passwd`/`group`/`hosts`/
/// `nsswitch.conf` win by *layer precedence* (the `kennel-etc` top lower built from `file_binds`),
/// so a Kennel regular file outranks an image symlink at the same path with no unlink-replace and
/// no dereference.
fn build_image_view_and_pivot(
    view: &ShimView,
    staging: &Path,
    img: &crate::plan::ImageRoot,
    file_binds: &[(PathBuf, PathBuf)],
    operator: Option<FsIdentity>,
) -> io::Result<()> {
    use crate::plan::Persistence;
    use kennel_lib_syscall::mount;

    // 1. A tmpfs backing under the kenneld staging dir holds the two Kennel-built lowers
    //    (`kennel-etc`, `scaffold`), the ephemeral upper+work (discard), and the `merged`
    //    mountpoint we build into and pivot to.
    mount::mount_tmpfs(staging, None, Some("0755"), false, false).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("mount tmpfs overlay backing {}: {e}", staging.display()),
        )
    })?;
    let kennel_etc = staging.join("kennel-etc");
    let scaffold = staging.join("scaffold");
    let root = staging.join("merged");
    std::fs::create_dir_all(&root)?;

    // 2. Build the `kennel-etc` top lower from the synthetic /etc (`file_binds`): each
    //    invariant file copied verbatim under `kennel-etc/<target>`. Highest precedence.
    std::fs::create_dir_all(&kennel_etc)?;
    let ketc = RootDir::open(&kennel_etc)?;
    ketc.ensure(Path::new("/etc"), NodeKind::Directory)?;
    for (source, target) in file_binds {
        ketc.copy_into(source, target)
            .map_err(|e| io::Error::new(e.kind(), format!("stage {}: {e}", target.display())))?;
    }
    // `/etc` overlays (W2): copy the granted REAL host `/etc` path (the W15 redirect `source`, or
    // the view path itself) over the synthetic one in the top `kennel-etc` lower, so the real
    // resolver/hosts / kennel-shipped config wins by overlay precedence (the bind-based equivalent
    // of the ordinary view's on-top overlay; the overlayfs upper is where precedence lives here). A
    // source that is absent is skipped; a directory source (`/etc/fonts`) copies recursively.
    for overlay in &view.etc_overlays {
        if overlay.source.symlink_metadata().is_err() {
            continue;
        }
        if overlay.source.is_dir() {
            let dest = ketc.ensure(&overlay.view_path, NodeKind::Directory)?;
            copy_dir_recursive(&overlay.source, &proc_path(&dest))?;
        } else {
            ketc.copy_into(&overlay.source, &overlay.view_path)?;
        }
    }

    // 3. Build the `scaffold` bottom lower: empty mountpoint dirs + empty /etc placeholders.
    for d in SCAFFOLD_DIRS {
        std::fs::create_dir_all(scaffold.join(d))?;
    }
    for f in KENNEL_ETC_FILES {
        let _ = std::fs::File::create(scaffold.join("etc").join(f))?;
    }

    // 4. The overlay: kennel-etc : image : scaffold (read-only lowers, leftmost wins). There is
    //    ALWAYS an upper (§7.11.4c — whole-tree-immutable is `readonly = ["/"]` via Landlock, not
    //    a no-upper mount); the image is never an upper. discard = ephemeral tmpfs, persist =
    //    managed store upper.
    // The two layers built above are the kennel's own scaffolding (the synthetic /etc that wins
    // by layer precedence, and the mount-point floor). They were written as the operator; hand
    // them to the kennel's uid 0 now, so the workload cannot alter them through the overlay. Both
    // sit on the staging tmpfs mounted above, with nothing mounted inside them, and the walk
    // neither follows a symlink nor crosses a mount — so no host inode is in reach.
    fs_as_root(operator)?;
    kennel_lib_syscall::fd::chown_tree_same_mount(&kennel_etc, 0, 0, None)?;
    kennel_lib_syscall::fd::chown_tree_same_mount(&scaffold, 0, 0, None)?;
    fs_as_operator(operator)?;

    let (upper, work) = match img.persistence {
        Persistence::Discard => {
            let upper = staging.join("upper");
            let work = staging.join("work");
            std::fs::create_dir_all(&upper)?;
            std::fs::create_dir_all(&work)?;
            (upper, work)
        }
        Persistence::Persist => {
            // kenneld validated/created these under the store entry; overlay requires `work`
            // empty and on the same fs as `upper`.
            img.store_upper.clone().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "persistence = persist but no store upper/work was provided",
                )
            })?
        }
    };
    mount_image_overlay(
        img,
        [&kennel_etc, &scaffold],
        (&upper, &work),
        &root,
        operator,
    )?;

    // Every destination below is resolved INSIDE the merged root, by descriptor. The tree is
    // image content (and, with `persist`, whatever an earlier workload left in the upper), so a
    // name here can be a symlink pointing anywhere.
    let stage = RootDir::open(&root)?;
    let home = stage.ensure(Path::new("/home"), NodeKind::Directory)?;
    mount::mount_tmpfs(&proc_path(&home), None, Some("0755"), false, true)?;

    // 6. Assembly (§7.11.4a): bind the granted ~/ + launcher + config + additive binds. `/etc` is
    //    writable-through (§7.11.4c) — the `kennel-etc` lower sets the defaults and a workload may
    //    copy-up-shadow them in its own upper, harming only its own view; enforcement is the
    //    netns/BPF/uid-map/Landlock/seccomp, never file content, so nothing is ro-bound here.
    materialize_binds(&view.binds, &stage, Some((&root, operator)))?;

    // 7. Closure-lock (§7.11.4c): see `lock_closure`.
    lock_closure(&stage, img)?;

    // 8. The seal tail (constructed /dev, binderfs, /proc, /tmp, home dir, masks, pivot). The
    //    root here is the overlay — image content, not scaffolding — so it is not re-owned.
    seal_view_tail(view, &root, &stage, operator, false)
}

/// The `/dev` part of the seal tail: a fresh tmpfs holding only the allowlisted nodes, and the
/// per-kennel binderfs instance with its one device.
fn seal_dev(view: &ShimView, stage: &RootDir, operator: Option<FsIdentity>) -> io::Result<()> {
    use kennel_lib_syscall::mount;
    let step = |what: &str, e: &io::Error| io::Error::new(e.kind(), format!("{what}: {e}"));

    // 4. A fresh constructed /dev tmpfs with only the allowlisted nodes bound in
    //    — never the host /dev (which exposes disks, kmsg, mem, …).
    let dev = stage
        .ensure(Path::new("/dev"), NodeKind::Directory)
        .map_err(|e| step("/dev", &e))?;
    mount::mount_tmpfs(&proc_path(&dev), None, Some("0755"), true, true)
        .map_err(|e| step("mount /dev tmpfs", &e))?;
    for node in &view.dev_allow {
        if node.is_dir() {
            // devpts: a private instance, never the host's (`/dev/pts`).
            let place = stage
                .ensure(node, NodeKind::Directory)
                .map_err(|e| step("devpts mount point", &e))?;
            mount::mount_devpts(&proc_path(&place)).map_err(|e| step("mount devpts", &e))?;
            if node == Path::new("/dev/pts") && stage.lookup(Path::new("/dev/ptmx"))?.is_none() {
                stage
                    .symlink(Path::new("pts/ptmx"), Path::new("/dev/ptmx"))
                    .map_err(|e| step("/dev/ptmx link", &e))?;
            }
        } else {
            let place = stage
                .ensure(node, NodeKind::File)
                .map_err(|e| step("device node mount point", &e))?;
            mount::bind(node, &proc_path(&place), false)
                .map_err(|e| step("bind device node", &e))?;
        }
    }

    // 4b. The per-kennel binderfs instance (§7.1): its own binder namespace, mounted in the
    //     constructed /dev, with one `binder` device the workload talks to kenneld over.
    if view.binder {
        let place = stage
            .ensure(Path::new("/dev/binderfs"), NodeKind::Directory)
            .map_err(|e| step("/dev/binderfs", &e))?;
        kennel_lib_binder::binderfs::mount_instance(
            &proc_path(&place),
            kennel_lib_binder::binderfs::DEFAULT_MAX_DEVICES,
        )
        .map_err(|e| io::Error::new(e.kind(), format!("binderfs mount_instance: {e}")))?;
        // Resolve again: the name now leads into the binderfs just mounted.
        let binderfs = mounted_at(stage, Path::new("/dev/binderfs"))?; // held: the path below names it
        let binderfs_dir = proc_path(&binderfs);
        // Allocating the device opens `binder-control`, which binderfs gives to uid 0 of the
        // mounting namespace (mode 0600) — the one pre-pivot step that needs root's identity. The
        // path is the binderfs just mounted above, on the /dev tmpfs mounted above that.
        fs_as_root(operator)?;
        let added = kennel_lib_binder::binderfs::add_binder_device(&binderfs_dir);
        fs_as_operator(operator)?;
        added.map_err(|e| io::Error::new(e.kind(), format!("binderfs add_binder_device: {e}")))?;
        stage
            .symlink(Path::new("binderfs/binder"), Path::new("/dev/binder"))
            .map_err(|e| io::Error::new(e.kind(), format!("binderfs symlink: {e}")))?;
    }
    Ok(())
}

/// The seal tail shared by [`build_view_and_pivot`]'s constructed-tmpfs head and
/// [`build_image_view_and_pivot`]'s OCI-overlay head: the constructed `/dev`, the
/// per-kennel binderfs, a fresh `/proc` + private `/tmp`, the shim `$HOME`, the
/// trust-manifest masks, and finally `pivot_root` into `root` (detaching the old
/// root). `root` is the about-to-be-pivoted-into mount; every path is keyed beneath it.
fn seal_view_tail(
    view: &ShimView,
    root: &Path,
    stage: &RootDir,
    operator: Option<FsIdentity>,
    root_is_scaffold: bool,
) -> io::Result<()> {
    use kennel_lib_syscall::mount;
    // Name the failing step: the construction child's only failure signal upstream is its exit.
    let step = |what: &str, e: &io::Error| io::Error::new(e.kind(), format!("{what}: {e}"));

    // 4. The constructed /dev, with the per-kennel binderfs.
    seal_dev(view, stage, operator)?;

    // 5. Fresh /proc for the new PID namespace, and the private /tmp.
    let proc = stage
        .ensure(Path::new("/proc"), NodeKind::Directory)
        .map_err(|e| step("/proc", &e))?;
    mount::mount_proc(&proc_path(&proc), view.proc_hidepid).map_err(|e| step("mount /proc", &e))?;
    let tmp = stage
        .ensure(Path::new("/tmp"), NodeKind::Directory)
        .map_err(|e| step("/tmp", &e))?;
    // `/tmp` is the workload's private scratch: a fresh tmpfs, owner-only (0700 — the workload
    // is the sole uid in the kennel), sized by `[fs.tmp].size_mib`. noexec unless the policy
    // opted into executable mappings there (`[fs.tmp].mmap_exec`).
    mount::mount_tmpfs(
        &proc_path(&tmp),
        Some(view.tmp_size_mib),
        Some("0700"),
        false,
        !view.tmp_mmap_exec,
    )
    .map_err(|e| step("mount /tmp tmpfs", &e))?;
    if let ProcView::Curated {
        synthesize,
        passthrough,
    } = &view.proc
    {
        let facts = procfs::ProcFacts::gather()?;
        let proc_mounted = mounted_at(stage, Path::new("/proc"))?;
        // The scratch dir is created and then REMOVED by name, which a descriptor path cannot
        // do. Naming it is safe here: `/tmp` was just checked to be a real directory directly
        // under the root and a fresh tmpfs was mounted on it, so `<root>/tmp/…` is that tmpfs.
        let scratch = root.join("tmp/.kennel-proc");
        procfs::curate(
            &proc_path(&proc_mounted),
            &scratch,
            synthesize,
            passthrough,
            &facts,
        )
        .map_err(|e| step("curate /proc", &e))?;
    }
    // POSIX shared memory (`shm_open`) needs a tmpfs at /dev/shm.
    let dev_shm = stage
        .ensure(Path::new("/dev/shm"), NodeKind::Directory)
        .map_err(|e| step("/dev/shm", &e))?;
    mount::mount_tmpfs(
        &proc_path(&dev_shm),
        Some(view.tmp_size_mib),
        Some("1777"),
        false,
        true,
    )
    .map_err(|e| step("mount /dev/shm tmpfs", &e))?;

    // 6. The home dir (the workload's `$HOME`; `fs.home.persist` sub-paths are already bound).
    stage
        .ensure(&view.shim_root, NodeKind::Directory)
        .map_err(|e| step("home directory", &e))?;

    // 6b. Trust-manifest masks (§7.4 / T2.8), over the manifest paths inside writable binds.
    materialize_masks(&view.mask_paths, stage)?;
    materialize_dir_masks(&view.mask_dir_paths, stage)?;

    // 7. pivot_root into the new root, then detach the old one. `put_old` was just checked to be
    //    a real directory directly under the root, so naming it is safe.
    stage
        .ensure(Path::new("/.kennel-oldroot"), NodeKind::Directory)
        .map_err(|e| step("/.kennel-oldroot", &e))?;
    let put_old = root.join(".kennel-oldroot");
    mount::pivot_root(root, &put_old).map_err(|e| step("pivot_root", &e))?;
    std::env::set_current_dir("/").map_err(|e| step("chdir /", &e))?;
    mount::unmount_detach(Path::new("/.kennel-oldroot"))
        .map_err(|e| step("detach old root", &e))?;

    // The host root is detached. Take root's filesystem identity back and hand the scaffolding
    // built above — as the operator — to the kennel's uid 0, so the workload (the operator's uid)
    // cannot alter it. Each walk stays on one mount we created and never follows a symlink or
    // crosses a mount point, so no bound host inode is touched. The workload's constructed home is
    // left the operator's, as is /tmp (its own mount, not walked).
    fs_as_root(operator)?;
    let _ = std::fs::remove_dir(Path::new("/.kennel-oldroot"));
    let mut scaffolds: Vec<&Path> = vec![Path::new("/dev"), Path::new("/dev/shm")];
    if root_is_scaffold {
        scaffolds.push(Path::new("/"));
    } else {
        // An OCI overlay root keeps its image content; only the dedicated /home tmpfs is ours.
        scaffolds.push(Path::new("/home"));
    }
    for base in scaffolds {
        let skip = view.shim_root.strip_prefix(base).ok();
        kennel_lib_syscall::fd::chown_tree_same_mount(base, 0, 0, skip).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("re-own scaffolding {}: {e}", base.display()),
            )
        })?;
    }
    Ok(())
}

/// What a mount point must be to take a bind of `source`.
fn kind_of(source: &Path) -> NodeKind {
    if source.is_dir() {
        NodeKind::Directory
    } else {
        NodeKind::File
    }
}

/// A handle to `path` **after** something was mounted there.
///
/// A handle taken before the mount names the covered inode; resolving the name again walks onto
/// the mount, which is what a remount or a lookup beneath it has to act on.
fn mounted_at(stage: &RootDir, path: &Path) -> io::Result<std::os::fd::OwnedFd> {
    stage.lookup(path)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} vanished after it was mounted", path.display()),
        )
    })
}

/// Mount the OCI overlay root: `kennel-etc : image : scaffold` over the upper/work pair.
///
/// `layers` are the two scaffolding lowers on the staging tmpfs (`kennel-etc`, then `scaffold`);
/// `upper_work` is the ephemeral pair on that tmpfs, or the persistent store pair.
fn mount_image_overlay(
    img: &crate::plan::ImageRoot,
    layers: [&Path; 2],
    upper_work: (&Path, &Path),
    root: &Path,
    operator: Option<FsIdentity>,
) -> io::Result<()> {
    use crate::plan::Persistence;
    let (upper, work) = upper_work;
    // overlayfs keeps the MOUNTER's credentials and uses them for every later access to the real
    // lower and upper inodes, and it needs them to carry root's filesystem capabilities (its work
    // directory is mode 000). So this one mount must be made as root — which would let a caller
    // who names `/etc` as the upper have root write there on a workload's behalf. Close that by
    // deciding, AS THE OPERATOR, which directories the mount may use, and then mounting those
    // exact inodes by descriptor (no path is resolved again as root):
    //   - the image (a lower, read-only) must be one the operator can read and search, and either
    //     the operator's own or a root-owned directory in a system location (see `image`);
    //   - no directory in the layer stacked above the image may cover an image directory the
    //     operator cannot enter — a merged directory is shown with the top layer's attributes;
    //   - a persistent upper and work dir must be reachable AND owned by the operator, so root's
    //     credentials are only ever exercised inside the operator's own directories.
    // The other layers are on the staging tmpfs built above.
    let owner = operator.map(|op| op.uid);
    let persist = matches!(img.persistence, Persistence::Persist);
    let image = image::image_dir(&img.image, owner, persist)?;
    let image_path = fd_path(&image);
    let [kennel_etc, scaffold] = layers;
    if owner.is_some() {
        image::guard_merges(&image, kennel_etc)?;
    }
    let lowers: [&Path; 3] = [kennel_etc, &image_path, scaffold];
    let (upper_dir, work_dir) = match img.persistence {
        Persistence::Discard => (None, None),
        Persistence::Persist => (
            Some(overlay_dir(upper, owner)?),
            Some(overlay_dir(work, owner)?),
        ),
    };
    let upper_path = upper_dir
        .as_ref()
        .map_or_else(|| upper.to_path_buf(), fd_path);
    let work_path = work_dir
        .as_ref()
        .map_or_else(|| work.to_path_buf(), fd_path);
    fs_as_root(operator)?;
    let mounted =
        kennel_lib_syscall::mount::mount_overlay(&lowers, Some((&upper_path, &work_path)), root);
    fs_as_operator(operator)?;
    mounted.map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("mount overlay (image {}): {e}", img.image.display()),
        )
    })?;
    drop((image, upper_dir, work_dir)); // the mount holds its own references now
    Ok(())
}

/// Open a directory the overlay mount will use, with the CURRENT filesystem identity (the
/// operator's), as an `O_PATH` handle — and, when `owner` is given, require that uid to own it.
///
/// The handle pins the inode the operator's identity resolved, so the mount (made as root, see the
/// call site) cannot be pointed anywhere else. Magic links are refused in the path.
fn overlay_dir(path: &Path, owner: Option<u32>) -> io::Result<std::fs::File> {
    use std::os::unix::fs::MetadataExt as _;
    let fd = kennel_lib_syscall::fd::open_no_magiclinks(path)
        .map_err(|e| io::Error::new(e.kind(), format!("overlay dir {}: {e}", path.display())))?;
    let dir = std::fs::File::from(fd);
    let meta = dir.metadata()?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("overlay dir {} is not a directory", path.display()),
        ));
    }
    if let Some(uid) = owner {
        if meta.uid() != uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "overlay dir {} is owned by uid {}, not the operator ({uid})",
                    path.display(),
                    meta.uid()
                ),
            ));
        }
    }
    Ok(dir)
}

/// The `/proc/self/fd/N` path naming an open descriptor's inode.
fn fd_path(file: &std::fs::File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

/// The operator's filesystem identity, assumed while a kennel's view is built.
///
/// The construction child is the kennel's uid 0, which the `0 0 1` map makes **host root**, and
/// it works on the host filesystem until `pivot_root`. Every path it is given comes from the
/// caller (`kenneld` — or anyone else who runs the helper), and directories a previous workload
/// could write may hold symlinks. So it does not act on those paths as root. It sets its
/// *filesystem* uid and gid to the operator's for the whole build: the kernel then checks every
/// lookup, read, create and overlay access against what the operator may do, and (leaving fsuid 0
/// clears the filesystem capabilities from the effective set) nothing overrides those checks.
/// The helper cannot be made to read or write a file its caller could not. `CAP_SYS_ADMIN` is not
/// a filesystem capability and stays, so the mounts still work.
///
/// Root's identity is taken back only for steps that touch what the factory itself just created:
/// allocating the binder device, and re-owning the scaffolding (after the pivot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsIdentity {
    /// The operator's uid.
    pub uid: u32,
    /// The operator's primary gid.
    pub gid: u32,
}

/// Assume the operator's filesystem identity (a no-op when there is none: the operator is root).
fn fs_as_operator(operator: Option<FsIdentity>) -> io::Result<()> {
    let Some(op) = operator else { return Ok(()) };
    kennel_lib_syscall::unistd::set_fsgid(op.gid)?;
    kennel_lib_syscall::unistd::set_fsuid(op.uid)
}

/// Take root's filesystem identity back (a no-op when it was never dropped).
fn fs_as_root(operator: Option<FsIdentity>) -> io::Result<()> {
    if operator.is_none() {
        return Ok(());
    }
    kennel_lib_syscall::unistd::set_fsuid(0)?;
    kennel_lib_syscall::unistd::set_fsgid(0)
}

/// Bind each granted system/home path into the view. Recursive, so submounts come along;
/// read-only unless the grant is writable (those resolve to the real host inode, the
/// persistence guarantee). `stage` resolves each in-kennel path inside the new root.
///
/// A bind whose **source does not exist** is skipped (skip-missing): a grant for an absent
/// path is vacuous (the Landlock rule is dropped too), and an optional socket shim — e.g. a
/// per-kennel agent not yet launched — must not abort the whole spawn. A read-only bind whose
/// **target already exists** is also skipped: a broader earlier grant (e.g. `/usr/**`) already
/// materialised it at the same host inode, and creating the mountpoint would land *inside* that
/// read-only bind and fail EROFS (the facade binaries under `/usr/libexec/kennel` are exactly
/// this case). A *writable* bind is never skipped — it must override a read-only parent. A
/// *redirected* bind (W15) is never skipped either: its source is a different host inode, so
/// an existing target is the parent's view to over-mount, not redundancy.
///
/// # Errors
///
/// Returns the OS error if creating a mountpoint, the bind mount, or the read-only remount
/// fails for a present, non-redundant bind.
fn materialize_binds(
    binds: &[BindMount],
    stage: &RootDir,
    overlay_root: Option<(&Path, Option<FsIdentity>)>,
) -> io::Result<()> {
    use kennel_lib_syscall::mount;
    for b in binds {
        if !b.source.exists() {
            continue;
        }
        // A read-only, non-redirected grant whose path the view already provides is left alone.
        if !b.writable && !b.redirected && stage.lookup(&b.target)?.is_some() {
            continue;
        }
        // The mount point: the target path itself, resolved inside the new root. A symlink there
        // is refused (it would send the bind elsewhere and leave the path unprotected).
        let want = kind_of(&b.source);
        let place = match (stage.ensure(&b.target, want), overlay_root) {
            // An OCI overlay root's directories belong to the kennel's uid 0, so the operator's
            // identity cannot create a mount point the image does not provide. Create that one
            // path with root's identity — confined to the overlay mount itself, so it can land
            // neither outside the root nor on a host directory already bound into it.
            (Err(e), Some((root, operator))) if e.kind() == io::ErrorKind::PermissionDenied => {
                let rel = b.target.strip_prefix("/").unwrap_or(&b.target);
                fs_as_root(operator)?;
                let made = kennel_lib_syscall::fd::create_in_root_same_mount(
                    root,
                    rel,
                    want == NodeKind::Directory,
                );
                fs_as_operator(operator)?;
                made.and_then(|()| stage.ensure(&b.target, want))
            }
            (result, _) => result,
        }
        .map_err(|e| {
            io::Error::new(e.kind(), format!("bind target {}: {e}", b.target.display()))
        })?;
        let dest = proc_path(&place);
        // Writable binds use RESOLVE_NO_SYMLINKS (via openat2) to prevent
        // source-path symlink aliasing (0.4.0 F1 residual): if any path
        // component is a symlink the bind is refused, so a writable grant
        // cannot be used to write the control socket or any other protected path.
        if b.writable {
            // All bind sources in the plan are absolute.
            let fd = kennel_lib_syscall::fd::open_no_symlinks(&b.source).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "writable bind source {}: {e} (symlink in path? \
                         RESOLVE_NO_SYMLINKS refuses symlink-aliased sources)",
                        b.source.display(),
                    ),
                )
            })?;
            let fd_path = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));
            mount::bind(&fd_path, &dest, true).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("bind {}->{}: {e}", b.source.display(), b.target.display()),
                )
            })?;
            // `fd` is dropped here — after mount::bind has consumed the
            // /proc/self/fd/N path and the bind is in place.
            // #229: a writable bind no longer carries the host mount's exec/suid/dev flags.
            // Harden the whole subtree (submounts too) noexec,nosuid,nodev; a grant that opted
            // into executable mappings keeps exec (nosuid,nodev still apply).
            let mounted = mounted_at(stage, &b.target)?;
            kennel_lib_syscall::namespace::harden_mount_tree(&proc_path(&mounted), b.mmap_exec)
                .map_err(|e| {
                    io::Error::new(e.kind(), format!("harden {}: {e}", b.target.display()))
                })?;
        } else {
            // A *redirected* read-only source (W15) resolves with RESOLVE_NO_MAGICLINKS:
            // the source path is an operator assertion of origin, and a procfs/sysfs magic
            // link in it would alias the bind out of the intended tree. Ordinary symlinks
            // are permitted (operator credential stores are commonly symlink farms). A
            // symmetric read-only bind stays unguarded as before — its source IS the
            // granted path, and read-only aliasing cannot reach a protected write.
            let magic_guard = if b.redirected {
                let fd = kennel_lib_syscall::fd::open_no_magiclinks(&b.source).map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!(
                            "redirected bind source {}: {e} (magic link in path? \
                             RESOLVE_NO_MAGICLINKS refuses procfs/sysfs-aliased sources)",
                            b.source.display(),
                        ),
                    )
                })?;
                Some(fd)
            } else {
                None
            };
            let source = magic_guard.as_ref().map_or_else(
                || b.source.clone(),
                |fd| PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd())),
            );
            mount::bind(&source, &dest, true).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("bind {}->{}: {e}", b.source.display(), b.target.display()),
                )
            })?;
            drop(magic_guard); // the bind is in place; the O_PATH fd has served its purpose
                               // The bind is recursive, so seal recursively: a mount nested in the granted tree
                               // must not stay writable under a read-only grant.
            let mounted = mounted_at(stage, &b.target)?;
            kennel_lib_syscall::namespace::readonly_mount_tree(&proc_path(&mounted)).map_err(
                |e| io::Error::new(e.kind(), format!("remount_ro {}: {e}", b.target.display())),
            )?;
        }
    }
    Ok(())
}

/// Over-mount each workspace trust-manifest path with an empty, read-only file so the
/// confined workload cannot read or forge the integrity pins (§7.4 / T2.8).
///
/// The manifest lives inside a writable bind, so its host inode is otherwise visible to
/// the workload. The mask source is a single empty file created in the root-tmpfs scaffold
/// (`/tmp/.kennel-mask`, outside any bind); it is bind-mounted over each in-view manifest path
/// and remounted read-only. A mask whose target directory is absent is skipped (no writable bind
/// materialised there). A mask path that is a **symlink** is refused: the mask must cover the
/// path itself, so construction fails rather than mount on the link's target.
///
/// # Errors
/// Returns the OS error if creating the scaffold file, a mountpoint, the bind, or the
/// read-only remount fails.
fn materialize_masks(mask_paths: &[PathBuf], stage: &RootDir) -> io::Result<()> {
    use kennel_lib_syscall::mount;
    if mask_paths.is_empty() {
        return Ok(());
    }
    let mask_src = stage.ensure(Path::new("/tmp/.kennel-mask"), NodeKind::File)?;
    for path in mask_paths {
        // No writable bind materialised there: nothing to mask.
        let Some(parent) = path.parent() else {
            continue;
        };
        if !stage.is_dir(parent)? {
            continue;
        }
        // The mask must cover THIS path. A symlink here would send the mount somewhere else and
        // leave the path under the workload's control, so `ensure` refuses one: fail closed.
        let place = stage.ensure(path, NodeKind::File).map_err(|e| {
            io::Error::new(e.kind(), format!("mask target {}: {e}", path.display()))
        })?;
        mount::bind(&proc_path(&mask_src), &proc_path(&place), false)
            .map_err(|e| io::Error::new(e.kind(), format!("mask bind {}: {e}", path.display())))?;
        let mounted = mounted_at(stage, path)?;
        mount::remount_readonly(&proc_path(&mounted)).map_err(|e| {
            io::Error::new(e.kind(), format!("mask remount_ro {}: {e}", path.display()))
        })?;
    }
    Ok(())
}

/// Over-mount each blob-store path with an empty, read-only *directory* so the confined
/// workload cannot read the pinned blobs or write into / create the host store (§2.3 / T2.8).
///
/// The directory analogue of [`materialize_masks`]: one shared empty scaffold directory in
/// the root tmpfs is bound over each in-view `.trust-manifest.d` and remounted read-only, so
/// `readdir` returns nothing and any write is `EROFS`. A path whose parent bind was not
/// materialised (source absent) is skipped.
///
/// # Errors
/// Returns the OS error if creating the scaffold dir, a mountpoint, the bind, or the
/// read-only remount fails.
fn materialize_dir_masks(mask_dir_paths: &[PathBuf], stage: &RootDir) -> io::Result<()> {
    use kennel_lib_syscall::mount;
    if mask_dir_paths.is_empty() {
        return Ok(());
    }
    let mask_src = stage.ensure(Path::new("/tmp/.kennel-mask-d"), NodeKind::Directory)?;
    for path in mask_dir_paths {
        let Some(parent) = path.parent() else {
            continue;
        };
        if !stage.is_dir(parent)? {
            continue;
        }
        // As for the file masks: the mount point is the path itself, never a symlink's target.
        let place = match stage.ensure(path, NodeKind::Directory) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::ReadOnlyFilesystem => continue,
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("store mask target {}: {e}", path.display()),
                ))
            }
        };
        mount::bind(&proc_path(&mask_src), &proc_path(&place), false).map_err(|e| {
            io::Error::new(e.kind(), format!("store mask bind {}: {e}", path.display()))
        })?;
        let mounted = mounted_at(stage, path)?;
        mount::remount_readonly(&proc_path(&mounted)).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("store mask remount_ro {}: {e}", path.display()),
            )
        })?;
    }
    Ok(())
}

/// Recursively copy `src` into `dest` (created if absent), preserving symlinks.
///
/// Used only by the OCI `/etc`-overlay path, where a granted directory (`/etc/fonts`, whose
/// `conf.d` is a farm of symlinks into `conf.avail`) must be copied into the `kennel-etc` overlay
/// lower rather than bind-mounted. Symlinks are recreated verbatim, not followed, so the copied
/// tree matches the source's structure. The ordinary (non-OCI) view binds the directory instead.
fn copy_dir_recursive(src: &Path, dest: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            std::os::unix::fs::symlink(std::fs::read_link(&from)?, &to)?;
        } else if ft.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kennel_lib_policy::{
        CapPolicy, DevPolicy, EffectivePolicy, ExecPolicy, FsPolicy, LifecyclePolicy, NetMode,
        NetPolicy, NetRule, ProcPolicy, Protocol, Provenance, SeccompAction, SeccompPolicy,
        SettledPolicy, SigningKey, TmpPolicy, TtlAction,
    };
    use kennel_lib_syscall::landlock::{AccessFs, AccessNet};
    use kennel_lib_syscall::namespace::Namespaces;
    use kennel_lib_syscall::seccomp::Action;
    use std::path::Path;

    #[allow(clippy::too_many_lines)] // one cohesive SettledPolicy test fixture literal
    fn policy_with_placeholders() -> SettledPolicy {
        SettledPolicy {
            settled_schema_version: kennel_lib_policy::SETTLED_SCHEMA_VERSION,
            name: "ai-coding".to_owned(),
            deferred_substitutions: vec!["<ctx>".to_owned(), "<home>".to_owned()],
            framework_invariants_asserted: Vec::new(),
            effective_policy: EffectivePolicy {
                net: NetPolicy {
                    mode: NetMode::Constrained,
                    udp: false,
                    udp_allow_names: Vec::new(),
                    proxy: kennel_lib_policy::ProxyListen::default(),
                    allow: Vec::new(),
                    allow_names: Vec::new(),
                    deny_invariant: vec![NetRule {
                        cidr: "169.254.169.254".to_owned(),
                        prefix_len: 32,
                        port_min: 0,
                        port_max: 65535,
                        protocol: Protocol::Any,
                    }],
                    deny_author: Vec::new(),
                    // The kernel connect ACL (defence-in-depth in proxied modes; the gate in
                    // host). Two CIDR allows the BPF/Landlock encoding tests verify.
                    bpf_connect_allow: vec![
                        NetRule {
                            cidr: "93.184.216.0".to_owned(),
                            prefix_len: 24,
                            port_min: 443,
                            port_max: 443,
                            protocol: Protocol::Tcp,
                        },
                        NetRule {
                            cidr: "10.1.0.0".to_owned(),
                            prefix_len: 16,
                            port_min: 1024,
                            port_max: 2048,
                            protocol: Protocol::Tcp,
                        },
                    ],
                    bpf_connect_deny: Vec::new(),
                    bpf_bind_allow: Vec::new(),
                    bpf_bind_deny: Vec::new(),
                    bind_port_min: 0,
                    bind_allowed_ports: Vec::new(),
                },
                fs: FsPolicy {
                    home_shadow: true,
                    read: vec!["/usr".to_owned(), "<home>/.config".to_owned()],
                    write: vec!["/run/kennel/<kennel>/home".to_owned()],
                    exclusive: Vec::new(),
                    home_persist: Vec::new(),
                    home_readonly: false,
                    redirect: Vec::new(),
                    write_mmap_exec: Vec::new(),
                    cwd: kennel_lib_policy::settled::CwdPolicy::default(),
                    tmp: TmpPolicy {
                        writable: true,
                        size_mib: 512,
                        mmap_exec: false,
                    },
                    dev: DevPolicy {
                        allow: vec!["/dev/null".to_owned(), "/dev/urandom".to_owned()],
                    },
                },
                exec: ExecPolicy {
                    deny_setuid: true,
                    deny_setgid: true,
                    deny_setcap: true,
                    deny_writable: true,
                    allow: vec!["/usr/bin/python3".to_owned()],
                    deny: Vec::new(),
                    path: Vec::new(),
                    shell: "/bin/sh".to_owned(),
                    loaders: Vec::new(),
                },
                proc: ProcPolicy { hidepid: true },
                cap: CapPolicy { no_new_privs: true },
                seccomp: SeccompPolicy {
                    deny_action: SeccompAction::Errno,
                    deny: vec!["bpf".to_owned(), "userfaultfd".to_owned()],
                },
                lifecycle: LifecyclePolicy {
                    ttl_seconds: None,
                    ttl_action: TtlAction::Warn,
                },
                tty: kennel_lib_policy::TtyPolicy::default(),
                trust: kennel_lib_policy::TrustPolicy::default(),
            },
            spawn: None,
            manifest: Vec::new(),
            provenance: Provenance {
                compiler_version: "0.0.0".to_owned(),
                schema_version: kennel_lib_policy::SETTLED_SCHEMA_VERSION,
                threat_catalogue_version: "0.1".to_owned(),
                resolved_artifacts: Vec::new(),
            },
            ssh: kennel_lib_policy::SshRuntime::default(),
            unix: kennel_lib_policy::UnixRuntime::default(),
            identity: kennel_lib_policy::IdentityRuntime::default(),
            mesh: kennel_lib_policy::MeshRuntime::default(),
            service: None,
            dbus: kennel_lib_policy::DbusRuntime::default(),
            audit: kennel_lib_policy::AuditRuntime::default(),
            env: kennel_lib_policy::EnvRuntime::default(),
            ulimits: kennel_lib_policy::UlimitsRuntime::default(),
            workload: kennel_lib_policy::WorkloadRuntime::default(),
            rootfs: kennel_lib_policy::settled::RootfsRuntime::default(),
        }
    }

    fn subst() -> RuntimeSubstitutions {
        RuntimeSubstitutions {
            ctx: 7,
            uid: 1000,
            kennel: "ai-coding".to_owned(),
            home: PathBuf::from("/home/dev"),
            namespace: "kennel-dev".to_owned(),
        }
    }

    #[test]
    fn substitution_fills_placeholders() {
        let p = substitute(&policy_with_placeholders(), &subst()).expect("substitute");
        assert_eq!(p.identity.user, "kennel");
        assert_eq!(
            p.effective_policy.fs.read,
            vec!["/usr".to_owned(), "/home/dev/.config".to_owned()]
        );
        assert_eq!(
            p.effective_policy.fs.write,
            vec!["/run/kennel/ai-coding/home".to_owned()]
        );
    }

    #[test]
    fn ctx_and_kennel_are_filled_at_spawn() {
        // The deferred placeholders the compiler leaves are filled here from the
        // RuntimeSubstitutions the daemon builds (loopback addressing is v6-only and
        // uid-derived, so there is no `<tag>`/`<gid>` to substitute anymore).
        let mut p = policy_with_placeholders();
        p.env
            .vars
            .insert("LABEL".to_owned(), "kennel-<kennel>-ctx<ctx>".to_owned());
        let out = substitute(&p, &subst()).expect("substitute");
        assert_eq!(
            out.env.vars.get("LABEL").map(String::as_str),
            Some("kennel-ai-coding-ctx7")
        );
    }

    #[test]
    fn user_and_group_are_filled_from_the_masked_identity() {
        // `<user>`/`<group>` resolve to the policy's own [identity], not runtime
        // context: the default is `kennel`, and an override flows through.
        let mut p = policy_with_placeholders();
        p.identity.user = "claude".to_owned();
        p.identity.group = "staff".to_owned();
        p.effective_policy
            .fs
            .read
            .push("/home/<user>/.cache".to_owned());
        p.env
            .vars
            .insert("WHO".to_owned(), "<user>:<group>".to_owned());
        let out = substitute(&p, &subst()).expect("substitute");
        assert!(out
            .effective_policy
            .fs
            .read
            .contains(&"/home/claude/.cache".to_owned()));
        assert_eq!(
            out.env.vars.get("WHO").map(String::as_str),
            Some("claude:staff")
        );
    }

    #[test]
    fn leftover_placeholder_is_rejected() {
        let mut p = policy_with_placeholders();
        p.effective_policy.fs.read.push("<unknown>/x".to_owned());
        let err = substitute(&p, &subst()).expect_err("must reject");
        assert!(
            matches!(&err, SpawnError::UnsubstitutedPlaceholder { field, .. } if field == "fs.read"),
            "got {err:?}"
        );
    }

    #[test]
    fn a_writable_cwd_grant_gets_the_trust_manifest_mask() {
        let masks = |writable: bool, manifest: bool| {
            let p = substitute(&policy_with_placeholders(), &subst()).expect("substitute");
            let mut plan =
                Plan::from_policy(&p, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");
            plan.grant_cwd(PathBuf::from("/work/project"), writable, manifest);
            let view = plan.view.expect("constructed view");
            (
                view.mask_paths
                    .contains(&PathBuf::from("/work/project/.trust-manifest.json")),
                view.mask_dir_paths
                    .contains(&PathBuf::from("/work/project/.trust-manifest.d")),
            )
        };
        // The workload must not read or rewrite the pins of the workspace it is writing in.
        assert_eq!(masks(true, true), (true, true));
        // A read-only cwd carries no manifest; `[trust].manifest = false` opts out.
        assert_eq!(masks(false, true), (false, false));
        assert_eq!(masks(true, false), (false, false));
    }

    #[test]
    fn home_is_writable_by_default_and_readonly_suppresses_the_grant() {
        // shim_root for the default identity (`kennel`).
        let home_root = PathBuf::from("/home/kennel");
        let home_writable = |plan: &Plan| {
            plan.landlock_fs
                .iter()
                .any(|(p, a)| *p == home_root && a.contains(AccessFs::WRITE_FILE))
        };

        let p = substitute(&policy_with_placeholders(), &subst()).expect("substitute");
        let plan = Plan::from_policy(&p, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");
        assert!(
            home_writable(&plan),
            "the constructed home is writable by default"
        );

        let mut ro = policy_with_placeholders();
        ro.effective_policy.fs.home_readonly = true;
        let ro = substitute(&ro, &subst()).expect("substitute");
        let plan = Plan::from_policy(&ro, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");
        assert!(
            !home_writable(&plan),
            "[fs.home].readonly suppresses the home write grant"
        );
    }

    #[test]
    fn a_path_in_both_read_and_write_dedups_to_one_writable_bind() {
        // A path is one bind mount with one mode. The implied rule folds every write path into read,
        // so a writable tree appears in both lists; the plan must collapse it to ONE bind, writable.
        let mut p = policy_with_placeholders();
        p.effective_policy.fs.read = vec![
            "/srv/data/project".to_owned(), // in both → must dedup to one, writable
            "/usr".to_owned(),              // read-only
        ];
        p.effective_policy.fs.write = vec!["/srv/data/project".to_owned()];
        let p = substitute(&p, &subst()).expect("substitute");
        let plan = Plan::from_policy(&p, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");
        let view = plan.view.as_ref().expect("view");

        let project: Vec<&BindMount> = view
            .binds
            .iter()
            .filter(|b| b.source == Path::new("/srv/data/project"))
            .collect();
        assert_eq!(
            project.len(),
            1,
            "the shared path binds exactly once, not twice"
        );
        assert!(
            project.first().expect("one bind").writable,
            "the deduped bind is writable (write wins over read)"
        );

        // /usr (read-only, never in write) stays a single read-only bind.
        let usr: Vec<&BindMount> = view
            .binds
            .iter()
            .filter(|b| b.source == Path::new("/usr"))
            .collect();
        assert_eq!(usr.len(), 1);
        assert!(
            !usr.first().expect("one bind").writable,
            "a read-only path is bound read-only"
        );
    }

    /// A redirected grant (W15) binds the `source` inode at the granted path's view location:
    /// the target, Landlock rule, and `~` remap all key on the granted path; only the bind's
    /// host origin diverges.
    #[test]
    fn a_redirected_grant_binds_the_source_at_the_granted_paths_view_location() {
        let mut p = policy_with_placeholders();
        p.effective_policy
            .fs
            .read
            .push("~/.app/cred.json".to_owned());
        p.effective_policy
            .fs
            .redirect
            .push(kennel_lib_policy::settled::FsRedirect {
                path: "~/.app/cred.json".to_owned(),
                source: "~/stores/acme/cred.json".to_owned(),
            });
        let p = substitute(&p, &subst()).expect("substitute");
        let plan = Plan::from_policy(&p, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");
        let view = plan.view.as_ref().expect("view");
        let bind = view
            .binds
            .iter()
            .find(|b| b.redirected)
            .expect("redirected bind");
        assert_eq!(bind.source, Path::new("/home/dev/stores/acme/cred.json"));
        assert_eq!(bind.target, Path::new("/home/kennel/.app/cred.json"));
        assert!(!bind.writable);

        // The cwd floor helper reports an intersecting directory and clears a disjoint one.
        assert_eq!(
            plan.redirected_source_within(Path::new("/home/dev/stores")),
            Some(Path::new("/home/dev/stores/acme/cred.json"))
        );
        assert_eq!(
            plan.redirected_source_within(Path::new("/home/dev/elsewhere")),
            None
        );
    }

    #[test]
    fn fs_binds_are_ordered_shortest_path_first() {
        // Mount order is by path length so a parent grant lands before a more-specific child.
        let mut p = policy_with_placeholders();
        p.effective_policy.fs.read = vec!["/srv/a/b/c".to_owned(), "/srv".to_owned()];
        p.effective_policy.fs.write = vec!["/srv/a".to_owned()];
        let p = substitute(&p, &subst()).expect("substitute");
        let plan = Plan::from_policy(&p, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");
        let view = plan.view.as_ref().expect("view");
        // The three fs grants, in the order they appear among the binds, are length-ascending.
        let order: Vec<usize> = view
            .binds
            .iter()
            .filter(|b| b.source.starts_with("/srv"))
            .map(|b| b.source.as_os_str().len())
            .collect();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(
            order, sorted,
            "fs binds under /srv are shortest-first: {order:?}"
        );
    }

    #[test]
    fn home_relative_grants_map_to_the_persona_home_not_the_operator_home() {
        // A `~/foo` fs grant + a `~/foo/bin/tool` exec grant both resolve to the in-kennel persona
        // home (/home/kennel/...), never the operator's real home — which must not appear in the
        // plan's targets/Landlock at all. The bind SOURCE is the real host path (that's where the
        // data is); the TARGET the kennel sees is the persona path.
        let mut p = policy_with_placeholders();
        p.effective_policy.fs.read = vec!["~/foo".to_owned()];
        p.effective_policy.fs.write = vec![];
        p.effective_policy.exec.allow = vec!["~/foo/bin/tool".to_owned()];
        p.effective_policy.exec.loaders = vec![];
        // subst() has home = /home/dev (the operator's real home).
        let p = substitute(&p, &subst()).expect("substitute");
        let plan = Plan::from_policy(&p, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");

        // The fs grant binds the real source to the persona target.
        let view = plan.view.as_ref().expect("view");
        let foo = view
            .binds
            .iter()
            .find(|b| b.target == Path::new("/home/kennel/foo"))
            .expect("~/foo binds at the persona home");
        assert_eq!(
            foo.source,
            Path::new("/home/dev/foo"),
            "bound from the real host path"
        );

        // The exec Landlock grant is on the persona path, so it matches what the workload execs.
        assert!(
            plan.landlock_fs
                .iter()
                .any(|(path, a)| path == Path::new("/home/kennel/foo/bin/tool")
                    && a.contains(AccessFs::EXECUTE)),
            "exec.allow ~/foo/bin/tool grants execute on the persona path"
        );

        // The operator's real home appears in NO target or Landlock path (only as a bind source).
        assert!(
            !plan
                .landlock_fs
                .iter()
                .any(|(path, _)| path.starts_with("/home/dev")),
            "the operator home never appears in a Landlock target"
        );
        assert!(
            !view.binds.iter().any(|b| b.target.starts_with("/home/dev")),
            "the operator home never appears as a bind target"
        );
    }

    #[test]
    fn exec_path_and_shell_resolve_tilde_to_the_persona_home() {
        // exec.path/exec.shell are persona STRINGS (the workload's $PATH / $SHELL), not binds:
        // ~ resolves straight to /home/<user>, the path that exists in the view — matching where a
        // ~/.local/bin/* exec.allow grant landed. This is the case that bites real workloads.
        let mut p = policy_with_placeholders();
        p.effective_policy.exec.path = vec!["~/.local/bin".to_owned(), "/usr/bin".to_owned()];
        p.effective_policy.exec.shell = "~/.local/bin/myshell".to_owned();
        // shell must be in allow (translate enforces this on the canonical ~ form).
        p.effective_policy.exec.allow = vec!["~/.local/bin/myshell".to_owned()];
        p.effective_policy.exec.loaders = vec![];
        let p = substitute(&p, &subst()).expect("substitute");

        assert_eq!(
            p.effective_policy.exec.path,
            vec!["/home/kennel/.local/bin".to_owned(), "/usr/bin".to_owned()],
            "exec.path ~ → persona home in $PATH"
        );
        assert_eq!(
            p.effective_policy.exec.shell, "/home/kennel/.local/bin/myshell",
            "exec.shell ~ → persona home"
        );
        // The <home> placeholder in a persona string resolves to the PERSONA home, never the
        // operator's — it must not leak the real home into the workload's $PATH.
        let mut q = policy_with_placeholders();
        q.effective_policy.exec.path = vec!["<home>/bin".to_owned()];
        let q = substitute(&q, &subst()).expect("substitute");
        assert_eq!(
            q.effective_policy.exec.path,
            vec!["/home/kennel/bin".to_owned()],
            "<home> in exec.path → persona home, not the operator home"
        );
        // And the matching exec.allow grant lands on the same persona path (Landlock execute),
        // so the shell the workload runs is the one it's allowed to run.
        let plan = Plan::from_policy(&p, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");
        assert!(
            plan.landlock_fs.iter().any(|(path, a)| path
                == Path::new("/home/kennel/.local/bin/myshell")
                && a.contains(AccessFs::EXECUTE)),
            "the persona shell path carries an execute grant"
        );
    }

    #[test]
    fn every_ulimit_resource_name_maps_to_a_kernel_resource() {
        // Lock-step with the policy crate's accepted names: a name translate admits
        // must resolve to a Resource here, or a valid policy would fail at spawn.
        for name in kennel_lib_policy::ULIMIT_RESOURCES {
            assert!(
                kennel_lib_syscall::process::resource_by_name(name).is_some(),
                "policy accepts ulimit `{name}` but spawn cannot map it"
            );
        }
    }

    #[test]
    fn ulimits_flow_from_policy_into_the_plan() {
        use kennel_lib_syscall::process::{Resource, RLIM_INFINITY};
        let mut p = policy_with_placeholders();
        p.ulimits
            .limits
            .insert("nofile".to_owned(), "8192".to_owned());
        p.ulimits
            .limits
            .insert("cpu".to_owned(), "unlimited".to_owned());
        p.ulimits
            .limits
            .insert("nproc".to_owned(), "256 512".to_owned());
        let p = substitute(&p, &subst()).expect("substitute");
        let plan = Plan::from_policy(&p, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");
        let find = |r: Resource| plan.ulimits.iter().find(|(res, _, _)| *res == r).copied();
        assert_eq!(
            find(Resource::RLIMIT_NOFILE),
            Some((Resource::RLIMIT_NOFILE, 8192, 8192))
        );
        assert_eq!(
            find(Resource::RLIMIT_CPU),
            Some((Resource::RLIMIT_CPU, RLIM_INFINITY, RLIM_INFINITY))
        );
        assert_eq!(
            find(Resource::RLIMIT_NPROC),
            Some((Resource::RLIMIT_NPROC, 256, 512))
        );
    }

    #[test]
    fn plan_translates_policy() {
        let mut p = substitute(&policy_with_placeholders(), &subst()).expect("substitute");
        // The resolved loaders (each binary's PT_INTERP, settled at compile) carry EXECUTE
        // alongside the binaries; libraries do NOT (07-3-exec). Seed one to exercise it.
        p.effective_policy.exec.loaders = vec!["/lib64/ld-linux-x86-64.so.2".to_owned()];
        let plan = Plan::from_policy(&p, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");

        // Namespaces at the plan level: user (the unprivileged foundation) + mount/pid/ipc, plus
        // the per-kennel net-ns (Namespaces::NET) for every mode except `open`. The test policy is
        // `constrained` (proxied), so it gets its own net-ns at the policy→plan translation — the
        // netns decision now lives here, by mode, not bolted on later by kenneld.
        assert_eq!(
            plan.namespaces,
            Namespaces::USER
                | Namespaces::MOUNT
                | Namespaces::PID
                | Namespaces::IPC
                | Namespaces::NET
        );
        assert!(plan.namespaces.contains(Namespaces::NET));

        // cgroup lives under the caller's resource namespace, keyed by ctx.
        assert_eq!(plan.cgroup, PathBuf::from("/sys/fs/cgroup/kennel-dev/7"));
        assert!(plan.cgroup_join, "policy-derived plans enter their cgroup");

        // Landlock with the exec allowlist active (exec.allow is non-empty):
        // a read path is read-only and NOT implicitly executable; the
        // allowlisted binary and its dynamic loader carry EXECUTE; writes
        // carry write access (§7.3).
        assert!(
            plan.landlock_fs
                .iter()
                .any(|(path, acc)| path == &PathBuf::from("/usr")
                    && acc.contains(AccessFs::READ_FILE)
                    && !acc.contains(AccessFs::EXECUTE)),
            "with an exec allowlist, a read path must not be executable"
        );
        assert!(
            plan.landlock_fs
                .iter()
                .any(|(path, acc)| path == &PathBuf::from("/usr/bin/python3")
                    && acc.contains(AccessFs::EXECUTE)),
            "the allowlisted binary gets EXECUTE"
        );
        assert!(
            plan.landlock_fs.iter().any(|(path, acc)| path
                == &PathBuf::from("/lib64/ld-linux-x86-64.so.2")
                && acc.contains(AccessFs::EXECUTE)),
            "the resolved loader (settled exec.loaders) gets EXECUTE"
        );
        assert!(
            !plan
                .landlock_fs
                .iter()
                .any(|(path, acc)| path == &PathBuf::from("/usr/lib")
                    && acc.contains(AccessFs::EXECUTE)),
            "a bare read-grant lib dir is NOT executable — only the binary and its loader are"
        );
        assert!(plan.landlock_fs.iter().any(|(path, acc)| path
            == &PathBuf::from("/run/kennel/ai-coding/home")
            && acc.contains(AccessFs::WRITE_FILE)));
        // The private /tmp is the workload's own scratch: read+write+list, and make-socket — with no
        // ambient network, a local socket/fifo in the writable view is the workload's only IPC.
        assert!(
            plan.landlock_fs
                .iter()
                .any(|(path, acc)| path == &PathBuf::from("/tmp")
                    && acc.contains(AccessFs::WRITE_FILE)
                    && acc.contains(AccessFs::READ_DIR)
                    && acc.contains(AccessFs::MAKE_SOCK)),
            "the private /tmp is writable + listable + socket-bindable"
        );
        // The view root is listable (`ls /`), READ_DIR only.
        assert!(
            plan.landlock_fs
                .iter()
                .any(|(path, acc)| path == &PathBuf::from("/")
                    && acc.contains(AccessFs::READ_DIR)
                    && !acc.contains(AccessFs::READ_FILE)),
            "the view root is listable but not file-readable"
        );

        // Landlock net: EMPTY base in a proxied (constrained) mode — the workload's only
        // reachable destination is the proxy endpoint, granted by `stamp_proxy` (called by
        // kenneld once the address is known), not by the policy's `[net.bpf].connect` rules.
        // The connect ACL is the gate only in `host` mode (covered by a dedicated test).
        assert!(
            plan.landlock_net.is_empty(),
            "constrained mode has no Landlock connect base (proxy endpoint is stamped later)"
        );

        // Seccomp deny names resolved to numbers, in order.
        assert_eq!(
            plan.seccomp_deny,
            vec![
                kennel_lib_syscall::seccomp::syscall_number("bpf").expect("bpf"),
                kennel_lib_syscall::seccomp::syscall_number("userfaultfd").expect("userfaultfd"),
            ]
        );
        assert_eq!(plan.seccomp_deny_action, Action::Errno(1));

        // The filter builds without panicking.
        let _filter = plan.seccomp_filter();

        // BPF egress: in a proxied (constrained) mode the connect-allow BASE is EMPTY — the
        // workload reaches only the proxy endpoint, added by `stamp_proxy` later, never the
        // `[net.bpf].connect` rules directly (a BPF allow is a union; the author cannot widen
        // past the proxy lock — D2). The host-mode path (where the connect ACL IS the gate) is
        // covered by `host_mode_connect_acl_encodes_to_bpf`.
        // The one exception is the kennel's own-net-ns loopback (#218): 127.0.0.0/8 any port,
        // private to this kennel — not a path past the proxy.
        assert_eq!(
            plan.bpf_allow_v4,
            crate::plan::own_netns_loopback(NetMode::Constrained).0,
            "constrained mode's connect-allow base is only the own-net-ns loopback (proxy \
             endpoint stamped later)"
        );
        // deny_invariant 169.254.169.254/32 any-proto is enforced in EVERY mode (deny-first).
        assert_eq!(plan.bpf_deny_v4.len(), 1);
        // meta: magic "KNEL", abi 2, ctx 7.
        let magic = {
            let [m0, m1, m2, m3] = 0x4B4E_454Cu32.to_ne_bytes();
            [m0, m1, m2, m3]
        };
        assert_eq!(plan.bpf_meta.get(0..4), Some(&magic[..]));
        assert_eq!(plan.bpf_meta.get(6), Some(&7u8), "ctx byte");
    }

    #[test]
    fn empty_exec_allowlist_denies_all_execution() {
        // Deny-by-default: with no exec.allow, a read path is NOT executable — nothing
        // runs. (This is what makes a bare `base-confined` a real floor.)
        let mut p = policy_with_placeholders();
        p.effective_policy.exec.allow.clear();
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");
        assert!(
            !plan.landlock_fs.iter().any(
                |(path, acc)| path == &PathBuf::from("/usr") && acc.contains(AccessFs::EXECUTE)
            ),
            "with an empty allowlist, read paths must NOT carry EXECUTE"
        );
    }

    #[test]
    fn permissive_exec_wildcard_restores_executable_reads() {
        // The `**` escape hatch (the `permissive-exec` opt-in) restores the open
        // posture: read paths carry EXECUTE again and no per-binary rule is needed.
        let mut p = policy_with_placeholders();
        p.effective_policy.exec.allow = vec!["**".to_owned()];
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");
        assert!(
            plan.landlock_fs.iter().any(
                |(path, acc)| path == &PathBuf::from("/usr") && acc.contains(AccessFs::EXECUTE)
            ),
            "`**` permissive-exec must keep read paths executable"
        );
    }

    #[test]
    fn exec_allow_under_writable_path_is_rejected_when_deny_writable() {
        // deny_writable (§7.3): refuse to make a writable path executable.
        let mut p = policy_with_placeholders(); // deny_writable = true
        p.effective_policy
            .exec
            .allow
            .push("/run/kennel/<kennel>/home/evil".to_owned());
        let err = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect_err("an allowlisted binary under a writable path must be rejected");
        assert!(matches!(err, SpawnError::InvalidPolicy(_)), "got {err:?}");
    }

    #[test]
    fn glob_grants_bind_the_directory_root() {
        // A `/**` or `/*` read/write/dev grant must bind its real directory root, not
        // the literal glob (which has no inode → ENOENT at mount). Regression for the
        // base-confined `/usr/**` / `/dev/pts/**` spawn failures.
        let mut p = policy_with_placeholders();
        p.effective_policy.fs.read.push("/opt/tools/**".to_owned());
        p.effective_policy.fs.dev.allow = vec!["/dev/pts/**".to_owned()];
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");
        let view = plan
            .view
            .as_ref()
            .expect("a policy-derived plan carries a view");
        assert!(
            view.binds
                .iter()
                .any(|b| b.source == Path::new("/opt/tools")),
            "a `/opt/tools/**` grant binds the stripped root, got {:?}",
            view.binds
                .iter()
                .map(|b| b.source.clone())
                .collect::<Vec<_>>()
        );
        assert!(
            !view
                .binds
                .iter()
                .any(|b| b.source.to_string_lossy().contains('*')),
            "no bind source may contain a glob"
        );
        assert!(
            view.dev_allow.iter().any(|d| d == Path::new("/dev/pts")),
            "a `/dev/pts/**` dev grant strips to /dev/pts, got {:?}",
            view.dev_allow
        );
    }

    #[test]
    fn view_classifies_system_home_and_etc_paths() {
        // System paths bind at their own location (read-only); paths under the
        // real $HOME remap beneath shim_root; /etc is the constructed synthetic
        // set and is never bound from the host (but still gets a Landlock rule).
        let mut p = policy_with_placeholders();
        p.effective_policy.fs.read.push("/etc/ssl".to_owned());
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");
        let view = plan
            .view
            .as_ref()
            .expect("a policy-derived plan carries a view");
        assert_eq!(view.shim_root, PathBuf::from("/home/kennel"));

        assert!(
            view.binds.iter().any(|b| b.source == Path::new("/usr")
                && b.target == Path::new("/usr")
                && !b.writable),
            "system path bound at its own location, read-only"
        );
        assert!(
            view.binds
                .iter()
                .any(|b| b.source == Path::new("/home/dev/.config")
                    && b.target == Path::new("/home/kennel/.config")
                    && !b.writable),
            "home path remapped beneath shim_root"
        );
        assert!(
            !view.binds.iter().any(|b| b.source.starts_with("/etc")),
            "no /etc bind: it is constructed"
        );
        assert!(
            plan.landlock_fs
                .iter()
                .any(|(path, _)| path == &PathBuf::from("/etc/ssl")),
            "the constructed /etc still gets a Landlock rule"
        );
        assert_eq!(
            view.dev_allow,
            vec![PathBuf::from("/dev/null"), PathBuf::from("/dev/urandom")]
        );
        assert!(view.proc_hidepid);
    }

    fn plan_with_reads(reads: &[&str]) -> Result<Plan, SpawnError> {
        let mut p = policy_with_placeholders();
        p.effective_policy
            .fs
            .read
            .retain(|r| !r.starts_with("/proc"));
        p.effective_policy
            .fs
            .read
            .extend(reads.iter().map(|s| (*s).to_owned()));
        Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
    }

    fn proc_rules(plan: &Plan) -> Vec<(PathBuf, AccessFs)> {
        plan.landlock_fs
            .iter()
            .filter(|(p, _)| p.starts_with("/proc"))
            .cloned()
            .collect()
    }

    /// #218: Landlock cannot follow `/proc/self` across processes, so every `/proc` read grant
    /// collapses to ONE read rule on `/proc` itself — the rule that covers every forked child's
    /// own `/proc/self` — and the curated view controls what it exposes.
    #[test]
    fn proc_read_grants_collapse_to_one_rule_on_proc() {
        use kennel_lib_policy::procfs::Synth;
        let plan = plan_with_reads(&[
            "/proc/self/**",
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/proc/stat",
            "/proc/version",
        ])
        .expect("plan");
        assert_eq!(
            proc_rules(&plan),
            vec![(
                PathBuf::from("/proc"),
                AccessFs::READ_FILE | AccessFs::READ_DIR
            )],
            "exactly one read rule, on /proc"
        );
        let view = plan.view.as_ref().expect("view");
        assert_eq!(
            view.proc,
            ProcView::Curated {
                synthesize: vec![Synth::Cpuinfo, Synth::Meminfo, Synth::Stat, Synth::Version],
                passthrough: Vec::new(),
            }
        );
        assert!(
            !view.binds.iter().any(|b| b.target.starts_with("/proc")),
            "/proc is a fresh mount, never a host bind"
        );
    }

    #[test]
    fn a_named_global_proc_entry_passes_through() {
        let plan =
            plan_with_reads(&["/proc/self/**", "/proc/loadavg", "/proc/sys/**"]).expect("plan");
        assert_eq!(
            plan.view.as_ref().expect("view").proc,
            ProcView::Curated {
                synthesize: Vec::new(),
                passthrough: vec!["loadavg".to_owned(), "sys".to_owned()],
            }
        );
        assert_eq!(proc_rules(&plan).len(), 1);
    }

    #[test]
    fn a_whole_proc_grant_serves_the_real_procfs() {
        for g in ["/proc", "/proc/**"] {
            let plan = plan_with_reads(&[g, "/proc/cpuinfo"]).expect("plan");
            assert_eq!(
                plan.view.as_ref().expect("view").proc,
                ProcView::Full,
                "{g}"
            );
            assert_eq!(proc_rules(&plan).len(), 1, "{g}");
        }
    }

    #[test]
    fn no_proc_grant_still_curates_and_grants_no_proc_rule() {
        let plan = plan_with_reads(&[]).expect("plan");
        assert_eq!(
            plan.view.as_ref().expect("view").proc,
            ProcView::Curated {
                synthesize: Vec::new(),
                passthrough: Vec::new(),
            }
        );
        assert!(proc_rules(&plan).is_empty());
    }

    /// The compiler refuses these; the runtime re-check fails closed on a hand-built policy.
    #[test]
    fn a_nested_or_non_canonical_proc_grant_fails_closed() {
        for g in ["/proc/sys/kernel/osrelease", "/proc/../etc"] {
            let r = plan_with_reads(&[g]);
            assert!(
                matches!(&r, Err(SpawnError::InvalidPolicy(m)) if m.contains(g)),
                "{g}: expected InvalidPolicy naming the grant, got {r:?}"
            );
        }
    }

    fn plan_in_mode(mode: NetMode, edit: impl FnOnce(&mut kennel_lib_policy::NetPolicy)) -> Plan {
        let mut p = policy_with_placeholders();
        p.effective_policy.net.mode = mode;
        p.effective_policy.net.bpf_connect_allow.clear();
        p.effective_policy.net.bpf_bind_allow.clear();
        edit(&mut p.effective_policy.net);
        Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan")
    }

    fn tcp_rule(cidr: &str, prefix_len: u8, port_min: u16, port_max: u16) -> NetRule {
        NetRule {
            cidr: cidr.to_owned(),
            prefix_len,
            port_min,
            port_max,
            protocol: Protocol::Tcp,
        }
    }

    /// #218: inside the kennel's OWN network namespace, loopback is the kennel's private `lo`, so
    /// an in-kennel client/server pair (an agent TUI and its server on an ephemeral port) must
    /// meet there by default: `127.0.0.0/8` and `::1` are any-port in BOTH BPF ACLs, and Landlock
    /// handles no TCP right (it cannot express "any port"; BPF is the address+port gate).
    #[test]
    fn own_netns_modes_open_loopback_and_leave_tcp_to_bpf() {
        let (lo_v4, lo_v6) = crate::plan::own_netns_loopback(NetMode::Constrained);
        assert_eq!(
            (lo_v4.len(), lo_v6.len()),
            (1, 1),
            "127.0.0.0/8 and ::1/128"
        );
        for mode in [NetMode::Constrained, NetMode::Unconstrained] {
            let plan = plan_in_mode(mode, |_| {});
            for e in &lo_v4 {
                assert!(
                    plan.bpf_allow_v4.contains(e),
                    "{mode:?}: connect allow 127/8"
                );
                assert!(
                    plan.bpf_bind_allow_v4.contains(e),
                    "{mode:?}: bind allow 127/8"
                );
            }
            for e in &lo_v6 {
                assert!(plan.bpf_allow_v6.contains(e), "{mode:?}: connect allow ::1");
                assert!(
                    plan.bpf_bind_allow_v6.contains(e),
                    "{mode:?}: bind allow ::1"
                );
            }
            assert_eq!(plan.landlock_net_handled, AccessNet::empty(), "{mode:?}");
        }
    }

    /// The loopback entries encode exactly `127.0.0.0/8` and `::1/128`, any port, any protocol,
    /// not the proxy flag.
    #[test]
    fn the_loopback_entries_are_slash_8_and_slash_128_any_port() {
        let (v4, v6) = crate::plan::own_netns_loopback(NetMode::Unconstrained);
        let mut key4 = 8u32.to_ne_bytes().to_vec();
        key4.extend([127, 0, 0, 0]);
        let mut key6 = 128u32.to_ne_bytes().to_vec();
        key6.extend(std::net::Ipv6Addr::LOCALHOST.octets());
        let mut any = 0u16.to_ne_bytes().to_vec();
        any.extend(u16::MAX.to_ne_bytes());
        any.extend([0, 0, 0, 0]);
        assert_eq!(
            v4.iter()
                .map(|(k, e)| (k.to_vec(), e.to_vec()))
                .collect::<Vec<_>>(),
            vec![(key4, any.clone())]
        );
        assert_eq!(
            v6.iter()
                .map(|(k, e)| (k.to_vec(), e.to_vec()))
                .collect::<Vec<_>>(),
            vec![(key6, any)]
        );
    }

    /// `host` shares the HOST's loopback (T1.6): no default opening, and Landlock keeps
    /// gating TCP. `none` leaves `lo` down by design: no opening either.
    #[test]
    fn host_and_none_open_no_loopback_and_keep_landlock_tcp() {
        for mode in [NetMode::Host, NetMode::None] {
            assert_eq!(
                crate::plan::own_netns_loopback(mode),
                (Vec::new(), Vec::new()),
                "{mode:?}"
            );
            let plan = plan_in_mode(mode, |_| {});
            assert_eq!(
                plan.landlock_net_handled,
                AccessNet::BIND_TCP | AccessNet::CONNECT_TCP,
                "{mode:?}"
            );
        }
    }

    /// In `host` mode a port-RANGE allow cannot be a Landlock rule, so that direction stops
    /// being handled (BPF alone gates it) — Landlock must never deny what BPF permits. A
    /// single-port rule keeps the direction handled.
    #[test]
    fn a_host_mode_port_range_unhandles_only_its_direction() {
        let bind_range = plan_in_mode(NetMode::Host, |n| {
            n.bpf_bind_allow.push(tcp_rule("127.0.0.1", 32, 3000, 3999));
        });
        assert_eq!(bind_range.landlock_net_handled, AccessNet::CONNECT_TCP);
        let connect_range = plan_in_mode(NetMode::Host, |n| {
            n.bpf_connect_allow
                .push(tcp_rule("10.0.0.0", 8, 0, u16::MAX));
        });
        assert_eq!(connect_range.landlock_net_handled, AccessNet::BIND_TCP);
        let single = plan_in_mode(NetMode::Host, |n| {
            n.bpf_bind_allow.push(tcp_rule("127.0.0.1", 32, 3000, 3000));
            n.bpf_connect_allow.push(tcp_rule("10.0.0.0", 8, 443, 443));
        });
        assert_eq!(
            single.landlock_net_handled,
            AccessNet::BIND_TCP | AccessNet::CONNECT_TCP
        );
    }

    /// The restriction tooling still works over the open default: an author `[net.bpf]` deny on
    /// loopback lands in the deny tries, which both BPF decisions consult FIRST.
    #[test]
    fn an_author_loopback_deny_still_lands_in_the_deny_tries() {
        let plan = plan_in_mode(NetMode::Constrained, |n| {
            n.bpf_connect_deny
                .push(tcp_rule("127.0.0.0", 8, 0, u16::MAX));
            n.bpf_bind_deny.push(tcp_rule("127.0.0.1", 32, 0, u16::MAX));
        });
        let mut connect_key = 8u32.to_ne_bytes().to_vec();
        connect_key.extend([127, 0, 0, 0]);
        let mut bind_key = 32u32.to_ne_bytes().to_vec();
        bind_key.extend([127, 0, 0, 1]);
        assert!(plan
            .bpf_deny_v4
            .iter()
            .any(|(k, _)| k.to_vec() == connect_key));
        assert!(plan
            .bpf_bind_deny_v4
            .iter()
            .any(|(k, _)| k.to_vec() == bind_key));
    }

    /// `[fs.tmp] mmap_exec` reaches the view (#218), and `/tmp` stays `noexec` by default.
    #[test]
    fn tmp_mmap_exec_reaches_the_view() {
        for on in [false, true] {
            let mut p = policy_with_placeholders();
            p.effective_policy.fs.tmp.mmap_exec = on;
            let plan = Plan::from_policy(
                &substitute(&p, &subst()).expect("subst"),
                7,
                "kennel-dev",
                Path::new("/home/dev"),
            )
            .expect("plan");
            assert_eq!(plan.view.as_ref().expect("view").tmp_mmap_exec, on);
        }
    }

    /// #229: only the writable grants listed in `write_mmap_exec` keep executable mappings;
    /// every other writable bind (and every read-only one) carries `mmap_exec = false`.
    #[test]
    fn write_mmap_exec_marks_only_its_writable_binds() {
        let mut p = policy_with_placeholders();
        p.effective_policy.fs.write = vec!["/srv/proj/**".to_owned(), "/srv/other".to_owned()];
        p.effective_policy.fs.write_mmap_exec = vec!["/srv/proj/**".to_owned()];
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");
        let view = plan.view.as_ref().expect("view");
        let flag = |t: &str| {
            view.binds
                .iter()
                .find(|b| b.target == Path::new(t))
                .map(|b| (b.writable, b.mmap_exec))
        };
        assert_eq!(flag("/srv/proj"), Some((true, true)));
        assert_eq!(flag("/srv/other"), Some((true, false)));
        assert!(view
            .binds
            .iter()
            .filter(|b| !b.writable)
            .all(|b| !b.mmap_exec));
    }

    /// Regression (#229 e2e): a `~/` opt-out must survive spawn-time substitution exactly like
    /// its `fs.write` grant, or the two never match and the bind silently stays noexec.
    #[test]
    fn a_home_relative_write_mmap_exec_survives_substitution() {
        let mut p = policy_with_placeholders();
        p.effective_policy.fs.write = vec!["~/proj/**".to_owned(), "~/other".to_owned()];
        p.effective_policy.fs.write_mmap_exec = vec!["~/proj/**".to_owned()];
        let substituted = substitute(&p, &subst()).expect("subst");
        assert_eq!(
            substituted.effective_policy.fs.write_mmap_exec,
            substituted
                .effective_policy
                .fs
                .write
                .iter()
                .filter(|w| w.ends_with("/proj/**"))
                .cloned()
                .collect::<Vec<_>>(),
            "substituted identically to its fs.write grant"
        );
        let plan =
            Plan::from_policy(&substituted, 7, "kennel-dev", Path::new("/home/dev")).expect("plan");
        let view = plan.view.as_ref().expect("view");
        let marked: Vec<_> = view
            .binds
            .iter()
            .filter(|b| b.mmap_exec)
            .map(|b| b.source.clone())
            .collect();
        assert_eq!(
            marked,
            vec![PathBuf::from("/home/dev/proj")],
            "{:?}",
            view.binds
        );
    }

    #[test]
    fn dev_nodes_get_landlock_read_write_ioctl() {
        // Allowlisted devices are Landlock-granted read+write+ioctl (so device
        // ioctls work on them), not merely made visible in the constructed /dev.
        let plan = Plan::from_policy(
            &substitute(&policy_with_placeholders(), &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");
        let want = AccessFs::READ_FILE | AccessFs::WRITE_FILE | AccessFs::IOCTL_DEV;
        for dev in ["/dev/null", "/dev/urandom"] {
            assert!(
                plan.landlock_fs
                    .iter()
                    .any(|(p, a)| p == Path::new(dev) && *a == want),
                "{dev} should carry a read+write+ioctl Landlock rule"
            );
        }
    }

    #[test]
    fn writable_home_grant_binds_to_the_persistent_host_path() {
        // The work an agent writes must outlive the kennel: a writable grant under
        // the real $HOME binds onto the real host inode, not the ephemeral tmpfs.
        let mut p = policy_with_placeholders();
        p.effective_policy
            .fs
            .write
            .push("<home>/projects/foo".to_owned());
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");
        let view = plan.view.as_ref().expect("view");
        let bind = view
            .binds
            .iter()
            .find(|b| b.target == Path::new("/home/kennel/projects/foo"))
            .expect("remapped writable bind");
        assert_eq!(
            bind.source,
            PathBuf::from("/home/dev/projects/foo"),
            "writes resolve to the persistent host path"
        );
        assert!(bind.writable);
    }

    #[test]
    fn from_policy_rejects_dev_paths_that_escape_dev() {
        for bad in ["/etc/shadow", "/dev/../etc/shadow", "/dev"] {
            let mut p = policy_with_placeholders();
            p.effective_policy.fs.dev.allow = vec![bad.to_owned()];
            let err = Plan::from_policy(
                &substitute(&p, &subst()).expect("subst"),
                7,
                "kennel-dev",
                Path::new("/home/dev"),
            )
            .expect_err("must reject");
            assert!(
                matches!(err, SpawnError::InvalidPolicy(_)),
                "{bad} should be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn v6_rules_encode_to_lpm_v6() {
        // host mode: the `[net.bpf].connect` allowlist IS the egress gate, so its rules encode
        // into the BPF allow maps (in proxied modes that base is empty — see plan_translates_policy).
        let mut p = policy_with_placeholders();
        p.effective_policy.net.mode = NetMode::Host;
        p.effective_policy.net.bpf_connect_allow.push(NetRule {
            cidr: "2606:2800:220::".to_owned(),
            prefix_len: 48,
            port_min: 443,
            port_max: 443,
            protocol: Protocol::Tcp,
        });
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");

        // The two fixture rules stay v4; the new one lands in v6.
        assert_eq!(plan.bpf_allow_v4.len(), 2);
        assert_eq!(plan.bpf_allow_v6.len(), 1);
        let (key, value) = plan.bpf_allow_v6.first().expect("v6 entry");
        // lpm_v6_key: prefixlen (4 bytes) then the 16 address octets.
        assert_eq!(key.get(0..4), Some(&48u32.to_ne_bytes()[..]));
        let octets = "2606:2800:220::"
            .parse::<std::net::Ipv6Addr>()
            .expect("v6")
            .octets();
        assert_eq!(key.get(4..20), Some(&octets[..]));
        let want_val = {
            let [a, b] = 443u16.to_ne_bytes();
            [a, b, a, b, 6, 0, 0, 0]
        };
        assert_eq!(value, &want_val);
    }

    #[test]
    fn host_mode_connect_acl_encodes_to_bpf_and_landlock() {
        // host mode: [net.bpf].connect is the egress gate. Author allow → BPF allow + Landlock
        // CONNECT_TCP (single-port); author deny → BPF deny (deny-first, alongside the invariant
        // floor). This is the gate that makes "deny 10/8 + allow *:443" hold on the host stack.
        let mut p = policy_with_placeholders();
        p.effective_policy.net.mode = NetMode::Host;
        // allow *:443 already present in the fixture (93.184.216.0/24:443 single-port); add an
        // author deny for a CIDR to prove deny-first encoding.
        p.effective_policy.net.bpf_connect_deny.push(NetRule {
            cidr: "10.0.0.0".to_owned(),
            prefix_len: 8,
            port_min: 0,
            port_max: 65535,
            protocol: Protocol::Any,
        });
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");

        // The two fixture connect-allow rules encode (host = the gate).
        assert_eq!(
            plan.bpf_allow_v4.len(),
            2,
            "host connect-allow encodes to BPF"
        );
        // The single-port (443) TCP rule maps to a Landlock CONNECT_TCP grant; the 1024-2048
        // range is left to BPF (Landlock has no range).
        assert_eq!(plan.landlock_net, vec![(443u16, AccessNet::CONNECT_TCP)]);
        // deny = invariant floor (169.254.169.254) + the author 10/8 deny, both deny-first.
        assert_eq!(
            plan.bpf_deny_v4.len(),
            2,
            "invariant + author deny both encode"
        );
    }

    #[test]
    fn bind_acl_encodes_author_rules_and_landlock() {
        // §7.5.7 inbound BIND ACL, deny-first + default-deny. from_policy must:
        //   (1) encode the author's [net.bpf].bind.allow as bind-allow + a Landlock BIND_TCP
        //       grant per single port;
        //   (2) encode the author's [net.bpf].bind.deny as bind-deny (deny-first, wins).
        // The kennel's own loopback /28 seed is added by stamp_proxy (it needs the spawn-time
        // loopback address); that path is covered separately below.
        let mut p = policy_with_placeholders();
        // Author allows binding 0.0.0.0/0 on 8080 (any addr, that port) and denies one host.
        p.effective_policy.net.bpf_bind_allow = vec![NetRule {
            cidr: "0.0.0.0".to_owned(),
            prefix_len: 0,
            port_min: 8080,
            port_max: 8080,
            protocol: Protocol::Tcp,
        }];
        p.effective_policy.net.bpf_bind_deny = vec![NetRule {
            cidr: "127.0.0.9".to_owned(),
            prefix_len: 32,
            port_min: 0,
            port_max: 65535,
            protocol: Protocol::Any,
        }];
        let plan = Plan::from_policy(
            &substitute(&p, &subst()).expect("subst"),
            7,
            "kennel-dev",
            Path::new("/home/dev"),
        )
        .expect("plan");

        // (1) the author allow encodes to a single bind-allow v4 entry, beside the own-net-ns
        // loopback seed (#218; the /28 own-subnet seed comes later, with the stamp).
        let lo = crate::plan::own_netns_loopback(NetMode::Constrained).0;
        assert_eq!(
            plan.bpf_bind_allow_v4.len(),
            1 + lo.len(),
            "author bind.allow 0.0.0.0/0:8080 encodes to one bind-allow entry, got {}",
            plan.bpf_bind_allow_v4.len()
        );
        assert!(lo.iter().all(|e| plan.bpf_bind_allow_v4.contains(e)));
        // (1b) the single-port author allow maps to a Landlock BIND_TCP grant on 8080.
        assert!(
            plan.landlock_net
                .iter()
                .any(|(port, a)| *port == 8080 && a.contains(AccessNet::BIND_TCP)),
            "author bind.allow :8080 → Landlock BIND_TCP, got {:?}",
            plan.landlock_net
        );
        // (2) the author deny encodes deny-first.
        assert_eq!(
            plan.bpf_bind_deny_v4.len(),
            1,
            "author bind.deny 127.0.0.9/32 encodes to bind-deny"
        );
    }

    #[test]
    fn stamp_proxy_seeds_the_loopback_28_into_bind_allow() {
        // A proxied kennel rewrites a wildcard bind to its own loopback and allows in-subnet
        // binds; stamp_proxy seeds that /28 into bind-allow so those binds pass the (default-deny)
        // ACL without the author writing a rule. The seed address is the proxy endpoint's v4.
        let plan = fixture_plan(); // constrained, from the shared fixture
        let before = plan.bpf_bind_allow_v4.len();
        let mut plan = plan;
        let v4 = std::net::Ipv4Addr::new(127, 2, 160, 16);
        plan.stamp_proxy(&ProxyEndpoint {
            v4: Some(v4),
            v6: std::net::Ipv6Addr::LOCALHOST,
            port: 1080,
        });
        // Exactly one new bind-allow entry: a /28 on the proxy endpoint's v4 (the loopback subnet).
        assert_eq!(
            plan.bpf_bind_allow_v4.len(),
            before + 1,
            "stamp_proxy adds one /28 bind-allow seed"
        );
        let is_loopback_28 = |(k, _): &([u8; 8], [u8; 8])| {
            let prefix = u32::from_ne_bytes([k[0], k[1], k[2], k[3]]);
            prefix == 28 && k.get(4..8) == Some(&v4.octets()[..])
        };
        assert!(
            plan.bpf_bind_allow_v4.iter().any(is_loopback_28),
            "the proxy endpoint's /28 is seeded into bind-allow"
        );
        // Intra-kennel loopback connects (facade-client → the workload's mirrored listener, §7.5.7)
        // pass the connect ACL via a single any-port /32 on the kennel's own loopback (not a /28 —
        // a /32 wins LPM cleanly without a port-restricted entry shadowing the mirror ports).
        let connect_has_own_loopback = plan.bpf_allow_v4.iter().any(|(k, val)| {
            let prefix = u32::from_ne_bytes([k[0], k[1], k[2], k[3]]);
            // any-port: port_max (bytes 2..4 of the value) is u16::MAX.
            prefix == 32
                && k.get(4..8) == Some(&v4.octets()[..])
                && val.get(2..4) == Some(&[0xff, 0xff][..])
        });
        assert!(
            connect_has_own_loopback,
            "the kennel's own loopback /32 (any port) is in connect-allow"
        );
    }

    /// A plan with two v4 allow rules and one deny, from the shared fixture.
    fn fixture_plan() -> Plan {
        let p = substitute(&policy_with_placeholders(), &subst()).expect("substitute");
        Plan::from_policy(&p, 7, "kennel-dev", Path::new("/home/dev")).expect("plan")
    }

    #[test]
    fn stamp_proxy_writes_meta_proxy_fields() {
        let mut plan = fixture_plan();
        let v4: std::net::Ipv4Addr = "127.0.144.1".parse().expect("v4");
        let v6: std::net::Ipv6Addr = "fd00:0:0:42::1".parse().expect("v6");
        plan.stamp_proxy(&ProxyEndpoint {
            v4: Some(v4),
            v6,
            port: 1080,
        });

        // proxy_addr_v4 @8 (network order = the octets).
        assert_eq!(plan.bpf_meta.get(8..12), Some(&v4.octets()[..]));
        // proxy_port @12 (network order).
        assert_eq!(plan.bpf_meta.get(12..14), Some(&1080u16.to_be_bytes()[..]));
        // _pad0 @14 stays zero.
        assert_eq!(plan.bpf_meta.get(14..16), Some(&[0u8, 0][..]));
        // proxy_addr_v6 @16.
        assert_eq!(plan.bpf_meta.get(16..32), Some(&v6.octets()[..]));
        // The magic/abi/ctx head is untouched.
        assert_eq!(plan.bpf_meta.get(6), Some(&7u8), "ctx byte preserved");
    }

    #[test]
    fn stamp_proxy_adds_a_flagged_allow_entry_v4_and_v6() {
        let mut plan = fixture_plan();
        let before_v4 = plan.bpf_allow_v4.len();
        let before_v6 = plan.bpf_allow_v6.len();
        let v4: std::net::Ipv4Addr = "127.0.144.1".parse().expect("v4");
        let v6: std::net::Ipv6Addr = "fd00:0:0:42::1".parse().expect("v6");
        plan.stamp_proxy(&ProxyEndpoint {
            v4: Some(v4),
            v6,
            port: 1080,
        });

        // One entry appended to each connect trie: a single /32 (v4) / /128 (v6) on the kennel's
        // own loopback with ANY port and the FLAG_PROXY marker. It covers both the workload's
        // connect to the proxy port AND facade-client's connect to the mirrored ports (§7.5.7) —
        // one /32 wins LPM cleanly, no port-restricted entry to shadow the mirror.
        assert_eq!(plan.bpf_allow_v4.len(), before_v4 + 1);
        assert_eq!(plan.bpf_allow_v6.len(), before_v6 + 1);

        // v4 entry: /32 host key + the any-port FLAG_PROXY allow_entry.
        let want_key_v4 = {
            let [p0, p1, p2, p3] = 32u32.to_ne_bytes();
            let [o0, o1, o2, o3] = v4.octets();
            [p0, p1, p2, p3, o0, o1, o2, o3]
        };
        let want_val = {
            let [lo, hi] = u16::MAX.to_ne_bytes();
            [0, 0, lo, hi, 0, 0x01, 0, 0] // port_min 0, port_max 65535, proto ANY, FLAG_PROXY
        };
        assert!(
            plan.bpf_allow_v4.contains(&(want_key_v4, want_val)),
            "the any-port /32 own-loopback connect entry is present"
        );

        // v6 entry: /128 host key + the same any-port flagged value.
        let (key_v6, val_v6) = plan
            .bpf_allow_v6
            .iter()
            .find(|(_, v)| v == &want_val)
            .expect("v6 own-loopback entry");
        assert_eq!(key_v6.get(0..4), Some(&128u32.to_ne_bytes()[..]));
        assert_eq!(key_v6.get(4..20), Some(&v6.octets()[..]));
        assert_eq!(val_v6, &want_val);
    }

    #[test]
    fn stamp_proxy_grants_landlock_connect_on_the_proxy_port() {
        // Landlock always handles net (TCP connect is denied except to listed ports). The workload
        // reaches facade-socks5 at the proxy port, so stamping the proxy must add a CONNECT_TCP
        // grant for it — else the in-net-ns connect to the egress endpoint is Landlock-denied.
        use kennel_lib_syscall::landlock::AccessNet;
        let mut plan = fixture_plan();
        assert!(
            !plan.landlock_net.iter().any(|(p, _)| *p == 1080),
            "fixture has no 1080 grant before stamping"
        );
        plan.stamp_proxy(&ProxyEndpoint {
            v4: Some("127.0.144.1".parse().expect("v4")),
            v6: "fd00:0:0:42::1".parse().expect("v6"),
            port: 1080,
        });
        assert!(
            plan.landlock_net.contains(&(1080, AccessNet::CONNECT_TCP)),
            "the proxy port carries a Landlock CONNECT_TCP grant"
        );
        // Idempotent: stamping again does not duplicate the grant.
        plan.stamp_proxy(&ProxyEndpoint {
            v4: Some("127.0.144.1".parse().expect("v4")),
            v6: "fd00:0:0:42::1".parse().expect("v6"),
            port: 1080,
        });
        assert_eq!(
            plan.landlock_net.iter().filter(|(p, _)| *p == 1080).count(),
            1,
            "no duplicate grant on re-stamp"
        );
    }

    #[test]
    fn stamp_proxy_v6_only_kennel_skips_v4() {
        let mut plan = fixture_plan();
        let before_v4 = plan.bpf_allow_v4.len();
        let v6: std::net::Ipv6Addr = "fd00:0:0:42::1".parse().expect("v6");
        plan.stamp_proxy(&ProxyEndpoint {
            v4: None,
            v6,
            port: 1080,
        });

        // No v4 entry added, and proxy_addr_v4 in meta stays zero.
        assert_eq!(plan.bpf_allow_v4.len(), before_v4, "no v4 proxy entry");
        assert_eq!(plan.bpf_meta.get(8..12), Some(&[0u8, 0, 0, 0][..]));
        // The v6 entry and meta are still stamped.
        assert_eq!(plan.bpf_meta.get(16..32), Some(&v6.octets()[..]));
        assert_eq!(plan.bpf_meta.get(12..14), Some(&1080u16.to_be_bytes()[..]));
    }

    #[test]
    fn prepare_end_to_end_from_signed_bytes() {
        // Sign the policy, then run the full runtime entry point over its bytes.
        let key = SigningKey::from_seed("k", &[3u8; 32]).expect("seed");
        let doc = kennel_lib_policy::sign_settled(&policy_with_placeholders(), &key).expect("sign");
        let bytes = kennel_lib_policy::to_bytes(&doc).expect("bytes");
        let mut ks = KeySet::new();
        ks.insert("k", &key.public_key_bytes()).expect("insert");

        let plan = prepare(&bytes, &ks, &subst()).expect("prepare");
        assert_eq!(plan.cgroup, PathBuf::from("/sys/fs/cgroup/kennel-dev/7"));
        assert_eq!(plan.seccomp_deny.len(), 2, "bpf + userfaultfd resolved");
    }

    #[test]
    fn prepare_rejects_bad_signature() {
        let key = SigningKey::from_seed("k", &[3u8; 32]).expect("seed");
        let doc = kennel_lib_policy::sign_settled(&policy_with_placeholders(), &key).expect("sign");
        let bytes = kennel_lib_policy::to_bytes(&doc).expect("bytes");
        let empty = KeySet::new(); // no trusted keys
        let err = prepare(&bytes, &empty, &subst()).expect_err("must reject");
        assert!(matches!(err, SpawnError::Policy(_)), "got {err:?}");
    }
}
