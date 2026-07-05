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
//! This crate is the pure half: verify → substitute → translate the signed policy into a
//! [`Plan`] and a [`ConstructionHalf`]/[`Supervision`] pair, all testable off the spawn path.
//! Execution is the privhelper **factory**: it clones the namespaces, writes the identity maps,
//! builds the constructed view (`build_view_and_pivot`), and `fexecve`s `kennel-bin-init` as the
//! kennel's uid-0 PID 1, which applies the irreversible seal (Landlock + seccomp + cgroup join)
//! before running the workload. The post-`fork` `unsafe` lives in `kennel-lib-syscall`; egress BPF
//! is attached in the same factory op. The root e2e exercises the whole vertical.

#![forbid(unsafe_code)]

pub mod mesh_rendezvous;
pub mod plan;
pub mod wire;

use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use kennel_lib_policy::{KeySet, PolicyError, SettledPolicy};
use kennel_lib_syscall::landlock::{AccessFs, AccessNet, Ruleset};

pub use plan::{
    AuxProcess, BindMount, ConstructionHalf, ImageRoot, LoopbackAddr, Persistence, Plan,
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
    skip_missing: bool,
) -> io::Result<Ruleset> {
    let mut ruleset = Ruleset::new()?;
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
) -> io::Result<()> {
    use kennel_lib_syscall::mount;

    // OCI substrate root (§7.11.4a / T3.8): boot the image as a layered overlay
    // (kennel-etc : image : scaffold) instead of a constructed tmpfs. Distinct head
    // (no host-closure mirror, /etc wins by layer precedence), shared seal tail.
    if let Some(img) = &view.image {
        return build_image_view_and_pivot(view, new_root, img, file_binds);
    }

    // Map an absolute in-kennel path to its staging location under `new_root`.
    let under = |abs: &Path| new_root.join(abs.strip_prefix("/").unwrap_or(abs));

    // 1. The new root: a fresh tmpfs (scaffolding only; bound content is host-backed).
    mount::mount_special("tmpfs", new_root).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("mount tmpfs new_root {}: {e}", new_root.display()),
        )
    })?;

    // 2. Bind the granted system + home paths in.
    materialize_binds(&view.binds, &under)?;

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
        let dest = under(&host);
        if dest.symlink_metadata().is_ok() {
            continue; // already present (e.g. bound in by a grant)
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::os::unix::fs::symlink(&target, &dest)?;
    }

    // 3. The synthetic /etc: a fresh dir in the root tmpfs populated with the
    //    staged vanilla files. The host /etc is never bound in (it carries host
    //    specifics). Writes are denied by the Landlock read grant on /etc.
    let etc = under(Path::new("/etc"));
    std::fs::create_dir_all(&etc)?;
    for (source, target) in file_binds {
        let dest = under(target);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(source, &dest)?;
    }

    // 3b. `/etc` overlays: bind the granted real host `/etc` files read-only ON TOP of the
    //     synthetic floor just built (the resolver/hosts a `net.mode = host` service needs). The
    //     synthetic `/etc` is the floor; an explicit `fs.read` grant layers the real file over it.
    materialize_etc_overlays(&view.etc_overlays, &under)?;

    // 4–7. The seal tail (constructed /dev, binderfs, /proc, /tmp, home, masks, pivot).
    seal_view_tail(view, new_root)
}

/// Bind each granted host `/etc` file read-only over the synthetic `/etc` floor (the real resolver
/// config / hosts a `net.mode = host` service resolves real names against, §8 / W2).
///
/// The synthetic `/etc` is built first (a floor of scrubbed files); this layers the real host path
/// on top of the specific entries the policy granted — a **file** (`/etc/resolv.conf`) or a whole
/// **directory** (`/etc/fonts`, `/etc/ssl/certs` — fontconfig and the CA bundle a GUI or TLS client
/// needs). Each `path` is the same on the host and in the view. A path whose host source does not
/// exist is skipped (nothing to overlay). The overlay set is already restricted to safe entries
/// ([`crate::plan`] never emits an identity-mask or credential path), so this trusts its input.
///
/// # Errors
/// The OS error if creating the target mountpoint, the bind, or the read-only remount fails.
fn materialize_etc_overlays(
    overlays: &[std::path::PathBuf],
    under: &impl Fn(&Path) -> PathBuf,
) -> io::Result<()> {
    use kennel_lib_syscall::mount;
    for path in overlays {
        // The host source (still reachable pre-pivot). Skip a grant whose host file is absent.
        if path.symlink_metadata().is_err() {
            continue;
        }
        let dest = under(path);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Ensure a mountpoint of the RIGHT TYPE exists to bind over: a directory for a
        // directory source (`/etc/fonts`, `/etc/ssl/certs`), an empty file otherwise
        // (`/etc/resolv.conf`, `/etc/hosts`). Binding a directory onto a file target — or a
        // file onto a directory — fails ENOTDIR/EISDIR, so the placeholder must match the
        // source. An existing synthetic-floor entry is left as-is (already the right kind).
        if dest.symlink_metadata().is_err() {
            if path.is_dir() {
                std::fs::create_dir_all(&dest)?;
            } else {
                std::fs::File::create(&dest)?;
            }
        }
        mount::bind(path, &dest, false).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("etc overlay bind {}: {e}", dest.display()),
            )
        })?;
        mount::remount_readonly(&dest).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("etc overlay remount_ro {}: {e}", dest.display()),
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
    let ketc = kennel_etc.join("etc");
    std::fs::create_dir_all(&ketc)?;
    for (source, target) in file_binds {
        let dest = kennel_etc.join(target.strip_prefix("/").unwrap_or(target));
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(source, &dest)?;
    }
    // `/etc` overlays (W2): copy the granted REAL host `/etc` file over the synthetic one in the
    // top `kennel-etc` lower, so the real resolver/hosts wins by overlay precedence (the bind-based
    // equivalent of the ordinary view's on-top overlay; the overlayfs upper is where precedence
    // lives here). A grant whose host source is absent is skipped.
    for overlay in &view.etc_overlays {
        if overlay.symlink_metadata().is_err() {
            continue;
        }
        let dest = kennel_etc.join(overlay.strip_prefix("/").unwrap_or(overlay));
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(overlay, &dest)?;
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
    let lowers: [&Path; 3] = [&kennel_etc, &img.image, &scaffold];
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
    mount::mount_overlay(&lowers, Some((&upper, &work)), &root).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("mount overlay (image {}): {e}", img.image.display()),
        )
    })?;

    // 5. A writable, ephemeral $HOME independent of the rootfs closure-lock: a tmpfs at `/home`
    //    (the scaffold supplies the mountpoint), so the persona home works even when the rootfs
    //    is `readonly = ["/"]`. `[fs.home].persist` paths bind on top via `view.binds`.
    let under = |abs: &Path| root.join(abs.strip_prefix("/").unwrap_or(abs));
    let home = under(Path::new("/home"));
    mount::mount_tmpfs(&home, None, Some("0755"), false, true)?;

    // 6. Assembly (§7.11.4a): bind the granted ~/ + launcher + config + additive binds. `/etc` is
    //    writable-through (§7.11.4c) — the `kennel-etc` lower sets the defaults and a workload may
    //    copy-up-shadow them in its own upper, harming only its own view; enforcement is the
    //    netns/BPF/uid-map/Landlock/seccomp, never file content, so nothing is ro-bound here.
    materialize_binds(&view.binds, &under)?;

    // 7. Closure-lock (§7.11.4c): lock the executable closure as **read-only mounts** — Landlock
    //    rights are additive (the `/` write grant cannot be subtracted at `/usr`), so the lock is a
    //    mount, robust against the persona workload (no `CAP_SYS_ADMIN` to remount, `mount`
    //    seccomp-blocked). The `writable` carve-outs bind FIRST (a fresh RW bind of the writable
    //    overlay inode at the deeper mountpoint), so a later read-only remount of the enclosing
    //    `readonly` path does not touch them — the deeper mount serves its own subtree.
    for w in &img.writable {
        let target = under(w);
        if target.exists() {
            mount::bind(&target, &target, false).map_err(|e| {
                io::Error::new(e.kind(), format!("writable carve-out {}: {e}", w.display()))
            })?;
        }
    }
    for ro in &img.readonly {
        let target = under(ro);
        if target.exists() {
            mount::bind(&target, &target, true)
                .and_then(|()| mount::remount_readonly(&target))
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("closure-lock ro mount {}: {e}", ro.display()),
                    )
                })?;
        }
    }

    // 8. The seal tail (constructed /dev, binderfs, /proc, /tmp, home dir, masks, pivot).
    seal_view_tail(view, &root)
}

/// The seal tail shared by [`build_view_and_pivot`]'s constructed-tmpfs head and
/// [`build_image_view_and_pivot`]'s OCI-overlay head: the constructed `/dev`, the
/// per-kennel binderfs, a fresh `/proc` + private `/tmp`, the shim `$HOME`, the
/// trust-manifest masks, and finally `pivot_root` into `root` (detaching the old
/// root). `root` is the about-to-be-pivoted-into mount; every path is keyed beneath it.
fn seal_view_tail(view: &ShimView, root: &Path) -> io::Result<()> {
    use kennel_lib_syscall::mount;

    // Map an absolute in-kennel path to its staging location under `root`.
    let under = |abs: &Path| root.join(abs.strip_prefix("/").unwrap_or(abs));

    // 4. The constructed /dev: a dev-permitting tmpfs with the allowlisted nodes
    //    bind-mounted from the host (same inode, so they function and the Landlock
    //    rules match). nosuid; devices come only from the explicit binds.
    let dev = under(Path::new("/dev"));
    std::fs::create_dir_all(&dev)?;
    mount::mount_tmpfs(&dev, None, Some("0755"), true, true)?;
    for node in &view.dev_allow {
        let dest = under(node);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // A directory dev grant (e.g. `/dev/pts`) is a pty filesystem, not a node:
        // mount a fresh, isolated `devpts` and symlink `/dev/ptmx -> pts/ptmx` so the
        // workload can allocate ptys (the symlink resolves into the Landlock-granted
        // `/dev/pts` subtree). Every other entry is a single node bound from the host.
        if node.is_dir() {
            std::fs::create_dir_all(&dest)?;
            mount::mount_devpts(&dest)?;
            if node == Path::new("/dev/pts") {
                let ptmx = under(Path::new("/dev/ptmx"));
                let _ = std::fs::remove_file(&ptmx);
                std::os::unix::fs::symlink("pts/ptmx", &ptmx)?;
            }
        } else {
            std::fs::File::create(&dest)?;
            mount::bind(node, &dest, false)?;
        }
    }

    // 4b. Binder IPC (07-1/02-4): a per-kennel binderfs instance with the standard
    //     `binder` device and the `/dev/binder` symlink libbinder opens by default.
    //     binderfs is FS_USERNS_MOUNT, so this mounts in the kennel's own userns with
    //     no real privilege. `binder-control` is allocated here but not Landlock-granted
    //     to the workload; kenneld takes node 0 of this instance via `/proc` at spawn.
    if view.binder {
        let binderfs_dir = under(Path::new("/dev/binderfs"));
        kennel_lib_binder::binderfs::mount_instance(
            &binderfs_dir,
            kennel_lib_binder::binderfs::DEFAULT_MAX_DEVICES,
        )
        .map_err(|e| io::Error::new(e.kind(), format!("binderfs mount_instance: {e}")))?;
        kennel_lib_binder::binderfs::add_binder_device(&binderfs_dir)
            .map_err(|e| io::Error::new(e.kind(), format!("binderfs add_binder_device: {e}")))?;
        std::os::unix::fs::symlink("binderfs/binder", under(Path::new("/dev/binder")))
            .map_err(|e| io::Error::new(e.kind(), format!("binderfs symlink: {e}")))?;
    }

    // 5. Fresh /proc (reflecting the PID namespace) and the private /tmp.
    let proc = under(Path::new("/proc"));
    std::fs::create_dir_all(&proc)?;
    mount::mount_proc(&proc, view.proc_hidepid)?;
    let tmp = under(Path::new("/tmp"));
    std::fs::create_dir_all(&tmp)?;
    // Mode 0700: the tmpfs is owned by the workload user inside its own mount namespace, so
    // owner-only is private-and-usable (no other uid exists in the kennel to grant). Fixed, not
    // policy-derived — a per-policy DAC mode gated no real adversary here.
    mount::mount_tmpfs(&tmp, Some(view.tmp_size_mib), Some("0700"), false, true)?;
    // Private POSIX shared memory at /dev/shm — a fresh per-kennel tmpfs like /tmp, so `shm_open(3)`
    // works (Wayland compositors, Chromium, …). The constructed minimal /dev exists above; this adds
    // the conventional shm tmpfs inside it (mode 1777 like the host's).
    let dev_shm = under(Path::new("/dev/shm"));
    std::fs::create_dir_all(&dev_shm)?;
    mount::mount_tmpfs(&dev_shm, Some(view.tmp_size_mib), Some("1777"), false, true)?;

    // 6. Ensure the shim $HOME exists even if no ~ path was granted, so HOME resolves.
    std::fs::create_dir_all(under(&view.shim_root))?;

    // 6b. Mask the workspace trust manifests (§7.4 / T2.8). Each lives inside a writable
    //     bind, so the host inode is reachable through that mount; overmount an empty,
    //     read-only file so the workload sees an empty file it cannot read pins from or
    //     forge, while the host IDE reads the untouched real inode. The mask source is a
    //     fresh empty file in the root tmpfs scaffold (never the host manifest).
    materialize_masks(&view.mask_paths, root, &under)?;
    // 6c. Mask the blob store directory (`.trust-manifest.d`, §2.3) the same way, but with an
    //     empty read-only *directory* over-mount: `readdir` shows nothing, the workload cannot
    //     read a pinned blob, and a write into — or creation of — the host store is denied.
    materialize_dir_masks(&view.mask_dir_paths, root, &under)?;

    // 7. pivot_root into the new root, then detach the old one.
    let put_old = under(Path::new("/.kennel-oldroot"));
    std::fs::create_dir_all(&put_old)?;
    mount::pivot_root(root, &put_old)?;
    std::env::set_current_dir("/")?;
    mount::unmount_detach(Path::new("/.kennel-oldroot"))?;
    let _ = std::fs::remove_dir(Path::new("/.kennel-oldroot"));
    Ok(())
}

/// Bind each granted system/home path into the view. Recursive, so submounts come along;
/// read-only unless the grant is writable (those resolve to the real host inode, the
/// persistence guarantee). `under` maps an in-kennel path to its staging location.
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
fn materialize_binds(binds: &[BindMount], under: &impl Fn(&Path) -> PathBuf) -> io::Result<()> {
    use kennel_lib_syscall::mount;
    for b in binds {
        if !b.source.exists() {
            continue;
        }
        let dest = under(&b.target);
        // The already-materialised skip holds only for a *symmetric* bind: the broader
        // earlier grant serves the same host inode, so the child bind is redundant. A
        // redirected bind (W15) serves a DIFFERENT inode — it must over-mount the parent's
        // view of the path, exactly like a writable child inside a read-only tree.
        if !b.writable && !b.redirected && dest.symlink_metadata().is_ok() {
            continue;
        }
        create_bind_target(&b.source, &dest).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("create_bind_target {}: {e}", dest.display()),
            )
        })?;
        // For writable binds, resolve the source with RESOLVE_NO_SYMLINKS
        // (openat2) so a source that symlink-escapes the granted tree is refused
        // before the mount is applied — closing the writable-bind-source
        // symlink-aliasing class (0.4.0 F1 residual). The returned O_PATH fd is
        // bound via /proc/self/fd/N, which resolves to the real inode. The fd
        // must stay alive until after mount::bind returns.
        //
        // Read-only binds are not guarded: a read-only symlink-aliased bind
        // cannot be used to write the control socket or any other protected path.
        if b.writable {
            // AT_FDCWD (-100) — resolve relative to cwd. For absolute paths the
            // kernel ignores it; all bind sources in the plan are absolute. We
            // use the raw value to avoid pulling libc into this crate.
            let fd = kennel_lib_syscall::fd::open_no_symlinks(
                -100, // AT_FDCWD
                &b.source,
            )
            .map_err(|e| {
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
                    format!("bind {}->{}: {e}", b.source.display(), dest.display()),
                )
            })?;
            // `fd` is dropped here — after mount::bind has consumed the
            // /proc/self/fd/N path and the bind is in place.
        } else {
            // A *redirected* read-only source (W15) resolves with RESOLVE_NO_MAGICLINKS:
            // the source path is an operator assertion of origin, and a procfs/sysfs magic
            // link in it would alias the bind out of the intended tree. Ordinary symlinks
            // are permitted (operator credential stores are commonly symlink farms). A
            // symmetric read-only bind stays unguarded as before — its source IS the
            // granted path, and read-only aliasing cannot reach a protected write.
            let magic_guard = if b.redirected {
                let fd = kennel_lib_syscall::fd::open_no_magiclinks(
                    -100, // AT_FDCWD; ignored for the absolute paths a plan carries
                    &b.source,
                )
                .map_err(|e| {
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
                    format!("bind {}->{}: {e}", b.source.display(), dest.display()),
                )
            })?;
            drop(magic_guard); // the bind is in place; the O_PATH fd has served its purpose
            mount::remount_readonly(&dest).map_err(|e| {
                io::Error::new(e.kind(), format!("remount_ro {}: {e}", dest.display()))
            })?;
        }
    }
    Ok(())
}

/// Over-mount each workspace trust-manifest path with an empty, read-only file so the
/// confined workload cannot read or forge the integrity pins (§7.4 / T2.8).
///
/// The manifest lives inside a writable bind, so its host inode is otherwise visible to
/// the workload. The mask source is a single empty file created in the root-tmpfs scaffold
/// (`/.kennel-mask`, outside any bind, gone after `pivot_root` detaches the construction
/// view); it is bind-mounted over each in-view manifest path and remounted read-only. A
/// mask whose target directory is absent is skipped (no writable bind materialised there).
///
/// # Errors
/// Returns the OS error if creating the scaffold file, a mountpoint, the bind, or the
/// read-only remount fails.
fn materialize_masks(
    mask_paths: &[PathBuf],
    new_root: &Path,
    under: &impl Fn(&Path) -> PathBuf,
) -> io::Result<()> {
    use kennel_lib_syscall::mount;
    if mask_paths.is_empty() {
        return Ok(());
    }
    // One shared empty source file in the view's private /tmp (a fresh tmpfs, writable in every
    // mode — including an OCI `readonly` root whose merged tree is immutable). The bind over each
    // target references this inode, so the source path is irrelevant once the overmount is up.
    let _ = new_root;
    let mask_src = under(Path::new("/tmp/.kennel-mask"));
    std::fs::File::create(&mask_src)?;
    for path in mask_paths {
        let dest = under(path);
        // The parent (the writable bind) must exist; if not, the bind was not materialised
        // (source absent), so there is nothing to mask.
        let Some(parent) = dest.parent() else {
            continue;
        };
        if !parent.exists() {
            continue;
        }
        // Ensure the target file exists to mount over (the host may or may not have written
        // a manifest there; either way we overmount an empty file).
        if dest.symlink_metadata().is_err() {
            std::fs::File::create(&dest)?;
        }
        mount::bind(&mask_src, &dest, false)
            .map_err(|e| io::Error::new(e.kind(), format!("mask bind {}: {e}", dest.display())))?;
        mount::remount_readonly(&dest).map_err(|e| {
            io::Error::new(e.kind(), format!("mask remount_ro {}: {e}", dest.display()))
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
fn materialize_dir_masks(
    mask_dir_paths: &[PathBuf],
    new_root: &Path,
    under: &impl Fn(&Path) -> PathBuf,
) -> io::Result<()> {
    use kennel_lib_syscall::mount;
    if mask_dir_paths.is_empty() {
        return Ok(());
    }
    // In the view's private /tmp tmpfs (writable in every mode); see [`materialize_masks`].
    let _ = new_root;
    let mask_src = under(Path::new("/tmp/.kennel-mask-d"));
    std::fs::create_dir_all(&mask_src)?;
    for path in mask_dir_paths {
        let dest = under(path);
        let Some(parent) = dest.parent() else {
            continue;
        };
        if !parent.exists() {
            continue;
        }
        // Create the mountpoint dir if the host has no store there yet — masking the path
        // also denies the workload *creating* a host `.trust-manifest.d`. A read-only parent
        // (an OCI image's closure-locked `/usr`, §7.11.4c) already denies that creation, so the
        // path cannot appear and there is nothing to mask — skip it rather than fault EROFS.
        if dest.symlink_metadata().is_err() {
            match std::fs::create_dir_all(&dest) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::ReadOnlyFilesystem => continue,
                Err(e) => return Err(e),
            }
        }
        mount::bind(&mask_src, &dest, false).map_err(|e| {
            io::Error::new(e.kind(), format!("store mask bind {}: {e}", dest.display()))
        })?;
        mount::remount_readonly(&dest).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("store mask remount_ro {}: {e}", dest.display()),
            )
        })?;
    }
    Ok(())
}

/// Create `dest` (and its parent) as the right type to bind `source` over: a
/// directory for a directory source, otherwise an empty file.
///
/// An already-present `dest` is left as-is — a mountpoint needs only existence, and the
/// present inode may be served by a read-only parent bind (the redirected-child case, W15),
/// where a truncating `File::create` would fail `EROFS` even though the over-mount itself
/// is fine.
fn create_bind_target(source: &Path, dest: &Path) -> io::Result<()> {
    if dest.symlink_metadata().is_ok() {
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if source.is_dir() {
        std::fs::create_dir_all(dest)?;
    } else {
        std::fs::File::create(dest)?;
    }
    Ok(())
}

/// Load the given BPF programs, populate their egress maps, and attach to a cgroup.
///
/// Populates each program's maps from `plan` and attaches it to `cgroup`. Returns
/// the loaded handles, which the caller must keep alive: dropping them closes the
/// map/program fds (and, with the program, the attachment).
///
/// `objects` pairs each program spec with its compiled object bytes (from
/// `kennel_lib_bpf::programs` in production, or compiled in tests). This in-process
/// helper mints each program its own maps and is used by the spawn root tests;
/// the production egress path (the privhelper, `kennel_privhelper::exec`) instead
/// creates one shared map set per kennel (`create_maps` + `load_program_against`)
/// and pins it. Pass the program(s) whose maps you populate (e.g. `connect4` for
/// the v4 egress allowlist).
///
/// # Errors
///
/// Returns [`SpawnError::Syscall`] if loading, map population, or attach fails.
pub fn attach_egress(
    cgroup: std::os::fd::BorrowedFd<'_>,
    plan: &Plan,
    objects: &[(&'static kennel_lib_bpf::ProgramSpec, &[u8])],
) -> Result<Vec<kennel_lib_bpf::Loaded>, SpawnError> {
    let mut loaded = Vec::new();
    for (spec, elf) in objects {
        let l = kennel_lib_bpf::load_program(elf, spec, kennel_lib_bpf::KENNEL_MAPS)
            .map_err(SpawnError::Syscall)?;
        populate_egress_maps(&l, plan)?;
        // Seal the write-once meta map (§02-7-bpf-abi.md), consistent with the
        // privhelper's production path.
        kennel_lib_bpf::freeze_maps(&l.maps, &["kennel_meta_map"]).map_err(SpawnError::Syscall)?;
        l.attach(cgroup, spec.attach_type)
            .map_err(SpawnError::Syscall)?;
        loaded.push(l);
    }
    Ok(loaded)
}

/// Write the plan's egress entries into whichever of a loaded program's maps it
/// references (`kennel_meta_map`, `allow_v4`, `deny_v4`).
fn populate_egress_maps(loaded: &kennel_lib_bpf::Loaded, plan: &Plan) -> Result<(), SpawnError> {
    use kennel_lib_bpf::sys::BPF_ANY;

    if loaded.maps.contains_key("kennel_meta_map") {
        loaded
            .update_map(
                "kennel_meta_map",
                &0u32.to_ne_bytes(),
                &plan.bpf_meta,
                BPF_ANY,
            )
            .map_err(SpawnError::Syscall)?;
    }
    if loaded.maps.contains_key("allow_v4") {
        for (key, value) in &plan.bpf_allow_v4 {
            loaded
                .update_map("allow_v4", key, value, BPF_ANY)
                .map_err(SpawnError::Syscall)?;
        }
    }
    if loaded.maps.contains_key("deny_v4") {
        for (key, value) in &plan.bpf_deny_v4 {
            loaded
                .update_map("deny_v4", key, value, BPF_ANY)
                .map_err(SpawnError::Syscall)?;
        }
    }
    if loaded.maps.contains_key("allow_v6") {
        for (key, value) in &plan.bpf_allow_v6 {
            loaded
                .update_map("allow_v6", key, value, BPF_ANY)
                .map_err(SpawnError::Syscall)?;
        }
    }
    if loaded.maps.contains_key("deny_v6") {
        for (key, value) in &plan.bpf_deny_v6 {
            loaded
                .update_map("deny_v6", key, value, BPF_ANY)
                .map_err(SpawnError::Syscall)?;
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
                    cwd: kennel_lib_policy::settled::CwdPolicy::default(),
                    tmp: TmpPolicy {
                        writable: true,
                        size_mib: 512,
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
        assert!(
            plan.bpf_allow_v4.is_empty(),
            "constrained mode has no BPF connect-allow base (proxy endpoint stamped later)"
        );
        // deny_invariant 169.254.169.254/32 any-proto is enforced in EVERY mode (deny-first).
        assert_eq!(plan.bpf_deny_v4.len(), 1);
        // meta: magic "KNEL", abi 1, ctx 7.
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

        // (1) the author allow encodes to a single bind-allow v4 entry (no seed yet — no stamp).
        assert_eq!(
            plan.bpf_bind_allow_v4.len(),
            1,
            "author bind.allow 0.0.0.0/0:8080 encodes to one bind-allow entry, got {}",
            plan.bpf_bind_allow_v4.len()
        );
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
