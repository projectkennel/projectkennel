//! Loading and verifying policies against a trust store.
//!
//! The daemon's production [`crate::server::PolicyLoader`]. The
//! trust store is a directory of Ed25519 public keys — one `*.pub` file per
//! signer, the file stem its key id and the contents its base64-encoded 32-byte
//! public key. The **system** store comes from the root-owned deployment config
//! ([`kennel_lib_config::Deployment::trust_dir`], default `/etc/kennel/keys`, plus the
//! vendor `/usr/lib/kennel/keys`) — never a user/environment override.
//!
//! The trust split (`07-paths`): a **settled run policy** the daemon enforces may be
//! signed by a system key **or** the calling user's own `~/.config/kennel/keys`
//! (a leaf only narrows within the template's re-asserted invariants and runs with
//! the user's own authority, so its own key grants no escalation). So the daemon
//! loads system keys **then** the user's keys ([`TrustStoreLoader::from_dirs`]),
//! system winning on a duplicate id. **Templates** — the security baseline — are a
//! separate, **system-only** trust enforced at compile time, never here. Loading a
//! policy reads the file, verifies its single signature against the trust store,
//! substitutes the per-instance placeholders, and translates the result into a
//! [`Plan`] — all via [`kennel_lib_spawn::prepare`].

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kennel_lib_config::{EnablementDir, ReservedNamespace};
use kennel_lib_policy::KeySet;
use kennel_lib_spawn::{Plan, RuntimeSubstitutions};

use crate::server::{Loaded, PolicyLoader};

/// The daemon trust store: the verifiable keys plus which key-ids are **vendor-provenance**.
///
/// Vendor-provenance ids are those loaded from the vendor key dir (`/usr/lib/kennel/keys`), where the
/// project maintainer key lives. The vendor set is the authority for the built-in
/// `org.projectkennel.*` reserved namespace (`07-13-service-catalog.md` §7.13.5); the catalogue gate
/// ([`crate::catalogue`]) consults it.
pub struct TrustStore {
    /// Every trusted key, looked up by id for signature verification.
    pub keys: KeySet,
    /// The subset of key-ids loaded from the vendor key dir (provenance = authority).
    pub vendor_key_ids: BTreeSet<String>,
}

/// Load every `*.pub` in `dir` into `keys`, the file stem as key id. A key id
/// already present is **skipped**, so when called over an ordered list the first
/// dir wins (the system store, loaded first, cannot be shadowed by a later user key).
///
/// A single unreadable or malformed `*.pub` is **warned about and skipped**, not
/// fatal: the trust store is re-read on every request, so one fat-fingered key file
/// must not brick verification of policies signed by the *valid* keys beside it.
/// Only an error reading the directory itself propagates.
fn load_dir_into(
    keys: &mut KeySet,
    dir: &Path,
    inserted: &mut BTreeSet<String>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pub") {
            continue;
        }
        let Some(key_id) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if keys.get(key_id).is_some() {
            continue; // an earlier dir already defined this id; do not shadow
        }
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(e) => {
                eprintln!(
                    "kenneld: warning: cannot read trust key {}: {e}",
                    path.display()
                );
                continue;
            }
        };
        if let Err(e) = keys.insert_pub_line(key_id, contents.trim()) {
            eprintln!(
                "kenneld: warning: ignoring malformed trust key {}: {e:?}",
                path.display()
            );
        } else {
            inserted.insert(key_id.to_owned());
        }
    }
    Ok(())
}

/// Where a [`TrustStoreLoader`] gets its keys.
enum TrustSource {
    /// Re-read these key dirs on **every** load (system dirs first, system winning a
    /// key-id clash; a missing dir skipped). Reading per-request — not once at
    /// startup — means a key added, changed, or removed on disk (e.g. by `kennel
    /// keygen`) takes effect on the next `kennel run` with no daemon restart.
    Dirs(Vec<PathBuf>),
    /// A fixed in-memory key set (tests/embedding); never re-read.
    Fixed(KeySet),
}

/// A [`PolicyLoader`] backed by a trust store of public keys.
pub struct TrustStoreLoader {
    source: TrustSource,
    /// The vendor key dir (`/usr/lib/kennel/keys`), loaded **first** so its keys win any id clash
    /// (the maintainer key is unshadowable) and are tagged vendor-provenance — the authority for the
    /// built-in `org.projectkennel.*` namespace (§7.13.5). `None` for the test/embedding constructors.
    vendor_dir: Option<PathBuf>,
    /// Host-declared reserved namespaces (§7.13.5a) for the runtime reserved-provide gate.
    reserved: Vec<ReservedNamespace>,
    /// The operator enablement directories (§7.13.6) the catalogue's membership is scanned from.
    enablement_dirs: Vec<EnablementDir>,
}

impl TrustStoreLoader {
    /// Build a loader that re-reads the public keys in `dir` (each `*.pub`) per load.
    #[must_use]
    pub fn from_dir(dir: &Path) -> Self {
        Self {
            source: TrustSource::Dirs(vec![dir.to_path_buf()]),
            vendor_dir: None,
            reserved: Vec::new(),
            enablement_dirs: Vec::new(),
        }
    }

    /// Build the **production** daemon loader: a `vendor_dir` searched first for provenance, then the
    /// `rest` dirs (admin trust dir, then the user's), the host-declared `reserved` namespaces for the
    /// reserved-provide gate, and the `enablement_dirs` the catalogue's membership is scanned from. A
    /// vendor key wins an id clash with a `rest` key (loaded first), so an admin or user cannot shadow
    /// the maintainer key; vendor keys are the `org.projectkennel.*` authority. A missing dir is
    /// skipped (not an error).
    #[must_use]
    pub fn from_trust_dirs(
        vendor_dir: Option<PathBuf>,
        rest: &[&Path],
        reserved: Vec<ReservedNamespace>,
        enablement_dirs: Vec<EnablementDir>,
    ) -> Self {
        Self {
            source: TrustSource::Dirs(rest.iter().map(|d| d.to_path_buf()).collect()),
            vendor_dir,
            reserved,
            enablement_dirs,
        }
    }

    /// Build a loader that re-reads several key dirs per load, **earlier dirs winning**
    /// on a duplicate key id; a missing dir is skipped (not an error).
    ///
    /// Pass the system trust dir(s) **first**, then the user's
    /// `~/.config/kennel/keys`: a settled run policy may be signed by a system key
    /// **or** the user's own key (`07-paths`, the trust split), but a user key can
    /// never shadow a system key of the same id (system is inserted first and wins).
    /// Templates are a separate, system-only trust handled at compile time, not here.
    ///
    /// The dirs are read on every [`load`](PolicyLoader::load), so trust-store edits
    /// are picked up live (no restart). Verification itself reports a malformed key.
    #[must_use]
    pub fn from_dirs(dirs: &[&Path]) -> Self {
        Self {
            source: TrustSource::Dirs(dirs.iter().map(|d| d.to_path_buf()).collect()),
            vendor_dir: None,
            reserved: Vec::new(),
            enablement_dirs: Vec::new(),
        }
    }

    /// Build a loader from an in-memory [`KeySet`] (for tests/embedding).
    #[must_use]
    pub const fn from_keys(keys: KeySet) -> Self {
        Self {
            source: TrustSource::Fixed(keys),
            vendor_dir: None,
            reserved: Vec::new(),
            enablement_dirs: Vec::new(),
        }
    }

    /// The current trust store: re-read from disk for [`TrustSource::Dirs`] (so it
    /// reflects on-disk edits since startup), or the fixed set for tests.
    ///
    /// The vendor dir (if any) is read **first**: its keys win an id clash with the later dirs (the
    /// maintainer key is unshadowable) and its ids are recorded as vendor-provenance.
    ///
    /// # Errors
    /// An OS error if a present dir cannot be read, or `InvalidData` for a malformed key.
    fn current_keys(&self) -> std::io::Result<TrustStore> {
        match &self.source {
            TrustSource::Fixed(keys) => Ok(TrustStore {
                keys: keys.clone(),
                vendor_key_ids: BTreeSet::new(),
            }),
            TrustSource::Dirs(dirs) => {
                let mut keys = KeySet::new();
                let mut vendor_key_ids = BTreeSet::new();
                if let Some(vendor) = &self.vendor_dir {
                    match load_dir_into(&mut keys, vendor, &mut vendor_key_ids) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e),
                    }
                }
                let mut rest = BTreeSet::new();
                for dir in dirs {
                    match load_dir_into(&mut keys, dir, &mut rest) {
                        Ok(()) => {}
                        // A missing layer (e.g. no ~/.config/kennel/keys) is fine.
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e),
                    }
                }
                Ok(TrustStore {
                    keys,
                    vendor_key_ids,
                })
            }
        }
    }

    /// The number of trusted keys right now (re-reads the dirs; best-effort `0` on a
    /// read error). For diagnostics/tests, not a hot path.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.current_keys().map_or(0, |k| k.keys.len())
    }
}

impl PolicyLoader for TrustStoreLoader {
    fn trust_keys(&self) -> kennel_lib_policy::KeySet {
        self.current_keys().map(|s| s.keys).unwrap_or_default()
    }

    fn enabled_providers(&self) -> Vec<crate::catalogue::EnabledProvider> {
        let store = match self.current_keys() {
            Ok(store) => store,
            Err(e) => {
                eprintln!("kenneld: enablement: trust store unreadable, no providers: {e}");
                return Vec::new();
            }
        };
        // The enabled providers, verified against the trust store (warnings logged).
        crate::enablement::scan(&self.enablement_dirs, &store.keys, |w| {
            eprintln!("kenneld: enablement: {w}");
        })
    }

    fn build_catalogue(&self) -> crate::catalogue::Catalogue {
        let store = match self.current_keys() {
            Ok(store) => store,
            Err(e) => {
                eprintln!("kenneld: catalogue: trust store unreadable, empty catalogue: {e}");
                return crate::catalogue::Catalogue::default();
            }
        };
        // Projection over the enabled membership: gate each `[[provides]]`; an unauthorized reserved
        // claim is dropped and audited.
        crate::catalogue::Catalogue::project(
            &self.enabled_providers(),
            &store.vendor_key_ids,
            &self.reserved,
            |name, provider| {
                eprintln!(
                    "kenneld: catalogue: provider `{provider}` is not authorized to provide reserved \
                     `{name}` — dropped (§7.13.5)"
                );
            },
        )
    }

    fn load(&self, path: &Path, subst: &RuntimeSubstitutions) -> Result<Loaded, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("cannot read policy {}: {e}", path.display()))?;
        // Re-read the trust store now, so a key created/changed since the daemon
        // started is honoured (the loader is built once at boot but keys live on disk).
        let store = self
            .current_keys()
            .map_err(|e| format!("reading trust store: {e}"))?;
        // Verify + recover the signing key id (the reserved-namespace gate turns on *which* trusted
        // key signed the policy). Substitute once; derive both artefacts from the one policy (the same
        // steps `kennel_lib_spawn::prepare` runs, kept open here so the net section is available to
        // configure the egress proxy).
        let (verified, signing_key_id) =
            kennel_lib_policy::verify_settled_signed(&bytes, &store.keys)
                .map_err(|e| e.to_string())?;
        // Authoritative reserved-namespace gate (§7.13.4): a settled policy may *provide* a reserved
        // capability name only when an authorized key signed it. A self-signed `org.projectkennel.*`
        // (or unauthorized host-namespace) provide is finally refused here — the runtime backstop to
        // the compile-time fail-fast (W1), closing the provider-name-spoofing channel.
        if let Some(name) = crate::catalogue::first_unauthorized_provide(
            &verified.mesh.provides,
            &signing_key_id,
            &store.vendor_key_ids,
            &self.reserved,
        ) {
            return Err(format!(
                "policy {} provides reserved capability `{name}`, but its signing key `{signing_key_id}` \
                 is not authorized for that namespace (§7.13.5)",
                path.display()
            ));
        }
        loaded_from_settled(&verified, subst)
    }
}

/// Derive the daemon-side [`Loaded`] runtime from an already-verified settled policy.
///
/// The post-verification half of [`TrustStoreLoader::load`], shared with the dynamic-spawn
/// construction path (§7.12): a `SPAWN` instance is patched in memory and never signed — its
/// integrity is the verified template plus the patch validator, so it carries no signature to verify
/// — but it still substitutes its `<ctx>`/`<uid>` placeholders, builds the kernel-enforcement plan,
/// and membership-checks its supplementary groups exactly as a path-loaded policy does.
///
/// # Errors
///
/// A human-readable reason if substitution leaves a placeholder unresolved, the plan cannot be
/// built, or a supplementary group is not one the operator holds.
pub fn loaded_from_settled(
    verified: &kennel_lib_policy::SettledPolicy,
    subst: &RuntimeSubstitutions,
) -> Result<Loaded, String> {
    let substituted = kennel_lib_spawn::substitute(verified, subst).map_err(|e| e.to_string())?;
    let mut plan = Plan::from_policy(&substituted, subst.ctx, &subst.namespace, &subst.home)
        .map_err(|e| e.to_string())?;
    // Backstop the control-socket ungrantability at the privileged factory (W15 F1). The compiler
    // refuses an `fs` grant that would expose the control socket (the loud primary guard), but a
    // grant written with the deferred `<uid>` placeholder resolves only at `substitute`, *after*
    // that lexical check — so it can still land the daemon's runtime dir in the view. The fix keeps
    // the privhelper a dumb applier (no searching the constructed tree — that is where TOCTOU /
    // symlink-race bugs live): the *unprivileged* daemon, which knows its own socket path, simply
    // adds it to the view's blind-mask list. The privhelper over-mounts an empty file there after
    // building the view, exactly as it already does for the T2.8 trust manifests, so a `connect(2)`
    // hits a plain file (`ENOTSOCK`) however the tree was bound. `materialize_masks` is a no-op when
    // no grant placed the runtime dir in the view, so this costs nothing on the common path.
    if let Some(view) = plan.view.as_mut() {
        view.mask_paths
            .push(kennel_lib_control::socket::socket_path());
    }
    // Resolve the policy's supplementary groups to GIDs and membership-check them (§7.4): kenneld
    // runs as the operator, so a group the operator is not in is refused — the privileged seal could
    // otherwise over-grant. The kennel always drops to exactly this set (empty ⇒ none at all).
    let groups = resolve_groups(&substituted.identity.groups)?;
    plan.supplementary_groups = Some(groups.iter().map(|(_, gid)| *gid).collect());
    // Re-derive the exec.deny footgun warnings (§7.3.4): a deny that falls inside an allowed
    // directory, or is set with no allow, cannot be enforced by the allow-only Landlock LSM.
    for w in substituted.effective_policy.exec.deny_warnings() {
        eprintln!("kenneld: warning: {w}");
    }
    let exec_path = substituted.effective_policy.exec.path.clone();
    let shell = substituted.effective_policy.exec.shell.clone();
    let home_persist = substituted.effective_policy.fs.home_persist.clone();
    let lifecycle = substituted.effective_policy.lifecycle.clone();
    let tty_filter = substituted.effective_policy.tty.filter_terminal_escapes;
    let on_change = substituted.effective_policy.trust.on_change;
    Ok(Loaded {
        plan,
        account: substituted.identity.user,
        account_group: substituted.identity.group,
        net: substituted.effective_policy.net,
        ssh: substituted.ssh,
        unix: substituted.unix,
        binder: substituted.binder,
        consumes: substituted.mesh.consumes,
        provides: substituted.mesh.provides,
        dbus: substituted.dbus,
        groups,
        audit: substituted.audit,
        env: substituted.env,
        exec_path,
        shell,
        home_persist,
        lifecycle,
        tty_filter,
        on_change,
        workload: substituted.workload,
        spawn: substituted.spawn,
    })
}

/// Resolve the policy's supplementary group names to `(name, gid)` pairs, refusing
/// any the operator is not a member of (§7.4).
///
/// kenneld runs as the operator, so its own group set is the operator's. A name that
/// does not resolve, or resolves to a group the operator does not hold, is a
/// fail-closed error: the privileged seal `setgroups` could otherwise grant a group
/// the operator lacks (privilege escalation). De-duplicated, order-preserving.
fn resolve_groups(names: &[String]) -> Result<Vec<(String, u32)>, String> {
    use kennel_lib_syscall::unistd;
    let real_gid = unistd::real_gid();
    let held = unistd::supplementary_groups();
    let mut out: Vec<(String, u32)> = Vec::new();
    for name in names {
        let gid = unistd::group_gid(name)
            .map_err(|e| format!("[identity] resolving group `{name}`: {e}"))?
            .ok_or_else(|| format!("[identity] group `{name}` does not exist on this host"))?;
        if gid != real_gid && !held.contains(&gid) {
            return Err(format!(
                "[identity] group `{name}` (gid {gid}): the user is not a member; refusing to grant it into the kennel"
            ));
        }
        if !out.iter().any(|(_, g)| *g == gid) {
            out.push((name.clone(), gid));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kennel_lib_policy::SigningKey;
    use std::path::PathBuf;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kenneld-trust-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir trust");
        dir
    }

    fn subst() -> RuntimeSubstitutions {
        RuntimeSubstitutions {
            ctx: 1,
            uid: 1000,
            kennel: "t".to_owned(),
            home: PathBuf::from("/home/dev"),
            namespace: "kennel-test".to_owned(),
            tag: 42,
            ula_gid: [0, 0, 0, 0, 2],
        }
    }

    /// Write a signer's public key as a `<key_id>.pub` base64 file in `dir`.
    fn write_pubkey(dir: &Path, key: &SigningKey) {
        let b64 = kennel_lib_policy::b64::encode(&key.public_key_bytes());
        std::fs::write(dir.join(format!("{}.pub", key.key_id())), b64).expect("write pubkey");
    }

    #[test]
    fn from_dir_loads_pub_keys() {
        let dir = temp_dir("keys");
        let key = SigningKey::from_seed("maint-2026", &[7u8; 32]).expect("key");
        write_pubkey(&dir, &key);
        // A non-.pub file is ignored.
        std::fs::write(dir.join("README"), "ignore me").expect("write");

        let loader = TrustStoreLoader::from_dir(&dir);
        assert_eq!(loader.key_count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_key_is_skipped_not_fatal() {
        // A malformed `.pub` is warned about and skipped (not loaded, not fatal) — one
        // bad file must not brick verification for the valid keys re-read beside it.
        let dir = temp_dir("bad");
        std::fs::write(dir.join("broken.pub"), "not base64!!!").expect("write");
        let good = SigningKey::from_seed("good", &[5u8; 32]).expect("key");
        write_pubkey(&dir, &good);
        let loader = TrustStoreLoader::from_dir(&dir);
        assert_eq!(
            loader.key_count(),
            1,
            "the good key loads; the broken one is skipped"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keys_are_re_read_each_load_not_cached() {
        // The fix for the startup-cache bug: a key added after the loader is built must
        // be visible on the next read (the daemon never restarts between keygen and run).
        let dir = temp_dir("live-reload");
        let loader = TrustStoreLoader::from_dir(&dir);
        assert_eq!(loader.key_count(), 0, "empty to start");
        let key = SigningKey::from_seed("late", &[9u8; 32]).expect("key");
        write_pubkey(&dir, &key);
        assert_eq!(
            loader.key_count(),
            1,
            "a key added after construction is picked up"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn from_dirs_loads_user_keys_but_system_wins_a_clash() {
        // The trust split: settled policies verify against system keys then the user's
        // own. A user-only key is loaded; a user key reusing a system id cannot shadow
        // the system key (system dir is passed first and wins).
        let system = temp_dir("split-sys");
        let user = temp_dir("split-usr");
        let sys_key = SigningKey::from_seed("shared", &[1u8; 32]).expect("sys key");
        let usr_key = SigningKey::from_seed("shared", &[2u8; 32]).expect("usr key");
        write_pubkey(&system, &sys_key);
        write_pubkey(&user, &usr_key);
        let mine = SigningKey::from_seed("mine", &[3u8; 32]).expect("user-only key");
        write_pubkey(&user, &mine);

        let loader = TrustStoreLoader::from_dirs(&[&system, &user]);
        let store = loader.current_keys().expect("read keys");
        let keys = &store.keys;
        assert_eq!(keys.len(), 2, "clashing id deduped; user-only added");
        assert!(keys.get("mine").is_some(), "user-only key is trusted");
        let got = keys.get("shared").expect("shared id present");
        let got_b64 = kennel_lib_policy::b64::encode(&**got);
        let want_b64 = kennel_lib_policy::b64::encode(&sys_key.public_key_bytes());
        assert_eq!(got_b64, want_b64, "the system key wins the id clash");

        let _ = std::fs::remove_dir_all(&system);
        let _ = std::fs::remove_dir_all(&user);
    }

    #[test]
    fn vendor_dir_keys_are_provenance_tagged_and_unshadowable() {
        // The vendor dir is searched first: its key-ids are recorded as vendor-provenance (the
        // org.projectkennel.* authority), and a `rest` (admin/user) key reusing a vendor id cannot
        // shadow it — the maintainer key is unshadowable.
        let vendor = temp_dir("prov-vendor");
        let admin = temp_dir("prov-admin");
        let maint = SigningKey::from_seed("kennel-maint-2026", &[1u8; 32]).expect("maint key");
        let imposter = SigningKey::from_seed("kennel-maint-2026", &[2u8; 32]).expect("imposter");
        let admin_only = SigningKey::from_seed("acme-admin", &[3u8; 32]).expect("admin key");
        write_pubkey(&vendor, &maint);
        write_pubkey(&admin, &imposter); // same id as the maintainer key, in the admin dir
        write_pubkey(&admin, &admin_only);

        let loader = TrustStoreLoader::from_trust_dirs(
            Some(vendor.clone()),
            &[&admin],
            Vec::new(),
            Vec::new(),
        );
        let store = loader.current_keys().expect("read keys");

        // The maintainer id is vendor-provenance; the admin-only id is not.
        assert!(store.vendor_key_ids.contains("kennel-maint-2026"));
        assert!(!store.vendor_key_ids.contains("acme-admin"));

        // The vendor key wins the id clash — the admin imposter cannot shadow it.
        let got = store.keys.get("kennel-maint-2026").expect("maint present");
        let got_b64 = kennel_lib_policy::b64::encode(&**got);
        let want_b64 = kennel_lib_policy::b64::encode(&maint.public_key_bytes());
        assert_eq!(got_b64, want_b64, "the vendor maintainer key wins");

        let _ = std::fs::remove_dir_all(&vendor);
        let _ = std::fs::remove_dir_all(&admin);
    }

    #[test]
    fn from_dirs_skips_a_missing_dir() {
        let system = temp_dir("split-present");
        let key = SigningKey::from_seed("k", &[7u8; 32]).expect("key");
        write_pubkey(&system, &key);
        let missing = system.join("no-such-user-keys");
        let loader = TrustStoreLoader::from_dirs(&[&system, &missing]);
        assert_eq!(
            loader.key_count(),
            1,
            "missing dir is skipped, not an error"
        );
        let _ = std::fs::remove_dir_all(&system);
    }

    #[test]
    fn load_reports_a_missing_policy_file() {
        let loader = TrustStoreLoader::from_keys(KeySet::new());
        let err = loader
            .load(Path::new("/nonexistent/policy"), &subst())
            .expect_err("must fail");
        assert!(err.contains("cannot read policy"), "got {err}");
    }

    #[test]
    fn loaded_from_settled_masks_the_control_socket() {
        // The privhelper backstop to F1: whatever the policy's fs grants, the constructed view's
        // blind-mask list carries the daemon's control socket, so the privileged factory over-mounts
        // an empty file there — the socket is neutralised however the tree was bound (closing the
        // `<uid>`-placeholder path the lexical compile guard cannot see).
        let settled = kennel_lib_policy::settled::sample_settled();
        let loaded = loaded_from_settled(&settled, &subst()).expect("loads");
        let view = loaded
            .plan
            .view
            .expect("a home-shadowing policy has a view");
        assert!(
            view.mask_paths
                .contains(&kennel_lib_control::socket::socket_path()),
            "the control socket must be in the view's blind-mask list: {:?}",
            view.mask_paths
        );
    }

    #[test]
    fn load_rejects_unsigned_garbage() {
        let dir = temp_dir("garbage");
        let policy = dir.join("p.policy");
        std::fs::write(&policy, b"this is not a signed policy").expect("write");
        let key = SigningKey::from_seed("maint-2026", &[7u8; 32]).expect("key");
        let mut keys = KeySet::new();
        keys.insert(key.key_id(), &key.public_key_bytes())
            .expect("insert");

        let loader = TrustStoreLoader::from_keys(keys);
        assert!(
            loader.load(&policy, &subst()).is_err(),
            "garbage must not verify"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
