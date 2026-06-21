//! The node-0 `SPAWN` handler (`docs/architecture/02-10-dynamic-spawn.md` §7.12).
//!
//! A requester workload transacts [`verb::SPAWN`](kennel_lib_binder::service::verb::SPAWN) naming an
//! operator-signed template and the manifest-field writes it wants. `kenneld` validates — all in the
//! **verify half**, never a compiler ([[tcb-only-shrinks]]):
//!
//! 1. **Grant.** The template must be in this kennel's `[spawn.allow]`.
//! 2. **Content-pin.** `kenneld` re-resolves the named template from the (mutable) trust store and
//!    [`verify_pinned`](kennel_lib_policy::verify_pinned)s it: its signature must equal the commitment
//!    the spawner recorded *and* verify against the trust keys — fail-closed on a re-signed-in-place
//!    TOCTOU.
//! 3. **Eligibility.** [`spawn_eligible`](kennel_lib_policy::spawn_eligible) re-runs on the resolved
//!    bytes (depth-1 / TTL / ceilings) — the authoritative gate, the install-time pass was advisory.
//! 4. **Patch.** The writes apply onto the resolved template as a typed mutation
//!    ([`patch::instantiate`](kennel_lib_policy::patch::instantiate)), bounded by the template's
//!    manifest and this requester's narrowing — never a re-parse, never a coined field.
//!
//! On success `kenneld` **claims** a `max_instances` slot (the fork-bomb bound), **mints** the stdio
//! channel (a socketpair for bidirectional JSON-RPC + a pipe for `stderr`), returns the requester's
//! two ends in the reply, and hands the validated instance + the claimed slot to the
//! [`SpawnConstructor`] — which builds it into a running sibling kennel off the looper, the channel's
//! spawned ends wired to its stdio. Node 0 stays fd-free inbound, so the only fd movement is the
//! outbound reply ([[binder-fd-passing-safety-verdict]]). The slot releases when the spawned kennel
//! terminates (soft `EOF`, the template's TTL self-reap, or a build abort — §7.12.7).

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use kennel_lib_audit::{Event, Outcome, Resource, Source, Value, Writer};
use kennel_lib_binder::client::Incoming;
use kennel_lib_binder::ctxmgr::Reply;
use kennel_lib_binder::service::{spawn as spawn_wire, status};
use kennel_lib_policy::patch::PatchEntry;
use kennel_lib_policy::{KeySet, SettledPolicy, SpawnGrant, SpawnTemplate};

/// Constructs a validated spawn instance asynchronously.
///
/// The daemon's construction machinery, behind a non-generic handle so the binder layer (which knows
/// neither `Privileged` nor the policy loader) can hand off the build without becoming generic.
pub trait SpawnConstructor: Send + Sync {
    /// Reserve a context for `name`, build the kennel from the in-memory `instance`, wire the three
    /// `stdio` fds (the spawned ends of the minted channel) to its workload, and supervise it — off
    /// the binder looper, asynchronously to the `SPAWN` reply (`02-10` §"Construction is asynchronous
    /// to the reply"). The instance is never written to disk (§7.12.6). `slot` is the claimed
    /// `max_instances` slot — held across the build so it releases (on drop) only when the spawned
    /// kennel terminates or the build aborts (§7.12.7).
    fn enqueue(&self, instance: SettledPolicy, stdio: [OwnedFd; 3], name: String, slot: SlotGuard);
}

/// An RAII claim on a `max_instances` slot.
///
/// The live count is decremented on drop — on the construction thread when the spawned kennel
/// terminates, or at once if the build aborts (§7.12.7). A boot failure cannot leak a slot, and a
/// flapping requester cannot leak across teardown races.
///
/// It also carries the requester's [`parent_alive`](SpawnRuntime) flag so the construction thread can
/// re-check it once the sibling's cgroup exists — the hard-reaper race close (§7.12.7): construction is
/// async to the `SPAWN` reply, so a requester can die (and its `reap_children` run) *before* this
/// sibling's cgroup exists for the reaper to kill. The reaper flips the flag false before it scans; the
/// construction thread re-checks after the cgroup is live, so a sibling cannot orphan past its requester.
pub struct SlotGuard {
    live: Arc<AtomicU32>,
    parent_alive: Arc<AtomicBool>,
}

impl SlotGuard {
    /// The requester's liveness flag (false once its `SpawnRuntime` has dropped). A spawned kennel's
    /// construction re-checks this once its cgroup is live, to self-terminate if the requester is gone.
    #[must_use]
    pub fn parent_liveness(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.parent_alive)
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Atomically claim a slot if the live count is below `max` (§7.12.7) — a single check-and-claim, so
/// two concurrent `SPAWN`s on different loopers cannot jointly exceed the ceiling. `None` if full. The
/// claimed guard carries `parent_alive` for the construction thread's post-cgroup liveness re-check.
fn claim_slot(
    live: &Arc<AtomicU32>,
    max: u32,
    parent_alive: &Arc<AtomicBool>,
) -> Option<SlotGuard> {
    let mut cur = live.load(Ordering::Acquire);
    loop {
        if cur >= max {
            return None;
        }
        match live.compare_exchange_weak(
            cur,
            cur.saturating_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                return Some(SlotGuard {
                    live: Arc::clone(live),
                    parent_alive: Arc::clone(parent_alive),
                })
            }
            Err(actual) => cur = actual,
        }
    }
}

/// A constructor that drops every job — for paths that never spawn: a depth-1 instance's own
/// construction (a spawn target carries no `[spawn]` grant, so it never reaches the handler) and tests.
pub struct NoopConstructor;

impl SpawnConstructor for NoopConstructor {
    fn enqueue(
        &self,
        _instance: SettledPolicy,
        _stdio: [OwnedFd; 3],
        _name: String,
        _slot: SlotGuard,
    ) {
    }
}

/// A shared [`NoopConstructor`] handle.
#[must_use]
pub fn noop_constructor() -> Arc<dyn SpawnConstructor> {
    Arc::new(NoopConstructor)
}

/// The per-kennel `[spawn]` runtime captured in the node-0 handler.
///
/// Holds the requester's grant (the allowed templates, each content-pinned, and `max_instances`),
/// the trust keys a re-resolved template is verified against, and the template directories
/// `name@version` resolves from (the user cascade `kenneld` runs at — safety rests on the keys and
/// the pin, not the directory).
pub struct SpawnRuntime {
    grant: SpawnGrant,
    keys: KeySet,
    template_dirs: Vec<PathBuf>,
    constructor: Arc<dyn SpawnConstructor>,
    /// Live spawn count for this grant — the `max_instances` accounting (§7.12.7). Shared across the
    /// looper pool so the check-and-claim is atomic; a [`SlotGuard`] holds one unit until teardown.
    live: Arc<AtomicU32>,
    /// Spawn-path tracer (the `log_level` knob): stamps each validate→mint milestone with a
    /// wall-clock `[t=<nanos>]` in the same `CLOCK_REALTIME` stream as `run_kennel`, so the
    /// spinup harness (`tools/spawn-spinup.sh`) can time the in-daemon SPAWN handler — the
    /// "one layer down" phase that precedes the construction the requester observes.
    tracer: kennel_lib_config::Tracer,
    /// Requester liveness, flipped false on [`Drop`] (when this kennel's node-0 server stops — ahead of
    /// its `reap_children`). A clone rides each [`SlotGuard`] to the construction thread, which re-checks
    /// it once the spawned cgroup is live, closing the async-reaper race (§7.12.7).
    parent_alive: Arc<AtomicBool>,
}

impl Drop for SpawnRuntime {
    fn drop(&mut self) {
        // The requester is tearing down: signal in-flight constructions to self-terminate if the hard
        // reaper's registry scan missed them (their cgroup did not yet exist). This Drop runs when the
        // node-0 server releases the last `Arc<SpawnRuntime>` — inside `Kennel::stop`'s `manager.stop()`,
        // before `run_kennel` calls `reap_children` — so the flag is false ahead of the reap.
        self.parent_alive.store(false, Ordering::Release);
    }
}

impl SpawnRuntime {
    /// Assemble the runtime from the kennel's grant, a trust-key snapshot, the template cascade, and
    /// the construction handle a validated instance is built through.
    #[must_use]
    pub fn new(
        grant: SpawnGrant,
        keys: KeySet,
        template_dirs: Vec<PathBuf>,
        constructor: Arc<dyn SpawnConstructor>,
        tracer: kennel_lib_config::Tracer,
    ) -> Self {
        Self {
            grant,
            keys,
            template_dirs,
            constructor,
            live: Arc::new(AtomicU32::new(0)),
            tracer,
            parent_alive: Arc::new(AtomicBool::new(true)),
        }
    }
}

/// The spawned kennel's ends of the minted channel — wired to its stdio at construction.
struct Channel {
    /// The spawned kennel's socketpair end (serves stdin + stdout, the bidirectional JSON-RPC).
    spawned_rpc: OwnedFd,
    /// The spawned kennel's `stderr` pipe write end.
    spawned_stderr: OwnedFd,
}

/// A refusal: the reply [`status`] byte and the audit detail.
struct Deny {
    status: u8,
    reason: String,
}

fn deny(status: u8, reason: impl Into<String>) -> Deny {
    Deny {
        status,
        reason: reason.into(),
    }
}

/// Handle one `verb::SPAWN` transaction: validate, mint the channel, and reply (`02-10` §7.12).
///
/// `rt` is `None` for a kennel that holds no `[spawn]` grant — a hard deny. Returns the requester's
/// two channel ends ([`Reply::DataAndFds`]) with the `spawn-<uuid>` on success, or a status byte on a
/// deny. Every outcome emits a `kennel.spawn` audit event.
pub fn handle_spawn(
    rt: Option<&SpawnRuntime>,
    incoming: &Incoming,
    ctx: u16,
    writer: &Writer,
) -> Reply {
    let Some(rt) = rt else {
        emit(
            writer,
            ctx,
            incoming,
            Outcome::Deny,
            "this kennel holds no [spawn] grant",
        );
        return Reply::Data(spawn_wire::encode_reply(status::DENIED, ""));
    };
    rt.tracer
        .step(&format!("spawn: SPAWN received on node 0, ctx={ctx}"));
    match validate_and_mint(rt, incoming) {
        Ok((instance, requester_ends, channel, slot)) => {
            // The spawned kennel's stdio: the socketpair end serves both stdin and stdout
            // (bidirectional JSON-RPC), so it is duplicated for the two; the pipe write end is stderr.
            let Ok(stdout) = channel.spawned_rpc.try_clone() else {
                emit(writer, ctx, incoming, Outcome::Deny, "stdio dup failed");
                return Reply::Data(spawn_wire::encode_reply(status::DENIED, ""));
            };
            let stdio = [channel.spawned_rpc, stdout, channel.spawned_stderr];
            // The transient name encodes the requester's ctx, so the hard reaper can find and kill
            // this kennel when the requester tears down (§7.12.7) — a registry scan for `spawn-<ctx>-*`.
            let name = spawn_name(ctx);
            // Hand the validated instance + its claimed slot to construction, off the looper (async to
            // this reply); the requester writes into its socketpair end, which buffers until the tool
            // reads (§7.12). The slot rides with the build and releases when the spawned kennel exits.
            rt.tracer.step(&format!(
                "spawn: validated + minted, enqueue construct `{name}`"
            ));
            rt.constructor.enqueue(instance, stdio, name.clone(), slot);
            emit(writer, ctx, incoming, Outcome::Allow, &name);
            Reply::DataAndFds(spawn_wire::encode_reply(status::OK, &name), requester_ends)
        }
        Err(d) => {
            emit(writer, ctx, incoming, Outcome::Deny, &d.reason);
            Reply::Data(spawn_wire::encode_reply(d.status, ""))
        }
    }
}

/// The validation pipeline: decode → grant → pin → eligibility → patch → claim → mint. On success
/// returns the validated in-memory instance (for construction), the requester's channel ends, the
/// spawned kennel's channel ends, and the claimed `max_instances` slot.
fn validate_and_mint(
    rt: &SpawnRuntime,
    incoming: &Incoming,
) -> Result<(SettledPolicy, Vec<OwnedFd>, Channel, SlotGuard), Deny> {
    let tr = rt.tracer;
    // 1. Decode the untrusted request.
    let (template_ref, patch_pairs) = spawn_wire::decode_request(&incoming.data)
        .ok_or_else(|| deny(status::BAD_REQUEST, "malformed SPAWN request"))?;
    tr.step(&format!(
        "spawn: decoded request, template `{template_ref}`"
    ));

    // 2. Grant: the template must be in this kennel's [spawn.allow].
    let pin = rt
        .grant
        .allow
        .iter()
        .find(|t| t.template == template_ref)
        .ok_or_else(|| {
            deny(
                status::DENIED,
                format!("template `{template_ref}` is not in this kennel's [spawn.allow]"),
            )
        })?;

    // 3. Resolve the template from the (mutable) trust store.
    let bytes = resolve_template(&rt.template_dirs, template_ref).ok_or_else(|| {
        deny(
            status::DENIED,
            format!("template `{template_ref}` was not found in the trust store"),
        )
    })?;
    tr.step("spawn: grant ok, template resolved from trust store");

    // 4. Content-pin + cryptographic verify against the trust keys (§7.12.8).
    let template =
        kennel_lib_policy::verify_pinned(&bytes, &rt.keys, &pin.signing_key_id, &pin.signature)
            .map_err(|e| deny(status::DENIED, e.to_string()))?;
    tr.step("spawn: content-pin + signature verified");

    // 5. Re-run spawn-eligibility on the resolved bytes (the authoritative gate).
    kennel_lib_policy::spawn_eligible(&template)
        .map_err(|e| deny(status::DENIED, e.to_string()))?;
    tr.step("spawn: eligibility re-check ok");

    // 6. Apply the manifest patch (narrowed per requester) onto the resolved template, producing the
    //    in-memory instance construction runs (never written to disk — §7.12.6).
    let entries = build_patch(pin, &patch_pairs).map_err(|e| deny(status::DENIED, e))?;
    let instance = kennel_lib_policy::patch::instantiate(&template, &entries)
        .map_err(|e| deny(status::DENIED, e.to_string()))?;
    tr.step("spawn: manifest patch applied");

    // 7. Atomically claim a max_instances slot (§7.12.7) — the fork-bomb bound. Held until the
    //    spawned kennel terminates (the construction thread holds the guard); full ⇒ a clean refusal.
    let max = rt.grant.max_instances;
    let slot = claim_slot(&rt.live, max, &rt.parent_alive).ok_or_else(|| {
        deny(
            status::CEILING_FULL,
            format!("max_instances ceiling ({max}) is full"),
        )
    })?;

    // 8. Mint the channel; return the instance plus the requester's and spawned ends and the slot.
    let (requester_ends, channel) =
        mint().map_err(|e| deny(status::DENIED, format!("channel mint failed: {e}")))?;
    Ok((instance, requester_ends, channel, slot))
}

/// Resolve `name@version` to the signed **settled** template bytes — the complete, chain-folded
/// policy a spawn instantiates (`<dir>/<name>/<name>.settled.toml`), beside the source the compiler
/// folds. A spawn target is load-verified and instantiated as-is; the daemon never compiles it.
fn resolve_template(dirs: &[PathBuf], reference: &str) -> Option<Vec<u8>> {
    let (name, version) = reference.split_once('@').unwrap_or((reference, "v1"));
    dirs.iter().find_map(|dir| {
        // The installed flat layout, then the in-tree `<name>/<name>.settled.toml` beside source.
        std::fs::read(dir.join(format!("{name}@{version}.settled.toml")))
            .or_else(|_| std::fs::read(dir.join(name).join(format!("{name}.settled.toml"))))
            .ok()
    })
}

/// Build the typed patch from the request pairs, enforcing this requester's manifest narrowing.
///
/// A non-empty `mutable_narrow` restricts the writable fields to a subset of the template's manifest
/// (§7.12.3); an empty one defers wholly to [`patch::instantiate`](kennel_lib_policy::patch::instantiate),
/// which enforces manifest membership. Narrowing never widens.
fn build_patch(pin: &SpawnTemplate, pairs: &[(&str, &str)]) -> Result<Vec<PatchEntry>, String> {
    let mut entries = Vec::with_capacity(pairs.len());
    for (field, value) in pairs {
        if !pin.mutable_narrow.is_empty() && !pin.mutable_narrow.iter().any(|f| f == field) {
            return Err(format!(
                "field `{field}` is outside this requester's narrowed manifest (§7.12.3)"
            ));
        }
        entries.push(PatchEntry {
            field: (*field).to_owned(),
            value: (*value).to_owned(),
        });
    }
    Ok(entries)
}

/// Mint the stdio channel: a socketpair (bidirectional JSON-RPC) and a `stderr` pipe. Returns the
/// requester's two ends (socketpair local + pipe read) and the spawned kennel's ends (socketpair
/// remote + pipe write) for construction.
fn mint() -> io::Result<(Vec<OwnedFd>, Channel)> {
    let (requester_rpc, spawned_rpc) = UnixStream::pair()?;
    let (stderr_read, stderr_write) = std::io::pipe()?;
    let requester_ends = vec![OwnedFd::from(requester_rpc), OwnedFd::from(stderr_read)];
    let channel = Channel {
        spawned_rpc: OwnedFd::from(spawned_rpc),
        spawned_stderr: OwnedFd::from(stderr_write),
    };
    Ok((requester_ends, channel))
}

/// A transient `spawn-<parent-ctx>-<id>` name (§7.12.7): the requester's ctx is encoded so the hard
/// reaper can find every child of a requester by registry prefix. The id is a process-global
/// monotonic counter — clocks/`Math::random` are unavailable in this build, and a counter is
/// collision-free within a daemon's life (all a transient name needs — `02-10` §Ephemerality).
fn spawn_name(parent_ctx: u16) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "spawn-{parent_ctx}-{:012x}",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// The registry-name prefix for every kennel spawned by the requester at `parent_ctx` — the hard
/// reaper's lookup key (§7.12.7).
#[must_use]
pub fn child_name_prefix(parent_ctx: u16) -> String {
    format!("spawn-{parent_ctx}-")
}

/// Emit a `kennel.spawn` audit event (`02-10` §Audit events).
fn emit(writer: &Writer, ctx: u16, incoming: &Incoming, outcome: Outcome, detail: &str) {
    writer.emit(
        &Event::new("kennel.spawn", Resource::Binder, outcome, Source::Kenneld)
            .pid(u32::try_from(incoming.sender_pid).unwrap_or(0))
            .field("detail", Value::untrusted(detail.to_owned()))
            .field("ctx", Value::Uint(u64::from(ctx))),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(template: &str, narrow: &[&str]) -> SpawnTemplate {
        SpawnTemplate {
            template: template.to_owned(),
            signing_key_id: "k".to_owned(),
            signature: "s".to_owned(),
            mutable_narrow: narrow.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn resolve_template_reads_name_from_at_version() {
        let dir = std::env::temp_dir().join(format!("kennel-spawn-resolve-{}", std::process::id()));
        let tdir = dir.join("net-fetch");
        std::fs::create_dir_all(&tdir).expect("mkdir");
        std::fs::write(tdir.join("net-fetch.settled.toml"), b"BYTES").expect("write");
        let got = resolve_template(std::slice::from_ref(&dir), "net-fetch@v1");
        assert_eq!(got.as_deref(), Some(b"BYTES".as_slice()));
        assert!(resolve_template(std::slice::from_ref(&dir), "absent@v1").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn build_patch_enforces_the_requester_narrowing() {
        // No narrowing → every field passes to instantiate (which enforces the manifest).
        let open = pin("net-fetch@v1", &[]);
        assert_eq!(
            build_patch(&open, &[("fs.write", "/w")]).expect("ok").len(),
            1
        );
        // Narrowed → a field outside the narrowing is rejected before instantiate.
        let narrow = pin("net-fetch@v1", &["net.proxy.allow"]);
        assert!(build_patch(&narrow, &[("net.proxy.allow", "h:443")]).is_ok());
        let err = build_patch(&narrow, &[("fs.write", "/w")]).expect_err("narrowed out");
        assert!(err.contains("narrowed manifest"));
    }

    #[test]
    fn claim_slot_bounds_the_ceiling_and_releases_on_drop() {
        let live = Arc::new(AtomicU32::new(0));
        let alive = Arc::new(AtomicBool::new(true));
        let g1 = claim_slot(&live, 2, &alive).expect("slot 1");
        let g2 = claim_slot(&live, 2, &alive).expect("slot 2");
        assert!(
            claim_slot(&live, 2, &alive).is_none(),
            "the ceiling is full"
        );
        drop(g1);
        let g3 = claim_slot(&live, 2, &alive).expect("a freed slot is re-claimable");
        assert_eq!(live.load(Ordering::Acquire), 2);
        drop((g2, g3));
        assert_eq!(
            live.load(Ordering::Acquire),
            0,
            "every slot released on drop"
        );
    }

    #[test]
    fn slot_carries_requester_liveness_for_the_reaper_race() {
        // The construction thread re-checks this once the spawned cgroup is live (§7.12.7): a guard
        // claimed while the requester is alive must observe the flag flip false when the requester's
        // SpawnRuntime drops, so an in-flight sibling whose cgroup the hard reaper missed self-terminates.
        let live = Arc::new(AtomicU32::new(0));
        let alive = Arc::new(AtomicBool::new(true));
        let slot = claim_slot(&live, 1, &alive).expect("slot");
        let liveness = slot.parent_liveness();
        assert!(
            liveness.load(Ordering::Acquire),
            "alive while the requester lives"
        );
        // SpawnRuntime::Drop is what flips it in production; emulate that store here.
        alive.store(false, Ordering::Release);
        assert!(
            !liveness.load(Ordering::Acquire),
            "the construction thread sees the requester gone"
        );
    }

    #[test]
    fn mint_yields_two_requester_ends() {
        let (ends, _ch) = mint().expect("mint");
        assert_eq!(ends.len(), 2, "socketpair local + stderr read");
    }

    #[test]
    fn spawn_name_encodes_the_parent_ctx_and_is_unique() {
        let n1 = spawn_name(7);
        let n2 = spawn_name(7);
        assert_ne!(n1, n2, "names are unique");
        assert!(
            n1.starts_with(&child_name_prefix(7)),
            "encodes the parent ctx"
        );
        assert!(
            !n1.starts_with(&child_name_prefix(8)),
            "distinguishes parents"
        );
    }
}
