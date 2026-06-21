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
//! On success `kenneld` **mints** the stdio channel (a socketpair for bidirectional JSON-RPC + a pipe
//! for `stderr`) and returns the requester's two ends in the reply; node 0 stays fd-free inbound, so
//! the only fd movement is this outbound reply ([[binder-fd-passing-safety-verdict]]). Construction
//! of the spawned kennel from the validated instance — and the `max_instances` claim — is W6.3; here
//! the spawned-kennel ends are dropped, so a requester sees its ends then `EOF`.

use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// to the reply"). The instance is never written to disk (§7.12.6).
    fn enqueue(&self, instance: SettledPolicy, stdio: [OwnedFd; 3], name: String);
}

/// A constructor that drops every job — for paths that never spawn: a depth-1 instance's own
/// construction (a spawn target carries no `[spawn]` grant, so it never reaches the handler) and tests.
pub struct NoopConstructor;

impl SpawnConstructor for NoopConstructor {
    fn enqueue(&self, _instance: SettledPolicy, _stdio: [OwnedFd; 3], _name: String) {}
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
    ) -> Self {
        Self {
            grant,
            keys,
            template_dirs,
            constructor,
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
    match validate_and_mint(rt, incoming) {
        Ok((instance, uuid, requester_ends, channel)) => {
            // The spawned kennel's stdio: the socketpair end serves both stdin and stdout
            // (bidirectional JSON-RPC), so it is duplicated for the two; the pipe write end is stderr.
            let Ok(stdout) = channel.spawned_rpc.try_clone() else {
                emit(writer, ctx, incoming, Outcome::Deny, "stdio dup failed");
                return Reply::Data(spawn_wire::encode_reply(status::DENIED, ""));
            };
            let stdio = [channel.spawned_rpc, stdout, channel.spawned_stderr];
            // Hand the validated instance to construction, off the looper (async to this reply); the
            // requester writes into its socketpair end, which buffers until the tool reads (§7.12).
            rt.constructor.enqueue(instance, stdio, uuid.clone());
            emit(writer, ctx, incoming, Outcome::Allow, &uuid);
            Reply::DataAndFds(spawn_wire::encode_reply(status::OK, &uuid), requester_ends)
        }
        Err(d) => {
            emit(writer, ctx, incoming, Outcome::Deny, &d.reason);
            Reply::Data(spawn_wire::encode_reply(d.status, ""))
        }
    }
}

/// The validation pipeline: decode → grant → pin → eligibility → patch → mint. On success returns the
/// validated in-memory instance (for construction), the `spawn-<uuid>`, the requester's channel ends,
/// and the spawned kennel's channel ends.
fn validate_and_mint(
    rt: &SpawnRuntime,
    incoming: &Incoming,
) -> Result<(SettledPolicy, String, Vec<OwnedFd>, Channel), Deny> {
    // 1. Decode the untrusted request.
    let (template_ref, patch_pairs) = spawn_wire::decode_request(&incoming.data)
        .ok_or_else(|| deny(status::BAD_REQUEST, "malformed SPAWN request"))?;

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

    // 4. Content-pin + cryptographic verify against the trust keys (§7.12.8).
    let template =
        kennel_lib_policy::verify_pinned(&bytes, &rt.keys, &pin.signing_key_id, &pin.signature)
            .map_err(|e| deny(status::DENIED, e.to_string()))?;

    // 5. Re-run spawn-eligibility on the resolved bytes (the authoritative gate).
    kennel_lib_policy::spawn_eligible(&template)
        .map_err(|e| deny(status::DENIED, e.to_string()))?;

    // 6. Apply the manifest patch (narrowed per requester) onto the resolved template, producing the
    //    in-memory instance construction runs (never written to disk — §7.12.6).
    let entries = build_patch(pin, &patch_pairs).map_err(|e| deny(status::DENIED, e))?;
    let instance = kennel_lib_policy::patch::instantiate(&template, &entries)
        .map_err(|e| deny(status::DENIED, e.to_string()))?;

    // 7. Mint the channel; return the instance plus the requester's and spawned ends.
    let (uuid, requester_ends, channel) =
        mint().map_err(|e| deny(status::DENIED, format!("channel mint failed: {e}")))?;
    Ok((instance, uuid, requester_ends, channel))
}

/// Resolve `name@version` to the signed template bytes from the first trust-store directory that
/// holds `<dir>/<name>/policy.toml` (the layout the compiler resolves at install — `05-templates`).
fn resolve_template(dirs: &[PathBuf], reference: &str) -> Option<Vec<u8>> {
    let name = reference.split('@').next().unwrap_or(reference);
    dirs.iter()
        .find_map(|dir| std::fs::read(dir.join(name).join("policy.toml")).ok())
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
/// `spawn-<uuid>`, the requester's two ends (socketpair local + pipe read), and the spawned kennel's
/// ends (socketpair remote + pipe write) for construction.
fn mint() -> io::Result<(String, Vec<OwnedFd>, Channel)> {
    let (requester_rpc, spawned_rpc) = UnixStream::pair()?;
    let (stderr_read, stderr_write) = std::io::pipe()?;
    let requester_ends = vec![OwnedFd::from(requester_rpc), OwnedFd::from(stderr_read)];
    let channel = Channel {
        spawned_rpc: OwnedFd::from(spawned_rpc),
        spawned_stderr: OwnedFd::from(stderr_write),
    };
    Ok((spawn_uuid(), requester_ends, channel))
}

/// A transient `spawn-<id>` name. A process-global monotonic counter — `Math::random`/clocks are
/// unavailable in this build, and a counter is collision-free within a daemon's life (which is all a
/// transient spawn name needs; it consumes no operator registry namespace — `02-10` §Ephemerality).
fn spawn_uuid() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!("spawn-{:012x}", COUNTER.fetch_add(1, Ordering::Relaxed))
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
        std::fs::write(tdir.join("policy.toml"), b"BYTES").expect("write");
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
    fn mint_yields_distinct_uuids_and_two_requester_ends() {
        let (u1, ends, _ch) = mint().expect("mint");
        assert_eq!(ends.len(), 2, "socketpair local + stderr read");
        let (u2, _e, _c) = mint().expect("mint");
        assert_ne!(u1, u2, "uuids are unique");
        assert!(u1.starts_with("spawn-"));
    }
}
