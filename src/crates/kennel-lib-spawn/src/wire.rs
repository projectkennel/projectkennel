//! Fixed-discipline codec for the [`Plan`] crossing process boundaries.
//!
//! The kennel is constructed by the privhelper (real root), which `execve`s the
//! root-owned `kennel-bin-init` as the kennel's uid-0 PID 1 (`kennel-bin-init-and-uid0`).
//! `kenneld` (the operator) builds the [`Plan`]; it must reach `kennel-bin-init` as bytes.
//! The privhelper forwards the blob opaquely; **`kennel-bin-init` (root) decodes it**, so
//! this is operator-supplied data parsed by a privileged process — every length is
//! bounded and every read is checked, in the same manual, serialization-language-free
//! style as `kennel-privhelper::wire` (auditable, fuzzable, no `unsafe`). A malformed
//! blob is a clean [`PlanWireError`], never a panic or an over-read.
//!
//! The `interactive_return_fd` is **not** serialised as a number — a raw fd does not
//! survive a byte stream or an `execve`. It is encoded as a presence flag; the real fd
//! is conveyed out of band (inherited at a fixed fd / `SCM_RIGHTS`) and injected by the
//! receiver. So `decode_plan(encode_plan(p))` reproduces `p` except that
//! `interactive_return_fd` decodes to `None` with the flag preserved separately.

use std::path::PathBuf;

use kennel_lib_syscall::landlock::{AccessFs, AccessNet};
use kennel_lib_syscall::namespace::Namespaces;
use kennel_lib_syscall::process::{resource_by_name, resource_name};
use kennel_lib_syscall::seccomp::Action;

use crate::plan::{AuxProcess, BindMount, ConstructionHalf, Plan, ShimView, Supervision};

/// Maximum element count for any length-prefixed vector (a `DoS`/corruption bound).
const MAX_ENTRIES: usize = 65_536;
/// Maximum byte length for any length-prefixed blob (paths, strings).
const MAX_BLOB: usize = 1 << 16;

/// A decode failure: the blob was truncated, a count/length exceeded its bound, a tag
/// was unknown, or a string was not UTF-8. Never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanWireError {
    /// The buffer ended before a field could be read.
    Truncated,
    /// A length or count field exceeded its sanity bound.
    TooLarge,
    /// An enum/option tag byte was not a defined value.
    BadTag,
    /// A string field was not valid UTF-8.
    BadString,
    /// A resource name did not resolve to a known `setrlimit` resource.
    BadResource,
}

// ---- writer ---------------------------------------------------------------

/// A growable byte sink with typed, length-prefixed appenders.
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn bool(&mut self, v: bool) {
        self.buf.push(u8::from(v));
    }

    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn bytes(&mut self, b: &[u8]) {
        // Lengths are bounded on decode; the encoder trusts its own (validated) Plan.
        self.u32(u32::try_from(b.len()).unwrap_or(u32::MAX));
        self.buf.extend_from_slice(b);
    }

    fn fixed(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    fn path(&mut self, p: &std::path::Path) {
        self.bytes(p.as_os_str().as_encoded_bytes());
    }

    fn count(&mut self, n: usize) {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX));
    }
}

// ---- reader ---------------------------------------------------------------

/// A bounds-checked cursor over the encoded blob.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], PlanWireError> {
        let end = self.pos.checked_add(n).ok_or(PlanWireError::TooLarge)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(PlanWireError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, PlanWireError> {
        Ok(*self.take(1)?.first().ok_or(PlanWireError::Truncated)?)
    }

    fn bool(&mut self) -> Result<bool, PlanWireError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(PlanWireError::BadTag),
        }
    }

    fn u16(&mut self) -> Result<u16, PlanWireError> {
        let b: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| PlanWireError::Truncated)?;
        Ok(u16::from_le_bytes(b))
    }

    fn u32(&mut self) -> Result<u32, PlanWireError> {
        let b: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| PlanWireError::Truncated)?;
        Ok(u32::from_le_bytes(b))
    }

    fn u64(&mut self) -> Result<u64, PlanWireError> {
        let b: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| PlanWireError::Truncated)?;
        Ok(u64::from_le_bytes(b))
    }

    fn i64(&mut self) -> Result<i64, PlanWireError> {
        let b: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| PlanWireError::Truncated)?;
        Ok(i64::from_le_bytes(b))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], PlanWireError> {
        self.take(N)?
            .try_into()
            .map_err(|_| PlanWireError::Truncated)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, PlanWireError> {
        let len = self.u32()? as usize;
        if len > MAX_BLOB {
            return Err(PlanWireError::TooLarge);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn path(&mut self) -> Result<PathBuf, PlanWireError> {
        let bytes = self.bytes()?;
        let s = String::from_utf8(bytes).map_err(|_| PlanWireError::BadString)?;
        Ok(PathBuf::from(s))
    }

    /// Read a vector length, enforcing the element bound before any allocation.
    fn count(&mut self) -> Result<usize, PlanWireError> {
        let n = self.u32()? as usize;
        if n > MAX_ENTRIES {
            return Err(PlanWireError::TooLarge);
        }
        Ok(n)
    }
}

// ---- enum codecs ----------------------------------------------------------

const ACT_ALLOW: u8 = 0;
const ACT_ERRNO: u8 = 1;
const ACT_KILL_PROCESS: u8 = 2;
const ACT_KILL_THREAD: u8 = 3;
const ACT_TRAP: u8 = 4;
const ACT_LOG: u8 = 5;

fn put_action(w: &mut Writer, a: Action) {
    match a {
        Action::Allow => w.u8(ACT_ALLOW),
        Action::Errno(e) => {
            w.u8(ACT_ERRNO);
            w.u16(e);
        }
        Action::KillProcess => w.u8(ACT_KILL_PROCESS),
        Action::KillThread => w.u8(ACT_KILL_THREAD),
        Action::Trap => w.u8(ACT_TRAP),
        Action::Log => w.u8(ACT_LOG),
    }
}

fn get_action(r: &mut Reader<'_>) -> Result<Action, PlanWireError> {
    Ok(match r.u8()? {
        ACT_ALLOW => Action::Allow,
        ACT_ERRNO => Action::Errno(r.u16()?),
        ACT_KILL_PROCESS => Action::KillProcess,
        ACT_KILL_THREAD => Action::KillThread,
        ACT_TRAP => Action::Trap,
        ACT_LOG => Action::Log,
        _ => return Err(PlanWireError::BadTag),
    })
}

// ---- Plan codec -----------------------------------------------------------

/// Encode a [`Plan`] to its wire bytes. The `interactive_return_fd` is encoded only as
/// a presence flag (the fd itself rides out of band).
#[must_use]
pub fn encode_plan(p: &Plan) -> Vec<u8> {
    let mut w = Writer::new();

    w.u32(p.namespaces.bits());
    w.path(&p.cgroup);
    w.bool(p.cgroup_join);

    // view: Option<ShimView>
    match &p.view {
        None => w.bool(false),
        Some(v) => {
            w.bool(true);
            put_view(&mut w, v);
        }
    }

    // new_root: Option<PathBuf>
    match &p.new_root {
        None => w.bool(false),
        Some(path) => {
            w.bool(true);
            w.path(path);
        }
    }

    // landlock_fs: Vec<(PathBuf, AccessFs)>
    w.count(p.landlock_fs.len());
    for (path, access) in &p.landlock_fs {
        w.path(path);
        w.u64(access.bits());
    }

    // landlock_net: Vec<(u16, AccessNet)>
    w.count(p.landlock_net.len());
    for (port, access) in &p.landlock_net {
        w.u16(*port);
        w.u64(access.bits());
    }

    // seccomp_deny: Vec<i64>
    w.count(p.seccomp_deny.len());
    for n in &p.seccomp_deny {
        w.i64(*n);
    }
    put_action(&mut w, p.seccomp_deny_action);

    // BPF LPM entries (fixed-size tuples) + meta + bind ports
    w.count(p.bpf_allow_v4.len());
    for (k, v) in &p.bpf_allow_v4 {
        w.fixed(k);
        w.fixed(v);
    }
    w.count(p.bpf_deny_v4.len());
    for (k, v) in &p.bpf_deny_v4 {
        w.fixed(k);
        w.fixed(v);
    }
    w.count(p.bpf_allow_v6.len());
    for (k, v) in &p.bpf_allow_v6 {
        w.fixed(k);
        w.fixed(v);
    }
    w.count(p.bpf_deny_v6.len());
    for (k, v) in &p.bpf_deny_v6 {
        w.fixed(k);
        w.fixed(v);
    }
    w.fixed(&p.bpf_meta);
    w.count(p.bind_allowed_ports.len());
    for port in &p.bind_allowed_ports {
        w.u16(*port);
    }

    // file_binds: Vec<(PathBuf, PathBuf)>
    w.count(p.file_binds.len());
    for (src, dst) in &p.file_binds {
        w.path(src);
        w.path(dst);
    }

    // supplementary_groups: Option<Vec<u32>>
    match &p.supplementary_groups {
        None => w.bool(false),
        Some(gids) => {
            w.bool(true);
            w.count(gids.len());
            for g in gids {
                w.u32(*g);
            }
        }
    }

    // ulimits: Vec<(Resource, u64, u64)> — Resource encoded by its canonical name
    w.count(p.ulimits.len());
    for (resource, soft, hard) in &p.ulimits {
        w.bytes(resource_name(*resource).unwrap_or("").as_bytes());
        w.u64(*soft);
        w.u64(*hard);
    }

    // interactive_return_fd: presence flag only
    w.bool(p.interactive_return_fd.is_some());

    // aux: Vec<AuxProcess>
    w.count(p.aux.len());
    for a in &p.aux {
        w.path(&a.path);
        w.count(a.args.len());
        for arg in &a.args {
            w.bytes(arg.as_bytes());
        }
    }

    match p.ttl_seconds {
        None => w.bool(false),
        Some(secs) => {
            w.bool(true);
            w.u64(secs);
        }
    }
    w.u8(ttl_action_byte(p.ttl_action));

    w.buf
}

/// The wire byte for a [`kennel_lib_policy::TtlAction`] (stable; mirrors `ttl_action_from_byte`).
const fn ttl_action_byte(a: kennel_lib_policy::TtlAction) -> u8 {
    match a {
        kennel_lib_policy::TtlAction::Exit => 0,
        kennel_lib_policy::TtlAction::Warn => 1,
        kennel_lib_policy::TtlAction::Renew => 2,
    }
}

/// Decode a [`kennel_lib_policy::TtlAction`] wire byte (unknown ⇒ the safe `Exit`).
const fn ttl_action_from_byte(b: u8) -> kennel_lib_policy::TtlAction {
    match b {
        1 => kennel_lib_policy::TtlAction::Warn,
        2 => kennel_lib_policy::TtlAction::Renew,
        _ => kennel_lib_policy::TtlAction::Exit,
    }
}

fn put_view(w: &mut Writer, v: &ShimView) {
    w.path(&v.shim_root);
    w.count(v.binds.len());
    for b in &v.binds {
        w.path(&b.source);
        w.path(&b.target);
        w.bool(b.writable);
    }
    w.count(v.dev_allow.len());
    for d in &v.dev_allow {
        w.path(d);
    }
    w.u32(v.tmp_size_mib);
    w.bytes(v.tmp_mode.as_bytes());
    w.bool(v.proc_hidepid);
    w.bool(v.binder);
}

/// Decode a [`Plan`] from its wire bytes (the inverse of [`encode_plan`]).
///
/// `interactive_return_fd` decodes to `None` regardless of the encoded presence flag
/// (the real fd is injected out of band by the caller). The recovered flag is the
/// second tuple element so the caller knows whether to expect/inject the fd.
///
/// # Errors
///
/// [`PlanWireError`] if the blob is truncated, a bound is exceeded, a tag is unknown,
/// a string is not UTF-8, or a resource name is unknown. Trailing bytes are rejected.
pub fn decode_plan(buf: &[u8]) -> Result<(Plan, bool), PlanWireError> {
    let mut r = Reader::new(buf);

    let namespaces = Namespaces::from_bits_truncate(r.u32()?);
    let cgroup = r.path()?;
    let cgroup_join = r.bool()?;

    let view = if r.bool()? {
        Some(get_view(&mut r)?)
    } else {
        None
    };
    let new_root = if r.bool()? { Some(r.path()?) } else { None };

    let mut landlock_fs = Vec::new();
    for _ in 0..r.count()? {
        let path = r.path()?;
        let access = AccessFs::from_bits_truncate(r.u64()?);
        landlock_fs.push((path, access));
    }

    let mut landlock_net = Vec::new();
    for _ in 0..r.count()? {
        let port = r.u16()?;
        let access = AccessNet::from_bits_truncate(r.u64()?);
        landlock_net.push((port, access));
    }

    let mut seccomp_deny = Vec::new();
    for _ in 0..r.count()? {
        seccomp_deny.push(r.i64()?);
    }
    let seccomp_deny_action = get_action(&mut r)?;

    let bpf_allow_v4 = get_lpm_v4(&mut r)?;
    let bpf_deny_v4 = get_lpm_v4(&mut r)?;
    let bpf_allow_v6 = get_lpm_v6(&mut r)?;
    let bpf_deny_v6 = get_lpm_v6(&mut r)?;
    let bpf_meta = r.fixed::<64>()?;
    let mut bind_allowed_ports = Vec::new();
    for _ in 0..r.count()? {
        bind_allowed_ports.push(r.u16()?);
    }

    let mut file_binds = Vec::new();
    for _ in 0..r.count()? {
        let src = r.path()?;
        let dst = r.path()?;
        file_binds.push((src, dst));
    }

    let supplementary_groups = if r.bool()? {
        let mut gids = Vec::new();
        for _ in 0..r.count()? {
            gids.push(r.u32()?);
        }
        Some(gids)
    } else {
        None
    };

    let mut ulimits = Vec::new();
    for _ in 0..r.count()? {
        let name = String::from_utf8(r.bytes()?).map_err(|_| PlanWireError::BadString)?;
        let resource = resource_by_name(&name).ok_or(PlanWireError::BadResource)?;
        let soft = r.u64()?;
        let hard = r.u64()?;
        ulimits.push((resource, soft, hard));
    }

    let interactive = r.bool()?;

    let mut aux = Vec::new();
    for _ in 0..r.count()? {
        let path = r.path()?;
        let mut args = Vec::new();
        for _ in 0..r.count()? {
            args.push(String::from_utf8(r.bytes()?).map_err(|_| PlanWireError::BadString)?);
        }
        aux.push(crate::plan::AuxProcess { path, args });
    }

    let ttl_seconds = if r.bool()? { Some(r.u64()?) } else { None };
    let ttl_action = ttl_action_from_byte(r.u8()?);

    if r.pos != buf.len() {
        return Err(PlanWireError::TooLarge); // trailing garbage
    }

    let plan = Plan {
        namespaces,
        cgroup,
        cgroup_join,
        view,
        new_root,
        landlock_fs,
        landlock_net,
        seccomp_deny,
        seccomp_deny_action,
        bpf_allow_v4,
        bpf_deny_v4,
        bpf_allow_v6,
        bpf_deny_v6,
        bpf_meta,
        bind_allowed_ports,
        file_binds,
        supplementary_groups,
        ulimits,
        interactive_return_fd: None,
        aux,
        ttl_seconds,
        ttl_action,
    };
    Ok((plan, interactive))
}

fn get_view(r: &mut Reader<'_>) -> Result<ShimView, PlanWireError> {
    let shim_root = r.path()?;
    let mut binds = Vec::new();
    for _ in 0..r.count()? {
        let source = r.path()?;
        let target = r.path()?;
        let writable = r.bool()?;
        binds.push(BindMount {
            source,
            target,
            writable,
        });
    }
    let mut dev_allow = Vec::new();
    for _ in 0..r.count()? {
        dev_allow.push(r.path()?);
    }
    let tmp_size_mib = r.u32()?;
    let tmp_mode = String::from_utf8(r.bytes()?).map_err(|_| PlanWireError::BadString)?;
    let proc_hidepid = r.bool()?;
    let binder = r.bool()?;
    Ok(ShimView {
        shim_root,
        binds,
        dev_allow,
        tmp_size_mib,
        tmp_mode,
        proc_hidepid,
        binder,
    })
}

fn get_lpm_v4(r: &mut Reader<'_>) -> Result<Vec<crate::plan::LpmV4Entry>, PlanWireError> {
    let mut v = Vec::new();
    for _ in 0..r.count()? {
        let k = r.fixed::<8>()?;
        let val = r.fixed::<8>()?;
        v.push((k, val));
    }
    Ok(v)
}

fn get_lpm_v6(r: &mut Reader<'_>) -> Result<Vec<crate::plan::LpmV6Entry>, PlanWireError> {
    let mut v = Vec::new();
    for _ in 0..r.count()? {
        let k = r.fixed::<20>()?;
        let val = r.fixed::<8>()?;
        v.push((k, val));
    }
    Ok(v)
}

// ---- Supervision codec ----------------------------------------------------

/// Encode the [`Supervision`] half to its wire bytes — the `GET_SANDBOX_PLAN` reply.
///
/// `kennel-bin-init` pulls and decodes this post-pivot. Same bounded discipline as
/// [`encode_plan`]; the pty fd rides out of band, so only `interactive` (a flag) is
/// serialised.
#[must_use]
pub fn encode_supervision(s: &Supervision) -> Vec<u8> {
    let mut w = Writer::new();

    w.path(&s.program);
    w.count(s.argv.len());
    for a in &s.argv {
        w.bytes(a.as_bytes());
    }
    w.count(s.env.len());
    for (k, v) in &s.env {
        w.bytes(k.as_bytes());
        w.bytes(v.as_bytes());
    }
    match &s.cwd {
        None => w.bool(false),
        Some(p) => {
            w.bool(true);
            w.path(p);
        }
    }
    w.u32(s.drop_uid);
    w.u32(s.drop_gid);

    match &s.groups {
        None => w.bool(false),
        Some(gids) => {
            w.bool(true);
            w.count(gids.len());
            for g in gids {
                w.u32(*g);
            }
        }
    }

    w.count(s.landlock_fs.len());
    for (path, access) in &s.landlock_fs {
        w.path(path);
        w.u64(access.bits());
    }
    w.count(s.landlock_net.len());
    for (port, access) in &s.landlock_net {
        w.u16(*port);
        w.u64(access.bits());
    }

    w.count(s.seccomp_deny.len());
    for n in &s.seccomp_deny {
        w.i64(*n);
    }
    put_action(&mut w, s.seccomp_deny_action);

    w.count(s.ulimits.len());
    for (resource, soft, hard) in &s.ulimits {
        w.bytes(resource_name(*resource).unwrap_or("").as_bytes());
        w.u64(*soft);
        w.u64(*hard);
    }

    w.count(s.aux.len());
    for a in &s.aux {
        w.path(&a.path);
        w.count(a.args.len());
        for arg in &a.args {
            w.bytes(arg.as_bytes());
        }
    }

    w.bool(s.interactive);

    match s.ttl_seconds {
        None => w.bool(false),
        Some(secs) => {
            w.bool(true);
            w.u64(secs);
        }
    }

    w.buf
}

/// Decode the [`Supervision`] half (the inverse of [`encode_supervision`]).
///
/// # Errors
///
/// [`PlanWireError`] if the blob is truncated, a bound is exceeded, a tag is unknown,
/// a string is not UTF-8, or a resource name is unknown. Trailing bytes are rejected.
// `drop_uid`/`drop_gid` and `argv`/`args` are the domain field names; the pedantic
// similar-names heuristic flags the pairs, but renaming would only obscure them.
#[allow(clippy::similar_names)]
pub fn decode_supervision(buf: &[u8]) -> Result<Supervision, PlanWireError> {
    let mut r = Reader::new(buf);

    let program = r.path()?;
    let mut argv = Vec::new();
    for _ in 0..r.count()? {
        argv.push(get_string(&mut r)?);
    }
    let mut env = Vec::new();
    for _ in 0..r.count()? {
        let k = get_string(&mut r)?;
        let v = get_string(&mut r)?;
        env.push((k, v));
    }
    let cwd = if r.bool()? { Some(r.path()?) } else { None };
    let drop_uid = r.u32()?;
    let drop_gid = r.u32()?;

    let groups = if r.bool()? {
        let mut gids = Vec::new();
        for _ in 0..r.count()? {
            gids.push(r.u32()?);
        }
        Some(gids)
    } else {
        None
    };

    let mut landlock_fs = Vec::new();
    for _ in 0..r.count()? {
        let path = r.path()?;
        let access = AccessFs::from_bits_truncate(r.u64()?);
        landlock_fs.push((path, access));
    }
    let mut landlock_net = Vec::new();
    for _ in 0..r.count()? {
        let port = r.u16()?;
        let access = AccessNet::from_bits_truncate(r.u64()?);
        landlock_net.push((port, access));
    }

    let mut seccomp_deny = Vec::new();
    for _ in 0..r.count()? {
        seccomp_deny.push(r.i64()?);
    }
    let seccomp_deny_action = get_action(&mut r)?;

    let mut ulimits = Vec::new();
    for _ in 0..r.count()? {
        let name = get_string(&mut r)?;
        let resource = resource_by_name(&name).ok_or(PlanWireError::BadResource)?;
        let soft = r.u64()?;
        let hard = r.u64()?;
        ulimits.push((resource, soft, hard));
    }

    let mut aux = Vec::new();
    for _ in 0..r.count()? {
        let path = r.path()?;
        let mut args = Vec::new();
        for _ in 0..r.count()? {
            args.push(get_string(&mut r)?);
        }
        aux.push(AuxProcess { path, args });
    }

    let interactive = r.bool()?;
    let ttl_seconds = if r.bool()? { Some(r.u64()?) } else { None };

    if r.pos != buf.len() {
        return Err(PlanWireError::TooLarge); // trailing garbage
    }

    Ok(Supervision {
        program,
        argv,
        env,
        cwd,
        drop_uid,
        drop_gid,
        groups,
        landlock_fs,
        landlock_net,
        seccomp_deny,
        seccomp_deny_action,
        ulimits,
        aux,
        interactive,
        ttl_seconds,
    })
}

/// Read a length-prefixed UTF-8 string (the common `bytes`→`String` pattern).
fn get_string(r: &mut Reader<'_>) -> Result<String, PlanWireError> {
    String::from_utf8(r.bytes()?).map_err(|_| PlanWireError::BadString)
}

// ---- ConstructionHalf codec -----------------------------------------------

/// Encode the [`ConstructionHalf`] to its wire bytes — the half the factory parses.
///
/// Reuses `put_view` (`07-2` §7.2.1); the operator uid/gid are deliberately not
/// serialised (the factory uses its own real ids).
#[must_use]
pub fn encode_construction(c: &ConstructionHalf) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(c.namespaces.bits());
    w.path(&c.cgroup);
    w.bool(c.cgroup_join);
    match &c.view {
        None => w.bool(false),
        Some(v) => {
            w.bool(true);
            put_view(&mut w, v);
        }
    }
    match &c.new_root {
        None => w.bool(false),
        Some(path) => {
            w.bool(true);
            w.path(path);
        }
    }
    w.count(c.file_binds.len());
    for (src, dst) in &c.file_binds {
        w.path(src);
        w.path(dst);
    }
    w.count(c.granted_gids.len());
    for g in &c.granted_gids {
        w.u32(*g);
    }
    w.bool(c.lo);
    w.u16(c.ctx);
    w.count(c.loopback.len());
    for lb in &c.loopback {
        // The address octets carry the family by length (4 = v4, 16 = v6); then the prefix.
        match lb.addr {
            std::net::IpAddr::V4(a) => w.bytes(&a.octets()),
            std::net::IpAddr::V6(a) => w.bytes(&a.octets()),
        }
        w.u8(lb.prefix);
    }
    w.buf
}

/// Decode the [`ConstructionHalf`] (the inverse of [`encode_construction`]).
///
/// # Errors
///
/// [`PlanWireError`] if the blob is truncated, a bound is exceeded, a tag is unknown,
/// or a string is not UTF-8. Trailing bytes are rejected.
pub fn decode_construction(buf: &[u8]) -> Result<ConstructionHalf, PlanWireError> {
    let mut r = Reader::new(buf);
    let namespaces = Namespaces::from_bits_truncate(r.u32()?);
    let cgroup = r.path()?;
    let cgroup_join = r.bool()?;
    let view = if r.bool()? {
        Some(get_view(&mut r)?)
    } else {
        None
    };
    let new_root = if r.bool()? { Some(r.path()?) } else { None };
    let mut file_binds = Vec::new();
    for _ in 0..r.count()? {
        let src = r.path()?;
        let dst = r.path()?;
        file_binds.push((src, dst));
    }
    let mut granted_gids = Vec::new();
    for _ in 0..r.count()? {
        granted_gids.push(r.u32()?);
    }
    let lo = r.bool()?;
    let ctx = r.u16()?;
    let mut loopback = Vec::new();
    for _ in 0..r.count()? {
        let octets = r.bytes()?;
        let addr = match octets.as_slice() {
            v4 if v4.len() == 4 => {
                std::net::IpAddr::V4(<[u8; 4]>::try_from(v4).unwrap_or([0; 4]).into())
            }
            v6 if v6.len() == 16 => {
                std::net::IpAddr::V6(<[u8; 16]>::try_from(v6).unwrap_or([0; 16]).into())
            }
            _ => return Err(PlanWireError::BadTag),
        };
        let prefix = r.u8()?;
        loopback.push(crate::plan::LoopbackAddr { addr, prefix });
    }
    if r.pos != buf.len() {
        return Err(PlanWireError::TooLarge); // trailing garbage
    }
    Ok(ConstructionHalf {
        namespaces,
        cgroup,
        cgroup_join,
        view,
        new_root,
        file_binds,
        granted_gids,
        lo,
        ctx,
        loopback,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::AuxProcess;
    use std::path::PathBuf;

    /// A fully-populated plan touching every field/variant the codec handles.
    fn rich_plan() -> Plan {
        Plan {
            namespaces: Namespaces::USER | Namespaces::MOUNT | Namespaces::PID | Namespaces::IPC,
            cgroup: PathBuf::from("/sys/fs/cgroup/user.slice/kennel-7"),
            cgroup_join: true,
            view: Some(ShimView {
                shim_root: PathBuf::from("/home/kennel"),
                binds: vec![
                    BindMount {
                        source: PathBuf::from("/usr"),
                        target: PathBuf::from("/usr"),
                        writable: false,
                    },
                    BindMount {
                        source: PathBuf::from("/home/op/work"),
                        target: PathBuf::from("/home/kennel/work"),
                        writable: true,
                    },
                ],
                dev_allow: vec![PathBuf::from("/dev/null"), PathBuf::from("/dev/net/tun")],
                tmp_size_mib: 512,
                tmp_mode: "0700".to_owned(),
                proc_hidepid: true,
                binder: true,
            }),
            new_root: Some(PathBuf::from("/run/user/1000/kennel/root-7")),
            landlock_fs: vec![
                (
                    PathBuf::from("/usr"),
                    AccessFs::READ_FILE | AccessFs::EXECUTE,
                ),
                (
                    PathBuf::from("/home/kennel"),
                    AccessFs::READ_FILE | AccessFs::WRITE_FILE | AccessFs::READ_DIR,
                ),
            ],
            landlock_net: vec![(443, AccessNet::CONNECT_TCP), (8080, AccessNet::BIND_TCP)],
            seccomp_deny: vec![101, 202, 303],
            seccomp_deny_action: Action::Errno(38),
            bpf_allow_v4: vec![([1, 2, 3, 4, 5, 6, 7, 8], [9, 10, 11, 12, 13, 14, 15, 16])],
            bpf_deny_v4: vec![([0; 8], [255; 8])],
            bpf_allow_v6: vec![([7; 20], [3; 8])],
            bpf_deny_v6: vec![([1; 20], [2; 8]), ([9; 20], [8; 8])],
            bpf_meta: {
                let mut m = [0u8; 64];
                m[0] = 0xAB;
                m[63] = 0xCD;
                m
            },
            bind_allowed_ports: vec![1080, 8443],
            file_binds: vec![(
                PathBuf::from("/run/etc/passwd"),
                PathBuf::from("/etc/passwd"),
            )],
            supplementary_groups: Some(vec![1000, 27, 44]),
            ulimits: vec![
                (resource_by_name("nofile").expect("nofile"), 1024, 4096),
                (resource_by_name("nproc").expect("nproc"), 64, 128),
            ],
            interactive_return_fd: None,
            aux: vec![AuxProcess {
                path: PathBuf::from("/usr/libexec/kennel/facade-afunix"),
                args: vec![
                    "/dev/binderfs/binder".to_owned(),
                    "/home/kennel/wl.sock=echo".to_owned(),
                ],
            }],
            ttl_seconds: Some(3600),
            ttl_action: kennel_lib_policy::TtlAction::Warn,
        }
    }

    #[test]
    fn round_trips_a_rich_plan() {
        let p = rich_plan();
        let (back, interactive) = decode_plan(&encode_plan(&p)).expect("decode");
        assert_eq!(back, p, "the decoded plan must equal the original");
        assert!(!interactive, "no interactive fd was set");
    }

    #[test]
    fn round_trips_a_minimal_plan() {
        let p = Plan {
            namespaces: Namespaces::empty(),
            cgroup: PathBuf::new(),
            cgroup_join: false,
            view: None,
            new_root: None,
            landlock_fs: Vec::new(),
            landlock_net: Vec::new(),
            seccomp_deny: Vec::new(),
            seccomp_deny_action: Action::KillProcess,
            bpf_allow_v4: Vec::new(),
            bpf_deny_v4: Vec::new(),
            bpf_allow_v6: Vec::new(),
            bpf_deny_v6: Vec::new(),
            bpf_meta: [0u8; 64],
            bind_allowed_ports: Vec::new(),
            file_binds: Vec::new(),
            supplementary_groups: None,
            ulimits: Vec::new(),
            interactive_return_fd: None,
            aux: Vec::new(),
            ttl_seconds: None,
            ttl_action: kennel_lib_policy::TtlAction::Exit,
        };
        let (back, _) = decode_plan(&encode_plan(&p)).expect("decode");
        assert_eq!(back, p);
    }

    #[test]
    fn interactive_fd_decodes_to_none_with_flag_preserved() {
        let mut p = rich_plan();
        p.interactive_return_fd = Some(42);
        let (back, interactive) = decode_plan(&encode_plan(&p)).expect("decode");
        assert!(interactive, "the presence flag must survive");
        assert_eq!(
            back.interactive_return_fd, None,
            "the raw fd is not serialised; it is injected out of band"
        );
    }

    /// A fully-populated supervision-half touching every field the codec handles.
    fn rich_supervision() -> Supervision {
        Supervision {
            program: PathBuf::from("/usr/bin/claude"),
            argv: vec!["claude".to_owned(), "--dangerously".to_owned()],
            env: vec![
                ("HOME".to_owned(), "/home/kennel".to_owned()),
                ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
                ("TERM".to_owned(), "xterm-256color".to_owned()),
            ],
            cwd: Some(PathBuf::from("/home/kennel")),
            drop_uid: 1000,
            drop_gid: 1000,
            groups: Some(vec![1000, 27, 44]),
            landlock_fs: vec![
                (
                    PathBuf::from("/usr"),
                    AccessFs::READ_FILE | AccessFs::EXECUTE,
                ),
                (PathBuf::from("/home/kennel"), AccessFs::READ_FILE),
            ],
            landlock_net: vec![(443, AccessNet::CONNECT_TCP)],
            seccomp_deny: vec![101, 202],
            seccomp_deny_action: Action::Errno(1),
            ulimits: vec![(resource_by_name("nofile").expect("nofile"), 1024, 4096)],
            aux: vec![AuxProcess {
                path: PathBuf::from("/usr/libexec/kennel/facade-afunix"),
                args: vec![
                    "/dev/binderfs/binder".to_owned(),
                    "/run/wl.sock=wayland".to_owned(),
                ],
            }],
            interactive: true,
            ttl_seconds: Some(3600),
        }
    }

    #[test]
    fn round_trips_a_rich_supervision() {
        let s = rich_supervision();
        let back = decode_supervision(&encode_supervision(&s)).expect("decode");
        assert_eq!(
            back, s,
            "the decoded supervision-half must equal the original"
        );
    }

    #[test]
    fn round_trips_a_minimal_supervision() {
        let s = Supervision {
            program: PathBuf::from("/bin/true"),
            argv: vec!["true".to_owned()],
            env: Vec::new(),
            cwd: None,
            drop_uid: 0,
            drop_gid: 0,
            groups: None,
            landlock_fs: Vec::new(),
            landlock_net: Vec::new(),
            seccomp_deny: Vec::new(),
            seccomp_deny_action: Action::KillProcess,
            ulimits: Vec::new(),
            aux: Vec::new(),
            interactive: false,
            ttl_seconds: None,
        };
        let back = decode_supervision(&encode_supervision(&s)).expect("decode");
        assert_eq!(back, s);
    }

    #[test]
    fn truncated_supervision_is_an_error_not_a_panic() {
        let full = encode_supervision(&rich_supervision());
        for cut in 0..full.len() {
            if let Some(prefix) = full.get(..cut) {
                let _ = decode_supervision(prefix);
            }
        }
    }

    #[test]
    fn trailing_garbage_on_supervision_is_rejected() {
        let mut bytes = encode_supervision(&rich_supervision());
        bytes.push(0);
        assert_eq!(decode_supervision(&bytes), Err(PlanWireError::TooLarge));
    }

    fn rich_construction() -> ConstructionHalf {
        let p = rich_plan();
        ConstructionHalf {
            namespaces: p.namespaces,
            cgroup: p.cgroup,
            cgroup_join: p.cgroup_join,
            view: p.view,
            new_root: p.new_root,
            file_binds: p.file_binds,
            granted_gids: vec![27, 44],
            lo: true,
            ctx: 7,
            loopback: vec![
                crate::plan::LoopbackAddr {
                    addr: std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 7, 0, 1)),
                    prefix: 28,
                },
                crate::plan::LoopbackAddr {
                    addr: std::net::IpAddr::V6("fd00:7:0::1".parse().expect("v6 literal")),
                    prefix: 64,
                },
            ],
        }
    }

    #[test]
    fn round_trips_a_rich_construction() {
        let c = rich_construction();
        let back = decode_construction(&encode_construction(&c)).expect("decode");
        assert_eq!(
            back, c,
            "the decoded construction-half must equal the original"
        );
    }

    #[test]
    fn round_trips_a_minimal_construction() {
        let c = ConstructionHalf {
            namespaces: Namespaces::empty(),
            cgroup: PathBuf::new(),
            cgroup_join: false,
            view: None,
            new_root: None,
            file_binds: Vec::new(),
            granted_gids: Vec::new(),
            lo: false,
            ctx: 0,
            loopback: Vec::new(),
        };
        let back = decode_construction(&encode_construction(&c)).expect("decode");
        assert_eq!(back, c);
    }

    #[test]
    fn truncated_construction_is_an_error_not_a_panic() {
        let full = encode_construction(&rich_construction());
        for cut in 0..full.len() {
            if let Some(prefix) = full.get(..cut) {
                let _ = decode_construction(prefix);
            }
        }
    }

    #[test]
    fn trailing_garbage_on_construction_is_rejected() {
        let mut bytes = encode_construction(&rich_construction());
        bytes.push(0);
        assert_eq!(decode_construction(&bytes), Err(PlanWireError::TooLarge));
    }

    #[test]
    fn every_seccomp_action_round_trips() {
        for a in [
            Action::Allow,
            Action::Errno(13),
            Action::KillProcess,
            Action::KillThread,
            Action::Trap,
            Action::Log,
        ] {
            let mut w = Writer::new();
            put_action(&mut w, a);
            let mut r = Reader::new(&w.buf);
            assert_eq!(get_action(&mut r).expect("action"), a);
        }
    }

    #[test]
    fn truncated_blob_is_an_error_not_a_panic() {
        let full = encode_plan(&rich_plan());
        for cut in 0..full.len() {
            // Every prefix must decode to an Err, never panic or over-read.
            if let Some(prefix) = full.get(..cut) {
                let _ = decode_plan(prefix);
            }
        }
        let half = full.get(..full.len() / 2).expect("half");
        assert!(decode_plan(half).is_err());
    }

    #[test]
    fn trailing_garbage_is_rejected() {
        let mut bytes = encode_plan(&rich_plan());
        bytes.push(0);
        assert_eq!(decode_plan(&bytes), Err(PlanWireError::TooLarge));
    }

    #[test]
    fn oversized_count_is_rejected_before_allocation() {
        // namespaces(4) + empty cgroup path(4) + cgroup_join(1) + view None(1)
        // + new_root None(1), then a landlock_fs count of u32::MAX.
        let mut w = Writer::new();
        w.u32(0); // namespaces
        w.bytes(b""); // cgroup
        w.bool(false); // cgroup_join
        w.bool(false); // view
        w.bool(false); // new_root
        w.u32(u32::MAX); // landlock_fs count — absurd
        assert_eq!(decode_plan(&w.buf), Err(PlanWireError::TooLarge));
    }

    #[test]
    fn unknown_resource_name_is_rejected() {
        // A plan with one `nofile` ulimit; tamper the encoded name in place to an unknown
        // (same-length) string and assert the decoder refuses it (Resource is a closed
        // enum, so the bad value can only arrive over the wire — exactly the case to gate).
        let mut p = rich_plan();
        p.ulimits = vec![(resource_by_name("nofile").expect("nofile"), 1, 2)];
        let mut bytes = encode_plan(&p);
        let needle = b"nofile";
        let at = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("the encoded name is present");
        let end = at + needle.len();
        bytes
            .get_mut(at..end)
            .expect("name range")
            .copy_from_slice(b"zzzzzz");
        assert_eq!(decode_plan(&bytes), Err(PlanWireError::BadResource));
    }

    #[test]
    fn resource_name_round_trips_every_known_resource() {
        for name in kennel_policy_resources() {
            let res = resource_by_name(name).expect("known");
            assert_eq!(resource_name(res), Some(*name), "round-trip {name}");
        }
    }

    /// The resource names the codec must handle (mirrors the policy's list).
    fn kennel_policy_resources() -> &'static [&'static str] {
        &[
            "as",
            "core",
            "cpu",
            "data",
            "fsize",
            "locks",
            "memlock",
            "msgqueue",
            "nice",
            "nofile",
            "nproc",
            "rtprio",
            "rttime",
            "sigpending",
            "stack",
        ]
    }
}
