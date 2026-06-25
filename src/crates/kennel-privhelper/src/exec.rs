//! Request dispatch: validate, then perform the one privileged operation.
//!
//! This is the privileged side of the trust boundary
//! (`docs/architecture/04-trust-boundaries.md`, boundary 1): every request is
//! validated against the reserved scope *before* any privileged syscall. The one
//! remaining standalone op here is the loopback-address *delete* (teardown); the
//! address *add* and the egress-BPF *attach* are folded into the `construct` factory,
//! which delegates the BPF attach to the `kennel-privhelper-bpf` sub-helper. The
//! privileged work routes through `kennel-lib-syscall` (netlink); this crate stays
//! `#![forbid(unsafe_code)]`.

use std::ffi::CString;

use crate::validate::{validate_addr, AddrRequest, Refusal, ReservedScope};
use crate::wire::{Op, Request, Response};

/// Stable refusal codes carried on the wire (`Response::refusal`).
const fn refusal_code(r: &Refusal) -> u8 {
    match r {
        Refusal::BadPrefix { .. } => 1,
        Refusal::AddrOutOfScope => 2,
        Refusal::InterfaceNotAllowed => 3,
        Refusal::InterfaceNameTooLong => 4,
    }
}

/// A refusal code for "this helper has no configured reserved scope, so it
/// cannot service an address request". Distinct from the validation refusals.
pub const REFUSAL_NO_SCOPE: u8 = 100;

/// A refusal code for "the target cgroup directory is not owned by the caller".
///
/// Under the delegated-subtree model (`08-enforcement-architecture.md` §8.5),
/// kenneld creates kennel cgroups inside the user's systemd-delegated subtree, so a
/// legitimate kennel cgroup is owned by the caller's uid. The `kennel-privhelper-bpf`
/// sub-helper performs the cgroup attach and rejects an unowned cgroup with this code;
/// `refusal_message` is the shared audit description for it.
pub const REFUSAL_CGROUP_NOT_OWNED: u8 = 101;

/// A short, stable description of a wire refusal code.
///
/// For the `message` field of a `priv.refuse` audit event (`02-3`). Mirrors the
/// `refusal_code` table and the scope/ownership constants so the audit and the
/// helper share one source of truth; an unrecognised code (a future helper
/// version) maps to `"refused"`.
#[must_use]
pub const fn refusal_message(code: u8) -> &'static str {
    match code {
        1 => "prefix length is wrong for the address family",
        2 => "address is outside the reserved per-kennel subnet",
        3 => "interface is not `lo` or a `<namespace>-<id>` dummy",
        4 => "interface name exceeds the kernel length limit",
        REFUSAL_NO_SCOPE => "helper has no configured reserved scope for this user",
        REFUSAL_CGROUP_NOT_OWNED => "target cgroup is not owned by the caller",
        _ => "refused",
    }
}

fn errno_of(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

/// Validate and perform `req` — the one remaining standalone op, `Op::DelAddr` (teardown).
///
/// (The address *add* and the egress-BPF *attach* are folded into the factory's
/// `construct` op — see `construct.rs` — which delegates the BPF attach to
/// `kennel-privhelper-bpf`.) Confined to the caller's allocation (`scope`), so a user
/// with no allocation can do nothing. Returns the [`Response`] to send back.
#[must_use]
pub fn perform(req: &Request, scope: Option<&ReservedScope>) -> Response {
    let Some(scope) = scope else {
        return Response::refused(REFUSAL_NO_SCOPE);
    };
    match req.op {
        Op::DelAddr => perform_addr(req, scope),
    }
}

fn perform_addr(req: &Request, scope: &ReservedScope) -> Response {
    let areq = AddrRequest {
        ctx: req.ctx,
        interface: req.interface.clone(),
        addr: req.addr,
        prefix: req.prefix,
    };
    if let Err(r) = validate_addr(&areq, scope) {
        return Response::refused(refusal_code(&r));
    }
    // Validation passed; resolve the interface and perform the netlink op.
    let Ok(cname) = CString::new(req.interface.clone()) else {
        return Response::protocol();
    };
    let ifindex = match kennel_lib_syscall::netlink::if_index(&cname) {
        Ok(i) => i,
        Err(e) => return Response::internal(errno_of(&e)),
    };
    // The only standalone address op is the teardown delete; the add is folded into construct.
    match kennel_lib_syscall::netlink::del_address(ifindex, req.addr, req.prefix) {
        Ok(()) => Response::ok(),
        Err(e) => Response::internal(errno_of(&e)),
    }
}
