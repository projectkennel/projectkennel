//! Request dispatch: validate, then perform the one privileged operation.
//!
//! This is the privileged side of the trust boundary
//! (`architecture/04-trust-boundaries.md`, boundary 1): every request is
//! validated against the reserved scope *before* any privileged syscall. The
//! privileged work routes through `kennel-syscall` (netlink for addresses) and
//! `std::fs` (cgroup directories); this crate stays `#![forbid(unsafe_code)]`.

use std::ffi::CString;

use crate::validate::{validate_addr, validate_cgroup, AddrRequest, CgroupRequest, Refusal, ReservedScope};
use crate::wire::{Op, Request, Response};

/// Stable refusal codes carried on the wire (`Response::refusal`).
const fn refusal_code(r: &Refusal) -> u8 {
    match r {
        Refusal::BadPrefix { .. } => 1,
        Refusal::AddrOutOfScope => 2,
        Refusal::InterfaceNotAllowed => 3,
        Refusal::InterfaceNameTooLong => 4,
        Refusal::CgroupPathNotAbsolute => 5,
        Refusal::CgroupPathTraversal => 6,
        Refusal::CgroupPathOutsidePrefix => 7,
    }
}

/// A refusal code for "this helper has no configured reserved scope, so it
/// cannot service an address request". Distinct from the validation refusals.
pub const REFUSAL_NO_SCOPE: u8 = 100;

fn errno_of(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

/// Validate and perform `req`. Address operations require a configured `scope`
/// (the installation constants, from a trusted source); cgroup operations do
/// not. Returns the [`Response`] to send back.
#[must_use]
pub fn perform(req: &Request, scope: Option<&ReservedScope>) -> Response {
    match req.op {
        Op::AddAddr | Op::DelAddr => {
            scope.map_or_else(|| Response::refused(REFUSAL_NO_SCOPE), |s| perform_addr(req, *s))
        }
        Op::CreateCgroup | Op::DeleteCgroup => perform_cgroup(req),
    }
}

fn perform_addr(req: &Request, scope: ReservedScope) -> Response {
    let areq = AddrRequest {
        ctx: req.ctx,
        interface: req.interface.clone(),
        addr: req.addr,
        prefix: req.prefix,
    };
    if let Err(r) = validate_addr(&areq, &scope) {
        return Response::refused(refusal_code(&r));
    }
    // Validation passed; resolve the interface and perform the netlink op.
    let Ok(cname) = CString::new(req.interface.clone()) else {
        return Response::protocol();
    };
    let ifindex = match kennel_syscall::netlink::if_index(&cname) {
        Ok(i) => i,
        Err(e) => return Response::internal(errno_of(&e)),
    };
    let result = match req.op {
        Op::AddAddr => kennel_syscall::netlink::add_address(ifindex, req.addr, req.prefix),
        _ => kennel_syscall::netlink::del_address(ifindex, req.addr, req.prefix),
    };
    match result {
        Ok(()) => Response::ok(),
        Err(e) => Response::internal(errno_of(&e)),
    }
}

fn perform_cgroup(req: &Request) -> Response {
    let creq = CgroupRequest { path: req.cgroup_path.clone() };
    if let Err(r) = validate_cgroup(&creq) {
        return Response::refused(refusal_code(&r));
    }
    // Create the leaf (and any missing ancestors, all under the validated
    // prefix); delete only the leaf.
    let result = match req.op {
        Op::CreateCgroup => std::fs::create_dir_all(&req.cgroup_path),
        _ => std::fs::remove_dir(&req.cgroup_path),
    };
    match result {
        Ok(()) => Response::ok(),
        Err(e) => Response::internal(errno_of(&e)),
    }
}
