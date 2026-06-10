//! The node-0 service protocol: transaction verb codes and reply status bytes.
//!
//! Shared by `kenneld`'s context manager and the in-kennel clients (the af-unix
//! proxy, future facades). Internal-stable (`02-4-binder.md` §Node 0): both ends ship
//! from one release, so this module is the single source of the convention.

/// Node-0 transaction verbs (the `code` field). `IServiceManager`-style semantics;
/// the numeric codes are Project Kennel's own (not Android-wire-compatible).
pub mod verb {
    /// Register a service the caller provides.
    pub const ADD_SERVICE: u32 = 1;
    /// Resolve a service name.
    pub const GET_SERVICE: u32 = 2;
    /// Whether a service is declared for the caller.
    pub const IS_DECLARED: u32 = 3;
    /// The service names the caller is granted to look up.
    pub const LIST_SERVICES: u32 = 4;
    /// Connect a granted `AF_UNIX` socket and return the connected fd (the af-unix
    /// facade; sent with `transact_fd`, the reply carries the socket fd).
    pub const CONNECT_AFUNIX: u32 = 5;
    /// Request an outbound network connection (the `INet` egress facade, §7.5.2).
    ///
    /// `kennel-netshim` transacts the request payload `[transport: u8 | port: u16
    /// big-endian | host: UTF-8]` (see [`transport`]) to kenneld, which decides under
    /// `[net.proxy]`, resolves the name, pins the vetted address, and (with the conduit
    /// built) returns the connection fd.
    pub const CONNECT_INET: u32 = 6;
}

/// The transport byte in a [`verb::CONNECT_INET`] request (the wire is internal-stable;
/// both ends ship from one release). Mirrors `kennel_netproxy::allow::Transport`.
pub mod transport {
    /// TCP (SOCKS5 `CONNECT`).
    pub const TCP: u8 = 0;
    /// UDP (SOCKS5 `UDP ASSOCIATE`; reserved — not yet served).
    pub const UDP: u8 = 1;
}

/// Node-0 **lifecycle/config verbs** spoken only by `kennel-init`, the kennel's uid-0
/// PID 1 (`docs/design/07-2-kennel-init.md` §7.2.4).
///
/// A distinct high code range, disjoint from the [`verb`] registry codes (1–5), so the
/// two protocols never collide and `kenneld` can gate the lifecycle branch separately:
/// it serves these **only** when the kernel-stamped
/// `sender_pid == init_host_pid && sender_euid == 0` (the privhelper reports
/// `init_host_pid`; a host-side context manager sees host pids, not the kennel-internal
/// `1`).
pub mod lifecycle {
    /// `kennel-init` pulls its supervision-half.
    ///
    /// The reply carries the `kennel-spawn::wire::encode_supervision` bytes as a plain data
    /// reply. (The interactive pty does NOT ride binder: the privhelper factory passes the
    /// return socket on the construction channel and `kennel-init` inherits it at
    /// `kennel_syscall::pty::PTY_RETURN_FD` — `07-2`, decoupled from the bus.)
    pub const GET_SANDBOX_PLAN: u32 = 0x100;
    /// `kennel-init` reports the facades are up (the facade→pid map), before it execs
    /// the workload.
    pub const NOTIFY_BOOT_SYNC: u32 = 0x101;
    /// `kennel-init` reports a facade died (so `kenneld` can audit / tear down).
    pub const NOTIFY_FACADE_CRASH: u32 = 0x102;
    /// `kennel-init` reports it is about to `execve` the workload.
    pub const NOTIFY_WORKLOAD_EXEC: u32 = 0x103;
    /// `kennel-init` reports it re-forked a crashed facade (payload: the new host pid).
    pub const NOTIFY_FACADE_RESTART: u32 = 0x104;
    /// `kennel-init`'s TTL timer fired (§9.7) — a **blocking** request.
    ///
    /// kenneld freezes the kennel's cgroup (atomic suspend — kennel-init is mid-call, so it just
    /// blocks), audits, and decides per the policy's expiry action. The **reply** byte is
    /// [`ttl::RESUME`] (kenneld thawed; the call returns and the kennel picks up where it left
    /// off) or [`ttl::TERMINATE`] (kennel-init should exit; kenneld may also kill the frozen
    /// cgroup outright). No payload.
    pub const NOTIFY_TTL_EXPIRED: u32 = 0x105;
}

/// The reply byte to a [`lifecycle::NOTIFY_TTL_EXPIRED`] call.
pub mod ttl {
    /// Resume: kenneld thawed the cgroup; the workload continues (`warn`/`renew`).
    pub const RESUME: u8 = 0;
    /// Terminate: the kennel should stop (`exit`); kenneld has frozen and will kill it.
    pub const TERMINATE: u8 = 1;
}

/// Reply status byte (the first byte of a data reply).
pub mod status {
    /// Success (registered / found / true).
    pub const OK: u8 = 0;
    /// Refused by policy (not declared for this caller).
    pub const DENIED: u8 = 1;
    /// Permitted but no such registered service.
    pub const NOT_FOUND: u8 = 2;
    /// Refused: the name is in the reserved `org.projectkennel.*` namespace.
    pub const REFUSED_RESERVED: u8 = 3;
    /// The request was malformed (bad verb, oversized/!UTF-8 name).
    pub const BAD_REQUEST: u8 = 4;
}
