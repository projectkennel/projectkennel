// SPDX-License-Identifier: Apache-2.0

//! System facts a confined workload can already learn by syscall: memory (`sysinfo(2)`),
//! the kernel identity (`uname(2)`), and the usable CPU count.
//!
//! # Purpose
//!
//! The view's synthesized `/proc` files (#218, `kennel_lib_policy::procfs`) are rendered from
//! templates filled with exactly these values, gathered in the construction child, so a
//! synthesized file never reveals more than the workload's own syscalls would. Thin, safe
//! wrappers over `nix` (no `unsafe` here).

use std::io;

/// Memory totals, in bytes, as `sysinfo(2)` reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Memory {
    /// Total usable RAM.
    pub total: u64,
    /// RAM not in use.
    pub free: u64,
    /// Seconds since boot.
    pub uptime_secs: u64,
}

/// The kernel identity, as `uname(2)` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kernel {
    /// `sysname` (`Linux`).
    pub sysname: String,
    /// `release` (`7.0.0-43-generic`).
    pub release: String,
    /// `version` (`#43-Ubuntu SMP PREEMPT_DYNAMIC …`).
    pub version: String,
    /// `machine` (`x86_64`, `aarch64`).
    pub machine: String,
}

/// Read memory totals and uptime via `sysinfo(2)`.
///
/// # Errors
///
/// Returns the OS error if `sysinfo(2)` fails.
pub fn memory() -> io::Result<Memory> {
    let info = nix::sys::sysinfo::sysinfo().map_err(io::Error::from)?;
    Ok(Memory {
        total: info.ram_total(),
        free: info.ram_unused(),
        uptime_secs: info.uptime().as_secs(),
    })
}

/// Read the kernel identity via `uname(2)`.
///
/// # Errors
///
/// Returns the OS error if `uname(2)` fails, or `InvalidData` if a field is not UTF-8.
pub fn kernel() -> io::Result<Kernel> {
    let uts = nix::sys::utsname::uname().map_err(io::Error::from)?;
    let text = |field: &std::ffi::OsStr, name: &str| {
        field.to_str().map(str::to_owned).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("uname {name} is not UTF-8"),
            )
        })
    };
    Ok(Kernel {
        sysname: text(uts.sysname(), "sysname")?,
        release: text(uts.release(), "release")?,
        version: text(uts.version(), "version")?,
        machine: text(uts.machine(), "machine")?,
    })
}

/// The number of CPUs this process may run on: its affinity mask, further capped by a cgroup
/// v2 `cpu.max` quota (`std::thread::available_parallelism`). At least 1.
#[must_use]
pub fn usable_cpus() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_reports_plausible_totals() {
        let m = memory().expect("sysinfo");
        assert!(m.total > 16 << 20, "at least 16 MiB of RAM: {m:?}");
        assert!(m.free <= m.total, "free never exceeds total: {m:?}");
    }

    #[test]
    fn kernel_reports_linux() {
        let k = kernel().expect("uname");
        assert_eq!(k.sysname, "Linux");
        assert!(!k.release.is_empty() && !k.version.is_empty(), "{k:?}");
        assert_eq!(k.machine, std::env::consts::ARCH, "{k:?}");
    }

    #[test]
    fn usable_cpus_is_at_least_one_and_within_the_affinity() {
        let n = usable_cpus();
        assert!(n >= 1);
        let affinity =
            nix::sched::sched_getaffinity(nix::unistd::Pid::from_raw(0)).expect("affinity");
        let in_mask = (0..nix::sched::CpuSet::count())
            .filter(|&c| affinity.is_set(c).unwrap_or(false))
            .count();
        assert!(n <= in_mask, "{n} usable vs {in_mask} in the affinity mask");
    }
}
