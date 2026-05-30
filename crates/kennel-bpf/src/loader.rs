//! ELF parsing (via `object`), map creation, relocation patching, and program
//! load. The map/program ABI mirrors `bpf/maps.h` and the `SEC()` names of
//! `bpf/*.bpf.c`.

use std::collections::BTreeMap;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget};

use crate::sys;

// Map types (enum bpf_map_type) and flags used by our maps.
const MAP_TYPE_ARRAY: u32 = 2;
const MAP_TYPE_LPM_TRIE: u32 = 11;
const MAP_TYPE_RINGBUF: u32 = 27;
const F_NO_PREALLOC: u32 = 1;

// Program type / attach types (enum bpf_prog_type / bpf_attach_type).
const PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
const CGROUP_INET4_BIND: u32 = 8;
const CGROUP_INET6_BIND: u32 = 9;
const CGROUP_INET4_CONNECT: u32 = 10;
const CGROUP_INET6_CONNECT: u32 = 11;
const CGROUP_UDP4_SENDMSG: u32 = 14;
const CGROUP_UDP6_SENDMSG: u32 = 15;

/// One BPF map, as declared in `bpf/maps.h`. Keyed by the symbol name the
/// programs reference it by.
#[derive(Debug, Clone, Copy)]
pub struct MapSpec {
    /// The map's symbol name (e.g. `"allow_v4"`).
    pub name: &'static str,
    /// `bpf_map_type`.
    pub map_type: u32,
    /// Key size in bytes (0 for ringbuf).
    pub key_size: u32,
    /// Value size in bytes (0 for ringbuf).
    pub value_size: u32,
    /// Maximum entries (the byte size for a ringbuf).
    pub max_entries: u32,
    /// `map_flags`.
    pub map_flags: u32,
}

/// The maps of `bpf/maps.h`. Value sizes match the structs there.
pub const KENNEL_MAPS: &[MapSpec] = &[
    MapSpec {
        name: "kennel_meta_map",
        map_type: MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: 64,
        max_entries: 1,
        map_flags: 0,
    },
    MapSpec {
        name: "deny_v4",
        map_type: MAP_TYPE_LPM_TRIE,
        key_size: 8,
        value_size: 8,
        max_entries: 256,
        map_flags: F_NO_PREALLOC,
    },
    MapSpec {
        name: "deny_v6",
        map_type: MAP_TYPE_LPM_TRIE,
        key_size: 20,
        value_size: 8,
        max_entries: 256,
        map_flags: F_NO_PREALLOC,
    },
    MapSpec {
        name: "allow_v4",
        map_type: MAP_TYPE_LPM_TRIE,
        key_size: 8,
        value_size: 8,
        max_entries: 1024,
        map_flags: F_NO_PREALLOC,
    },
    MapSpec {
        name: "allow_v6",
        map_type: MAP_TYPE_LPM_TRIE,
        key_size: 20,
        value_size: 8,
        max_entries: 1024,
        map_flags: F_NO_PREALLOC,
    },
    MapSpec {
        name: "bind_subnet_map",
        map_type: MAP_TYPE_ARRAY,
        key_size: 4,
        value_size: 28,
        max_entries: 1,
        map_flags: 0,
    },
    MapSpec {
        name: "audit_ringbuf",
        map_type: MAP_TYPE_RINGBUF,
        key_size: 0,
        value_size: 0,
        max_entries: 1 << 20,
        map_flags: 0,
    },
];

/// One BPF program: its ELF section (the `SEC()` name), program type, and the
/// cgroup attach type.
#[derive(Debug, Clone, Copy)]
pub struct ProgramSpec {
    /// Stable identifier.
    pub name: &'static str,
    /// ELF section name (the `SEC("...")` argument).
    pub section: &'static str,
    /// `bpf_prog_type`.
    pub prog_type: u32,
    /// `bpf_attach_type` for the cgroup attach.
    pub attach_type: u32,
}

/// The `cgroup/sock_addr` family of `bpf/*.bpf.c` (connect/bind/sendmsg, v4/v6).
/// `sock_create` and `setsockopt` use other program types and are added with
/// their loaders.
pub const KENNEL_PROGRAMS: &[ProgramSpec] = &[
    ProgramSpec {
        name: "connect4",
        section: "cgroup/connect4",
        prog_type: PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type: CGROUP_INET4_CONNECT,
    },
    ProgramSpec {
        name: "connect6",
        section: "cgroup/connect6",
        prog_type: PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type: CGROUP_INET6_CONNECT,
    },
    ProgramSpec {
        name: "bind4",
        section: "cgroup/bind4",
        prog_type: PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type: CGROUP_INET4_BIND,
    },
    ProgramSpec {
        name: "bind6",
        section: "cgroup/bind6",
        prog_type: PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type: CGROUP_INET6_BIND,
    },
    ProgramSpec {
        name: "sendmsg4",
        section: "cgroup/sendmsg4",
        prog_type: PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type: CGROUP_UDP4_SENDMSG,
    },
    ProgramSpec {
        name: "sendmsg6",
        section: "cgroup/sendmsg6",
        prog_type: PROG_TYPE_CGROUP_SOCK_ADDR,
        attach_type: CGROUP_UDP6_SENDMSG,
    },
];

/// A loaded program plus the maps created for it (kept open so the caller can
/// populate them; the kernel also pins them via the program).
pub struct Loaded {
    /// The loaded program.
    pub program: OwnedFd,
    /// The created maps, by name.
    pub maps: BTreeMap<String, OwnedFd>,
}

impl Loaded {
    /// Attach the program to `cgroup` (exclusive) with its configured attach type.
    ///
    /// # Errors
    ///
    /// Returns the OS error if the attach is rejected.
    pub fn attach(&self, cgroup: BorrowedFd<'_>, attach_type: u32) -> io::Result<()> {
        sys::prog_attach_cgroup(cgroup, self.program.as_fd(), attach_type)
    }
}

fn other(msg: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Patch a map-fd `ld_imm64` at `off`: set `src_reg = BPF_PSEUDO_MAP_FD` and the
/// 32-bit immediate to the map's fd.
fn patch_map_fd(insns: &mut [u8], off: usize, fd: i32) -> io::Result<()> {
    let reg_idx = off
        .checked_add(1)
        .ok_or_else(|| other("reloc offset overflow"))?;
    let imm_lo = off
        .checked_add(4)
        .ok_or_else(|| other("reloc offset overflow"))?;
    let imm_hi = off
        .checked_add(8)
        .ok_or_else(|| other("reloc offset overflow"))?;
    let reg = insns
        .get_mut(reg_idx)
        .ok_or_else(|| other("reloc past end of program"))?;
    // src_reg is the high nibble; BPF_PSEUDO_MAP_FD == 1 -> high nibble 0x10.
    *reg = (*reg & 0x0f) | 0x10;
    let fd_bytes = fd.to_le_bytes();
    let dst = insns
        .get_mut(imm_lo..imm_hi)
        .ok_or_else(|| other("reloc past end of program"))?;
    dst.copy_from_slice(&fd_bytes);
    Ok(())
}

/// Load `prog` from the compiled BPF object `elf`, creating (and relocating) the
/// maps it references from `map_specs`.
///
/// # Errors
///
/// Returns an error if the ELF is malformed, a referenced map is unknown, a map
/// cannot be created, or the program fails to load/verify (the kernel's verifier
/// log is included in the error message).
pub fn load_program(elf: &[u8], prog: &ProgramSpec, map_specs: &[MapSpec]) -> io::Result<Loaded> {
    let file = object::File::parse(elf).map_err(other)?;
    let section = file
        .section_by_name(prog.section)
        .ok_or_else(|| other(format!("no section {}", prog.section)))?;
    let mut insns = section.data().map_err(other)?.to_vec();

    let mut maps: BTreeMap<String, OwnedFd> = BTreeMap::new();
    for (off, reloc) in section.relocations() {
        let RelocationTarget::Symbol(symidx) = reloc.target() else {
            continue;
        };
        let sym = file.symbol_by_index(symidx).map_err(other)?;
        let name = sym.name().map_err(other)?;
        if name.is_empty() {
            continue;
        }
        // Create the map once, then patch this instruction with its fd.
        if !maps.contains_key(name) {
            let spec = map_specs
                .iter()
                .find(|m| m.name == name)
                .ok_or_else(|| other(format!("relocation references unknown map `{name}`")))?;
            let fd = sys::map_create(
                spec.map_type,
                spec.key_size,
                spec.value_size,
                spec.max_entries,
                spec.map_flags,
            )?;
            maps.insert(name.to_owned(), fd);
        }
        let fd = maps.get(name).ok_or_else(|| other("map vanished"))?.as_fd();
        let raw = std::os::fd::AsRawFd::as_raw_fd(&fd);
        let off = usize::try_from(off).map_err(|_| other("reloc offset too large"))?;
        patch_map_fd(&mut insns, off, raw)?;
    }

    let mut log = vec![0u8; 64 * 1024];
    let program = sys::prog_load(prog.prog_type, prog.attach_type, &insns, c"GPL", &mut log)
        .map_err(|e| {
            let end = log.iter().position(|&b| b == 0).unwrap_or(0);
            let text = String::from_utf8_lossy(log.get(..end).unwrap_or(&[]));
            other(format!("prog_load failed: {e}\nverifier log:\n{text}"))
        })?;
    Ok(Loaded { program, maps })
}

#[cfg(all(test, feature = "root-tests"))]
mod root_tests {
    //! Run via `sudo -E cargo test -p kennel-bpf --features root-tests`. Compiles
    //! connect4 against UAPI headers (no CO-RE), loads it through this loader,
    //! attaches it to a fresh cgroup, and confirms it enforces: with empty maps
    //! connect4 fails closed, so a connect from inside the cgroup is denied.

    use super::*;
    use std::os::fd::AsFd;
    use std::path::Path;
    use std::process::Command;

    fn compile_connect4_uapi() -> Vec<u8> {
        let bpf = concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf");
        let tmp = std::env::temp_dir().join("kennel-bpf-test");
        std::fs::create_dir_all(&tmp).expect("mkdir");
        for f in ["maps.h", "audit_events.h", "kennel.bpf.h", "connect4.bpf.c"] {
            std::fs::copy(format!("{bpf}/{f}"), tmp.join(f)).expect("copy bpf src");
        }
        // Swap the CO-RE vmlinux.h include for the UAPI header.
        let c = tmp.join("connect4.bpf.c");
        let src = std::fs::read_to_string(&c).expect("read");
        std::fs::write(
            &c,
            src.replace("#include \"vmlinux.h\"", "#include <linux/bpf.h>"),
        )
        .expect("write");
        let obj = tmp.join("connect4.o");
        let status = Command::new("clang")
            .args(["-O2", "-Wall", "-target", "bpf", "-D__TARGET_ARCH_x86"])
            .arg("-I")
            .arg(&tmp)
            .args(["-I/usr/include", "-I/usr/include/x86_64-linux-gnu"])
            .arg("-c")
            .arg(&c)
            .arg("-o")
            .arg(&obj)
            .status()
            .expect("run clang");
        assert!(status.success(), "clang failed to compile connect4 (UAPI)");
        std::fs::read(&obj).expect("read object")
    }

    #[test]
    fn load_attach_and_enforce_connect4() {
        let elf = compile_connect4_uapi();
        let spec = KENNEL_PROGRAMS
            .iter()
            .find(|p| p.name == "connect4")
            .expect("connect4 spec");
        let loaded = load_program(&elf, spec, KENNEL_MAPS).expect("load connect4");
        // It referenced real maps.
        assert!(loaded.maps.contains_key("kennel_meta_map"));
        assert!(loaded.maps.contains_key("allow_v4"));

        // Fresh cgroup, attach the program.
        let cg = Path::new("/sys/fs/cgroup/kennel-bpf-test");
        let _ = std::fs::create_dir(cg);
        let cgfd = std::fs::File::open(cg).expect("open cgroup");
        loaded
            .attach(cgfd.as_fd(), spec.attach_type)
            .expect("attach connect4");

        // A child joins the cgroup and tries to connect; empty maps => fail closed.
        // SAFETY: fork(); the child only writes its pid, attempts one connect, and
        // _exit()s — never returning to the harness.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        let verdict = if child == 0 {
            let pid = std::process::id().to_string();
            let _ = std::fs::write(cg.join("cgroup.procs"), &pid);
            let denied = connect_denied();
            // SAFETY: _exit without unwinding/atexit after fork.
            unsafe { libc::_exit(i32::from(!denied)) };
        } else {
            let mut status = 0;
            // SAFETY: waitpid on our child with a valid status pointer.
            unsafe { libc::waitpid(child, std::ptr::from_mut(&mut status), 0) };
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        };

        // Cleanup before asserting so a failure does not leak the attach/cgroup.
        let _ = std::fs::remove_dir(cg);
        assert!(
            verdict,
            "connect4 with empty maps should deny the connect (fail closed)"
        );
    }

    /// Try to connect to 127.0.0.1:9; return true iff the connect was denied with
    /// EPERM/EACCES (the cgroup BPF verdict), false if it was permitted.
    fn connect_denied() -> bool {
        // SAFETY: a standard socket()/connect() sequence with a stack sockaddr_in
        // valid for the length passed; errno is read immediately after.
        unsafe {
            let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if s < 0 {
                return false;
            }
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            addr.sin_family = u16::try_from(libc::AF_INET).unwrap_or(2);
            addr.sin_port = 9u16.to_be();
            addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            let len = u32::try_from(std::mem::size_of::<libc::sockaddr_in>()).unwrap_or(16);
            let rc = libc::connect(s, std::ptr::from_ref(&addr).cast::<libc::sockaddr>(), len);
            let err = io::Error::last_os_error().raw_os_error();
            libc::close(s);
            rc < 0 && matches!(err, Some(libc::EPERM | libc::EACCES))
        }
    }
}
