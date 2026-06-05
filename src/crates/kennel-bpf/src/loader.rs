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
const PROG_TYPE_CGROUP_SOCK: u32 = 9;
const PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
const PROG_TYPE_CGROUP_SOCKOPT: u32 = 25;
const CGROUP_INET_SOCK_CREATE: u32 = 2;
const CGROUP_INET4_BIND: u32 = 8;
const CGROUP_INET6_BIND: u32 = 9;
const CGROUP_INET4_CONNECT: u32 = 10;
const CGROUP_INET6_CONNECT: u32 = 11;
const CGROUP_UDP4_SENDMSG: u32 = 14;
const CGROUP_UDP6_SENDMSG: u32 = 15;
const CGROUP_SETSOCKOPT: u32 = 22;

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

/// Every program in `bpf/*.bpf.c`.
///
/// The `cgroup/sock_addr` family (connect/bind/sendmsg, v4/v6), plus
/// `sock_create` (`cgroup/sock`) and `setsockopt` (`cgroup/sockopt`), which use
/// distinct program and attach types.
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
    ProgramSpec {
        name: "sock_create",
        section: "cgroup/sock_create",
        prog_type: PROG_TYPE_CGROUP_SOCK,
        attach_type: CGROUP_INET_SOCK_CREATE,
    },
    ProgramSpec {
        name: "setsockopt",
        section: "cgroup/setsockopt",
        prog_type: PROG_TYPE_CGROUP_SOCKOPT,
        attach_type: CGROUP_SETSOCKOPT,
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

    /// Insert or overwrite an element of the named map (`BPF_MAP_UPDATE_ELEM`).
    /// `key`/`value` must match the map's declared key/value sizes.
    ///
    /// # Errors
    ///
    /// Returns an error if the program did not reference a map of that name, or
    /// the OS error if the kernel rejects the update.
    pub fn update_map(&self, name: &str, key: &[u8], value: &[u8], flags: u64) -> io::Result<()> {
        let map = self
            .maps
            .get(name)
            .ok_or_else(|| other(format!("no map `{name}` in this program")))?;
        sys::map_update(map.as_fd(), key, value, flags)
    }

    /// Detach this program's `attach_type` from `cgroup` (`BPF_PROG_DETACH`).
    ///
    /// # Errors
    ///
    /// Returns the OS error if nothing of that type is attached to the cgroup.
    pub fn detach(&self, cgroup: BorrowedFd<'_>, attach_type: u32) -> io::Result<()> {
        sys::prog_detach_cgroup(cgroup, attach_type)
    }

    /// Pin the loaded program to a bpffs `path` so it outlives the process
    /// (`BPF_OBJ_PIN`). Reopen it later with [`sys::obj_get`].
    ///
    /// # Errors
    ///
    /// Returns the OS error if the path exists, is not on bpffs, or the pin is
    /// rejected.
    pub fn pin_program(&self, path: &std::ffi::CStr) -> io::Result<()> {
        sys::obj_pin(self.program.as_fd(), path)
    }

    /// Map the named ringbuf for reading. `map_specs` supplies the map's byte
    /// capacity (its `max_entries`); pass the same slice used to load.
    ///
    /// # Errors
    ///
    /// Returns an error if the program did not reference a ringbuf of that name,
    /// the spec is missing, or the `mmap` fails.
    pub fn ringbuf<'a>(
        &'a self,
        name: &str,
        map_specs: &[MapSpec],
    ) -> io::Result<crate::ringbuf::RingBuffer<'a>> {
        let map = self
            .maps
            .get(name)
            .ok_or_else(|| other(format!("no map `{name}` in this program")))?;
        let spec = map_specs
            .iter()
            .find(|m| m.name == name)
            .ok_or_else(|| other(format!("no spec for map `{name}`")))?;
        let size = usize::try_from(spec.max_entries).map_err(|_| other("ringbuf size overflow"))?;
        crate::ringbuf::RingBuffer::new(map.as_fd(), size)
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

    /// Skip a root-only test when not running as root, matching the
    /// skip-with-cause convention of the other crates' root-tests (a skip is not
    /// a proof). BPF cgroup load needs privilege, so without it these tests can
    /// only fail; skipping keeps `cargo test --all-features` green for an
    /// unprivileged runner while `sudo … --features root-tests` still exercises them.
    fn skip_if_unprivileged(test: &str) -> bool {
        // SAFETY: geteuid() only reads the calling process's effective uid; it
        // takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            eprintln!("skipping {test}: requires root (euid={euid}) for BPF load");
            return true;
        }
        false
    }

    /// Compile `bpf/<name>.bpf.c` against the kernel UAPI (no CO-RE) and return
    /// the resulting object bytes. The three shared headers are copied alongside.
    fn compile_uapi(name: &str) -> Vec<u8> {
        let bpf = concat!(env!("CARGO_MANIFEST_DIR"), "/../../bpf");
        let tmp = std::env::temp_dir().join("kennel-bpf-test");
        std::fs::create_dir_all(&tmp).expect("mkdir");
        for f in ["maps.h", "audit_events.h", "kennel.bpf.h"] {
            std::fs::copy(format!("{bpf}/{f}"), tmp.join(f)).expect("copy bpf header");
        }
        let src = format!("{name}.bpf.c");
        std::fs::copy(format!("{bpf}/{src}"), tmp.join(&src)).expect("copy bpf src");
        // The sources already include <linux/bpf.h> (UAPI, no CO-RE).
        let c = tmp.join(&src);
        let obj = tmp.join(format!("{name}.o"));
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
        assert!(status.success(), "clang failed to compile {name} (UAPI)");
        std::fs::read(&obj).expect("read object")
    }

    /// Every program in `KENNEL_PROGRAMS` compiles, parses, and loads/verifies
    /// through this loader (with its maps created and relocated). This is the
    /// load-and-verify matrix; `load_attach_and_enforce_connect4` covers the
    /// attach-and-enforce behaviour for one representative program.
    #[test]
    fn all_programs_load() {
        if skip_if_unprivileged("all_programs_load") {
            return;
        }
        let mut failures = Vec::new();
        for spec in KENNEL_PROGRAMS {
            let elf = compile_uapi(spec.name);
            match load_program(&elf, spec, KENNEL_MAPS) {
                // The program FD is live; dropping `loaded` closes it (and the maps).
                Ok(loaded) => {
                    let fd = std::os::fd::AsRawFd::as_raw_fd(&loaded.program.as_fd());
                    if fd < 0 {
                        failures.push(format!("{}: invalid program fd", spec.name));
                    }
                }
                Err(e) => failures.push(format!("{}: {e}", spec.name)),
            }
        }
        assert!(
            failures.is_empty(),
            "programs failed to load:\n{}",
            failures.join("\n")
        );
    }

    /// Build the `(key, value)` byte pair for an `allow_v4` entry: a /32 LPM key
    /// for `addr` (network-order bytes) and an `allow_entry` permitting any
    /// protocol on `[port_min, port_max]`. Layouts match `bpf/maps.h`.
    fn allow_v4_entry(addr: [u8; 4], port_min: u16, port_max: u16) -> ([u8; 8], [u8; 8]) {
        let mut key = [0u8; 8];
        key[0..4].copy_from_slice(&32u32.to_ne_bytes()); // prefixlen
        key[4..8].copy_from_slice(&addr); // addr, already network order
        let mut val = [0u8; 8]; // allow_entry: port_min, port_max, protocol, flags, _pad[2]
        val[0..2].copy_from_slice(&port_min.to_ne_bytes());
        val[2..4].copy_from_slice(&port_max.to_ne_bytes());
        // val[4] protocol = 0 (KENNEL_PROTO_ANY); val[5] flags = 0; val[6..8] pad.
        (key, val)
    }

    /// Fork a child that joins `cg`, attempts one connect to 127.0.0.1:9, and
    /// `_exit`s with the verdict. Returns true iff the BPF verdict *denied* the
    /// connect (EPERM/EACCES); an allowed connect reaches the stack and is
    /// refused (ECONNREFUSED), which reads here as not-denied.
    fn connect_denied_in_cgroup(cg: &Path) -> bool {
        // SAFETY: fork(); the child only writes its pid, attempts one connect, and
        // _exit()s — never returning to the harness.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            let pid = std::process::id().to_string();
            let _ = std::fs::write(cg.join("cgroup.procs"), &pid);
            let denied = connect_denied();
            // SAFETY: _exit without unwinding/atexit after fork.
            unsafe { libc::_exit(i32::from(denied)) };
        }
        let mut status = 0;
        // SAFETY: waitpid on our child with a valid status pointer.
        unsafe { libc::waitpid(child, std::ptr::from_mut(&mut status), 0) };
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 1
    }

    /// Attach `loaded` (a connect4 program) to a fresh cgroup at `cg`, run `body`
    /// while it is attached, then remove the cgroup on the happy path. A panic in
    /// `body` leaks the test cgroup, which is harmless and visible.
    fn with_attached_connect4(cg: &Path, loaded: &Loaded, body: impl FnOnce()) {
        let _ = std::fs::create_dir(cg);
        let cgfd = std::fs::File::open(cg).expect("open cgroup");
        let spec = KENNEL_PROGRAMS
            .iter()
            .find(|p| p.name == "connect4")
            .expect("connect4 spec");
        loaded
            .attach(cgfd.as_fd(), spec.attach_type)
            .expect("attach connect4");
        body();
        let _ = std::fs::remove_dir(cg);
    }

    fn load_connect4() -> Loaded {
        let elf = compile_uapi("connect4");
        let spec = KENNEL_PROGRAMS
            .iter()
            .find(|p| p.name == "connect4")
            .expect("connect4 spec");
        load_program(&elf, spec, KENNEL_MAPS).expect("load connect4")
    }

    #[test]
    fn load_attach_and_enforce_connect4() {
        if skip_if_unprivileged("load_attach_and_enforce_connect4") {
            return;
        }
        let loaded = load_connect4();
        // It referenced real maps.
        assert!(loaded.maps.contains_key("kennel_meta_map"));
        assert!(loaded.maps.contains_key("allow_v4"));

        // Empty maps => fail closed: a connect from inside the cgroup is denied.
        let cg = Path::new("/sys/fs/cgroup/kennel-bpf-test");
        let mut denied = false;
        with_attached_connect4(cg, &loaded, || denied = connect_denied_in_cgroup(cg));
        assert!(
            denied,
            "connect4 with empty maps should deny the connect (fail closed)"
        );
    }

    #[test]
    fn connect_allowed_when_map_populated() {
        if skip_if_unprivileged("connect_allowed_when_map_populated") {
            return;
        }
        let loaded = load_connect4();
        // Allow 127.0.0.1/32 on any port via BPF_MAP_UPDATE_ELEM.
        let (key, val) = allow_v4_entry([127, 0, 0, 1], 0, u16::MAX);
        loaded
            .update_map("allow_v4", &key, &val, sys::BPF_ANY)
            .expect("populate allow_v4");

        // With a matching allow entry the BPF verdict permits the connect; the
        // stack then refuses :9 (no listener), which is *not* a BPF denial.
        let cg = Path::new("/sys/fs/cgroup/kennel-bpf-test-allow");
        let mut denied = true;
        with_attached_connect4(cg, &loaded, || denied = connect_denied_in_cgroup(cg));
        assert!(
            !denied,
            "connect4 with a matching allow_v4 entry should permit the connect"
        );
    }

    #[test]
    fn drains_audit_event_on_connect() {
        if skip_if_unprivileged("drains_audit_event_on_connect") {
            return;
        }
        let loaded = load_connect4();
        // Map the audit ringbuf before triggering traffic.
        let mut rb = loaded
            .ringbuf("audit_ringbuf", KENNEL_MAPS)
            .expect("map audit ringbuf");

        let cg = Path::new("/sys/fs/cgroup/kennel-bpf-test-audit");
        let _ = std::fs::create_dir(cg);
        let cgfd = std::fs::File::open(cg).expect("open cgroup");
        let spec = KENNEL_PROGRAMS
            .iter()
            .find(|p| p.name == "connect4")
            .expect("connect4 spec");
        loaded
            .attach(cgfd.as_fd(), spec.attach_type)
            .expect("attach connect4");

        // One connect from inside the cgroup; empty maps => denied, which emits an
        // AUDIT_NET_CONNECT_DENY event to the ringbuf.
        let denied = connect_denied_in_cgroup(cg);

        let mut samples: Vec<Vec<u8>> = Vec::new();
        let _ = rb.poll(1000);
        rb.consume(|s| samples.push(s.to_vec()))
            .expect("consume ringbuf");

        let _ = std::fs::remove_dir(cg);

        assert!(denied, "precondition: the connect should have been denied");
        let ev = samples
            .first()
            .expect("expected an audit event after connect");
        assert!(ev.len() >= 48, "event too short: {} bytes", ev.len());
        // audit_hdr: magic @0 (LE u32), kind @6 (LE u16). See bpf/audit_events.h.
        let magic = u32::from_le_bytes(
            ev.get(0..4)
                .and_then(|b| b.try_into().ok())
                .expect("magic bytes"),
        );
        assert_eq!(magic, 0x4145_564E, "KENNEL_AUDIT_MAGIC (\"AEVN\")");
        let kind = u16::from_le_bytes(
            ev.get(6..8)
                .and_then(|b| b.try_into().ok())
                .expect("kind bytes"),
        );
        assert_eq!(kind, 1, "AUDIT_NET_CONNECT_DENY");
        // audit_payload_connect starts at offset 40 (hdr is 40 bytes).
        assert_eq!(ev.get(40), Some(&2u8), "family AF_INET");
        assert_eq!(
            ev.get(42..44),
            Some(&[0x00, 0x09][..]),
            "port 9, network order"
        );
        assert_eq!(
            ev.get(44..48),
            Some(&[127u8, 0, 0, 1][..]),
            "addr 127.0.0.1"
        );
    }

    #[test]
    fn detach_restores_connectivity() {
        if skip_if_unprivileged("detach_restores_connectivity") {
            return;
        }
        let loaded = load_connect4();
        let spec = KENNEL_PROGRAMS
            .iter()
            .find(|p| p.name == "connect4")
            .expect("connect4 spec");
        let cg = Path::new("/sys/fs/cgroup/kennel-bpf-test-detach");
        let _ = std::fs::create_dir(cg);
        let cgfd = std::fs::File::open(cg).expect("open cgroup");
        loaded
            .attach(cgfd.as_fd(), spec.attach_type)
            .expect("attach connect4");

        let denied_before = connect_denied_in_cgroup(cg);
        loaded
            .detach(cgfd.as_fd(), spec.attach_type)
            .expect("detach connect4");
        let denied_after = connect_denied_in_cgroup(cg);

        let _ = std::fs::remove_dir(cg);
        assert!(
            denied_before,
            "attached connect4 with empty maps should deny the connect"
        );
        assert!(
            !denied_after,
            "after detach the connect should no longer be BPF-denied"
        );
    }

    #[test]
    fn pin_and_get_program() {
        if skip_if_unprivileged("pin_and_get_program") {
            return;
        }
        let loaded = load_connect4();
        let pin = c"/sys/fs/bpf/kennel-bpf-test-pin";
        let pin_path = Path::new("/sys/fs/bpf/kennel-bpf-test-pin");
        // Clear any stale pin from an interrupted prior run.
        let _ = std::fs::remove_file(pin_path);

        loaded.pin_program(pin).expect("pin program to bpffs");
        let got = sys::obj_get(pin).expect("get pinned program back");
        assert!(
            std::os::fd::AsRawFd::as_raw_fd(&got.as_fd()) >= 0,
            "reopened pinned program fd should be valid"
        );

        let _ = std::fs::remove_file(pin_path);
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

    fn load_bind4() -> Loaded {
        let elf = compile_uapi("bind4");
        let spec = KENNEL_PROGRAMS
            .iter()
            .find(|p| p.name == "bind4")
            .expect("bind4 spec");
        load_program(&elf, spec, KENNEL_MAPS).expect("load bind4")
    }

    /// A 64-byte `kennel_meta` value with the magic/abi head and `bind_port_min`
    /// (offset 14, host order) set; everything else zero. Native byte order, as the
    /// producer (`kennel-spawn::plan`) writes it.
    fn meta_with_bind_floor(min_port: u16) -> [u8; 64] {
        const MAGIC: u32 = 0x4B4E_454C;
        const ABI: u16 = 1;
        let mut m = [0u8; 64];
        m[0..4].copy_from_slice(&MAGIC.to_ne_bytes());
        m[4..6].copy_from_slice(&ABI.to_ne_bytes());
        m[14..16].copy_from_slice(&min_port.to_ne_bytes());
        m
    }

    /// A 28-byte `bind_subnet` value: v4 `127.0.0.1//24`, v6 zero `/64`. The
    /// `INADDR_ANY` rewrite target, so an allowed wildcard bind lands on the loopback.
    fn bind_subnet_loopback() -> [u8; 28] {
        let mut v = [0u8; 28];
        v[0..4].copy_from_slice(&[127, 0, 0, 1]);
        v[4..8].copy_from_slice(&24u32.to_ne_bytes());
        v[24] = 64;
        v
    }

    /// In a child joined to `cg`, `bind()` a fresh TCP socket to `0.0.0.0:port` (which
    /// `bind4` rewrites to the kennel loopback when it allows). Returns true if the
    /// bind was refused by the cgroup BPF verdict (`EPERM`/`EACCES`).
    fn wildcard_bind_denied_in_cgroup(cg: &Path, port: u16) -> bool {
        // SAFETY: fork(); the child only joins the cgroup, binds once, and _exit()s.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            let pid = std::process::id().to_string();
            let _ = std::fs::write(cg.join("cgroup.procs"), &pid);
            // SAFETY: a standard socket()/bind() with a stack sockaddr_in valid for the
            // length passed; errno is read immediately after.
            let denied = unsafe {
                let s = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                let mut addr: libc::sockaddr_in = std::mem::zeroed();
                addr.sin_family = u16::try_from(libc::AF_INET).unwrap_or(2);
                addr.sin_port = port.to_be();
                addr.sin_addr.s_addr = 0; // INADDR_ANY
                let len = u32::try_from(std::mem::size_of::<libc::sockaddr_in>()).unwrap_or(16);
                let rc = libc::bind(s, std::ptr::from_ref(&addr).cast::<libc::sockaddr>(), len);
                let err = io::Error::last_os_error().raw_os_error();
                libc::close(s);
                rc < 0 && matches!(err, Some(libc::EPERM | libc::EACCES))
            };
            // SAFETY: _exit without unwinding/atexit after fork.
            unsafe { libc::_exit(i32::from(denied)) };
        }
        let mut status = 0;
        // SAFETY: waitpid on our child with a valid status pointer.
        unsafe { libc::waitpid(child, std::ptr::from_mut(&mut status), 0) };
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 1
    }

    fn with_attached_bind4(cg: &Path, loaded: &Loaded, body: impl FnOnce()) {
        let _ = std::fs::create_dir(cg);
        let cgfd = std::fs::File::open(cg).expect("open cgroup");
        let spec = KENNEL_PROGRAMS
            .iter()
            .find(|p| p.name == "bind4")
            .expect("bind4 spec");
        loaded
            .attach(cgfd.as_fd(), spec.attach_type)
            .expect("attach bind4");
        body();
        let _ = std::fs::remove_dir(cg);
    }

    #[test]
    fn bind4_enforces_the_min_port_floor() {
        if skip_if_unprivileged("bind4_enforces_the_min_port_floor") {
            return;
        }
        let loaded = load_bind4();
        loaded
            .update_map(
                "bind_subnet_map",
                &0u32.to_ne_bytes(),
                &bind_subnet_loopback(),
                sys::BPF_ANY,
            )
            .expect("populate bind_subnet");

        // Floor at 1024: a wildcard bind below it is denied; one at/above it is allowed
        // (rewritten to the loopback). The denied/allowed pair is the adversarial proof
        // (§8.3): the deny path actually denies on the running kernel.
        loaded
            .update_map(
                "kennel_meta_map",
                &0u32.to_ne_bytes(),
                &meta_with_bind_floor(1024),
                sys::BPF_ANY,
            )
            .expect("populate meta (floor 1024)");
        let cg = Path::new("/sys/fs/cgroup/kennel-bpf-test-bindfloor");
        let (mut low_denied, mut high_denied) = (false, true);
        with_attached_bind4(cg, &loaded, || {
            low_denied = wildcard_bind_denied_in_cgroup(cg, 80);
            high_denied = wildcard_bind_denied_in_cgroup(cg, 8080);
        });
        assert!(
            low_denied,
            "a bind to :80 below the 1024 floor must be denied"
        );
        assert!(
            !high_denied,
            "a bind to :8080 at/above the floor must be allowed"
        );

        // No floor (0): even :80 is allowed — the floor is opt-in.
        loaded
            .update_map(
                "kennel_meta_map",
                &0u32.to_ne_bytes(),
                &meta_with_bind_floor(0),
                sys::BPF_ANY,
            )
            .expect("populate meta (no floor)");
        let cg = Path::new("/sys/fs/cgroup/kennel-bpf-test-nofloor");
        let mut denied = true;
        with_attached_bind4(cg, &loaded, || {
            denied = wildcard_bind_denied_in_cgroup(cg, 80);
        });
        assert!(!denied, "with no floor a bind to :80 must be allowed");
    }
}
