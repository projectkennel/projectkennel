//! Project Kennel BPF loader.
//!
//! # Purpose
//!
//! Load and attach the cgroup BPF programs of `bpf/` (verified separately) using
//! a hand-rolled `bpf(2)` loader over `libc`, with `object` for the generic ELF
//! parsing only. This mirrors the project's calculus elsewhere: a vetted crate
//! for the fiddly-but-generic part (ELF section/symbol/relocation parsing — like
//! `seccompiler` for BPF bytecode), our own code for the narrow, security-bearing
//! part (the `bpf()` syscalls, map creation, relocation patching, cgroup attach).
//!
//! The programs are compiled **without** CO-RE (against `<linux/bpf.h>`, not
//! `vmlinux.h`): they touch only the stable hook-context structs and our own
//! maps, so there is no BTF/CO-RE relocation to resolve. The only relocations are
//! `R_BPF_64_64` references from instructions to map symbols, which we resolve by
//! symbol *name* against [`KENNEL_MAPS`] and patch as map-fd `ld_imm64` loads.
//!
//! # `unsafe`
//!
//! This is the workspace's second `unsafe` crate (`UNSAFE-CRATES.md`): the
//! `unsafe` is the `bpf(2)` FFI in [`sys`] and the ringbuf `mmap`/lock-free
//! drain in [`ringbuf`], each block carrying the §4 `SAFETY:` /
//! `INVARIANTS UPHELD:` / `FAILURE MODE:` comment. ELF parsing (`object`) and
//! relocation patching are safe.

#![allow(unsafe_code)]

pub mod loader;
pub mod ringbuf;
pub mod sys;

pub use loader::{
    create_maps, freeze_maps, load_program, load_program_against, update_kennel_map, Loaded,
    MapSpec, ProgramSpec, KENNEL_MAPS, KENNEL_PROGRAMS,
};
pub use ringbuf::RingBuffer;

/// Compiled BPF program objects, embedded at build time.
///
/// Available only under the `embed-programs` feature (which runs clang in
/// `build.rs`). The runtime loads these via [`load_program`] rather than
/// compiling at run time.
#[cfg(feature = "embed-programs")]
pub mod programs {
    include!(concat!(env!("OUT_DIR"), "/programs.rs"));

    /// The compiled object bytes for the program named `name`, if present.
    #[must_use]
    pub fn object(name: &str) -> Option<&'static [u8]> {
        PROGRAM_OBJECTS
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, bytes)| *bytes)
    }
}
