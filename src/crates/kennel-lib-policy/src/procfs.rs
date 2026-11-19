//! How a `fs.read` grant under `/proc` is served in the constructed view (#218).
//!
//! # Purpose
//!
//! A kennel's `/proc` is a fresh procfs mount, not a host bind, and Landlock cannot express
//! "the calling process's own `/proc/<pid>`": a rule anchors on the inode opened when the
//! ruleset is built, so a rule on `/proc/self` covers only the process that sealed — every
//! child the workload forks has a different `/proc/<pid>` and is denied its own `/proc/self`.
//! The one rule that covers every process in the kennel is a read rule on `/proc` itself.
//!
//! So the view grants `/proc` read as a whole and curates what is *in* it instead: every
//! top-level entry that is not per-process is over-mounted, either with a synthesized file
//! rendered from a template ([`Synth`]) or with an empty one, unless the policy names it. This
//! module is the single classifier both the compiler (which warns and refuses) and the spawn
//! plan (which builds the curated mount) key on, so the two cannot disagree.
//!
//! The crate stays pure: this is lexical classification of a grant string, no I/O.

/// A top-level `/proc` file the view synthesizes from a template rather than exposing the
/// host's real one. Templates are filled only with values a syscall already exposes to the
/// workload (`sched_getaffinity`/cgroup quota, `sysinfo(2)`, `uname(2)`), so a synthesized
/// file reveals nothing the workload could not learn anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Synth {
    /// `/proc/cpuinfo`: one `processor` entry per CPU the kennel may use.
    Cpuinfo,
    /// `/proc/meminfo`: total/free memory as `sysinfo(2)` reports it.
    Meminfo,
    /// `/proc/stat`: one zeroed `cpu` line per usable CPU plus the boot time.
    Stat,
    /// `/proc/version`: the kernel release and version as `uname(2)` reports them.
    Version,
}

impl Synth {
    /// Every synthesizable entry.
    pub const ALL: [Self; 4] = [Self::Cpuinfo, Self::Meminfo, Self::Stat, Self::Version];

    /// The entry's file name under `/proc`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cpuinfo => "cpuinfo",
            Self::Meminfo => "meminfo",
            Self::Stat => "stat",
            Self::Version => "version",
        }
    }

    /// The entry named `name` (a top-level `/proc` file name), if it is synthesizable.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let _ = name;
        todo!("procfs curation (#218)")
    }
}

/// Top-level `/proc` names that are per-process, so served by the real procfs under the
/// whole-`/proc` Landlock rule: the `self`/`thread-self` links and the two compatibility
/// links that resolve into them (`net` → `self/net`, `mounts` → `self/mounts`). Numeric
/// (`/proc/<pid>`) entries are per-process too and are recognised separately.
pub const PER_PROCESS_LINKS: [&str; 4] = ["self", "thread-self", "net", "mounts"];

/// How one `fs.read` entry under `/proc` is served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcRead {
    /// `/proc`, `/proc/*` or `/proc/**`: the real, uncurated procfs — every host-global entry
    /// readable. The compiler warns; the view skips curation entirely.
    Whole,
    /// A per-process path (`/proc/self/**`, `/proc/<pid>/…`, `/proc/net/dev`, …): served by the
    /// real procfs, readable by every process in the kennel for its own `/proc/self`.
    PerProcess,
    /// A synthesized top-level file (`/proc/cpuinfo`, …).
    Synthesized(Synth),
    /// Any other top-level entry the policy names (`/proc/loadavg`, `/proc/sys/**`): left
    /// uncovered, so the real procfs entry is readable.
    Passthrough(String),
    /// A path *inside* a host-global top-level entry (`/proc/sys/kernel/osrelease`): not
    /// servable — the whole-`/proc` rule cannot narrow below a top-level entry, so granting it
    /// would silently expose the whole entry. The compiler refuses it.
    Nested {
        /// The top-level entry it sits inside (`sys` for `/proc/sys/kernel/osrelease`).
        top: String,
    },
    /// A path with a `.`/`..` component or other non-canonical form. The compiler refuses it.
    NonCanonical,
}

/// Classify one `fs.read` entry. `None` when the entry is not under `/proc` (matched on a
/// component boundary: `/procfoo` is not under `/proc`). A trailing `/**` or `/*` glob is
/// stripped first, as for every other grant.
#[must_use]
pub fn classify_read(entry: &str) -> Option<ProcRead> {
    let _ = entry;
    todo!("procfs curation (#218)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(entry: &str) -> Option<ProcRead> {
        classify_read(entry)
    }

    #[test]
    fn paths_outside_proc_are_not_classified() {
        for p in [
            "/usr/**",
            "/",
            "/procfoo",
            "/procfoo/bar",
            "proc/self",
            "~/proc",
            "",
        ] {
            assert_eq!(class(p), None, "{p}");
        }
    }

    #[test]
    fn the_whole_of_proc_is_whole() {
        for p in ["/proc", "/proc/", "/proc/*", "/proc/**"] {
            assert_eq!(class(p), Some(ProcRead::Whole), "{p}");
        }
    }

    #[test]
    fn per_process_paths_are_per_process() {
        for p in [
            "/proc/self",
            "/proc/self/**",
            "/proc/self/status",
            "/proc/thread-self/**",
            "/proc/1",
            "/proc/1234/maps",
            // The compatibility links resolve into /proc/self.
            "/proc/net",
            "/proc/net/dev",
            "/proc/mounts",
        ] {
            assert_eq!(class(p), Some(ProcRead::PerProcess), "{p}");
        }
    }

    #[test]
    fn the_synthesized_files_are_synthesized() {
        assert_eq!(
            class("/proc/cpuinfo"),
            Some(ProcRead::Synthesized(Synth::Cpuinfo))
        );
        assert_eq!(
            class("/proc/meminfo"),
            Some(ProcRead::Synthesized(Synth::Meminfo))
        );
        assert_eq!(
            class("/proc/stat"),
            Some(ProcRead::Synthesized(Synth::Stat))
        );
        assert_eq!(
            class("/proc/version"),
            Some(ProcRead::Synthesized(Synth::Version))
        );
    }

    #[test]
    fn other_top_level_entries_pass_through() {
        assert_eq!(
            class("/proc/loadavg"),
            Some(ProcRead::Passthrough("loadavg".to_owned()))
        );
        // A glob on a top-level directory is still the top-level entry.
        assert_eq!(
            class("/proc/sys/**"),
            Some(ProcRead::Passthrough("sys".to_owned()))
        );
        assert_eq!(
            class("/proc/sys"),
            Some(ProcRead::Passthrough("sys".to_owned()))
        );
    }

    #[test]
    fn a_path_inside_a_global_entry_is_nested() {
        assert_eq!(
            class("/proc/sys/kernel/osrelease"),
            Some(ProcRead::Nested {
                top: "sys".to_owned()
            })
        );
        assert_eq!(
            class("/proc/sys/kernel/**"),
            Some(ProcRead::Nested {
                top: "sys".to_owned()
            })
        );
        // Below a synthesized *file* is nested too (it cannot have children).
        assert_eq!(
            class("/proc/cpuinfo/x"),
            Some(ProcRead::Nested {
                top: "cpuinfo".to_owned()
            })
        );
    }

    #[test]
    fn non_canonical_paths_are_refused() {
        for p in [
            "/proc/../etc",
            "/proc/self/../1",
            "/proc/./cpuinfo",
            "/proc//cpuinfo",
        ] {
            assert_eq!(class(p), Some(ProcRead::NonCanonical), "{p}");
        }
    }

    #[test]
    fn synth_names_round_trip() {
        for s in Synth::ALL {
            assert_eq!(Synth::from_name(s.name()), Some(s));
        }
        assert_eq!(Synth::from_name("loadavg"), None);
        assert_eq!(Synth::Cpuinfo.name(), "cpuinfo");
        assert_eq!(Synth::Meminfo.name(), "meminfo");
        assert_eq!(Synth::Stat.name(), "stat");
        assert_eq!(Synth::Version.name(), "version");
    }
}
