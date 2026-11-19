//! The curated `/proc` (#218): render the synthesized top-level files and over-mount the
//! view's fresh procfs.
//!
//! # Purpose
//!
//! Every `fs.read` grant under `/proc` is served by one Landlock read rule on `/proc` (see
//! [`kennel_lib_policy::procfs`] for why), so the view controls what that rule exposes by
//! curating the procfs mount itself, in the construction child, before `pivot_root`:
//!
//! - **per-process** entries (`/proc/<pid>`, `self`, `thread-self`, and the `net`/`mounts`
//!   links into them) stay real;
//! - **synthesized** entries ([`Synth`]) are over-mounted with a file rendered from a
//!   template ([`render`]) filled only with values a syscall already exposes ([`ProcFacts`]);
//! - **passthrough** entries the policy names stay real;
//! - **everything else** at the top level is over-mounted empty and read-only: an empty file
//!   over a file, an empty directory over a directory.
//!
//! The top level is *enumerated* at mount time, so the curation is an allowlist: an entry a
//! future kernel adds is masked without a code change.
//!
//! Synthesized files are snapshots taken at spawn: counters (`/proc/stat` CPU times) are
//! zero and memory figures do not move. Tools that read totals (`os.cpus()`,
//! `os.totalmem()`, `nproc`) are served; tools that compute load from deltas see none.

use std::io;
use std::path::Path;

use kennel_lib_policy::procfs::Synth;
use kennel_lib_syscall::sysinfo::{Kernel, Memory};

/// The values the templates are filled with — all of them already visible to the workload
/// through its own syscalls (`sched_getaffinity`, `sysinfo(2)`, `uname(2)`, `time(2)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcFacts {
    /// CPUs the kennel may run on ([`kennel_lib_syscall::sysinfo::usable_cpus`]).
    pub cpus: usize,
    /// Memory totals and uptime (`sysinfo(2)`).
    pub memory: Memory,
    /// Kernel identity (`uname(2)`).
    pub kernel: Kernel,
    /// Wall-clock seconds since the epoch at spawn (with `memory.uptime_secs`, the boot time).
    pub now_secs: u64,
}

impl ProcFacts {
    /// Gather the facts in the construction child.
    ///
    /// # Errors
    ///
    /// Returns the OS error if `sysinfo(2)` or `uname(2)` fails.
    pub fn gather() -> io::Result<Self> {
        todo!("procfs curation (#218)")
    }
}

/// Render the synthesized `/proc` file `synth` from its template.
#[must_use]
pub fn render(synth: Synth, facts: &ProcFacts) -> String {
    let _ = (synth, facts);
    todo!("procfs curation (#218)")
}

/// Curate the freshly mounted procfs at `proc_dir`: over-mount every top-level entry that is
/// not per-process, synthesized, or passed through with an empty read-only one, and every
/// `synthesize` entry with its rendered template. `scratch` is a directory on a writable
/// tmpfs for the over-mount sources; they are unlinked once mounted.
///
/// # Errors
///
/// Returns the OS error if reading the directory, writing a source, or a mount fails.
pub fn curate(
    proc_dir: &Path,
    scratch: &Path,
    synthesize: &[Synth],
    passthrough: &[String],
    facts: &ProcFacts,
) -> io::Result<()> {
    let _ = (proc_dir, scratch, synthesize, passthrough, facts);
    todo!("procfs curation (#218)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(cpus: usize) -> ProcFacts {
        ProcFacts {
            cpus,
            memory: Memory {
                total: 8 << 30,
                free: 3 << 30,
                uptime_secs: 1_000,
            },
            kernel: Kernel {
                sysname: "Linux".to_owned(),
                release: "7.0.0-43-generic".to_owned(),
                version: "#43-Ubuntu SMP PREEMPT_DYNAMIC".to_owned(),
                machine: "aarch64".to_owned(),
            },
            now_secs: 1_795_000_000,
        }
    }

    /// `key: value` lines of a `/proc`-style file.
    fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
        text.lines()
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim() == key))
            .map(|(_, v)| v.trim())
    }

    #[test]
    fn cpuinfo_lists_one_processor_per_usable_cpu() {
        for n in [1, 4, 64] {
            let text = render(Synth::Cpuinfo, &facts(n));
            let procs: Vec<&str> = text
                .lines()
                .filter(|l| l.starts_with("processor"))
                .collect();
            assert_eq!(procs.len(), n, "{text}");
            for (i, line) in procs.iter().enumerate() {
                assert_eq!(
                    line.split(':').nth(1).map(str::trim),
                    Some(i.to_string().as_str())
                );
            }
        }
    }

    #[test]
    fn meminfo_reports_kib_from_sysinfo() {
        let text = render(Synth::Meminfo, &facts(2));
        assert_eq!(field(&text, "MemTotal"), Some("8388608 kB"));
        assert_eq!(field(&text, "MemFree"), Some("3145728 kB"));
        assert_eq!(field(&text, "MemAvailable"), Some("3145728 kB"));
        assert_eq!(field(&text, "SwapTotal"), Some("0 kB"));
        // Every line is `Key: <n> kB`, the shape every parser expects.
        for line in text.lines() {
            let (_, v) = line.split_once(':').expect("key: value");
            let v = v.trim();
            assert!(
                v.strip_suffix(" kB")
                    .is_some_and(|n| n.parse::<u64>().is_ok()),
                "{line}"
            );
        }
    }

    #[test]
    fn stat_has_an_aggregate_and_one_line_per_cpu_and_the_boot_time() {
        let text = render(Synth::Stat, &facts(3));
        let cpu_lines: Vec<&str> = text.lines().filter(|l| l.starts_with("cpu")).collect();
        assert_eq!(cpu_lines.len(), 1 + 3, "{text}");
        assert!(cpu_lines[0].starts_with("cpu "), "aggregate first: {text}");
        for (i, l) in cpu_lines[1..].iter().enumerate() {
            assert!(l.starts_with(&format!("cpu{i} ")), "{l}");
        }
        // Ten zeroed counters per cpu line (user..guest_nice), so delta-readers see no load.
        for l in &cpu_lines {
            let counters: Vec<&str> = l.split_whitespace().skip(1).collect();
            assert_eq!(counters, vec!["0"; 10], "{l}");
        }
        assert!(
            text.lines().any(|l| l == "btime 1794999000"),
            "btime = now - uptime: {text}"
        );
    }

    #[test]
    fn version_is_built_from_uname() {
        assert_eq!(
            render(Synth::Version, &facts(1)),
            "Linux version 7.0.0-43-generic #43-Ubuntu SMP PREEMPT_DYNAMIC\n"
        );
    }

    #[test]
    fn every_template_ends_in_a_newline_and_is_deterministic() {
        for s in Synth::ALL {
            let a = render(s, &facts(2));
            assert!(a.ends_with('\n'), "{s:?}");
            assert_eq!(a, render(s, &facts(2)), "{s:?}");
        }
    }

    #[test]
    fn gather_reads_this_host() {
        let f = ProcFacts::gather().expect("gather");
        assert!(f.cpus >= 1);
        assert!(f.memory.total > 0);
        assert_eq!(f.kernel.sysname, "Linux");
        assert!(f.now_secs > f.memory.uptime_secs);
    }
}
