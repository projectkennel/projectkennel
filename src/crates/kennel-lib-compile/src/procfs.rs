//! Compile-time checks on `fs.read` grants under `/proc` (#218).
//!
//! # Purpose
//!
//! The view serves `/proc` as one Landlock read grant over a curated procfs (see
//! [`kennel_lib_policy::procfs`]): per-process entries are real, a few host-global files are
//! synthesized from templates, and every other top-level entry is masked unless the policy
//! names it. This module is where a grant that cannot be honoured as written is caught, and
//! where the wide one is made loud.
//!
//! # What this checks
//!
//! - **`/proc` or `/proc/**` warns.** It serves the host's real, uncurated procfs — every
//!   host-global entry (`/proc/sys`, `/proc/kallsyms`, `/proc/modules`, …) becomes readable. A
//!   legitimate choice (footgun-warn-dont-forbid), but never a silent one.
//! - **A path inside a host-global entry is refused** (`/proc/sys/kernel/osrelease`): the one
//!   `/proc` rule cannot narrow below a top-level entry, so it would expose the whole of
//!   `/proc/sys`. The author grants the top-level entry explicitly instead.
//! - **A non-canonical path is refused** (`/proc/../etc`, `/proc//x`).
//!
//! Validation runs on the translated (substituted) read set.

use kennel_lib_policy::procfs::{classify_read, ProcRead};
use kennel_lib_policy::PolicyError;

/// Validate the `fs.read` entries under `/proc`, returning the warnings to surface.
///
/// # Errors
///
/// Returns [`PolicyError::SourceValidation`] with one message per refused entry.
pub fn validate(read: &[String]) -> Result<Vec<String>, PolicyError> {
    let _ = (read, classify_read, std::marker::PhantomData::<ProcRead>);
    todo!("procfs curation (#218)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reads(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    fn errors(r: Result<Vec<String>, PolicyError>) -> Vec<String> {
        match r {
            Err(PolicyError::SourceValidation(ms)) => ms,
            other => panic!("expected SourceValidation, got {other:?}"),
        }
    }

    #[test]
    fn the_base_template_set_is_clean() {
        let w = validate(&reads(&[
            "/usr/**",
            "/proc/self/**",
            "/proc/cpuinfo",
            "/proc/meminfo",
            "/proc/stat",
            "/proc/version",
        ]))
        .expect("valid");
        assert!(w.is_empty(), "no warnings expected, got {w:?}");
    }

    #[test]
    fn no_proc_grant_is_clean() {
        assert!(validate(&reads(&["/usr/**"])).expect("valid").is_empty());
        assert!(validate(&[]).expect("valid").is_empty());
    }

    #[test]
    fn whole_proc_warns_once_and_names_the_exposure() {
        for p in ["/proc", "/proc/**"] {
            let w = validate(&reads(&[p, "/proc/self/**"])).expect("valid");
            assert_eq!(w.len(), 1, "{p}: {w:?}");
            assert!(w[0].contains(p), "{p}: names the grant: {w:?}");
            assert!(
                w[0].contains("/proc/sys"),
                "{p}: names what it exposes: {w:?}"
            );
        }
        // Both spellings at once still warn once.
        assert_eq!(
            validate(&reads(&["/proc", "/proc/**"]))
                .expect("valid")
                .len(),
            1
        );
    }

    #[test]
    fn a_passthrough_top_level_entry_is_accepted_silently() {
        assert!(validate(&reads(&["/proc/loadavg", "/proc/sys/**"]))
            .expect("valid")
            .is_empty());
    }

    #[test]
    fn a_path_inside_a_global_entry_is_refused_with_the_fix() {
        let e = errors(validate(&reads(&["/proc/sys/kernel/osrelease"])));
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].contains("/proc/sys/kernel/osrelease"), "{e:?}");
        assert!(
            e[0].contains("/proc/sys/**"),
            "suggests the top-level grant: {e:?}"
        );
    }

    #[test]
    fn non_canonical_proc_paths_are_refused() {
        let e = errors(validate(&reads(&["/proc/../etc/shadow", "/proc//cpuinfo"])));
        assert_eq!(e.len(), 2, "{e:?}");
    }
}
