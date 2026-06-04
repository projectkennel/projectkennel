//! Wall-clock time for the envelope `ts` field, and its RFC 3339 rendering.
//!
//! The writer reads the time through a [`Clock`] so tests can pin it. Formatting
//! is the standard civil-from-days conversion (Howard Hinnant's algorithm),
//! hand-rolled rather than pulling a date crate: it is calendar arithmetic, not
//! the crypto/DNS/`unsafe` that the no-hand-roll rule reserves for vetted code.
//! Arithmetic uses `div_euclid`/`rem_euclid` and the `wrapping_*` methods to
//! satisfy the workspace `arithmetic_side_effects` lint; every intermediate is
//! far inside `i64` for any representable timestamp.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of wall-clock time, injectable so tests are deterministic.
pub trait Clock: Send + Sync {
    /// The current time as `(unix_seconds, sub_second_microseconds)`.
    fn now_unix_micros(&self) -> (i64, u32);
}

/// The real system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_micros(&self) -> (i64, u32) {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => (
                i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                d.subsec_micros(),
            ),
            // Clock set before the epoch: represent as negative seconds.
            Err(e) => {
                let secs =
                    i64::try_from(e.duration().as_secs()).map_or(i64::MIN, i64::wrapping_neg);
                (secs, 0)
            }
        }
    }
}

const SECS_PER_DAY: i64 = 86_400;

/// Render `(unix_seconds, microseconds)` as an RFC 3339 UTC timestamp with
/// microsecond precision, e.g. `2026-05-25T12:34:56.789012Z`.
#[must_use]
pub fn format_rfc3339_micros(unix_seconds: i64, micros: u32) -> String {
    let days = unix_seconds.div_euclid(SECS_PER_DAY);
    let secs_of_day = unix_seconds.rem_euclid(SECS_PER_DAY);
    let hour = secs_of_day.div_euclid(3_600);
    let minute = secs_of_day.div_euclid(60).rem_euclid(60);
    let second = secs_of_day.rem_euclid(60);
    let (year, month, day) = civil_from_days(days);

    let mut out = String::with_capacity(27);
    // Year is zero-padded to at least four digits; write! handles the width.
    let _ = write!(
        out,
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:06}Z",
        micros.min(999_999),
    );
    out
}

/// Convert a count of days since the Unix epoch to `(year, month, day)`.
/// Howard Hinnant's `civil_from_days`, valid across the whole representable
/// range. Month is 1..=12, day is 1..=31.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01 so leap days fall at the end of the era.
    let z = days.wrapping_add(719_468);
    let era = if z >= 0 { z } else { z.wrapping_sub(146_096) }.div_euclid(146_097);
    let doe = z.wrapping_sub(era.wrapping_mul(146_097)); // [0, 146096]
    let yoe = doe
        .wrapping_sub(doe.div_euclid(1_460))
        .wrapping_add(doe.div_euclid(36_524))
        .wrapping_sub(doe.div_euclid(146_096))
        .div_euclid(365); // [0, 399]
    let year = yoe.wrapping_add(era.wrapping_mul(400));
    let doy = doe.wrapping_sub(
        yoe.wrapping_mul(365)
            .wrapping_add(yoe.div_euclid(4))
            .wrapping_sub(yoe.div_euclid(100)),
    ); // [0, 365]
    let mp = doy.wrapping_mul(5).wrapping_add(2).div_euclid(153); // [0, 11]
    let day = doy
        .wrapping_sub(mp.wrapping_mul(153).wrapping_add(2).div_euclid(5))
        .wrapping_add(1); // [1, 31]
    let month = if mp < 10 {
        mp.wrapping_add(3)
    } else {
        mp.wrapping_sub(9)
    }; // [1, 12]
    let year = if month <= 2 {
        year.wrapping_add(1)
    } else {
        year
    };
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock pinned to a fixed instant, for deterministic tests.
    struct FixedClock(i64, u32);
    impl Clock for FixedClock {
        fn now_unix_micros(&self) -> (i64, u32) {
            (self.0, self.1)
        }
    }

    #[test]
    fn epoch_is_1970() {
        assert_eq!(format_rfc3339_micros(0, 0), "1970-01-01T00:00:00.000000Z");
    }

    #[test]
    fn known_instant_matches() {
        // 2026-05-25T12:34:56.789012Z — the schema doc's representative line.
        // Days from 1970-01-01 to 2026-05-25 = 20598; 12:34:56 = 45296 s.
        let secs = 20_598 * SECS_PER_DAY + 45_296;
        assert_eq!(
            format_rfc3339_micros(secs, 789_012),
            "2026-05-25T12:34:56.789012Z"
        );
    }

    #[test]
    fn leap_day_2024() {
        // 2024-02-29 is day 19782 since the epoch.
        assert_eq!(
            &format_rfc3339_micros(19_782 * SECS_PER_DAY, 0)[..10],
            "2024-02-29"
        );
    }

    #[test]
    fn micros_are_clamped_and_padded() {
        assert!(format_rfc3339_micros(0, 5).ends_with(".000005Z"));
        assert!(format_rfc3339_micros(0, 9_999_999).ends_with(".999999Z"));
    }

    #[test]
    fn fixed_clock_reads_back() {
        let c = FixedClock(42, 7);
        assert_eq!(c.now_unix_micros(), (42, 7));
    }

    #[test]
    fn system_clock_is_after_2025() {
        // 2025-01-01 = 1735689600. A sanity floor that the real clock advances.
        let (secs, _) = SystemClock.now_unix_micros();
        assert!(secs > 1_735_689_600, "system clock looks wrong: {secs}");
    }
}
