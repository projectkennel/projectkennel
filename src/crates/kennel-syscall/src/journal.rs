//! systemd-journald submission via `sd_journal_sendv` (feature `audit-journald`).
//!
//! This is the only FFI the audit subsystem needs. `sd_journal_send` is
//! variadic and awkward to call from Rust; `sd_journal_sendv` takes an array of
//! `struct iovec` (`"FIELD=value"` strings) and is the portable entry point.
//! Linking libsystemd is gated behind the `audit-journald` feature so the
//! default build needs neither the library nor this `unsafe`.

use std::io;

#[link(name = "systemd")]
extern "C" {
    // int sd_journal_sendv(const struct iovec *iov, int n);
    fn sd_journal_sendv(iov: *const libc::iovec, n: libc::c_int) -> libc::c_int;
}

/// Submit one journal entry. Each element of `fields` is a `FIELD=value` string
/// (the field name must match journald's `[A-Z0-9_]+`).
///
/// # Errors
/// Returns the OS error if `sd_journal_sendv` reports failure (it returns
/// `-errno`), or `InvalidInput` if there are more fields than `c_int` can hold.
pub fn sendv(fields: &[String]) -> io::Result<()> {
    if fields.is_empty() {
        return Ok(());
    }
    let n = libc::c_int::try_from(fields.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many journal fields"))?;
    let iov: Vec<libc::iovec> = fields
        .iter()
        .map(|f| libc::iovec {
            iov_base: f.as_ptr().cast::<libc::c_void>().cast_mut(),
            iov_len: f.len(),
        })
        .collect();
    // SAFETY: `iov` holds exactly `n` iovecs, each pointing at the bytes of one
    // `String` in `fields`. `fields` outlives this call, so every range stays
    // valid and initialised; sd_journal_sendv only reads them.
    // INVARIANTS UPHELD: n == iov.len(); no range aliases writable memory.
    // FAILURE MODE: returns -errno on failure, surfaced below; nothing is freed.
    let ret = unsafe { sd_journal_sendv(iov.as_ptr(), n) };
    if ret == 0 {
        Ok(())
    } else {
        // ret is -errno; negate to the positive errno from_raw_os_error wants.
        Err(io::Error::from_raw_os_error(ret.wrapping_neg()))
    }
}
