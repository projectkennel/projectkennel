//! OS CSPRNG access via `getrandom(2)`.
//!
//! Used for the random bits of the audit `kennel_uuid` (a `UUIDv7`). The system
//! call is the vetted source; we wrap it so callers stay `#![forbid(unsafe_code)]`.

use std::io;

/// Fill `buf` with bytes from the OS CSPRNG (`getrandom(2)`, default flags).
///
/// Retries on `EINTR` and on short reads until the buffer is full.
///
/// # Errors
/// Returns the underlying OS error if `getrandom` fails for any reason other
/// than interruption.
pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    let len = buf.len();
    let mut filled = 0_usize;
    while filled < len {
        let remaining = len.saturating_sub(filled);
        let ptr = buf
            .as_mut_ptr()
            .wrapping_add(filled)
            .cast::<libc::c_void>();
        // SAFETY: `ptr` points `filled` bytes into `buf`, and `remaining` is the
        // exact number of bytes left in `buf` from there, so getrandom writes
        // only within `buf`. flags = 0 (blocking until the pool is initialised).
        // INVARIANTS UPHELD: ptr/len describe a live, writable, in-bounds slice.
        // FAILURE MODE: returns -1/errno on failure; we surface it (or retry on
        // EINTR) and never advance `filled` past what getrandom reports written.
        let ret = unsafe { libc::getrandom(ptr, remaining, 0) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        let written = usize::try_from(ret).unwrap_or(0);
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "getrandom returned no bytes",
            ));
        }
        filled = filled.saturating_add(written);
    }
    Ok(())
}

/// Return `N` bytes from the OS CSPRNG.
///
/// # Errors
/// Propagates any error from [`fill`].
pub fn bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut out = [0_u8; N];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_changes_the_buffer() {
        let mut a = [0_u8; 32];
        fill(&mut a).expect("getrandom");
        // Astronomically unlikely to be all-zero from a working CSPRNG.
        assert!(a.iter().any(|&b| b != 0));
    }

    #[test]
    fn two_draws_differ() {
        let a = bytes::<16>().expect("draw a");
        let b = bytes::<16>().expect("draw b");
        assert_ne!(a, b);
    }

    #[test]
    fn empty_is_ok() {
        fill(&mut []).expect("empty fill");
    }
}
