//! Reader for a `BPF_MAP_TYPE_RINGBUF`, draining the shared audit ringbuf.
//!
//! The kernel exposes the ringbuf through two `mmap` regions and a lock-free
//! single-consumer protocol (the same one libbpf implements; we hand-roll it
//! rather than take libbpf — see `DEPENDENCIES.md`):
//!
//! - a read-write **consumer page** (offset 0) whose first 8 bytes hold
//!   `consumer_pos`, the byte offset we have consumed up to;
//! - a read-only **producer region** (offset `page_size`): one page whose first
//!   8 bytes hold `producer_pos`, followed by the data area mapped **twice**
//!   back-to-back so a record that wraps the ring stays contiguous in memory.
//!
//! Each record is an 8-byte header (`len` with the busy/discard flags in its top
//! two bits, then 4 reserved bytes) followed by the sample, the whole thing
//! rounded up to 8 bytes. We advance `consumer_pos` past each committed record.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::NonNull;
use std::slice;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Set while the producer is still writing a record; we must not read past it.
const BUSY_BIT: u32 = 1 << 31;
/// Set on a reserved-then-discarded record; skip its bytes without delivering.
const DISCARD_BIT: u32 = 1 << 30;
/// The record length occupies the low 30 bits of the header word.
const LEN_MASK: u32 = 0x3fff_ffff;
/// `BPF_RINGBUF_HDR_SZ`: the per-record header preceding each sample.
const HDR_SZ: usize = 8;

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// A mapped ringbuf, tied to the borrowed map fd it was created from.
pub struct RingBuffer<'fd> {
    fd: BorrowedFd<'fd>,
    /// Consumer page (read-write), `page_size` bytes.
    consumer: NonNull<u8>,
    /// Producer page + double-mapped data (read-only), `page_size + 2*data_size`.
    producer: NonNull<u8>,
    /// Start of the data area within the producer mapping (`producer + page`).
    data: NonNull<u8>,
    page_size: usize,
    data_size: usize,
    /// `data_size - 1`; `data_size` is a power of two, so this masks an offset.
    data_mask: u64,
}

impl<'fd> RingBuffer<'fd> {
    /// Map the ringbuf behind `fd`. `data_size` is the map's byte capacity (its
    /// `max_entries`), which the kernel requires to be a power of two.
    ///
    /// # Errors
    ///
    /// Returns the OS error if either `mmap` fails, or `InvalidData` if
    /// `data_size` is not a non-zero power of two.
    pub fn new(fd: BorrowedFd<'fd>, data_size: usize) -> io::Result<Self> {
        if data_size == 0 || !data_size.is_power_of_two() {
            return Err(invalid("ringbuf size must be a non-zero power of two"));
        }
        // SAFETY: sysconf(_SC_PAGESIZE) returns the page size or -1; we reject
        // non-positive results before using it.
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .map_err(|_| invalid("bad page size"))?;
        if page_size == 0 {
            return Err(invalid("bad page size"));
        }
        let producer_len = page_size
            .checked_add(data_size.checked_mul(2).ok_or_else(|| invalid("size overflow"))?)
            .ok_or_else(|| invalid("size overflow"))?;

        // SAFETY: a fresh anonymous request (addr NULL) for `page_size` bytes of
        // the map at offset 0 — the consumer page. The kernel validates fd/offset;
        // MAP_FAILED is checked. We own the mapping until Drop munmaps it.
        let consumer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if consumer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let consumer = NonNull::new(consumer.cast::<u8>())
            .ok_or_else(|| invalid("mmap returned null"))?;

        // SAFETY: as above, for the producer page + double-mapped data at offset
        // `page_size`. On failure we must munmap the consumer page we already hold.
        let producer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                producer_len,
                libc::PROT_READ,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                // offset is page-aligned (one page).
                libc::off_t::try_from(page_size).map_err(|_| invalid("page size overflow"))?,
            )
        };
        if producer == libc::MAP_FAILED {
            let err = io::Error::last_os_error();
            // SAFETY: unmapping the consumer page we successfully mapped above.
            unsafe { libc::munmap(consumer.as_ptr().cast(), page_size) };
            return Err(err);
        }
        let producer = NonNull::new(producer.cast::<u8>())
            .ok_or_else(|| invalid("mmap returned null"))?;
        // SAFETY: `producer` is valid for `producer_len >= page_size` bytes, so
        // `producer + page_size` (the data area start) is within the mapping.
        let data = unsafe { NonNull::new_unchecked(producer.as_ptr().add(page_size)) };

        Ok(Self {
            fd,
            consumer,
            producer,
            data,
            page_size,
            data_size,
            data_mask: (data_size as u64).wrapping_sub(1),
        })
    }

    /// Wait up to `timeout_ms` for the ringbuf to become readable.
    ///
    /// Returns `true` if data is (or may be) available, `false` on timeout.
    ///
    /// # Errors
    ///
    /// Returns the OS error if `poll(2)` fails (other than `EINTR`, which is
    /// reported as `false`).
    pub fn poll(&self, timeout_ms: i32) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: a single valid pollfd; poll writes back only revents.
        let rc = unsafe { libc::poll(std::ptr::from_mut(&mut pfd), 1, timeout_ms) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                return Ok(false);
            }
            return Err(err);
        }
        Ok(rc > 0 && pfd.revents & libc::POLLIN != 0)
    }

    /// Drain all committed records, calling `f` with each sample's bytes.
    /// Returns the number of samples delivered (discarded records are skipped).
    ///
    /// # Errors
    ///
    /// Returns `InvalidData` if a record's length would run past the ring (a
    /// corrupt header); the consumer position is not advanced past it.
    // The atomic-pointer casts are sound: `consumer`/`producer` come from `mmap`
    // (page-aligned, so 8-aligned) and `data + off` is 8-aligned because records
    // are 8-rounded and `off` is a multiple of 8. clippy can't see this.
    #[allow(clippy::cast_ptr_alignment)]
    pub fn consume<F: FnMut(&[u8])>(&mut self, mut f: F) -> io::Result<usize> {
        // SAFETY: the first 8 bytes of the consumer page hold `consumer_pos` and
        // of the producer page `producer_pos`; both pages are page-aligned, so the
        // u64 references are aligned. All accesses to these locations (here and in
        // the kernel) are atomic, matching the kernel's acquire/release protocol.
        let cons_atomic = unsafe { &*self.consumer.as_ptr().cast::<AtomicU64>() };
        let prod_atomic = unsafe { &*self.producer.as_ptr().cast::<AtomicU64>() };

        let mut cons_pos = cons_atomic.load(Ordering::Acquire);
        let mut delivered = 0usize;
        loop {
            let prod_pos = prod_atomic.load(Ordering::Acquire);
            if cons_pos >= prod_pos {
                break;
            }
            let off = usize::try_from(cons_pos & self.data_mask)
                .map_err(|_| invalid("ring offset overflow"))?;
            // SAFETY: `off < data_size`; the data area is mapped for `2*data_size`,
            // so `data + off` is in-bounds and 8-aligned (records are 8-aligned).
            let len_atomic = unsafe { &*self.data.as_ptr().add(off).cast::<AtomicU32>() };
            let len = len_atomic.load(Ordering::Acquire);
            if len & BUSY_BIT != 0 {
                break; // producer still committing this record
            }
            let sample_len = usize::try_from(len & LEN_MASK)
                .map_err(|_| invalid("sample length overflow"))?;
            // The sample (header + payload) must fit inside one ring's worth of the
            // double map starting at `off`.
            let need = HDR_SZ
                .checked_add(sample_len)
                .ok_or_else(|| invalid("record length overflow"))?;
            if need > self.data_size {
                return Err(invalid("record larger than ring"));
            }
            if len & DISCARD_BIT == 0 {
                let start = off
                    .checked_add(HDR_SZ)
                    .ok_or_else(|| invalid("record offset overflow"))?;
                // SAFETY: `start + sample_len <= off + data_size`, within the
                // double-mapped data area; the bytes are committed (BUSY clear) and
                // read-only for the lifetime of this borrow.
                let sample = unsafe { slice::from_raw_parts(self.data.as_ptr().add(start), sample_len) };
                f(sample);
                delivered = delivered.saturating_add(1);
            }
            // Advance past the 8-rounded record and publish the new consumer pos.
            let rounded = need
                .checked_add(7)
                .ok_or_else(|| invalid("record round overflow"))?
                & !7usize;
            cons_pos = cons_pos.wrapping_add(rounded as u64);
            cons_atomic.store(cons_pos, Ordering::Release);
        }
        Ok(delivered)
    }
}

impl Drop for RingBuffer<'_> {
    fn drop(&mut self) {
        let producer_len = self
            .page_size
            .saturating_add(self.data_size.saturating_mul(2));
        // SAFETY: both pointers and lengths are exactly what we mapped in `new`;
        // after this the mappings are gone and the struct is being dropped.
        unsafe {
            libc::munmap(self.consumer.as_ptr().cast(), self.page_size);
            libc::munmap(self.producer.as_ptr().cast(), producer_len);
        }
    }
}
