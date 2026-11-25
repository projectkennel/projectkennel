// SPDX-License-Identifier: Apache-2.0

//! Per-user context (`ctx`) allocation.
//!
//! Each running kennel gets a small `ctx` number that selects its loopback
//! subnet (`07-5-network.md`) and names its cgroup. The allocator is per-user
//! and in-memory: a kenneld instance owns the allocations for the kennels it is
//! running, and they vanish when the user session (and kenneld) ends.
//!
//! `ctx 0` is reserved for the user's *default* (unconfined) context — the
//! normal shell — so it is never handed to a kennel. IPv4-capable kennels use
//! `ctx` in the 8-bit field `1..=255` (the user's earlier cap of 256 contexts);
//! the allocator hands out the lowest free value in that range. Name-keyed
//! *reuse* across restarts is the registry's concern (it remembers which name
//! held which `ctx`), not the allocator's.

use kennel_lib_spawn::Ctx;
use std::collections::BTreeSet;

/// The `ctx` reserved for the default (unconfined) context; never allocated.
pub const DEFAULT_CTX: u16 = 0;

/// The highest `ctx` an IPv4-capable kennel can use (the 8-bit v4 field).
pub const MAX_V4_CTX: u16 = 255;

/// A per-user allocator of kennel context numbers.
#[derive(Debug)]
pub struct CtxAllocator {
    used: BTreeSet<Ctx>,
    max: u16,
}

impl Default for CtxAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl CtxAllocator {
    /// An allocator over `1..=MAX_V4_CTX` (ctx 0 reserved for the default context).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            used: BTreeSet::new(),
            max: MAX_V4_CTX,
        }
    }

    /// An allocator whose highest value is `max` (still skipping ctx 0). Useful in
    /// tests and for v6-only ranges beyond the 8-bit v4 field.
    #[must_use]
    pub const fn with_max(max: u16) -> Self {
        Self {
            used: BTreeSet::new(),
            max,
        }
    }

    /// Allocate the lowest free `ctx`, or `None` if the range is exhausted.
    pub fn allocate(&mut self) -> Option<Ctx> {
        // A `Ctx` is never the reserved default context; scan upward for the first gap.
        let free = (1..=self.max)
            .filter_map(Ctx::new)
            .find(|c| !self.used.contains(c))?;
        self.used.insert(free);
        Some(free)
    }

    /// Mark `ctx` as in use (e.g. reusing a name's previous context). Returns
    /// `true` if it was free and is now reserved, `false` if already in use or out
    /// of range.
    pub fn reserve(&mut self, ctx: Ctx) -> bool {
        if ctx.get() > self.max || self.used.contains(&ctx) {
            return false;
        }
        self.used.insert(ctx)
    }

    /// Return `ctx` to the pool.
    pub fn release(&mut self, ctx: Ctx) {
        self.used.remove(&ctx);
    }

    /// Whether `ctx` is currently allocated.
    #[must_use]
    pub fn is_allocated(&self, ctx: Ctx) -> bool {
        self.used.contains(&ctx)
    }

    /// The number of allocated contexts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.used.len()
    }

    /// Whether no contexts are allocated.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.used.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(n: u16) -> Ctx {
        Ctx::new(n).expect("a non-zero ctx")
    }

    #[test]
    fn allocates_lowest_free_skipping_zero() {
        let mut a = CtxAllocator::new();
        assert_eq!(a.allocate(), Some(c(1)));
        assert_eq!(a.allocate(), Some(c(2)));
        assert_eq!(a.allocate(), Some(c(3)));
    }

    #[test]
    fn release_makes_a_context_reusable_lowest_first() {
        let mut a = CtxAllocator::new();
        let (one, two, three) = (a.allocate(), a.allocate(), a.allocate());
        assert_eq!((one, two, three), (Some(c(1)), Some(c(2)), Some(c(3))));
        a.release(c(2));
        assert_eq!(
            a.allocate(),
            Some(c(2)),
            "the freed slot is the lowest free"
        );
        assert_eq!(a.allocate(), Some(c(4)));
    }

    #[test]
    fn reserve_pins_a_specific_context() {
        let mut a = CtxAllocator::new();
        assert!(a.reserve(c(5)), "5 was free");
        assert!(!a.reserve(c(5)), "5 is now taken");
        // Context 0, the default context, cannot even be named as a kennel's.
        assert_eq!(Ctx::new(DEFAULT_CTX), None);
        // Allocation skips the reserved 5.
        assert_eq!(a.allocate(), Some(c(1)));
        for _ in 1..4 {
            a.allocate();
        }
        assert_eq!(a.allocate(), Some(c(6)), "5 stays pinned, so 6 follows 4");
    }

    #[test]
    fn exhaustion_yields_none() {
        let mut a = CtxAllocator::with_max(2); // contexts 1 and 2
        assert_eq!(a.allocate(), Some(c(1)));
        assert_eq!(a.allocate(), Some(c(2)));
        assert_eq!(a.allocate(), None, "range exhausted");
        assert_eq!(a.len(), 2);
        a.release(c(1));
        assert!(!a.is_allocated(c(1)));
        assert_eq!(a.allocate(), Some(c(1)));
        // A context above the allocator's range cannot be reserved.
        assert!(!a.reserve(c(3)));
    }
}
