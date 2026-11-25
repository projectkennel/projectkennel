// SPDX-License-Identifier: Apache-2.0

//! A kennel's context number, as a type (CODING-STANDARDS.md §11.1).

use std::num::NonZeroU16;

/// The context number of a kennel: never 0.
///
/// A context selects a kennel's loopback subnet and names its cgroup. Context 0 is the
/// operator's own, unconfined context, and no kennel is given it. A `Ctx` can only be built
/// from a non-zero number, so a function that takes one cannot be asked to set up, address or
/// tear down the operator's own context as if it were a kennel's.
///
/// On the wire a context is still a `u16`; the decoders turn it into a `Ctx` and refuse 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ctx(NonZeroU16);

impl Ctx {
    /// A context from its number; `None` for 0.
    #[must_use]
    pub fn new(ctx: u16) -> Option<Self> {
        NonZeroU16::new(ctx).map(Self)
    }

    /// The context's number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl std::fmt::Display for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Ctx> for u16 {
    fn from(ctx: Ctx) -> Self {
        ctx.get()
    }
}

impl From<Ctx> for u64 {
    fn from(ctx: Ctx) -> Self {
        Self::from(ctx.get())
    }
}

#[cfg(test)]
mod tests {
    use super::Ctx;

    #[test]
    fn a_context_is_never_zero() {
        assert_eq!(Ctx::new(0), None);
        let ctx = Ctx::new(7).expect("non-zero");
        assert_eq!(ctx.get(), 7);
        assert_eq!(ctx.to_string(), "7");
        assert_eq!(u16::from(ctx), 7);
        assert_eq!(u64::from(ctx), 7);
        assert_eq!(Ctx::new(u16::MAX).map(Ctx::get), Some(u16::MAX));
    }
}
