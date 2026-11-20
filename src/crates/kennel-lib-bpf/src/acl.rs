//! Build the LPM-trie entries for an address ACL from its individual rules.
//!
//! # Why this exists
//!
//! A policy states an ACL as a list of rules, each a CIDR with one port range on one protocol.
//! The kernel side is a longest-prefix-match trie: looking up an address returns the single most
//! specific entry that contains it, and nothing else. Two consequences follow, and both used to
//! be wrong when every rule was written to the trie as its own entry:
//!
//! - Two rules on the same CIDR (`10.0.0.0/8` on 443 and on 80) are the same trie key, so the
//!   second replaced the first.
//! - A rule on a wider CIDR is hidden from any address that also has a narrower entry. For an
//!   allow list that fails closed. For a deny list it fails open: a deny of `10.0.0.0/8` stopped
//!   applying to `10.1.2.3` as soon as some narrower deny mentioned `10.1.0.0/16`.
//!
//! So an entry carries a small set of rules (`struct allow_entry` in `bpf/maps.h`), and
//! [`build_entries`] gives each prefix the rules written for it plus the rules of every wider
//! prefix that contains it. The entry the kernel finds then holds exactly the rules that apply.

use std::io;

/// The most rules one entry carries (`KENNEL_ENTRY_RULES` in `bpf/maps.h`).
pub const ENTRY_RULES: usize = 8;

/// The size of the encoded `struct allow_entry`: a 4-byte head and [`ENTRY_RULES`] 6-byte rules.
pub const ENTRY_SIZE: usize = 52;

/// The encoded single rule the plan carries per ACL line: `port_min`, `port_max` (host order),
/// `protocol`, `flags`, two bytes of padding.
pub type RuleBytes = [u8; 8];

/// One port range on one protocol (`0` is any protocol).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rule {
    port_min: u16,
    port_max: u16,
    protocol: u8,
}

impl Rule {
    /// Whether `self` covers everything `other` does.
    const fn covers(self, other: Self) -> bool {
        (self.protocol == 0 || self.protocol == other.protocol)
            && self.port_min <= other.port_min
            && self.port_max >= other.port_max
    }
}

/// The rules gathered for one prefix.
struct Group<K> {
    key: K,
    prefix_len: u32,
    addr: Vec<u8>,
    rules: Vec<Rule>,
    flags: u8,
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// Whether the first `bits` bits of `a` and `b` are equal.
fn same_prefix(a: &[u8], b: &[u8], bits: u32) -> bool {
    let whole = usize::try_from(bits / 8).unwrap_or(usize::MAX);
    let (Some(head_a), Some(head_b)) = (a.get(..whole), b.get(..whole)) else {
        return false;
    };
    if head_a != head_b {
        return false;
    }
    let rest = bits % 8;
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8.checked_shl(8u32.saturating_sub(rest)).unwrap_or(0);
    match (a.get(whole), b.get(whole)) {
        (Some(x), Some(y)) => x & mask == y & mask,
        _ => false,
    }
}

/// Split an LPM key into its prefix length and address bytes.
fn split_key(key: &[u8]) -> io::Result<(u32, &[u8])> {
    let (Some(len), Some(addr)) = (key.get(..4), key.get(4..)) else {
        return Err(invalid(
            "an LPM key is shorter than its prefix length".to_owned(),
        ));
    };
    let prefix_len = u32::from_ne_bytes(<[u8; 4]>::try_from(len).unwrap_or_default());
    let width = u32::try_from(addr.len().saturating_mul(8)).unwrap_or(u32::MAX);
    if prefix_len > width {
        return Err(invalid(format!(
            "an LPM key has prefix length {prefix_len}, longer than its {width}-bit address"
        )));
    }
    Ok((prefix_len, addr))
}

/// Add `rule` to `rules` unless one already there covers it; drop any it covers.
fn add_rule(rules: &mut Vec<Rule>, rule: Rule) {
    if rules.iter().any(|have| have.covers(rule)) {
        return;
    }
    rules.retain(|have| !rule.covers(*have));
    rules.push(rule);
}

/// Encode a rule set as a `struct allow_entry`.
fn encode(rules: &[Rule], flags: u8) -> Option<[u8; ENTRY_SIZE]> {
    let mut out = [0u8; ENTRY_SIZE];
    *out.get_mut(0)? = u8::try_from(rules.len()).ok()?;
    *out.get_mut(1)? = flags;
    for (slot, rule) in out.get_mut(4..)?.chunks_exact_mut(6).zip(rules) {
        let [lo0, lo1] = rule.port_min.to_ne_bytes();
        let [hi0, hi1] = rule.port_max.to_ne_bytes();
        slot.copy_from_slice(&[lo0, lo1, hi0, hi1, rule.protocol, 0]);
    }
    Some(out)
}

/// Turn an ACL's rules into the entries to write to its LPM trie.
///
/// `rules` pairs an LPM key (a 4-byte native-endian prefix length, then the address bytes) with
/// one encoded rule. The result has one entry per distinct prefix, holding the rules written for
/// that prefix and for every wider prefix containing it, with redundant rules removed.
///
/// # Errors
///
/// `InvalidInput` if a key is malformed, or if some prefix would need more than [`ENTRY_RULES`]
/// rules. The ACL is refused whole: writing a subset would enforce a different policy from the
/// one that was signed.
pub fn build_entries<K>(rules: &[(K, RuleBytes)]) -> io::Result<Vec<(K, [u8; ENTRY_SIZE])>>
where
    K: AsRef<[u8]> + Clone,
{
    let mut groups: Vec<Group<K>> = Vec::new();
    for (key, value) in rules {
        let (prefix_len, addr) = split_key(key.as_ref())?;
        let [lo0, lo1, hi0, hi1, protocol, flags, _, _] = *value;
        let rule = Rule {
            port_min: u16::from_ne_bytes([lo0, lo1]),
            port_max: u16::from_ne_bytes([hi0, hi1]),
            protocol,
        };
        // Bits past the prefix do not distinguish trie keys, so they do not distinguish groups.
        let found = groups
            .iter_mut()
            .find(|g| g.prefix_len == prefix_len && same_prefix(&g.addr, addr, prefix_len));
        if let Some(group) = found {
            add_rule(&mut group.rules, rule);
            group.flags |= flags;
        } else {
            groups.push(Group {
                key: key.clone(),
                prefix_len,
                addr: addr.to_vec(),
                rules: vec![rule],
                flags,
            });
        }
    }

    let mut out = Vec::with_capacity(groups.len());
    for group in &groups {
        let mut effective = group.rules.clone();
        for wider in &groups {
            if wider.prefix_len < group.prefix_len
                && same_prefix(&wider.addr, &group.addr, wider.prefix_len)
            {
                for rule in &wider.rules {
                    add_rule(&mut effective, *rule);
                }
            }
        }
        if effective.len() > ENTRY_RULES {
            return Err(invalid(format!(
                "an address rule set needs {} port/protocol rules on one prefix (/{}); at most \
                 {ENTRY_RULES} fit — widen the port ranges or split the prefix",
                effective.len(),
                group.prefix_len
            )));
        }
        let value = encode(&effective, group.flags)
            .ok_or_else(|| invalid("an ACL entry could not be encoded".to_owned()))?;
        out.push((group.key.clone(), value));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: u8 = 6;
    const UDP: u8 = 17;

    fn key(addr: [u8; 4], prefix_len: u32) -> [u8; 8] {
        let [p0, p1, p2, p3] = prefix_len.to_ne_bytes();
        let [a0, a1, a2, a3] = addr;
        [p0, p1, p2, p3, a0, a1, a2, a3]
    }

    fn rule(port_min: u16, port_max: u16, protocol: u8) -> RuleBytes {
        let [lo0, lo1] = port_min.to_ne_bytes();
        let [hi0, hi1] = port_max.to_ne_bytes();
        [lo0, lo1, hi0, hi1, protocol, 0, 0, 0]
    }

    /// The `(port_min, port_max, protocol)` rules of the built entry for `k`.
    fn rules_of(built: &[([u8; 8], [u8; ENTRY_SIZE])], k: [u8; 8]) -> Vec<(u16, u16, u8)> {
        let Some((_, value)) = built.iter().find(|(have, _)| *have == k) else {
            return Vec::new();
        };
        let n = usize::from(value.first().copied().unwrap_or(0));
        let mut rules: Vec<(u16, u16, u8)> = value
            .get(4..)
            .unwrap_or(&[])
            .chunks_exact(6)
            .take(n)
            .map(|c| {
                let b = <[u8; 6]>::try_from(c).unwrap_or_default();
                let [lo0, lo1, hi0, hi1, protocol, _] = b;
                (
                    u16::from_ne_bytes([lo0, lo1]),
                    u16::from_ne_bytes([hi0, hi1]),
                    protocol,
                )
            })
            .collect();
        rules.sort_unstable();
        rules
    }

    #[test]
    fn rules_on_one_cidr_share_an_entry() {
        // Two ports and a second protocol on the same CIDR: one trie key, all three rules.
        let net = key([10, 0, 0, 0], 8);
        let built = build_entries(&[
            (net, rule(443, 443, TCP)),
            (net, rule(80, 80, TCP)),
            (net, rule(53, 53, UDP)),
        ])
        .expect("built");
        assert_eq!(built.len(), 1);
        assert_eq!(
            rules_of(&built, net),
            [(53, 53, UDP), (80, 80, TCP), (443, 443, TCP)]
        );
    }

    #[test]
    fn a_narrower_prefix_inherits_the_rules_of_the_wider_ones() {
        // The lookup for 10.1.2.3 finds only the /16 entry, so that entry must also carry the
        // /8's rule; otherwise a narrower deny would hide the wider one.
        let wide = key([10, 0, 0, 0], 8);
        let narrow = key([10, 1, 0, 0], 16);
        let other = key([192, 168, 0, 0], 16);
        let built = build_entries(&[
            (wide, rule(0, u16::MAX, 0)),
            (narrow, rule(22, 22, TCP)),
            (other, rule(22, 22, TCP)),
        ])
        .expect("built");
        // The any-port rule covers the port-22 rule, so the narrow entry is just "everything".
        assert_eq!(rules_of(&built, narrow), [(0, u16::MAX, 0)]);
        assert_eq!(rules_of(&built, wide), [(0, u16::MAX, 0)]);
        // An unrelated prefix inherits nothing.
        assert_eq!(rules_of(&built, other), [(22, 22, TCP)]);

        let built = build_entries(&[(wide, rule(443, 443, TCP)), (narrow, rule(22, 22, TCP))])
            .expect("built");
        assert_eq!(rules_of(&built, narrow), [(22, 22, TCP), (443, 443, TCP)]);
        assert_eq!(rules_of(&built, wide), [(443, 443, TCP)]);
    }

    #[test]
    fn host_bits_do_not_make_a_second_key() {
        // 10.0.0.0/8 and 10.9.9.9/8 are one trie node; their rules must be merged, not raced.
        let built = build_entries(&[
            (key([10, 0, 0, 0], 8), rule(80, 80, TCP)),
            (key([10, 9, 9, 9], 8), rule(443, 443, TCP)),
        ])
        .expect("built");
        assert_eq!(built.len(), 1);
        assert_eq!(
            rules_of(&built, key([10, 0, 0, 0], 8)),
            [(80, 80, TCP), (443, 443, TCP)]
        );
    }

    #[test]
    fn more_rules_than_an_entry_holds_is_refused() {
        let net = key([10, 0, 0, 0], 8);
        let many: Vec<_> = (0..9u16)
            .map(|i| {
                (
                    net,
                    rule(
                        1000u16.saturating_add(i.saturating_mul(2)),
                        1000u16.saturating_add(i.saturating_mul(2)),
                        TCP,
                    ),
                )
            })
            .collect();
        let err = build_entries(&many).expect_err("nine distinct rules do not fit");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(build_entries(many.get(..8).unwrap_or(&[])).is_ok());
    }

    #[test]
    fn a_malformed_key_is_refused() {
        assert!(build_entries(&[(key([10, 0, 0, 0], 33), rule(1, 1, TCP))]).is_err());
        assert!(build_entries(&[([0u8; 2], rule(1, 1, TCP))]).is_err());
    }
}
