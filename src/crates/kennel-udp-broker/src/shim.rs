//! The broker's DNS naming shim (W2 Part D): allowlist check → mint a synthetic → build the reply.
//!
//! A query arrives at the broker's reserved resolver address. The shim checks the queried name
//! against the allowlist ([`kennel_lib_policy::name_matches`], the same dot-convention the egress
//! proxy uses); if an **AAAA** query names an allowed host, it mints a stable `name → synthetic
//! IPv6` mapping in the tun's `/64` (persistent for the kennel's life) and answers **AAAA** with
//! the synthetic. Everything else — a denied name, or an A / CNAME / other type — is **NODATA**
//! (`NOERROR`, no answer), never `NXDOMAIN` (which would suppress the AAAA a dual-stack client then
//! needs). **Zero wire activity in every case**: the shim mints, it never resolves. The real
//! resolution happens host-side when a flow to the synthetic is dialled (the forwarder half).

use std::collections::HashMap;
use std::net::Ipv6Addr;

use kennel_lib_policy::name_matches;
use simple_dns::rdata::{RData, AAAA};
use simple_dns::{Packet, ResourceRecord, CLASS};

use crate::QTYPE_AAAA;

/// The interface address's host suffix in the tun `/64` (`::1`) — reserved, never minted.
const TUN_HOST: u64 = 1;
/// The broker resolver's host suffix (`::2`) — reserved, never minted.
const RESOLVER_HOST: u64 = 2;
/// The first host suffix the synthetic pool mints from (`::10`), leaving `::1`/`::2` and a small
/// reserved gap below it. The pool is the rest of the `/64`.
const FIRST_POOL_HOST: u64 = 0x10;
/// The TTL (seconds) on a minted AAAA answer. The mapping is stable for the kennel's life, so the
/// exact value is not load-bearing (rebinding is closed structurally at the dial); a modest TTL
/// keeps re-queries down without pinning a client to a stale view across a kennel restart.
const SYNTH_TTL: u32 = 60;

// The pool must start strictly above the reserved interface (`::1`) and resolver (`::2`) suffixes,
// so a mint can never collide with either — enforced at compile time.
const _: () = assert!(FIRST_POOL_HOST > RESOLVER_HOST && RESOLVER_HOST > TUN_HOST);

/// The per-kennel name allowlist: the `[[net.udp.allow]]` patterns, matched by the shared
/// dot-convention (`example.com` exact; `.example.com` apex + subdomains).
pub struct Allowlist {
    patterns: Vec<String>,
}

impl Allowlist {
    /// Build the allowlist from the settled grant names (each a `NameRule.name`).
    pub fn new(patterns: impl IntoIterator<Item = String>) -> Self {
        Self {
            patterns: patterns.into_iter().collect(),
        }
    }

    /// Whether `name` is permitted by any pattern.
    #[must_use]
    pub fn allows(&self, name: &str) -> bool {
        self.patterns.iter().any(|p| name_matches(p, name))
    }
}

/// The synthetic-address pool: one stable `name → synthetic IPv6` per allowed name.
///
/// Mints in the tun's `/64` and remembers each for the kennel's life. `::1` (interface) and `::2`
/// (resolver) are reserved; the pool starts at `::10`.
pub struct Pool {
    prefix: [u8; 8],
    next_host: u64,
    mapping: HashMap<String, Ipv6Addr>,
}

impl Pool {
    /// A pool over the tun's `/64` (`prefix` = its first eight octets).
    #[must_use]
    pub fn new(prefix: [u8; 8]) -> Self {
        Self {
            prefix,
            next_host: FIRST_POOL_HOST,
            mapping: HashMap::new(),
        }
    }

    /// The synthetic address for `name`, minting one on first sight and returning the existing one
    /// thereafter (stable for the kennel's life).
    pub fn mint(&mut self, name: &str) -> Ipv6Addr {
        if let Some(addr) = self.mapping.get(name) {
            return *addr;
        }
        let addr = self.synthetic(self.next_host);
        // Saturating: the /64 host space is 2^64 and a per-kennel flow cap bounds live names long
        // before this, but never wrap into the reserved low suffixes.
        self.next_host = self.next_host.saturating_add(1);
        self.mapping.insert(name.to_owned(), addr);
        addr
    }

    /// The name a synthetic address maps to, if it was minted (the forwarder's reverse lookup).
    #[must_use]
    pub fn name_of(&self, addr: Ipv6Addr) -> Option<&str> {
        self.mapping
            .iter()
            .find_map(|(n, a)| (*a == addr).then_some(n.as_str()))
    }

    /// Build the `/64` address for `host` from the prefix.
    fn synthetic(&self, host: u64) -> Ipv6Addr {
        let mut octets = [0u8; 16];
        let (prefix, suffix) = octets.split_at_mut(8);
        prefix.copy_from_slice(&self.prefix);
        suffix.copy_from_slice(&host.to_be_bytes());
        Ipv6Addr::from(octets)
    }
}

/// Answer a DNS query per the shim rules, returning the reply's wire bytes (or `None` if the query
/// does not parse or carries no question — a malformed query is dropped, not answered).
///
/// AAAA for an allowed name → the minted synthetic; anything else → NODATA. Never `NXDOMAIN`, and
/// never any wire lookup.
#[must_use]
pub fn respond(query: &[u8], allow: &Allowlist, pool: &mut Pool) -> Option<Vec<u8>> {
    let parsed = Packet::parse(query).ok()?;
    let question = parsed.questions.first()?;
    let name = question.qname.to_string();

    let mut reply = Packet::new_reply(parsed.id());
    reply.questions.push(question.clone());
    if u16::from(question.qtype) == QTYPE_AAAA && allow.allows(&name) {
        let synth: u128 = pool.mint(&name).into();
        reply.answers.push(ResourceRecord::new(
            question.qname.clone(),
            CLASS::IN,
            SYNTH_TTL,
            RData::AAAA(AAAA { address: synth }),
        ));
    }
    // NODATA (denied, or A/CNAME/other): a reply with the question echoed and no answers — NOERROR
    // by default, deliberately not NXDOMAIN.
    reply.build_bytes_vec().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use simple_dns::{Name, Question, QCLASS, QTYPE, TYPE};

    // fd6b:6e9c:691c:8001::/64 — a kennel tun /64.
    const PREFIX: [u8; 8] = [0xfd, 0x6b, 0x6e, 0x9c, 0x69, 0x1c, 0x80, 0x01];

    fn query(name: &str, qtype: QTYPE) -> Vec<u8> {
        let mut p = Packet::new_query(0x4242);
        p.questions.push(Question::new(
            Name::new(name).expect("name"),
            qtype,
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        p.build_bytes_vec().expect("query")
    }

    /// Parse a reply and return (answer count, first AAAA address if any).
    fn reply_summary(bytes: &[u8]) -> (usize, Option<Ipv6Addr>) {
        let p = Packet::parse(bytes).expect("reply parses");
        let aaaa = p.answers.iter().find_map(|rr| match &rr.rdata {
            RData::AAAA(a) => Some(Ipv6Addr::from(a.address)),
            _ => None,
        });
        (p.answers.len(), aaaa)
    }

    #[test]
    fn allowed_aaaa_gets_a_synthetic_in_the_pool() {
        let allow = Allowlist::new([".example.com".to_owned()]);
        let mut pool = Pool::new(PREFIX);
        let bytes = respond(
            &query("api.example.com", QTYPE::TYPE(TYPE::AAAA)),
            &allow,
            &mut pool,
        )
        .expect("reply");
        let (n, aaaa) = reply_summary(&bytes);
        assert_eq!(n, 1, "one AAAA answer");
        let addr = aaaa.expect("AAAA present");
        // The synthetic is in the tun /64 and above the reserved low suffixes.
        assert_eq!(&addr.octets()[..8], &PREFIX, "synthetic is in the tun /64");
        assert!(u128::from(addr) & 0xffff_ffff_ffff_ffff >= u128::from(FIRST_POOL_HOST));
        // Reverse lookup resolves for the forwarder.
        assert_eq!(pool.name_of(addr), Some("api.example.com"));
    }

    #[test]
    fn the_mapping_is_stable_across_queries() {
        let allow = Allowlist::new(["example.com".to_owned()]);
        let mut pool = Pool::new(PREFIX);
        let first = reply_summary(
            &respond(
                &query("example.com", QTYPE::TYPE(TYPE::AAAA)),
                &allow,
                &mut pool,
            )
            .expect("reply"),
        )
        .1;
        let again = reply_summary(
            &respond(
                &query("example.com", QTYPE::TYPE(TYPE::AAAA)),
                &allow,
                &mut pool,
            )
            .expect("reply"),
        )
        .1;
        assert_eq!(first, again, "the same name mints the same synthetic");
    }

    #[test]
    fn denied_name_is_nodata_not_nxdomain() {
        let allow = Allowlist::new(["example.com".to_owned()]);
        let mut pool = Pool::new(PREFIX);
        let bytes = respond(
            &query("evil.test", QTYPE::TYPE(TYPE::AAAA)),
            &allow,
            &mut pool,
        )
        .expect("reply");
        let (n, _) = reply_summary(&bytes);
        assert_eq!(n, 0, "no answer");
        let p = Packet::parse(&bytes).expect("parse");
        assert_eq!(
            p.rcode(),
            simple_dns::RCODE::NoError,
            "NODATA is NOERROR, never NXDOMAIN"
        );
    }

    #[test]
    fn allowed_a_query_is_nodata() {
        // An A query for an allowed name still gets NODATA — the shim only answers AAAA.
        let allow = Allowlist::new(["example.com".to_owned()]);
        let mut pool = Pool::new(PREFIX);
        let bytes = respond(
            &query("example.com", QTYPE::TYPE(TYPE::A)),
            &allow,
            &mut pool,
        )
        .expect("reply");
        assert_eq!(reply_summary(&bytes).0, 0, "no A answer; NODATA");
    }

    #[test]
    fn junk_is_dropped() {
        let allow = Allowlist::new(["example.com".to_owned()]);
        let mut pool = Pool::new(PREFIX);
        assert_eq!(respond(&[], &allow, &mut pool), None);
        assert_eq!(respond(&[0xff; 5], &allow, &mut pool), None);
    }
}
