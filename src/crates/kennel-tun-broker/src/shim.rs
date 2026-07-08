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
use kennel_lib_policy::settled::NameRule;
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

/// Absolute ceiling on distinct minted names per kennel — the synthetic pool's coarse bound (the
/// flow cap bounds live flows, not mints). A spraying workload hits NODATA past it, and only
/// inflates its own fate-shared broker until then.
const MAX_POOL: usize = 4096;

/// Ceiling on distinct minted names per allowlist grant — the wildcard-exfil bound. A wildcard grant
/// (`.example.com`) can mint at most this many distinct subdomains, so a DNS tunnel through it
/// carries at most this many distinct labels; an exact grant mints one. Generous for real use (a
/// service reaches a handful of subdomains); past it a new name under that grant is answered NODATA.
const MAX_PER_GRANT: usize = 32;

// The pool must start strictly above the reserved interface (`::1`) and resolver (`::2`) suffixes,
// so a mint can never collide with either — enforced at compile time.
const _: () = assert!(FIRST_POOL_HOST > RESOLVER_HOST && RESOLVER_HOST > TUN_HOST);

/// The per-kennel UDP allowlist: the settled `[[net.udp.allow]]` grants (`udp_allow_names`),
/// matched by the shared dot-convention (`example.com` exact; `.example.com` apex + subdomains).
///
/// The shim answers DNS **by name** ([`allows_name`](Self::allows_name)) — no port is known at
/// query time — and the flow gate re-checks the datagram's destination port
/// ([`allows`](Self::allows)) against the same grants. One source, two phases: the shim never
/// admits a port the flow gate would reject, because both consult these rules.
pub struct Allowlist {
    rules: Vec<NameRule>,
}

impl Allowlist {
    /// Build the allowlist from the settled UDP grants (`udp_allow_names`).
    pub fn new(rules: impl IntoIterator<Item = NameRule>) -> Self {
        Self {
            rules: rules.into_iter().collect(),
        }
    }

    /// Whether any grant permits `name`, regardless of port — the DNS-time check (a query carries no
    /// port, so the shim mints a synthetic for any allowed name and the flow gate vets the port).
    #[must_use]
    pub fn allows_name(&self, name: &str) -> bool {
        self.first_match(name).is_some()
    }

    /// The index of the first grant that permits `name` (regardless of port) — the DNS-time match,
    /// used to attribute a mint to its grant for the per-grant cap. `None` if no grant matches.
    #[must_use]
    pub fn first_match(&self, name: &str) -> Option<usize> {
        self.rules.iter().position(|r| name_matches(&r.name, name))
    }

    /// Whether any grant permits `(name, port)` — the flow-time check the forwarder applies before
    /// dialling.
    #[must_use]
    pub fn allows(&self, name: &str, port: u16) -> bool {
        self.rules
            .iter()
            .any(|r| name_matches(&r.name, name) && port_permitted(&r.ports, port))
    }
}

/// Whether `port` is permitted by a grant's port set. An empty set means "any port".
fn port_permitted(ports: &[u16], port: u16) -> bool {
    ports.is_empty() || ports.contains(&port)
}

/// The synthetic-address pool: one stable `name → synthetic IPv6` per allowed name.
///
/// Mints in the tun's `/64` and remembers each for the kennel's life. `::1` (interface) and `::2`
/// (resolver) are reserved; the pool starts at `::10`.
pub struct Pool {
    prefix: [u8; 8],
    next_host: u64,
    mapping: HashMap<String, Ipv6Addr>,
    /// Distinct names minted per allowlist grant index — the per-grant cap's counters.
    per_grant: HashMap<usize, usize>,
}

impl Pool {
    /// A pool over the tun's `/64` (`prefix` = its first eight octets).
    #[must_use]
    pub fn new(prefix: [u8; 8]) -> Self {
        Self {
            prefix,
            next_host: FIRST_POOL_HOST,
            mapping: HashMap::new(),
            per_grant: HashMap::new(),
        }
    }

    /// The synthetic address for `name` (minted under allowlist grant `grant`), minting one on first
    /// sight and returning the existing one thereafter (stable for the kennel's life). Returns `None`
    /// when a NEW name would exceed the absolute pool ceiling (`MAX_POOL`) or the grant's own
    /// per-grant ceiling (`MAX_PER_GRANT`).
    ///
    /// A mint costs only a DNS AAAA query (cheap, zero-wire) and opens no flow, so the flow cap does
    /// not bound it. The per-grant cap is the wildcard-exfil bound (a wildcard grant mints at most
    /// `MAX_PER_GRANT` distinct subdomains); the pool cap is the absolute backstop across all grants.
    /// Past either, a new name is answered NODATA, like a denied name; existing mints keep resolving.
    pub fn mint(&mut self, name: &str, grant: usize) -> Option<Ipv6Addr> {
        if let Some(addr) = self.mapping.get(name) {
            return Some(*addr);
        }
        // A new name: bounded globally and per grant. Check before minting so a refused name leaves
        // no counter or pool residue.
        if self.mapping.len() >= MAX_POOL
            || self
                .per_grant
                .get(&grant)
                .is_some_and(|c| *c >= MAX_PER_GRANT)
        {
            return None;
        }
        let addr = self.synthetic(self.next_host);
        // Saturating so a mint never wraps into the reserved low suffixes (unreachable under the cap,
        // but the invariant holds regardless).
        self.next_host = self.next_host.saturating_add(1);
        self.mapping.insert(name.to_owned(), addr);
        let count = self.per_grant.entry(grant).or_insert(0);
        *count = count.saturating_add(1);
        Some(addr)
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
    // Mint under the matching grant. A mint past the pool cap OR the grant's per-grant cap answers
    // NODATA (empty NOERROR), exactly like a denied name — the workload gets no new synthetic and no
    // wire activity, and can neither grow the pool unbounded nor tunnel unlimited labels through a
    // single wildcard grant.
    if u16::from(question.qtype) == QTYPE_AAAA {
        if let Some(grant) = allow.first_match(&name) {
            if let Some(addr) = pool.mint(&name, grant) {
                let synth: u128 = addr.into();
                reply.answers.push(ResourceRecord::new(
                    question.qname.clone(),
                    CLASS::IN,
                    SYNTH_TTL,
                    RData::AAAA(AAAA { address: synth }),
                ));
            }
        }
    }
    // NODATA (denied, or A/CNAME/other): a reply with the question echoed and no answers — NOERROR
    // by default, deliberately not NXDOMAIN.
    reply.build_bytes_vec().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kennel_lib_policy::settled::Protocol;
    use simple_dns::{Name, Question, QCLASS, QTYPE, TYPE};

    // fd6b:6e9c:691c:8001::/64 — a kennel tun /64.
    const PREFIX: [u8; 8] = [0xfd, 0x6b, 0x6e, 0x9c, 0x69, 0x1c, 0x80, 0x01];

    /// A UDP grant for `name` permitting any port (the common shim case).
    fn grant(name: &str) -> NameRule {
        NameRule {
            name: name.to_owned(),
            ports: Vec::new(),
            protocol: Protocol::Udp,
        }
    }

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
        let allow = Allowlist::new([grant(".example.com")]);
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
        let allow = Allowlist::new([grant("example.com")]);
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
        let allow = Allowlist::new([grant("example.com")]);
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
        let allow = Allowlist::new([grant("example.com")]);
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
        let allow = Allowlist::new([grant("example.com")]);
        let mut pool = Pool::new(PREFIX);
        assert_eq!(respond(&[], &allow, &mut pool), None);
        assert_eq!(respond(&[0xff; 5], &allow, &mut pool), None);
    }

    #[test]
    fn a_wildcard_grant_mints_at_most_max_per_grant_distinct_names() {
        let allow = Allowlist::new([grant(".example.com")]);
        let mut pool = Pool::new(PREFIX);
        let aaaa = |n: &str, pool: &mut Pool| {
            reply_summary(
                &respond(&query(n, QTYPE::TYPE(TYPE::AAAA)), &allow, pool).expect("reply"),
            )
            .0
        };
        // The first MAX_PER_GRANT distinct subdomains each mint a synthetic.
        for i in 0..MAX_PER_GRANT {
            assert_eq!(
                aaaa(&format!("s{i}.example.com"), &mut pool),
                1,
                "distinct name {i}"
            );
        }
        // The next distinct subdomain is NODATA — the wildcard-exfil bound (bounds distinct tunnelled
        // labels through one grant).
        assert_eq!(
            aaaa("overflow.example.com", &mut pool),
            0,
            "past per-grant cap = NODATA"
        );
        // An already-minted name still resolves (the cap bounds distinct names, not queries).
        assert_eq!(
            aaaa("s0.example.com", &mut pool),
            1,
            "existing mint still resolves"
        );
    }
}
