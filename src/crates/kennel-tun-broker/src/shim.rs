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

use std::collections::{HashMap, HashSet};
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

/// Ceiling on **concurrent** minted names per allowlist grant — the wildcard-exfil bound as a
/// rotating window (0.7.0 W8). A wildcard grant (`.example.com`) holds at most this many live
/// subdomain mints at once; past it, minting a NEW name evicts the least-recently-used mint of
/// the same grant that has **no live flow** — so a legitimate app fanning out to more than 32
/// subdomains over its life keeps working, while a flow-spray holding 32 live flows still gets
/// NODATA for a 33rd name (the concurrent bound holds where it matters). An evicted mint's
/// synthetic address is never reused (the `/64` pool is monotonic), so a client holding a stale
/// AAAA can never reach a different name's destination; it simply re-queries and re-mints.
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

/// One minted name: its synthetic address, the grant it was minted under, and its recency
/// (a monotonic tick, touched on every query) — what the per-grant rotating window evicts by.
struct Mint {
    addr: Ipv6Addr,
    grant: usize,
    last_use: u64,
}

/// The synthetic-address pool: one stable `name → synthetic IPv6` per allowed name.
///
/// Mints in the tun's `/64`. `::1` (interface) and `::2` (resolver) are reserved; the pool
/// starts at `::10` and host suffixes are **monotonic, never reused** — an evicted mint's
/// address stays dead, so a stale cached AAAA can never alias another name. Per grant the
/// pool is a rotating window (`MAX_PER_GRANT` concurrent mints): eviction picks the least-recently-used
/// mint of the same grant whose synthetic has no live flow.
pub struct Pool {
    prefix: [u8; 8],
    next_host: u64,
    mapping: HashMap<String, Mint>,
    /// Live mints per allowlist grant index — the rotating window's occupancy counters.
    per_grant: HashMap<usize, usize>,
    /// The recency clock: bumped on every mint and every repeat query.
    tick: u64,
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
            tick: 0,
        }
    }

    /// The synthetic address for `name` (minted under allowlist grant `grant`), minting one on
    /// first sight and returning (and recency-touching) the existing one thereafter. Returns
    /// `None` when a NEW name is refused: the absolute pool ceiling (`MAX_POOL`, hard), or the
    /// grant's window is full of mints whose synthetics all carry **live flows** (`live`, from
    /// the flow table) — the concurrent wildcard-exfil bound.
    ///
    /// Past the per-grant window with an inactive mint available, the least-recently-used
    /// inactive mint of the same grant is evicted to make room — the rotation (W8). A mint
    /// costs only a DNS AAAA query (cheap, zero-wire) and opens no flow, so the flow cap does
    /// not bound minting itself.
    pub fn mint<S: std::hash::BuildHasher>(
        &mut self,
        name: &str,
        grant: usize,
        live: &HashSet<Ipv6Addr, S>,
    ) -> Option<Ipv6Addr> {
        self.tick = self.tick.saturating_add(1);
        if let Some(m) = self.mapping.get_mut(name) {
            m.last_use = self.tick;
            return Some(m.addr);
        }
        // A new name: the absolute ceiling is hard (never rotated — it is the fate-shared
        // broker's own memory bound, not a policy bound).
        if self.mapping.len() >= MAX_POOL {
            return None;
        }
        if self
            .per_grant
            .get(&grant)
            .is_some_and(|c| *c >= MAX_PER_GRANT)
        {
            // The window is full: evict the least-recently-used mint of THIS grant whose
            // synthetic has no live flow. All live ⇒ refuse (NODATA) — eviction never
            // breaks a live flow.
            let victim = self
                .mapping
                .iter()
                .filter(|(_, m)| m.grant == grant && !live.contains(&m.addr))
                .min_by_key(|(_, m)| m.last_use)
                .map(|(n, _)| n.clone())?;
            self.mapping.remove(&victim);
            if let Some(count) = self.per_grant.get_mut(&grant) {
                *count = count.saturating_sub(1);
            }
        }
        let addr = self.synthetic(self.next_host);
        // Monotonic and saturating: an evicted suffix is never re-minted (a stale cached AAAA
        // must never alias another name), and a mint never wraps into the reserved low suffixes.
        self.next_host = self.next_host.saturating_add(1);
        self.mapping.insert(
            name.to_owned(),
            Mint {
                addr,
                grant,
                last_use: self.tick,
            },
        );
        let count = self.per_grant.entry(grant).or_insert(0);
        *count = count.saturating_add(1);
        Some(addr)
    }

    /// The name a synthetic address maps to, if it is currently minted (the forwarder's reverse
    /// lookup). An evicted mint resolves to `None` — its flow attempt is refused like any
    /// unknown synthetic, and the client re-queries.
    #[must_use]
    pub fn name_of(&self, addr: Ipv6Addr) -> Option<&str> {
        self.mapping
            .iter()
            .find_map(|(n, m)| (m.addr == addr).then_some(n.as_str()))
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
pub fn respond<S: std::hash::BuildHasher>(
    query: &[u8],
    allow: &Allowlist,
    pool: &mut Pool,
    live: &HashSet<Ipv6Addr, S>,
) -> Option<Vec<u8>> {
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
            if let Some(addr) = pool.mint(&name, grant, live) {
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
            &HashSet::new(),
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
                &HashSet::new(),
            )
            .expect("reply"),
        )
        .1;
        let again = reply_summary(
            &respond(
                &query("example.com", QTYPE::TYPE(TYPE::AAAA)),
                &allow,
                &mut pool,
                &HashSet::new(),
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
            &HashSet::new(),
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
            &HashSet::new(),
        )
        .expect("reply");
        assert_eq!(reply_summary(&bytes).0, 0, "no A answer; NODATA");
    }

    #[test]
    fn junk_is_dropped() {
        let allow = Allowlist::new([grant("example.com")]);
        let mut pool = Pool::new(PREFIX);
        assert_eq!(respond(&[], &allow, &mut pool, &HashSet::new()), None);
        assert_eq!(
            respond(&[0xff; 5], &allow, &mut pool, &HashSet::new()),
            None
        );
    }

    /// The rotating window (W8): a wildcard grant holds `MAX_PER_GRANT` concurrent mints;
    /// a fan-out past it keeps working by evicting the least-recently-used INACTIVE mint,
    /// evicted synthetics are never reused, and a window full of live flows still refuses.
    #[test]
    fn the_per_grant_window_rotates_without_breaking_live_flows() {
        let allow = Allowlist::new([grant(".example.com")]);
        let mut pool = Pool::new(PREFIX);
        let mut live: HashSet<Ipv6Addr> = HashSet::new();
        let aaaa = |n: &str, pool: &mut Pool, live: &HashSet<Ipv6Addr>| {
            reply_summary(
                &respond(&query(n, QTYPE::TYPE(TYPE::AAAA)), &allow, pool, live).expect("reply"),
            )
        };

        // Fill the window, capturing s0/s1's synthetics as minted (no recency side effects).
        let mut minted = Vec::new();
        for i in 0..MAX_PER_GRANT {
            let (n, addr) = aaaa(&format!("s{i}.example.com"), &mut pool, &live);
            assert_eq!(n, 1);
            minted.push(addr.expect("minted"));
        }
        let s0 = *minted.first().expect("s0 minted");
        let s1 = *minted.get(1).expect("s1 minted");

        // Touch s0 so s1 is the least-recently-used, then fan out past the window:
        // each new name mints (the rotation), s1 goes first, s0 survives.
        let _ = aaaa("s0.example.com", &mut pool, &live);
        for j in 0..3 {
            assert_eq!(
                aaaa(&format!("extra{j}.example.com"), &mut pool, &live).0,
                1,
                "fan-out past the window keeps minting (rotation)"
            );
        }
        assert_eq!(
            pool.name_of(s0),
            Some("s0.example.com"),
            "recently-used survives"
        );
        assert_eq!(pool.name_of(s1), None, "the LRU mint was evicted");

        // A re-mint of the evicted name gets a NEW synthetic — suffixes are never reused,
        // so a stale cached AAAA can never alias another name.
        let s1_again = aaaa("s1.example.com", &mut pool, &live).1.expect("re-mint");
        assert_ne!(s1_again, s1, "evicted synthetic is never reused");

        // Live-flow protection: with every current mint's synthetic carrying a live flow,
        // a new name is NODATA — the CONCURRENT bound holds under the flow-spray case.
        let mut all_live = Pool::new(PREFIX);
        for i in 0..MAX_PER_GRANT {
            let a = aaaa(&format!("l{i}.example.com"), &mut all_live, &live)
                .1
                .expect("mint");
            live.insert(a);
        }
        assert_eq!(
            aaaa("blocked.example.com", &mut all_live, &live).0,
            0,
            "all-live window refuses: eviction never breaks a live flow"
        );
        // Freeing ONE flow re-opens exactly one slot, and the freed mint is the victim.
        let freed = aaaa("l5.example.com", &mut all_live, &live).1.expect("l5");
        live.remove(&freed);
        assert_eq!(
            aaaa("unblocked.example.com", &mut all_live, &live).0,
            1,
            "one inactive mint = one rotation slot"
        );
        assert_eq!(
            all_live.name_of(freed),
            None,
            "the inactive mint was the victim"
        );
    }
}
