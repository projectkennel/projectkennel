//! A kennel's synthetic `/etc`: the standard libc / NSS files.
//!
//! A confined workload still calls into libc — `getaddrinfo`, `getservbyname`,
//! `getpwuid`, `getprotobyname` — which read a handful of `/etc` files. The host's
//! versions are wrong for a kennel (they point DNS at the host resolver, map
//! `localhost` to the host's `127.0.0.1`, and list the host's users), so kenneld
//! renders synthetic versions and the spawn binds them over `/etc/<file>` in the
//! kennel's mount namespace (the "shadow" of `docs/design/07-3-network.md` §7.3.5/§7.3.10).
//!
//! The set:
//! - `hosts` — `localhost` → the kennel's own primary address (so the kennel's own
//!   bound dev servers are reachable as `localhost`, §7.3.10), plus its hostname.
//! - `resolv.conf` — points at the proxy address and fails fast; the kennel does
//!   no direct DNS (cgroup BPF denies it), clients use `socks5h` so the proxy
//!   resolves (§7.3.5).
//! - `nsswitch.conf` — `files` for everything, `files dns` for hosts (the standard
//!   order; `dns` is inert in-kennel but harmless).
//! - `services`, `protocols` — the common IANA entries, so name↔number lookups
//!   work without the host's (identical, non-secret) copies.
//! - `passwd`, `group` — minimal synthetic entries for the kennel's uid/gid (so
//!   `getpwuid` resolves `$HOME`/shell/name) without leaking the host's user list.
//! - `host.conf` — the legacy `multi on`.
//!
//! Rendering is pure and unit-tested; [`materialize`] writes the set to a staging
//! directory the spawn then bind-mounts.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// The files this module renders, in a stable order. The spawn binds each over
/// `/etc/<name>` in the kennel's mount namespace.
pub const FILES: &[&str] = &[
    "hosts",
    "resolv.conf",
    "nsswitch.conf",
    "services",
    "protocols",
    "passwd",
    "group",
    "host.conf",
    "profile",
    "bash.bashrc",
];

/// The masked account/group name the workload's uid and gid resolve to inside a kennel.
///
/// A constant, never the real login name: `getpwuid`/`getgrgid` (and so `id`,
/// `whoami`, `ls -l`) report `kennel`, not the operator's identity. The uid/gid
/// *numbers* are unchanged (they must match the host inodes of bind-mounted files);
/// only the name is masked.
pub const ACCOUNT_NAME: &str = "kennel";

/// What the synthetic `/etc` is rendered from: the kennel's network identity and
/// the workload's credentials.
#[derive(Debug, Clone)]
pub struct EtcParams<'a> {
    /// The kennel's hostname (its runtime name).
    pub hostname: &'a str,
    /// The workload's uid.
    pub uid: u32,
    /// The workload's gid.
    pub gid: u32,
    /// The workload's in-kennel home directory — the constructed shim `$HOME`, *not*
    /// the operator's real home (which would re-leak the identity the [`ACCOUNT_NAME`]
    /// mask hides). The `passwd` entry's home field.
    pub home: &'a Path,
    /// The granted supplementary groups `(name, gid)` (§7.2): resolved + membership-
    /// checked by `kenneld`, named in `/etc/group` so `id` shows names not bare
    /// numbers. These are exactly the gids the seal `setgroups` to. Empty by default.
    pub groups: &'a [(String, u32)],
    /// The kennel's login shell (§7.7.2a): the `passwd` `pw_shell` field. `/bin/sh`
    /// unless the policy set `[exec].shell`.
    pub shell: &'a str,
    /// The kennel's primary IPv4 address, if it has one.
    pub v4: Option<Ipv4Addr>,
    /// The kennel's primary IPv6 address.
    pub v6: Ipv6Addr,
}

impl EtcParams<'_> {
    /// The address the kennel's `localhost` and its proxy resolve to: the primary
    /// v4 when present, else the v6.
    fn primary(&self) -> IpAddr {
        self.v4.map_or(IpAddr::V6(self.v6), IpAddr::V4)
    }
}

/// `/etc/hosts` — `localhost` maps to the kennel's own primary address.
///
/// So a tool checking `localhost:<port>` reaches the kennel's bound service rather
/// than the host's loopback (`docs/design/07-3-network.md` §7.3.10). The hostname maps
/// there too.
#[must_use]
pub fn hosts(p: &EtcParams<'_>) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    if let Some(v4) = p.v4 {
        let _ = writeln!(s, "{v4}\tlocalhost {}", p.hostname);
    }
    let _ = writeln!(
        s,
        "{}\tlocalhost ip6-localhost ip6-loopback {}",
        p.v6, p.hostname
    );
    s
}

/// `/etc/resolv.conf` — pointed at the proxy address with a fast-fail timeout.
///
/// The kennel never resolves directly (cgroup BPF denies it); `socks5h` clients
/// have the proxy resolve. A stray direct query fails fast instead of hanging.
#[must_use]
pub fn resolv_conf(p: &EtcParams<'_>) -> String {
    format!(
        "# Project Kennel: names resolve through the egress proxy (socks5h); direct\n\
         # DNS is denied by cgroup BPF. Pointed at the proxy so a stray query fails\n\
         # fast rather than hanging on a host resolver.\n\
         nameserver {}\n\
         options timeout:1 attempts:1\n",
        p.primary()
    )
}

/// `/etc/nsswitch.conf`: `files` for every database, `files dns` for hosts. The
/// `dns` source is inert in-kennel (no direct DNS) but is the conventional order
/// and harmless.
#[must_use]
pub const fn nsswitch_conf() -> &'static str {
    "passwd:     files\n\
     group:      files\n\
     shadow:     files\n\
     hosts:      files dns\n\
     networks:   files\n\
     protocols:  files\n\
     services:   files\n\
     ethers:     files\n\
     rpc:        files\n\
     netgroup:   files\n"
}

/// `/etc/passwd` — `root`, the kennel's own uid (as the masked [`ACCOUNT_NAME`]), and
/// `nobody`.
///
/// Synthetic — the host's users are not leaked — but enough for
/// `getpwuid(geteuid())` to resolve the home/shell/name a shell or tool expects. The
/// workload's uid resolves to `kennel`, not the operator's login name, and its home
/// is the in-kennel shim `$HOME`, so `id`/`whoami`/`getpwuid` reveal no host identity.
#[must_use]
pub fn passwd(p: &EtcParams<'_>) -> String {
    format!(
        "root:x:0:0:root:/root:/usr/sbin/nologin\n\
         {user}:x:{uid}:{gid}:Kennel user:{home}:{shell}\n\
         nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
        user = ACCOUNT_NAME,
        uid = p.uid,
        gid = p.gid,
        home = p.home.display(),
        shell = p.shell,
    )
}

/// `/etc/group`: `root`, the kennel's own gid (as the masked [`ACCOUNT_NAME`]), and
/// `nogroup`.
///
/// The workload's gid resolves to `kennel`. Inherited *supplementary* gids are not
/// listed here, so they appear in `id` as bare numbers; dropping them entirely is the
/// group-isolation hardening (needs privilege/userns, §7.2.8).
#[must_use]
pub fn group(p: &EtcParams<'_>) -> String {
    use std::fmt::Write as _;
    let mut s = format!(
        "root:x:0:\n\
         {grp}:x:{gid}:\n",
        grp = ACCOUNT_NAME,
        gid = p.gid,
    );
    // One line per granted supplementary group, with the kennel account as a member,
    // so getgrgid resolves the gid to its name and `id` shows it. Skip a group equal
    // to the primary gid (already the `kennel` line above).
    for (name, gid) in p.groups {
        if *gid != p.gid {
            let _ = writeln!(s, "{name}:x:{gid}:{ACCOUNT_NAME}");
        }
    }
    s.push_str("nogroup:x:65534:\n");
    s
}

/// `/etc/host.conf`: the legacy resolver order; `multi on` so a host with several
/// addresses returns them all.
#[must_use]
pub const fn host_conf() -> &'static str {
    "multi on\n"
}

/// `/etc/protocols`: the common IP protocol numbers (a curated subset of the IANA
/// registry — what `getprotobyname`/`getprotobynumber` realistically need).
#[must_use]
pub const fn protocols() -> &'static str {
    "ip      0   IP\n\
     icmp    1   ICMP\n\
     igmp    2   IGMP\n\
     tcp     6   TCP\n\
     udp     17  UDP\n\
     ipv6    41  IPv6\n\
     ipv6-icmp 58 IPv6-ICMP\n\
     ipv6-frag 44 IPv6-Frag\n\
     gre     47  GRE\n\
     esp     50  IPSEC-ESP\n\
     ah      51  IPSEC-AH\n\
     sctp    132 SCTP\n"
}

/// `/etc/services`: the common service↔port entries (a curated subset of the IANA
/// registry — the services a confined dev/agent workload actually uses).
#[must_use]
pub const fn services() -> &'static str {
    "ftp-data    20/tcp\n\
     ftp         21/tcp\n\
     ssh         22/tcp\n\
     telnet      23/tcp\n\
     smtp        25/tcp      mail\n\
     domain      53/tcp\n\
     domain      53/udp\n\
     http        80/tcp      www\n\
     pop3        110/tcp\n\
     ntp         123/udp\n\
     imap        143/tcp\n\
     snmp        161/udp\n\
     ldap        389/tcp\n\
     https       443/tcp\n\
     submission  587/tcp\n\
     ldaps       636/tcp\n\
     imaps       993/tcp\n\
     pop3s       995/tcp\n\
     socks       1080/tcp\n\
     mysql       3306/tcp\n\
     postgresql  5432/tcp\n\
     redis       6379/tcp\n\
     http-alt    8080/tcp\n\
     https-alt   8443/tcp\n"
}

/// Render the file named `name` (one of [`FILES`]) for `p`, or `None` for an
/// unknown name.
#[must_use]
pub fn render(name: &str, p: &EtcParams<'_>) -> Option<String> {
    let body = match name {
        "hosts" => hosts(p),
        "resolv.conf" => resolv_conf(p),
        "nsswitch.conf" => nsswitch_conf().to_owned(),
        "services" => services().to_owned(),
        "protocols" => protocols().to_owned(),
        "passwd" => passwd(p),
        "group" => group(p),
        "host.conf" => host_conf().to_owned(),
        "profile" => profile().to_owned(),
        "bash.bashrc" => bash_bashrc(p),
        _ => return None,
    };
    Some(body)
}

/// `/etc/profile` — the system-level POSIX login-shell init (§7.7.2a).
///
/// Synthesised, read-only, and rebuilt every spawn (never a persistence surface).
/// It only sets a sane `umask` and sources `/etc/bash.bashrc` for bash; `PATH` and
/// the rest of the environment are already synthesised into the workload's `envp`
/// (§7.7.2), so this deliberately does not set them.
#[must_use]
pub const fn profile() -> &'static str {
    "# Synthesised by Project Kennel (07-7-other.md §7.7.2a). Read-only; rebuilt each spawn.\n\
     umask 022\n\
     if [ -n \"${BASH_VERSION-}\" ] && [ -r /etc/bash.bashrc ]; then\n\
     \t. /etc/bash.bashrc\n\
     fi\n"
}

/// `/etc/bash.bashrc` — the system-level interactive-bash init (§7.7.2a).
///
/// Sets a kennel-identifying prompt so an interactive shell is visibly inside the
/// kennel. Synthesised, read-only, rebuilt every spawn.
#[must_use]
pub fn bash_bashrc(p: &EtcParams<'_>) -> String {
    format!(
        "# Synthesised by Project Kennel (07-7-other.md §7.7.2a). Read-only; rebuilt each spawn.\n\
         case $- in *i*) ;; *) return ;; esac\n\
         PS1='[kennel:{host} \\w]\\$ '\n",
        host = p.hostname,
    )
}

/// Write the synthetic `/etc` set into `dir` (created if absent), returning the
/// `(source, /etc/<name>)` pairs the spawn should bind-mount.
///
/// # Errors
///
/// An OS error if `dir` cannot be created or a file cannot be written.
pub fn materialize(dir: &Path, p: &EtcParams<'_>) -> io::Result<Vec<(PathBuf, PathBuf)>> {
    std::fs::create_dir_all(dir)?;
    let mut binds = Vec::with_capacity(FILES.len());
    for name in FILES {
        let body =
            render(name, p).ok_or_else(|| io::Error::other(format!("no renderer for {name}")))?;
        let source = dir.join(name);
        std::fs::write(&source, body)?;
        binds.push((source, Path::new("/etc").join(name)));
    }
    Ok(binds)
}

/// The vanilla TLS + dynamic-linker `/etc` subtrees that exist on this host.
///
/// Returned as the subset present on the host (§7.2.5, the "complete-but-vanilla"
/// `/etc`): the files a confined workload needs for TLS and dynamic linking.
/// The synthetic set ([`materialize`]) covers the libc/NSS files that must be
/// scrubbed (passwd/group/hosts/…). These, by contrast, are package-managed
/// distro content carrying no host-specific detail — the CA-certificate bundle
/// and the dynamic-linker configuration — so binding the host's own copy
/// read-only into the constructed `/etc` is sound. Cross-distro: Debian's
/// `/etc/ssl` versus Red Hat's `/etc/pki` (only existing paths are returned).
/// The caller binds each read-only; `/etc` itself is never bound wholesale.
#[must_use]
pub fn essential_etc_subtrees() -> Vec<PathBuf> {
    const CANDIDATES: &[&str] = &[
        "/etc/ssl/certs",       // Debian/Ubuntu/Arch CA bundle + hash symlinks
        "/etc/ca-certificates", // Debian CA store
        "/etc/pki",             // Red Hat/Fedora CA store + crypto policies
        "/etc/ld.so.conf",      // dynamic-linker search configuration
        "/etc/ld.so.conf.d",
        "/etc/ld.so.cache", // cache; references /usr,/lib (bound at the same paths)
    ];
    CANDIDATES
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> EtcParams<'static> {
        EtcParams {
            hostname: "agent",
            uid: 1000,
            gid: 1000,
            home: Path::new("/run/kennel/agent/home"),
            groups: &[],
            shell: "/bin/sh",
            v4: Some(Ipv4Addr::new(127, 0, 144, 17)),
            v6: "fd00:0:1:1::1".parse().expect("v6"),
        }
    }

    #[test]
    fn hosts_maps_localhost_to_the_kennel_primary() {
        let h = hosts(&params());
        assert!(
            h.contains("127.0.144.17\tlocalhost agent"),
            "v4 localhost → primary: {h}"
        );
        assert!(
            h.contains("fd00:0:1:1::1\tlocalhost"),
            "v6 localhost → primary"
        );
        assert!(!h.contains("127.0.0.1"), "the host's loopback is not used");
    }

    #[test]
    fn passwd_carries_the_policy_shell() {
        // Default shell.
        assert!(
            passwd(&params()).contains(":/run/kennel/agent/home:/bin/sh\n"),
            "{}",
            passwd(&params())
        );
        // A policy-selected shell.
        let mut bash = params();
        bash.shell = "/bin/bash";
        assert!(passwd(&bash).contains(":/bin/bash\n"), "{}", passwd(&bash));
    }

    #[test]
    fn system_rc_files_are_synthesised() {
        assert!(FILES.contains(&"profile") && FILES.contains(&"bash.bashrc"));
        let prof = render("profile", &params()).expect("profile renders");
        assert!(prof.contains("umask 022"));
        assert!(prof.contains("/etc/bash.bashrc"), "profile sources bashrc");
        let rc = render("bash.bashrc", &params()).expect("bashrc renders");
        assert!(rc.contains("PS1="));
        assert!(rc.contains("kennel:agent"), "prompt names the kennel: {rc}");
    }

    #[test]
    fn resolv_conf_points_at_the_proxy_and_fails_fast() {
        let r = resolv_conf(&params());
        assert!(
            r.contains("nameserver 127.0.144.17"),
            "points at the primary/proxy address"
        );
        assert!(r.contains("timeout:1"), "fails fast");
    }

    #[test]
    fn passwd_masks_the_account_and_leaks_no_host_identity() {
        let pw = passwd(&params());
        // The uid resolves to `kennel`, with the in-kennel home — never the real login
        // name or the operator's home directory.
        assert!(
            pw.contains("kennel:x:1000:1000:Kennel user:/run/kennel/agent/home:/bin/sh"),
            "got {pw}"
        );
        assert!(!pw.contains("dev"), "no real username leaks");
        assert!(!pw.contains("/home/"), "no real home leaks");
        assert!(pw.contains("root:x:0:0:"));
        assert!(pw.contains("nobody:x:65534:"));
    }

    #[test]
    fn group_masks_the_gid_name() {
        let g = group(&params());
        assert!(
            g.contains("kennel:x:1000:"),
            "the gid resolves to `kennel`: {g}"
        );
        assert!(!g.contains("dev"), "no real group/user name leaks");
    }

    #[test]
    fn group_names_the_granted_supplementary_groups() {
        let mut p = params();
        let granted = [("dialout".to_owned(), 20u32), ("netdev".to_owned(), 28u32)];
        p.groups = &granted;
        let g = group(&p);
        assert!(
            g.contains("dialout:x:20:kennel"),
            "granted group named with the kennel member: {g}"
        );
        assert!(g.contains("netdev:x:28:kennel"));
        // The primary gid is still the masked `kennel` line, not duplicated.
        assert!(g.contains("kennel:x:1000:"));
    }

    #[test]
    fn v6_only_kennel_uses_v6_for_localhost_and_resolver() {
        let mut p = params();
        p.v4 = None;
        let h = hosts(&p);
        assert!(!h.contains("127.0.144.17"), "no v4 line");
        assert!(h.contains("fd00:0:1:1::1\tlocalhost"));
        assert!(resolv_conf(&p).contains("nameserver fd00:0:1:1::1"));
    }

    #[test]
    fn materialize_writes_every_file_and_returns_etc_binds() {
        let dir = std::env::temp_dir().join(format!("kenneld-etc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let binds = materialize(&dir, &params()).expect("materialize");

        assert_eq!(binds.len(), FILES.len());
        for (source, target) in &binds {
            assert!(source.exists(), "{} written", source.display());
            assert!(
                target.starts_with("/etc/"),
                "target is under /etc: {}",
                target.display()
            );
        }
        // Spot-check a rendered file on disk.
        let hosts = std::fs::read_to_string(dir.join("hosts")).expect("read hosts");
        assert!(hosts.contains("localhost"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_is_none_for_an_unknown_file() {
        assert!(render("shadow", &params()).is_none());
    }

    #[test]
    fn essential_subtrees_are_existing_paths_under_etc() {
        // Returns only host paths that exist, all under /etc (the vanilla TLS +
        // linker set). A bare CI image may have few; whatever is returned must be
        // a real, /etc-rooted path the caller can bind read-only.
        for p in essential_etc_subtrees() {
            assert!(p.starts_with("/etc"), "{} is under /etc", p.display());
            assert!(p.exists(), "{} exists (filtered by existence)", p.display());
        }
    }
}
