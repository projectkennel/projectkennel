//! A kennel's synthetic `/etc`: the standard libc / NSS files.
//!
//! A confined workload still calls into libc — `getaddrinfo`, `getservbyname`,
//! `getpwuid`, `getprotobyname` — which read a handful of `/etc` files. The host's
//! versions are wrong for a kennel (they point DNS at the host resolver, map
//! `localhost` to the host's `127.0.0.1`, and list the host's users), so kenneld
//! renders synthetic versions and the spawn binds them over `/etc/<file>` in the
//! kennel's mount namespace (the "shadow" of `docs/design/07-5-network.md` §7.5.5/§7.5.10).
//!
//! The set:
//! - `hosts` — `localhost` → the kennel's own primary address (so the kennel's own
//!   bound dev servers are reachable as `localhost`, §7.5.10), plus its hostname.
//! - `resolv.conf` — points at the proxy address and fails fast; the kennel does
//!   no direct DNS (cgroup BPF denies it), clients use `socks5h` so the proxy
//!   resolves (§7.5.5).
//! - `nsswitch.conf` — `files` for everything, `files dns` for hosts (the standard
//!   order; `dns` is inert in-kennel but harmless).
//! - `services`, `protocols` — the common IANA entries, so name↔number lookups
//!   work without the host's (identical, non-secret) copies.
//! - `passwd`, `group` — minimal synthetic entries for the kennel's uid/gid (so
//!   `getpwuid` resolves `$HOME`/shell/name) without leaking the host's user list.
//! - `host.conf` — the legacy `multi on`.
//! - `profile`, `bash.bashrc` — the system shell-init files (§7.9.2a): a sane
//!   `umask` and a kennel-identifying prompt; read-only, rebuilt each spawn.
//!
//! Rendering is pure and unit-tested; [`materialize`] writes the set to a staging
//! directory the spawn then bind-mounts. [`materialize_home_dotfiles`] does the same
//! for the user shell-init dotfiles (`~/.bashrc`, `~/.profile`, §7.9.2a), which are
//! copied into the kennel home and reconstructed each spawn.

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

/// What the synthetic `/etc` is rendered from: the kennel's network identity and
/// the workload's credentials.
#[derive(Debug, Clone)]
pub struct EtcParams<'a> {
    /// The kennel's hostname (its runtime name).
    pub hostname: &'a str,
    /// The workload's masked user name (`[identity].user`, default `kennel`): the
    /// `passwd` account name and the member of each supplementary `/etc/group` line.
    pub user: &'a str,
    /// The workload's masked primary-group name (`[identity].group`, default
    /// `kennel`): the `/etc/group` name for the primary gid.
    pub group: &'a str,
    /// The workload's uid.
    pub uid: u32,
    /// The workload's gid.
    pub gid: u32,
    /// The workload's in-kennel home directory — the constructed shim `$HOME`, *not*
    /// the operator's real home (which would re-leak the identity the account name
    /// mask hides). The `passwd` entry's home field.
    pub home: &'a Path,
    /// The granted supplementary groups `(name, gid)` (§7.4): resolved + membership-
    /// checked by `kenneld`, named in `/etc/group` so `id` shows names not bare
    /// numbers. These are exactly the gids the seal `setgroups` to. Empty by default.
    pub groups: &'a [(String, u32)],
    /// The kennel's login shell (§7.9.2a): the `passwd` `pw_shell` field. `/bin/sh`
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
/// than the host's loopback (`docs/design/07-5-network.md` §7.5.10). The hostname maps
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

/// `/etc/passwd` — `root`, the kennel's own uid (as the masked account name), and
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
        user = p.user,
        uid = p.uid,
        gid = p.gid,
        home = p.home.display(),
        shell = p.shell,
    )
}

/// `/etc/group`: `root`, the kennel's own gid (as the masked primary-group name), and
/// `nogroup`.
///
/// The workload's gid resolves to `kennel`. Inherited *supplementary* gids are not
/// listed here, so they appear in `id` as bare numbers; dropping them entirely is the
/// group-isolation hardening (needs privilege/userns, §7.4.8).
#[must_use]
pub fn group(p: &EtcParams<'_>) -> String {
    use std::fmt::Write as _;
    let mut s = format!(
        "root:x:0:\n\
         {grp}:x:{gid}:\n",
        grp = p.group,
        gid = p.gid,
    );
    // One line per granted supplementary group, with the kennel account as a member,
    // so getgrgid resolves the gid to its name and `id` shows it. Skip a group equal
    // to the primary gid (already the primary-group line above).
    for (name, gid) in p.groups {
        if *gid != p.gid {
            let _ = writeln!(s, "{name}:x:{gid}:{user}", user = p.user);
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

/// `/etc/profile` — the system-level POSIX login-shell init (§7.9.2a).
///
/// Synthesised, read-only, and rebuilt every spawn (never a persistence surface).
/// It only sets a sane `umask` and sources `/etc/bash.bashrc` for bash; `PATH` and
/// the rest of the environment are already synthesised into the workload's `envp`
/// (§7.9.2), so this deliberately does not set them.
#[must_use]
pub const fn profile() -> &'static str {
    "# Synthesised by Project Kennel (07-9-other.md §7.9.2a). Read-only; rebuilt each spawn.\n\
     umask 022\n\
     if [ -n \"${BASH_VERSION-}\" ] && [ -r /etc/bash.bashrc ]; then\n\
     \t. /etc/bash.bashrc\n\
     fi\n"
}

/// `/etc/bash.bashrc` — the system-level interactive-bash init (§7.9.2a).
///
/// Sets a kennel-identifying prompt so an interactive shell is visibly inside the
/// kennel. Synthesised, read-only, rebuilt every spawn.
#[must_use]
pub fn bash_bashrc(p: &EtcParams<'_>) -> String {
    format!(
        "# Synthesised by Project Kennel (07-9-other.md §7.9.2a). Read-only; rebuilt each spawn.\n\
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

/// The default user shell-init dotfiles synthesised into the kennel home (§7.9.2a).
///
/// Thin shims that source the (also-synthesised, reconstructed) system rc, so the
/// real prompt/`umask`/etc. live in `/etc/profile` + `/etc/bash.bashrc` and these
/// stay tiny. `(filename, body)`.
const HOME_DOTFILES: &[(&str, &str)] = &[
    (
        ".profile",
        "# Synthesised by Project Kennel (07-9-other.md §7.9.2a). Rebuilt each spawn.\n\
         [ -r /etc/profile ] && . /etc/profile\n",
    ),
    (
        ".bashrc",
        "# Synthesised by Project Kennel (07-9-other.md §7.9.2a). Rebuilt each spawn.\n\
         [ -r /etc/bash.bashrc ] && . /etc/bash.bashrc\n",
    ),
];

/// Synthesise the user shell-init dotfiles into `dir`, returning the
/// `(source, <home>/<name>)` binds the spawn copies into the kennel home (§7.9.2a).
///
/// Reconstructed every spawn (the view root is a fresh tmpfs), so a workload's edits
/// within a run never persist — no self-poisoning surface. A dotfile whose name is in
/// `persist` is **skipped** (not reconstructed), leaving it to the workload's own
/// home grant to carry across runs.
///
/// # Errors
///
/// An OS error if `dir` cannot be created or a file cannot be written.
pub fn materialize_home_dotfiles(
    dir: &Path,
    home: &Path,
    persist: &[String],
) -> io::Result<Vec<(PathBuf, PathBuf)>> {
    std::fs::create_dir_all(dir)?;
    let mut binds = Vec::new();
    for (name, body) in HOME_DOTFILES {
        if persist.iter().any(|p| p == name) {
            continue;
        }
        let source = dir.join(name);
        std::fs::write(&source, body)?;
        binds.push((source, home.join(name)));
    }
    Ok(binds)
}

/// The catalogue filename on the etc-binds cascade (W14).
const ETC_BINDS_FILENAME: &str = "etc-binds.catalog";

/// The vanilla TLS + dynamic-linker `/etc` subtrees that exist on this host.
///
/// The subtrees a confined workload needs for TLS and dynamic linking — the CA-certificate
/// bundle, the dynamic-linker configuration, and the `update-alternatives` symlink farm — bound
/// read-only into the constructed `/etc` (§7.4.5; `/etc` itself is never bound wholesale, and the
/// synthetic libc/NSS files come from [`materialize`]). Returned as the subset present on the host
/// (cross-distro: Debian `/etc/ssl` vs Red Hat `/etc/pki`).
///
/// The set is **not** a baked-in list (that would be a footgun: the operator could neither see nor
/// tune what the view exposes, and could only subtract an invisible default). It loads from the
/// `etc-binds.catalog` **vendor + system** cascade — `/usr/lib/kennel` (the package default) then
/// `/etc/kennel` (admin) — composed additively (a line adds a subtree, a leading `-` prunes one).
/// There is **no user layer**: widening this binds host paths into kennels, a capability, so it is
/// integrity-sensitive (vendor+system only, like the trust store, [[no-hardcoded-paths-config-cascade]]).
#[must_use]
pub fn essential_etc_subtrees() -> Vec<PathBuf> {
    essential_etc_subtrees_from(&etc_binds_layer_paths())
}

/// The body of [`essential_etc_subtrees`] over explicit layer paths (for testing without env).
fn essential_etc_subtrees_from(layer_paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut set: Vec<String> = Vec::new();
    let mut any_found = false;
    for path in layer_paths {
        if let Ok(text) = std::fs::read_to_string(path) {
            any_found = true;
            apply_etc_binds_layer(&mut set, &text);
        }
    }
    if !any_found {
        eprintln!(
            "kenneld: warning: no `{ETC_BINDS_FILENAME}` found under /usr/lib/kennel or /etc/kennel \
             — the constructed view will bind no host /etc subtrees, so TLS / dynamic linking / \
             update-alternatives may break inside kennels. Install the package default."
        );
    }
    set.into_iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
}

/// Apply one line-oriented etc-binds layer: a path adds a subtree, a leading `-` prunes one,
/// `#` starts a comment, blank lines are ignored. Additive + deduplicated.
fn apply_etc_binds_layer(set: &mut Vec<String>, text: &str) {
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('-') {
            let pruned = rest.trim();
            set.retain(|p| p != pruned);
        } else if !set.iter().any(|p| p == line) {
            set.push(line.to_owned());
        }
    }
}

/// The etc-binds cascade paths, lowest priority first: the vendor dir (`$KENNEL_VENDOR_DIR`,
/// default `/usr/lib/kennel`) then the system dir (`$KENNEL_ETC_DIR`, default `/etc/kennel`).
/// **No user layer** — this is integrity-sensitive (widening exposes host paths).
fn etc_binds_layer_paths() -> Vec<PathBuf> {
    let vendor = std::env::var_os("KENNEL_VENDOR_DIR")
        .map_or_else(|| PathBuf::from("/usr/lib/kennel"), PathBuf::from);
    let etc = std::env::var_os("KENNEL_ETC_DIR")
        .map_or_else(|| PathBuf::from("/etc/kennel"), PathBuf::from);
    vec![
        vendor.join(ETC_BINDS_FILENAME),
        etc.join(ETC_BINDS_FILENAME),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> EtcParams<'static> {
        EtcParams {
            hostname: "agent",
            user: "kennel",
            group: "kennel",
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
    fn home_dotfiles_synthesise_and_persist_skips() {
        let dir = std::env::temp_dir().join(format!("kennel-dot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let home = Path::new("/run/kennel/agent");

        // Default: both dotfiles, targeted under the kennel home; .bashrc sources the
        // system rc.
        let binds = materialize_home_dotfiles(&dir, home, &[]).expect("dotfiles");
        assert_eq!(binds.len(), 2);
        assert!(binds.iter().any(|(_s, t)| t == &home.join(".bashrc")));
        assert!(binds.iter().any(|(_s, t)| t == &home.join(".profile")));
        let bashrc = std::fs::read_to_string(dir.join(".bashrc")).expect("read .bashrc");
        assert!(bashrc.contains("/etc/bash.bashrc"), "{bashrc}");

        // A persisted path is not reconstructed.
        let kept =
            materialize_home_dotfiles(&dir, home, &[".bashrc".to_owned()]).expect("dotfiles");
        assert_eq!(kept.len(), 1);
        assert!(kept.iter().all(|(_s, t)| t != &home.join(".bashrc")));
        let _ = std::fs::remove_dir_all(&dir);
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
    fn etc_binds_layer_composes_additively_with_prune() {
        let mut set: Vec<String> = Vec::new();
        apply_etc_binds_layer(&mut set, "# defaults\n/etc/ssl/certs\n/etc/alternatives\n");
        assert_eq!(set, vec!["/etc/ssl/certs", "/etc/alternatives"]);
        // A higher layer adds a new subtree, dedups a re-add, and prunes one with `-`.
        apply_etc_binds_layer(&mut set, "/etc/ssl/certs\n/etc/pki\n-/etc/alternatives\n");
        assert_eq!(set, vec!["/etc/ssl/certs", "/etc/pki"]);
    }

    #[test]
    fn essential_etc_subtrees_loads_the_cascade_and_filters_by_existence() {
        let dir = std::env::temp_dir().join(format!("kennel-etcbinds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let cat = dir.join("etc-binds.catalog");
        // `/etc` exists; a bogus path does not — only the existing subtree is returned.
        std::fs::write(&cat, "/etc\n/etc/kennel-nope-xyz\n").expect("write catalogue");
        let got = essential_etc_subtrees_from(std::slice::from_ref(&cat));
        assert_eq!(got, vec![PathBuf::from("/etc")]);
        for p in &got {
            assert!(p.starts_with("/etc") && p.exists());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
