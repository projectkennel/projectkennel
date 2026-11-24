# As-built log

The durable record of **as-built facts** — what the running code actually does — kept in this
repository, deliberately **separate from the design corpus**. The corpus (the two-volume book,
`github.com/projectkennel/books`, checked out in-tree at `books/`) states the design and the
intended mechanism; this log states where the built system elaborates or diverges from it. When the
two disagree, the book is the design of record and this log is the ground truth about the code — a
code↔design gap is code-owed, and this log is where it is written down.

It is the steady-state successor of the freeze-era patch log (the frozen `docs/archive/design/` and
`docs/archive/architecture/` trees retired with the corpus cutover). It is **not** an ingestion queue:
as-built facts live here; they are not drained into the book.

Each entry: the **bears-on** book chapter (Vol N ch.M, best-effort — the book may restructure), the
**as-built fact**, the **why**, and the **source** (PR / commit). Newest first. Entries dated before
the cutover reference the pre-book chapters; their target lines were repointed to the archived copies
under `docs/archive/` when the trees moved.

---

<!-- Template:
## YYYY-MM-DD — <short title>
- **Bears-on:** Kennel book Vol <N> ch.<M> (<Title>) §<x> (best-effort)
- **Change:** <what is now true as-built / what the book's design would otherwise imply>
- **Why:** <one line>
- **Source:** #<PR> / <commit>
-->

## 2026-11-24 — the follow-up review's remaining findings

- **Bears-on:** Kennel book Vol 2 ch.8 (The Network: the tun path, the INet facade, the inbound
  mirror §7.5.7), §7.6 (`[unix]` grants), §7.12 (spawn), §7.13 (the mesh and the supervisor),
  §9.7 (the TTL custodian), and the audit chapter.
- **Change:**
  - *The tun session channel is `SOCK_SEQPACKET`*, not a connected `SOCK_DGRAM` pair. Frames
    are still one per message. A mediator exits on hang-up, on a zero-length read, or on a send
    that reports the peer gone; `EINTR` no longer ends it. The broker admits two live sessions
    for one kennel (keyed by the tun address kenneld writes into the session payload) and 256
    overall, and reaps mediators from one thread. A refused session is answered at once, not
    retried until the consume deadline. `facade-tun` exits when the channel closes.
  - *A `[[unix.allow]]` `real`* may not be in the daemon's runtime directory
    (`$XDG_RUNTIME_DIR/kennel/`, any part of it) nor in the workload-writable surface (`write` ∪
    `exclusive` ∪ `home_persist` ∪ write-redirect sources). The daemon opens the socket with
    `O_PATH`, applies the first rule to `/proc/self/fd/<n>`'s target, and connects through that
    same path. A `shim`, and the `at` of an af-unix `[[consumes]]`, must be rooted at `/`,
    `~/`, `$HOME/`, `$XDG_RUNTIME_DIR/` or `<home>/`, have no `.`, `..` or `=`, and not sit
    directly under `/`.
  - *The inbound mirror listener is bound to the `lo` device* (`SO_BINDTODEVICE`) before it is
    bound to the kennel's address. `host-inetd` caps conduits per process. kenneld writes a
    `net.inbound-connect` record per accepted connection, releases the binder reference a
    repeated `REGISTER_MIRROR` replaced, and drains held conduits on each arrival.
  - *Egress refuses the host's own addresses.* The INet decision and the UDP mediator list the
    host's interface addresses (`getifaddrs`) at decision time and refuse a literal or resolved
    destination that is one of them, on the same terms as special-use space. A `[net.udp]`
    `name` must be a DNS name.
  - *Enforcement results are reported.* The tripwire and the TTL handler audit a failed
    freeze, kill or thaw as `error`. A registration whose death notification cannot be
    requested is refused.
  - *Spawn narrowing.* `mutable = []` is a compile error. A child's `[[spawn.allow.add]]` for
    an inherited template replaces the inherited entry.
  - *Load-time rules.* `invariant::validate` checks the identity names, the hostname, the
    bind-port cap and the digest form with the compiler's predicates, and `patch::instantiate`
    runs it on the policy it produces.
  - *Smaller items.* The mesh rendezvous datagram is all or nothing; the loopback-address cap
    refuses when it cannot count; a context manager that does not start fails the bring-up;
    kennel names of the form `spawn-<number>-…` are reserved to the daemon; a provider's restart count
    resets after a minute of readiness; start refusals, foreign control connections and
    `stop`/`attach`/`reload` are audited through a daemon-level writer, and
    `lifecycle.kennel-exit` carries `exited`, `stopped` or `reaped`.
- **Not changed:** any local user can connect to a mirrored port (TCP has no peer identity to
  check); the UDP path dials RFC1918, CGNAT and ULA by design; "narrowed to no fields" cannot
  be expressed in a spawn grant (it would need a settled-schema field); `[fs.cwd]` is not part
  of the load-time write-set check, because it is known only at spawn.
- **Why:** each was a place where a control was stated and not enforced, enforced in one of two
  places, or failed open on an error.
- **Source:** the 2026-11-24 follow-up review (findings N-03 to N-23); branch
  `fix/overlay-options-and-dotted-keys`.

## 2026-11-24 — the overlay option string and dotted keys are bounded

- **Bears-on:** Kennel book Vol 2: the view construction chapter (the OCI overlay, §7.11) and
  the policy-parsing chapter (the parser's limits).
- **Change:**
  - *Overlay layers.* `mount_overlay` refuses a lower, upper or work path that is not UTF-8 or
    contains `,`, `:` or `\`, before it attempts the mount. The rule was a comment on the
    function ("callers pass only … paths, none of which carries those bytes"); the OCI staging
    root is named by the factory's caller and was not checked.
  - *Dotted keys.* Each part of a dotted key after the first counts toward `MAX_NESTING` (64),
    the budget arrays, inline tables and table headers already share. A key is refused as soon
    as it would pass the limit. A key of 100,000 parts used to overflow the stack.
- **Why:** the factory performs the overlay mount with root's filesystem identity, so its
  option string must not be shaped by its caller; and the parser runs on a file before the
  file's signature is checked, so no input may cost unbounded stack.
- **Source:** the 2026-11-24 follow-up review (findings N-01 and N-02); branch
  `fix/overlay-options-and-dotted-keys`.

## 2026-11-20 — low-severity hardening, second group

- **Bears-on:** Kennel book Vol 2: the view construction chapter (scaffolding, the OCI closure
  lock §7.11.4c), ch.2 (init and its hand-off descriptors), §7.9 (the PTY broker), §7.5 (the INet
  conduit, the loopback mirror), §7.7 (the D-Bus broker), the audit chapter, the lockfile, and
  the installer.
- **Change:**
  - *View modes.* The view's root tmpfs is mounted `mode=0755` (it was the tmpfs default,
    1777), the construction sets umask 022, and a staged file is copied without group/other
    write. On the VM `/` and `/etc` are 755 and `/etc/passwd` 644.
  - *Init's descriptors.* `kennel-bin-init` marks the boot-sync socket, the pty return socket
    and the injected-stdio originals close-on-exec before it forks anything, and the tun
    descriptor in the workload's seal. The workload and facades used to inherit them.
  - *Orphans.* Only a pid init forked as a facade is reported as `NOTIFY_FACADE_CRASH`; every
    orphan init reaped as PID 1 used to be.
  - *PTY broker.* Writes to an attached client have a 2 s send timeout; a client that stops
    reading is detached instead of holding the broker's lock (which `kennel list` takes).
  - *INet conduit.* `CONNECT_INET` refuses a UDP request: the conduit is a TCP stream, and a
    `protocol = "udp"` allow used to be answered with a TCP connection.
  - *Limits.* The D-Bus broker holds at most 1024 sessions and 1024 queued frames per consumer
    (it stops reading for a consumer whose queue is full) and no longer panics when a thread
    cannot be created; the egress delegate carries at most 1024 conduits; the net sub-helper
    refuses to put more than 1024 of one user's reserved addresses on the loopback.
  - *Closure lock.* A `[rootfs].readonly` path absent from the image is created empty and
    locked; it used to be skipped, leaving the name free for the workload to create.
  - *Audit directories.* Spawned kennels of one requester share `spawn-<ctx>`; each spawn used
    to leave its own directory for good.
  - *CLI output.* Text from a workspace or a policy is sanitised before it reaches the terminal
    in `review`, `risks`, `show` and `oci revert --list`; `review` shows a diff only for a
    regular file and pipes the pinned content to `diff` instead of staging it in `/tmp`.
  - *Lockfile.* A changed signer is a mismatch, not only a changed signature.
  - *`kennel-compose`.* A script's shebang outside the system directories grants that one file,
    not its parent directory.
  - *Installer.* GUI config is installed root-owned file by file (not `cp -a`), and a
    relocated `--prefix` directory is never swept.
  - *`sock_create`.* The header now says which families the hook can see (inet only).
- **Not changed:** the lockfile still cannot pin an unsigned artefact (it pins by signature and
  the tree has no content hash); the documented egress rate limit and volume audit (L-05) still
  do not exist.

## 2026-11-20 — low-severity hardening, first group

- **Bears-on:** Kennel book Vol 2 ch.10 (the bastion's `authorized_keys`), §2.7 (exclusive
  binds, T2.8), the audit chapter (file modes; BPF audit), §7.12.7 (`max_instances`), the BPF
  ABI (`02-7-bpf-abi.md`: maps), and the framework invariants.
- **Change:**
  - `authorized_keys_line` writes a `"` in a destination or option as `\"` and drops line
    breaks, so neither can end the forced command or start a second key line.
  - `recv_with_fds` takes ownership of the descriptors that arrived before it rejects a message
    whose control data was truncated; before, each such message left them open in the receiver.
  - A failed exclusive over-mount is fatal to the construction (the shadows already placed are
    released). It used to be logged and the kennel ran with the path shared.
  - The audit directory is created 0700 and its files 0600; the control socket's directory is
    0700 and the socket 0600, independent of the umask.
  - `SPAWN` claims its `max_instances` slot before it reads and verifies the template, so a
    requester at its ceiling cannot make the daemon do that work by asking again.
  - A new map, `audit_lost`, counts audit events the programs could not reserve; the drain
    reports growth as `net.audit-lost`. `net.bind-allow` (kind 8) is now decoded instead of
    dropped.
  - `kennel-privhelper-bpf` freezes every map but the ringbuf after populating it. The pins are
    owned by the caller's uid, which is the workload's.
  - The metadata-deny invariant requires the deny to cover the whole address (`/32`, every
    port, every protocol), not merely to name it.
- **Behaviour change:** a kennel whose `exclusive` path cannot be shadowed does not start.
- **Not verified:** the exclusive failure path and the lost-event counter have no end-to-end
  case; an audit file that already existed keeps its old mode.

## 2026-11-20 — authoring pipeline: parser limits, key precedence, fragments, the diff

- **Bears-on:** Kennel book Vol 2, the policy pipeline chapters (TOML subset; trust tiers,
  §7.13.5; fragments and `include`; `policy diff`), and the device section (`fs.dev`).
- **Change:**
  - *Parser limits.* `kennel-lib-toml` parses a file before its signature is checked. It had no
    size cap, recursed once per nested `[` or `{`, and indexed tables by pairwise header
    comparison. It now refuses a document over 1 MiB, nesting (or a header) deeper than 64, and
    more than 4096 tables.
  - *Key precedence.* A signer's tier is read off its key id, and a key set resolves an id to
    the first key loaded under it. The daemon reads the vendor store first; the CLI's
    `load_trust_store` read directories in the order given, with the vendor store last, so a
    user's `<vendor-id>.pub` verified a signature whose id then read as vendor. The CLI now
    orders directories vendor, host, then the rest, and warns when a later file redefines an id
    with a different key.
  - *`fs.dev.allow`.* The baseline list takes no reason and no threat tag, and accepted any
    path, so a host device could be bound without the `[[fs.dev.passthrough]]` requirements. It
    now accepts only `/dev/null`, `zero`, `full`, `random`, `urandom`, `tty`, `ptmx` and
    `/dev/pts/**`.
  - *Fragments.* `is_additive_only` did not look at `fs.cwd`, `fs.dev.allow` or `net.udp`, so a
    fragment could set them. An included fragment was never validated: it now passes
    `validate_fragment` (references, redirect sources, mmap-exec entries, D-Bus) and the device
    rules.
  - *`policy diff`.* The grant enumeration stopped at the carriers the risk engine tags; a
    change to `[dbus]`, `[fs.cwd]`, `fs.home.persist`, `[env]`, `[seccomp]`, `fs.deny`,
    `exec.deny`, `fs.exclusive`, `fs.dev.allow`, `[cap]`, `[rootfs]`, `[spawn]`, `[ulimits]`,
    `[audit]` and others diffed as no change. Lists are now itemised and the remaining sections
    compared whole.
- **Not changed:** the `reason` rule is not applied to fragments, because the shipped,
  maintainer-signed `gui-desktop` fragment has an `fs.read` entry without one; `policy risks`
  still derives no exposure from the sections the diff now shows.
- **Why:** each is a place where the tooling an author relies on to see or bound a policy looked
  at less than the policy.

## 2026-11-20 — runtime hardening: handles, x32, OCI revert, the cwd workspace, the redirect floor

- **Bears-on:** Kennel book Vol 2, the binder chapter (registration verbs); the seccomp section
  (§7.4); the OCI substrate (§7.11.4a, selective revert); the trust manifest (§7.4, T2.8) and
  `[fs.cwd]` (§7.9); `fs.redirect` (W15).
- **Change:**
  - *Binder handles.* `REGISTER_MIRROR`, `REGISTER_TUN_SINK` and mesh `ADD_SERVICE` read the
    registered node's handle from the last 24 bytes of the payload. Nothing tied those bytes to
    an object the driver had translated, so a sender could write the bytes of a handle object
    itself and name any number in kenneld's handle table — another kennel's node. `Incoming`
    now carries the object offsets the driver delivered, and `Incoming::trailing_handle` returns
    a handle only for an object at a listed offset.
  - *x32.* The seccomp filter matches native syscall numbers under `AUDIT_ARCH_X86_64`. On a
    kernel built with the x32 ABI the same calls exist a second time with bit 30 set, under the
    same architecture value, so every denylist entry had an unfiltered twin. On `x86_64` the
    compiled filter is now preceded by three instructions that apply the filter's refusal action
    to any syscall number at or above `0x40000000`.
  - *`oci revert -- <path>`.* The persisted upper is written by the workload. The target was
    `upper.join(path)` with a lexical containment check, so a directory in the upper replaced
    by a symlink led `remove_dir_all` out of the store. The target is now reached through a
    handle on its parent, resolved inside the upper (`RootDir`), and removed by its final name.
  - *`[fs.cwd] write`.* The trust-manifest mask, the pre-flight that writes a baseline manifest,
    the live tripwire and `kennel review` all walked `fs.write` only. A project made writable by
    the cwd grant had no mask (the workload could read and rewrite `.trust-manifest.json`), no
    tripwire and no review. `Plan::grant_cwd` now adds the mask for a writable cwd, and the CLI
    walks `review::writable_roots`, which adds the invocation directory when the policy grants
    `[fs.cwd] write`.
  - *Redirect floor.* The settle-time `fs.redirect.write-set` check compares policy strings:
    before per-user substitution, before a spawn patch, and without counting the host side of a
    *writable* redirect as writable. The invariant now counts those sources, and the daemon
    re-runs the rule on the plan (`Plan::writable_redirect_source`: resolved host paths, every
    writable bind) and refuses the start.
- **Behaviour change:** x32 binaries do not run in a kennel on `x86_64`. `kennel review` run from
  a project directory reviews that directory when the policy grants `[fs.cwd] write`.
- **Not verified:** x32 was tested as a filter-shape unit test only (the VM is aarch64). The
  handle rule has no end-to-end case with a forged object. `kennel review` learns the cwd from
  where it is run, not from where the kennel was run.

## 2026-11-20 — host mode judges inbound traffic; a deny with no protocol is every protocol

- **Bears-on:** Kennel book Vol 2, the network chapter (§7.5.7 the bind ACL; §7.3.7 the bind
  floor and port allowlist) and the BPF ABI (`02-7-bpf-abi.md`: programs, audit kinds).
- **Change:**
  - *A ninth program, `cgroup_skb/ingress`.* The bind hooks judge a `bind()` call, but
    `listen()` on an unbound TCP socket binds it to the wildcard address on a kernel-chosen port
    with no hook, and a bind to port 0 is admitted without the address ACL or the wildcard
    rewrite (an outbound socket needs that). Either gave a host-mode kennel a service reachable
    from the network that the policy never admitted. There is no cgroup hook on `listen()`, so
    the decision is made on arrival: a packet for a TCP listener is dropped unless the
    listener's own address and port pass the bind policy (floor, port allowlist, bind ACL; a
    wildcard listener never passes, since a bind the policy saw is rewritten to the kennel's
    loopback); a datagram for a UDP socket is delivered if the socket passes the bind policy or
    the sender is a peer the connect ACL lets the kennel send to (a reply). Packets for
    connected TCP sockets pass. Two audit kinds: `net.listen-deny` (9) and `net.ingress-deny`
    (10); they carry no pid or comm, because there is no task in that context.
  - *Deny protocol.* With denies now matched on port and protocol (previous entry), a
    `[net.bpf]` deny written with no `protocol` had become TCP-only, because the compiler's
    default protocol is TCP. A deny with no `protocol` is now compiled as every protocol, and
    the plan widens any every-port deny to every protocol whatever it names, so a policy signed
    by an older compiler does not start admitting UDP to an address it denies.
- **Behaviour change:** a `host`-mode workload that listened without binding, or relied on
  unsolicited UDP to a port-0 socket, no longer receives. A deny of `protocol = "tcp"` with no
  ports also denies UDP (only a port-limited deny is protocol-specific).
- **Why:** the bind policy is a statement about what can reach the kennel; it has to hold for
  every socket that can receive, not only for those that called `bind()`.
- **Not changed:** an IPv6 datagram with extension headers is dropped (the sender's port cannot
  be read at a fixed offset). ICMP errors for a kennel's sockets are not handled here.

## 2026-11-20 — host mode: only TCP and UDP sockets, every port rule applies, and a scope floor

- **Bears-on:** Kennel book Vol 2, the network chapter (§7.5.4 the host-mode connect ACL, §7.5.7
  the bind ACL), the BPF ABI (`02-7-bpf-abi.md`: `struct allow_entry`, `KENNEL_ABI_VERSION`), and
  ch.9 (Local Services, `unix.abstract`).
- **Change:**
  - *Socket creation.* `sock_create` admitted any type and protocol in `AF_INET`/`AF_INET6`. The
    address ACL is the connect, sendmsg and bind hooks, which exist for TCP and UDP; an ICMP
    datagram ("ping") socket needs no capability and reached a denied address with no audit
    event, and SCTP, UDP-Lite and MPTCP sockets were likewise created. The program now admits
    `SOCK_STREAM` with `IPPROTO_TCP` and `SOCK_DGRAM` with `IPPROTO_UDP` (the resolved protocol,
    so a `0` protocol reads as TCP or UDP) and refuses the rest with a `net.sock-deny` event.
  - *Map value format.* `struct allow_entry` was one `(port_min, port_max, protocol)`. An LPM
    lookup returns one entry per address, and each policy rule was written as its own entry, so
    several ports or protocols on one CIDR overwrote each other (the last one won), and the deny
    tries were consulted for presence only, so a deny with `ports` denied every port. The value
    is now a set of up to eight rules (`KENNEL_ENTRY_RULES`, 52 bytes; `KENNEL_ABI_VERSION` 2).
    `kennel_lib_bpf::acl::build_entries` builds one entry per prefix carrying the rules of that
    prefix and of every wider prefix that contains it, drops rules another rule covers, and
    refuses an ACL that needs more than eight on one prefix. Deny entries are matched on port
    and protocol exactly like allow entries. The plan and the privhelper wire format are
    unchanged (one rule per line); the merge happens in `kennel-privhelper-bpf` as it writes the
    maps.
  - *Landlock floor.* The seal enables the scopes the kernel's Landlock supports, so on ABI 5
    (kernel 6.10–6.11) a kennel started unscoped with no error. A `host`-mode kennel shares the
    host's abstract-socket namespace, and the scope is the only thing that keeps it off those
    sockets. `kenneld` now refuses to start a `host`-mode policy when the kernel's Landlock ABI
    is below 6. Other modes have their own network namespace and are not affected; the README's
    blanket "ABI ≥ 6" is corrected to say this.
- **Behaviour change:** in a `host`-mode kennel (the only mode these programs are attached in;
  the others have a private network namespace), `ping` (ICMP sockets), SCTP, UDP-Lite and MPTCP sockets
  fail at `socket()` with `EPERM`. A deny with `ports` now denies only those ports.
- **Why:** an ACL on addresses has to see every socket that can carry data to an address, and has
  to apply every rule that was written for it.
- **Not changed:** `listen()` on an unbound socket and UDP port-0 binds still bypass the bind
  ACL (R-26). The floor was tested only as a decision function; no ABI 5 kernel was available.

## 2026-11-20 — a daemon-initiated binder transaction sleeps, and gives up at a deadline

- **Bears-on:** Kennel book Vol 2, the binder chapter (`02-4-binder.md` §Threading model) and the
  mesh mediation path (§7.7, §7.13).
- **Change:** `kenneld` sends two synchronous transactions to a process inside a kennel: the
  mediation broker's `NEW_SESSION` and the tun broker's `DELIVER_TUN_SESSION`. Its endpoint is
  non-blocking (the looper pool needs that), and the wait for the reply was `loop { cycle() }`
  with `EAGAIN` treated as an empty cycle: a busy loop, with no deadline. A peer that did not
  answer held a daemon thread at full CPU until it did. As-built now (`Connection::turn`), an
  empty cycle sleeps in `poll` on the binder descriptor, and after `TRANSACT_DEADLINE` (30 s)
  the thread discards its binder state with `BINDER_THREAD_EXIT`, re-enters the looper, and the
  caller gets `TimedOut`. Discarding the state detaches the unanswered transaction, so a late
  reply fails at the replier instead of being read as the answer to the thread's next call.
- **Consequence:** the inbound transaction the thread was serving (the consumer's connect) is
  detached with it and is not answered; replies are skipped until the thread's next read. That
  consumer stays blocked until the silent peer answers or exits — as it was before, without the
  daemon thread.
- **Why:** the peer of these transactions is confined code; its silence must cost the daemon a
  bounded wait and nothing else.
- **Not changed:** a transaction the peer sends back to the waiting thread (a nested inbound
  call) is still ignored and its buffer not freed; handles are still taken from payload bytes
  (R-18).

## 2026-11-20 — daemon and view hardening: the pin, the bastion, accept, audit size, nested mounts

- **Bears-on:** Kennel book Vol 2 ch.10 (Cryptographic Services, the SSH bastion §7.10.3–6);
  the workload pin (§7.4); the audit schema chapter (`02-3`, event size); the view construction
  chapter (read-only grants, the OCI closure lock §7.11.4c); the inbound mirror (§7.5.7).
- **Change:**
  - *Workload digest pin.* The sha256 pin was checked only when no `--` command was given. A
    pinned workload with `allowed_args = true` runs the policy's program with the caller's
    arguments appended, and that path skipped the check. The pin now applies whenever the
    policy's own program runs (`runs_policy_program`).
  - *Bastion.* The forced command is now `ssh -o EscapeChar=none -o ClearAllForwardings=yes
    <options> -- <dest> …`. The session has a pty, so the host-side client read `~` escapes from
    the workload's bytes (on OpenSSH before 9.2, `~C` opens a command line that adds
    forwardings from the operator's side), and forwardings set in the operator's `ssh_config`
    for the destination were honoured. The two options lead, so they win over `options`.
  - *Control socket.* Any `accept` error ended `serve`, and with it the daemon. A failure is now
    logged and retried after 100 ms; only 300 consecutive failures end the loop.
  - *Inbound bounce buffer.* Conduits that arrive before a facade registers are queued per port;
    the queue was unbounded, each entry an open descriptor in the daemon, the count chosen by
    whoever connects to the mirrored port. It now holds at most 64 per port; a further conduit
    is closed.
  - *Audit event size.* The line sinks refuse an event over 4096 bytes, and behind the timeout
    wrapper that refusal was discarded: no record and no drop record. An event's size is set by
    what it reports (a spawned command line). The writer now cuts an oversized event down —
    longest event-specific string first, then values — and marks it `"truncated": true`; the
    envelope is never cut. The timeout worker reports a sink failure on stderr.
  - *Read-only binds.* A read-only grant is bound with `MS_REC` but was sealed with a
    non-recursive `MS_REMOUNT | MS_RDONLY`, so a filesystem mounted inside the granted tree
    stayed writable at the mount layer. In an OCI root, whose `readonly` paths are held by the
    mount alone, nothing else denied the write. Both sites now seal with
    `mount_setattr(AT_RECURSIVE, MOUNT_ATTR_RDONLY)` (`namespace::readonly_mount_tree`).
- **Why:** each is a place where an input the workload or a local peer controls decided
  something the daemon should have decided.
- **Not verified:** the escape-character behaviour was not exercised against an OpenSSH older
  than 9.2; the nested-mount case has no suite case (it needs a host mount inside a granted tree).

## 2026-11-20 — the signed bytes are the policy; a rule that cannot be matched does not sign

- **Bears-on:** Kennel book Vol 2, the policy pipeline chapters (canonical form and signing;
  template chains and the `{ add, remove }` increment; `[net]` address rules).
- **Change:** three places where what was signed and what was enforced could differ.
  - *Canonical form.* The canonical form omits `[workload]` when `argv` is empty, `[rootfs]` when
    `path` is empty and `[dbus]` when no bus is enabled, but the loader parsed and honoured the
    other fields of those sections (`pinned`, `sha256`, `allowed_args`, `cwd`; `writable`,
    `readonly`, `persistence`; `audit_level`). Such a field could be added to a settled file
    without invalidating its signature. As-built now, `canonical::canonical_bytes` reads the body
    back from its own canonical form and requires it to equal the body; signer and verifier both
    go through it, so a policy with content its signature would not cover neither signs nor loads.
  - *Chain fold.* `fold_listfield`, `fold_pathfield` and `fold_groupfield` treated an inherited
    `{ add, remove }` as an empty list. That happens when a root template uses the increment form
    itself, or when the first artefact in a chain to declare a section is not the root (its raw
    increment becomes the accumulator). The next increment then replaced it: a template's
    `[[net.proxy.deny.policy.add]]`, `[[net.bpf.connect.deny.add]]` or `[[fs.deny.add]]` vanished
    from every leaf that added one of its own. An inherited increment is now resolved (its `add`
    minus its `remove`) before the child's is applied.
  - *Address rules.* `parse_cidr` checked only that the prefix was a `u8`. `10.0.0/8`, a
    hostname, or `/33` on an IPv4 address compiled and signed; `kenneld` then dropped the rule
    when it failed to parse (`inet.rs`, `filter_map`). For a deny that is a rule the author
    believes in and does not have. The compiler now requires an IP literal and a prefix that fits
    its family, and `invariant::validate` re-asserts it at load for all seven address-rule lists.
- **Why:** the signature is the statement of what a kennel is allowed; anything honoured outside
  it, or signed and then not enforced, makes that statement false.
- **Not changed:** `fold_redirects` (the `source` axis of a path increment) was not revisited.

## 2026-11-19 — the D-Bus driver is mediated by method; `own` is enforced

- **Bears-on:** Kennel book Vol 2, the D-Bus mediation chapter (§7.7.4 name ownership, §7.7.6
  the match table, §7.7.10). The archived design said `RequestName` outside `own` returns
  not-allowed and `StartServiceByName` is permitted only for allowed destinations; the code did
  neither.
- **Change:** `Filter::decide` judged a call by its destination name only, and the bus driver
  (`org.freedesktop.DBus`) was a destination like any other. A client cannot work without it
  (`AddMatch`), so every `[dbus]` policy grants it — and with that grant every driver method was
  forwarded. `BusRules.own` was carried from the policy to the broker and read by nothing. On the
  test VM, a kennel with `talk = ["org.freedesktop.DBus"]` and an empty `own` called
  `RequestName` for an arbitrary name and the bus granted it. As-built now, a call to the driver
  that the policy admits is further decided by method (`filter::driver_decision`), default-deny:
  - admitted: the read-only queries (`GetId`, `GetNameOwner`, `NameHasOwner`, `ListNames`,
    `ListActivatableNames`, `ListQueuedOwners`, `GetConnection*`), `RemoveMatch`, `Hello`, and
    `Peer.Ping`/`GetMachineId`, `Introspectable.Introspect`, `Properties.Get`/`GetAll`;
  - `AddMatch`, unless the rule mentions `eavesdrop`;
  - `RequestName` / `ReleaseName`, only for a name `own` admits;
  - `StartServiceByName`, only for a destination the kennel may call anyway (not refused to
    brokering, not denied, admitted by `talk` or a `call` entry);
  - everything else is refused — notably `UpdateActivationEnvironment`, which sets the
    environment of services the bus later activates outside any kennel, and `BecomeMonitor`.
  A method call that omits its interface is judged as the driver's own interface, since the
  driver resolves it by member alone. The string argument is read from a little-endian body
  whose signature starts with `s`; if it cannot be read the call is refused.
- **Behaviour change:** an application that requests its own bus name (most GUI toolkits do)
  now needs that name in `[dbus.<bus>.allow] own`.
- **Why:** the driver's methods act on the bus, not on a peer, so a name-based allowlist does not
  describe what granting it permits.
- **Not changed:** signals are still admitted by the sender-chosen interface string against
  `broadcast ∪ talk`, not by sending service; replies are still matched on `reply_serial` alone;
  the compiler still accepts a `talk` grant of the driver without comment (it is now safe to).
- **Source:** branch `fix/root-owned-kennel-userns`.

## 2026-11-19 — node 0 frees the inbound buffer before it replies

- **Bears-on:** Kennel book Vol 2, the binder chapter (§7.1, the transaction/buffer discipline);
  the TTL custodian (§9.7). THREATS T5.1.
- **Change:** every reply was one write of `[BC_REPLY][BC_FREE_BUFFER]`, and `write_only` never
  looked at `write_consumed`. The binder driver stops processing a write at the first command
  that fails and still returns success, so a reply the **sender** could make fail left the free
  unprocessed and the inbound buffer allocated for the life of the endpoint. The simplest way to
  make it fail is to send one-way: there is no transaction stack to reply onto. On the test VM a
  workload's node 0 accepted eight 8 KiB one-way transactions (the 64 KiB one-way allowance) and
  refused every one after — with which `kennel-bin-init`'s TTL-expiry notice can no longer be
  delivered, and on a mesh bus every participant's `SVC_CONNECT` is affected. As-built now:
  - the write is `[BC_FREE_BUFFER][BC_REPLY]` (`Connection::reply_write`): the free is
    unconditional. The reply rides the thread's transaction stack, not the buffer, and handlers
    already take their own reference to anything they keep from it;
  - `Incoming` carries `one_way`, and a one-way transaction is freed and **not** replied to.
- **Why:** a resource the peer fills must be released on a path the peer cannot interrupt.
- **Not changed:** `write_only` still ignores `write_consumed`, so after a reply that fails for
  another reason (the peer died, or did not accept a returned fd) a command queued behind it in
  the same write — the handle release after `HandleOnce` — is still skipped. The transact loops
  still discard a nested inbound transaction without freeing it, still busy-spin on a
  non-blocking fd, and still have no deadline.
- **Source:** branch `fix/root-owned-kennel-userns`.

## 2026-11-19 — the trust manifest is validated on load; revert and re-pin act inside the workspace

- **Bears-on:** Kennel book Vol 2, the workspace trust-manifest chapter (§7.4, T2.8) — the
  `kennel review` flow.
- **Change:** `kennel review` runs as the operator, on the host, over a workspace a confined
  workload could write and which may be a freshly cloned repository. It trusted both.
  - **The manifest itself.** `Manifest::from_json` checked only the schema version. Trigger keys
    were joined to the workspace root and written to on `--revert`; a content hash was used as a
    blob file name. A repository could ship a `.trust-manifest.json` whose trigger path was
    `../../.config/autostart/x.desktop` and a matching blob. `Manifest::validate` now runs on
    load: a trigger path must be relative plain names, a content hash exactly `sha256:` plus 64
    lowercase hex digits. `read_blob` refuses anything else too.
  - **Revert.** `restore_entry` did `fs::write` and `chmod` on the path, which follow a symlink:
    a pinned `Makefile` swapped for a link to `~/.bashrc` had the pinned content written over the
    link's target. It now resolves the path inside the workspace by descriptor
    (`fd::RootDir`), removes whatever is there and creates the file new; a planted trigger is
    removed the same way. The blob is hashed and must match its pin before it is written
    anywhere, and set-id bits are not restored.
  - **Enumeration.** A catalogue directory trigger (`.git/hooks/`) replaced by a symlink to
    another directory was listed through, so files outside the workspace appeared as "new
    triggers" — removed on revert, copied into the store on re-pin. A directory trigger must now
    be a real directory.
  - **Re-pin.** `apply_review` re-read and re-hashed each file at confirm time and never compared
    the result with what the review had shown; a still-running workload could swap the content
    after the diff. It now pins only if the fresh signature equals the reviewed one, and reports
    the trigger otherwise.
- **Why:** the reviewer's tool must not be steerable by the thing under review.
- **Not changed:** `review` still does not require the kennel to be stopped; `New` triggers are
  still pinned without their content being displayed; the diff and trigger paths are still
  printed without terminal sanitisation; `disk_signature` and `pin_entry` still read through a
  symlinked parent directory of a trigger that was pinned before the directory was swapped.
- **Source:** branch `fix/root-owned-kennel-userns`.

## 2026-11-19 — mesh names are one safe path component; the rendezvous connect is pinned to a socket; signing stages nothing on disk

- **Bears-on:** Kennel book Vol 2, the service catalogue and mesh chapters (§7.13.3, §7.13.4b);
  the signing chapter. THREATS T3.10.
- **Change:**
  - **Capability `name` / `key` grammar.** `kenneld` joins a provider's `name` and `key` into a
    host path — the rendezvous directory it creates, chmods `0700`, and binds writable into the
    provider — and its path builder documented them as "filesystem-safe single components by
    compile validation". The compiler checked only that `name` was non-empty, unreserved and
    unique, and never looked at `key`: on the test VM a `[[provides]] name = "x/../../../../tmp/…"`
    compiled. `kennel_lib_policy::meshname` now defines the grammar (letters, digits, `.`, `-`,
    `_`; no empty label; bounded length). It is enforced for `[[provides]]` and `[[consumes]]` at
    compile, re-asserted by `invariant::validate` when a settled policy loads (an artefact can be
    signed without passing through the compiler), and `kenneld::mesh::component` refuses to
    build a path from anything else.
  - **The rendezvous connect.** On an af-unix consume, `kenneld` path-connected, from the host,
    to `<rendezvous dir>/<endpoint leaf>` — a directory the provider can write. A provider that
    replaced its socket with a symlink sent the consumer's connection to any host socket the
    operator can reach (reproduced on the VM with a scratch socket; `kenneld`'s own control
    socket is such a socket, and its peer-credential check would see `kenneld`). The connect now
    goes through `fd::socket_in_dir`: the directory is reached with no symlink followed, the leaf
    is opened without being followed and must be a **socket** on that filesystem, and the connect
    is made to that inode.
  - **Signing.** `sshsig_sign` wrote the message to `/tmp/kennel-sign-<pid>/canonical` (a
    directory made with `create_dir_all`, so a pre-existing one of any owner was accepted) and
    read `canonical.sig` back; root went through this with the host key at install. The message
    now goes to `ssh-keygen -Y sign` on stdin and the signature is read from stdout.
- **Why:** a name the daemon turns into a path must be validated where the daemon can rely on
  it; a connect made by the daemon into a directory a workload writes must not follow what the
  workload put there; and a privileged signer must not stage its input where others can write.
- **Not changed:** the other predictable `/tmp` paths in the CLI (the clone staging file, the
  `TempSettled` fallback when `XDG_RUNTIME_DIR` is unset, the pinned-baseline temp file).
- **Source:** branch `fix/root-owned-kennel-userns`.

## 2026-11-19 — an address is judged as the destination the kernel will dial

- **Bears-on:** Kennel book Vol 2, the network chapter (§7.5: the proxied modes' special-use gate,
  the `host`-mode cgroup BPF ACL, §7.5.6 the kennel loopback); the BPF ABI. THREATS T1.6.
- **Change:** three address forms were judged as something other than what gets dialled.
  Confirmed on the test VM before the fix.
  - **IPv4-mapped IPv6 (`::ffff:a.b.c.d`).** A dual-stack socket makes an IPv4 connection to
    `a.b.c.d`. The proxy's `is_special_use` and `Cidr::contains` treated it as IPv6, so it was
    neither loopback nor covered by any IPv4 deny: in `unconstrained` mode `CONNECT
    [::ffff:127.0.0.1]` reached the host's loopback. `netaddr::canonical` now maps it to the IPv4
    address before an address is classified, CIDR-matched, pinned or dialled, for literals and
    for every address a name resolves to. IPv4-compatible (`::/96`) is refused outright, and the
    IPv4 address embedded in NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`) is classified as IPv4.
  - **The same at the BPF layer.** `connect6` consulted only the IPv6 tries, and a `*` allow
    covers `::/0`. `kennel_decide_v6` now hands a mapped address to `kennel_decide_v4`. An
    IPv4-mapped **bind** is refused (it binds an IPv4 address the IPv6 tries cannot judge).
  - **The unspecified address.** A connect to `0.0.0.0` or `::` is routed to the host's
    loopback, so it walked past a deny of `127.0.0.1`/`::1`. Both decide functions now judge it
    as loopback.
  - **Host mode and the proxy stamp.** `bring_up` stamped the "kennel's own loopback" allow
    (any port on `127.0.0.1`/`::1`, plus the loopback bind subnet) whenever the mode was not
    `none`. In `host` mode there is no private net namespace, so that opened the **host's**
    loopback: a host-mode kennel with no loopback rule could send UDP to `127.0.0.1` on any port.
    The stamp is now made only in the proxied modes.
- **Also fixed (found while testing):** the BPF loader always requested a verifier log into a
  fixed 64 KiB buffer, and the kernel fails `BPF_PROG_LOAD` with `ENOSPC` when the log outgrows
  the buffer — even for a program it accepts. A small addition to `bind6` was enough to stop
  every host-mode kennel from starting. The loader now loads without a log and asks for one (1
  MiB) only to explain a rejection.
- **Why:** an ACL that matches the spelling of an address, not its destination, is bypassed by
  respelling it.
- **Not changed:** `sock_create` still admits every inet socket type (ICMP ping sockets), and a
  `listen()` on an unbound socket or a UDP bind to port 0 still skips the bind policy. The
  `IPV6_V6ONLY` setsockopt hook is left as it was; it is no longer what the mapped-address
  defence rests on.
- **Source:** branch `fix/root-owned-kennel-userns`.

## 2026-11-19 — node-0 registration verbs authorise their sender

- **Bears-on:** Kennel book Vol 2, the service-catalogue and mesh chapters (§7.13.4a/c), the tun
  egress chapter (§8 / W2). THREATS T5.1 ("only kenneld may register them" — untrue as built).
- **Change:** three node-0 verbs gave their sender a cross-kennel role and none checked who sent
  them. Confirmed on the test VM from an ordinary `[dbus]` consumer kennel: `REGISTER_TUN_SINK`
  and `ADD_SERVICE org.projectkennel.dbus-broker` were both answered `OK`.
  - `ADD_SERVICE` (mesh bus): the handle map was overwritten for any sender. The mesh device is
    mounted into every participant, so a consumer could replace the provider — for the D-Bus bus,
    become the broker for every other kennel. Now honoured only if the sender's kennel (kernel-
    stamped pid → cgroup → ctx) is, in the daemon's registry, a **supervised provider at the bus's
    tier** whose signed policy `[[provides]]` that name (`server::provides_at`). `KennelMeta`
    gains `provider_tier`, set by the daemon when the supervisor starts a provider.
  - `GET_SESSION_POLICY` (mesh bus): answered any participant for any ctx. Now only that bus's
    broker (the same predicate, for the bus's broker service).
  - `REGISTER_TUN_SINK` (every kennel's own bus): the handler's comment said "reaching the handler
    is the authorization", but every kennel can send it, and the sink is daemon-global. Now only
    a kennel whose **signed policy provides** `org.projectkennel.tun-udp` may register, and only
    such a kennel's manager clears the sink on a death notification. Not restricted to supervised
    start: the suite (and an operator) may run the broker by hand.
  - Refusals reply `DENIED` and are audited (`mesh.add-service` / `mesh.session-policy` /
    `binder.tun`, outcome `deny`).
- **Why:** arrival on a channel every kennel can reach proves nothing about the sender.
- **Not changed:** an overwritten mesh handle is still not released, the handle map is unbounded
  for an authorised provider, and handlers still take a handle from payload bytes without proof
  the driver translated it.
- **Source:** branch `fix/root-owned-kennel-userns`.

## 2026-11-19 — the helpers check what they are given: granted gids, the bpffs pin root, the exclusive over-mount

- **Bears-on:** Kennel book Vol 2 ch.2 (Process and Privilege Model) — the factory and its
  capability-split sub-helpers; `[identity].groups` (§7.4); the host-mode egress pins (§7.5);
  exclusive binds (§2.7 / T2.8). Archived `04-trust-boundaries.md` ("the helper refuses any gid
  the caller is not a member of" — it did not).
- **Change:** the helpers are world-executable and identify their caller only by real uid, so
  every check that lived in `kenneld` was on the wrong side of the boundary. Three are now made
  by the helper itself:
  - **Granted gids.** The factory wrote wire-supplied `granted_gids` into `gid_map` with
    `CAP_SETGID`. It now refuses any gid that is not the caller's real gid or one of its
    supplementary groups (its own, kernel-stamped), and never gid 0. `kennel-bin-init` refuses a
    persona whose gid or supplementary groups include 0.
  - **The bpffs pin root.** `ensure_bpf_pin_bpffs` did `create_dir_all` and `mount` by name on
    `/run/user/<uid>/kennel/bpf`, a path under the caller's control, with `CAP_SYS_ADMIN` in the
    host mount namespace. It now reaches the directory with no symlink followed in any component
    (`fd::dir_no_symlinks`), mounts on that descriptor, and only on a directory the caller owns.
  - **`kennel-privhelper-mounts`.** `mount` checked ownership of a name and then mounted on the
    name; `unmount` was gated only on a sentinel file the caller could create anywhere. Both now
    pin the directory first (`open_no_symlinks`) and act on that inode. `mount` verifies
    afterwards that the path leads to a fresh, empty, caller-owned tmpfs on a new device.
    `unmount` requires a tmpfs **mount root** owned by the caller that carries the sentinel.
- **Why:** a privileged helper cannot rely on its caller having checked.
- **Not changed:** the unbounded host-`lo` address adds through `kennel-privhelper-net`, and the
  exclusive over-mount still failing open when the sub-helper refuses.
- **Source:** branch `fix/root-owned-kennel-userns`.

## 2026-11-19 — view destinations are resolved by descriptor inside the new root; a symlink at a mount point is refused

- **Bears-on:** Kennel book Vol 2, the filesystem chapter's view construction (§7.4) and the
  trust-manifest masks (T2.8); the OCI substrate (§7.11.4a/c); the mesh rendezvous (§7.13.4a);
  `kennel-bin-init` (§7.2). THREATS T5.4.
- **Change:** view construction built every destination as a string (`new_root` + the in-view
  path) and handed it to `create_dir_all`, `File::create`, `fs::copy` and `mount(2)`, all of which
  follow symlinks. Parts of that tree are not the factory's: a writable grant is a host directory
  an earlier workload could fill, and an OCI root is image content plus, with `persist`, a
  workload-written upper. A symlink there could send a copy onto another file the operator owns,
  or make a mask or bind land on the link's target and leave the path itself unprotected — on
  main, a symlink at `.trust-manifest.d` in a writable grant made the kennel start with that mask
  misplaced. As-built now:
  - `kennel_lib_syscall::fd::RootDir` resolves a view path by descriptor, one plain name at a
    time (`..` refused). A symlink in a **parent** component is followed only inside the root
    (`RESOLVE_IN_ROOT`), as it will resolve after the pivot. The **final** component is never
    followed: `ensure` refuses a symlink there.
  - Every destination in `build_view_and_pivot`, the OCI head and the seal tail goes through it:
    bind mount points, `/etc` overlays, masks, the `/dev` nodes, binderfs, `/proc`, `/tmp`,
    `/dev/shm`, the home directory and `put_old`. Mounts are made on the returned handle
    (`/proc/self/fd/N`) and the name is resolved again afterwards to act on the new mount.
  - A mount point that is a symlink makes construction **fail**: the kennel does not start.
  - Staged files are copied with `RootDir::copy_into`, which does not follow the destination and
    drops set-id and sticky bits.
  - OCI closure-lock paths (`[rootfs].readonly` / `writable`) name image content, so a link such
    as `/bin` → `usr/bin` is still followed — but inside the root (`RootDir::resolve`).
  - `kennel-bin-init`, which is root in a view holding host binds, no longer creates a mesh
    mount target by name. `fd::scaffold_dir` walks from `/` by descriptor, follows no symlink,
    and requires every component to be on a filesystem the factory created (`/`, `/dev`, `/tmp`);
    the mount is attached to that descriptor (`move_mount` with `MOVE_MOUNT_T_EMPTY_PATH`). A mesh
    `at`/`endpoint` whose directory lies inside a bound host path is therefore refused.
  - `create_bind_target` is removed.
- **Why:** before the pivot a name is resolved against the host; the view's own resolution is the
  only safe meaning for a path inside it.
- **Still by name, and why that is safe:** the `/proc` curation scratch directory
  (`<root>/tmp/.kennel-proc`, created and removed by name on the tmpfs just mounted at a `/tmp`
  already checked to be a real directory), and `pivot_root`'s `put_old` (checked likewise).
- **Not covered:** `kennel-bin-init`'s other root path uses are a `chdir` to the workload's
  directory and a `stat` while resolving the program; neither writes.
- **Source:** branch `fix/root-owned-kennel-userns`.

## 2026-11-19 — the view is built with the operator's filesystem identity, not root's

- **Bears-on:** Kennel book Vol 2 ch.2 (Process and Privilege Model) — the factory's construction
  child; Vol 1 §2.8; the filesystem chapter's view construction; the OCI substrate (§7.11.4a).
  THREATS T5.4.
- **Change (corpus defect):** §2.8 and T5.4 state that "from the moment uid 0 could touch anything,
  the host root is already detached". As built, the construction child became host kuid 0 and then
  ran `build_view_and_pivot` — `create_dir_all`, `File::create`, `fs::copy`, binds, the overlay
  mount — on caller-supplied paths **before** `pivot_root`. A caller who runs the helper directly
  chose those paths (root read and write on the host); and with an honest `kenneld`, a symlink a
  previous workload left in a writable grant redirected the same operations. As-built now:
  - `build_view_and_pivot` takes an `FsIdentity` and sets the child's **fsuid/fsgid to the
    operator** for the whole build. Leaving fsuid 0 clears the filesystem capabilities from the
    effective set, so the kernel enforces "nothing the caller could not do itself" on every
    path. `CAP_SYS_ADMIN` is unaffected, so the mounts still work.
  - Root's identity is taken back for three steps only: `add_binder_device` (opens the root-only
    `binder-control` on the binderfs just mounted); the **OCI overlay mount** (overlayfs requires
    the mounter to hold root's file capabilities — its work directory is mode 000 — so the image,
    upper and work directories are opened as the operator first, a persistent upper/work must be
    operator-owned, and the mount is made on those descriptors via `/proc/self/fd`); and the
    post-pivot **re-own** of the scaffolding.
  - Ownership is inverted: scaffolding used to be built as root and `$HOME` chowned to the
    operator (`chown_constructed_home`, a device-and-uid heuristic that could be pointed at a bound
    host directory). Now everything is built as the operator and the scaffolding is handed to uid 0
    by `fd::chown_tree_same_mount`, which resolves each step with
    `RESOLVE_NO_XDEV | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`. `chown_constructed_home` is removed.
  - Side effect: the trust-manifest mask placeholders construction creates inside a writable
    grant are now the operator's on the host, not root's.
- **Why:** a privileged helper acting on its caller's paths must use its caller's authority.
- **Follow-up:** the two residuals this left — destinations resolved by name, and
  `kennel-bin-init` creating a peer-directed path as root — are closed by the entry above.
- **Source:** branch `fix/root-owned-kennel-userns`.

## 2026-11-19 — the kennel user namespace is root-owned; kenneld holds descriptors, not namespace access

- **Bears-on:** Kennel book Vol 2 ch.2 (Process and Privilege Model) — the factory, the boot-sync
  handshake (§7.2.1a) and the mapped-uid-0 analysis (Vol 1 §2.8); the binder chapter's mount
  sequencing; the mesh rendezvous (§7.13.4a). THREATS T5.4.
- **Change (corpus defect — the book's analysis is wrong, not only the code):** the factory used to
  drop its effective uid to the operator across the `clone`, making the **operator the owner** of a
  user namespace that maps **host uid 0** (`0 0 1`). The stated purpose was `CAP_SYS_PTRACE` for
  `kenneld`, so it could open the binderfs through `/proc/<init>/root`. But a namespace's owner
  holds *every* capability in it, so any process at the operator's uid could `setns` into a running
  kennel's user namespace, `setuid(0)`, and be host kuid 0 with the host filesystem still mounted
  — or join the mount namespace too and be uid 0 inside the kennel. §2.8 and T5.4 analysed only
  code that goes through the pivot; a bare `setns` does not. Reproduced on Ubuntu 26.04 / kernel 7.0.
  As-built now:
  - The factory **raises** its effective uid to 0 across the clone (filesystem uid pinned to the
    operator for the `CLONE_INTO_CGROUP` permission check), so the namespace owner is **root**.
    The new invariant: *no user-owned namespace ever contains host uid 0*.
  - `kenneld` no longer touches `/proc/<init>/root`. The construction child sends the factory an
    `O_PATH` handle to the kennel's binder device; the factory relays it in its reply (second
    `SCM_RIGHTS` fd, after the boot-sync socket); `kenneld` re-opens it (`/proc/self/fd/N`) to claim
    node 0.
  - The mesh rendezvous datagram rides the **boot-sync socket**, sent right after GO. The in-view
    datagram socket (`/dev/.kennel-mesh.sock`, mode 0666) is gone.
  - `kennel-bin-init` no longer sets `PR_SET_PTRACER_ANY`; the Yama relaxation existed only for the
    `/proc/<init>/root` open.
  - Removed: `scm::bind_dgram`, `scm::send_to_with_fds`, `process::set_ptracer_any`,
    `mesh_rendezvous::RENDEZVOUS_SOCK`.
- **Why:** entering a kennel-built namespace from outside was never meant to be possible; operator
  ownership made it possible and, with host uid 0 mapped, made it a local root.
- **Not changed by this:** the construction child is still host kuid 0 before `pivot_root`, so the
  factory's handling of caller-supplied paths remains a separate, open defect.
- **Source:** branch `fix/root-owned-kennel-userns`.

## 2026-07-04 — D-Bus mediation has ONE home: the standing dbus-broker (host-dbus retired)

- **Bears-on:** Kennel book Vol 2, the D-Bus mediation chapter (§7.7 in the pre-book numbering)
- **Change:** the legacy per-kennel `host-dbus` operator delegate, its two-declaration contract,
  and kenneld's routing split are **gone** (W4). `[dbus.session]` / `[dbus.system]` alone routes
  over `dbus-broker@v1`: kenneld synthesizes the per-bus `dbus-name` consume
  (`org.projectkennel.dbus` / `.dbus-system`) when the policy does not spell it out, so the
  section IS the brokered path. The node-0 `DBUS_OPEN` verb and the per-kennel D-Bus relay
  membrane are deleted (`DBUS_SEND`/`RECV`/`CLOSE` survive as the facade↔broker per-session-node
  wire); with no enabled broker the `SVC_CONNECT(dbus-name)` locator refuses and the bus is
  unserved, fail-closed. The broker template gains the system-bus leg + the
  `org.projectkennel.dbus-system` provide (the delegate served both buses; subsumption had to
  too), and `install.sh` enables the broker ondemand at the per-host layer
  (`/etc/kennel/ondemand/dbus-broker`). The `mediate` engine moved into `kennel-dbus-broker`
  (its one consumer); the `kennel-host-dbus` crate, the `host_dbus` system.toml key, and the
  daemon's bus-address knowledge are deleted. Measured: TCB 22,851 → 22,300 SLOC.
- **Why:** the 0.5.0 gate ("until the broker has demonstrably subsumed it") is met — the policy
  suite's dbus cases pass with every consumer brokered and the delegate deleted; one auditable
  mediation home.
- **Source:** the W4 PR.

## 2026-07-01 — the policy JSON Schema is *derived* from the parser structs, not a hand-kept table

- **Target:** docs/archive/architecture/02-2-config-schema.md §intro (the "It is **generated**, not
  hand-maintained" paragraph), and any prose describing how `schema/policy.toml.schema` is produced.
- **Change (as-built; drop the stale claim):** the schema is **no longer emitted from an in-repo data
  table that mirrors the source structs**, and there is **no cross-check test that "pins that table to
  the real parser."** `gen-schema` now reflects the `kennel-lib-compile` source structs **directly**
  via `#[derive(SchemaType)]` (a tiny first-party derive on the already-vendored `syn`/`quote` stack,
  behind a `schema` feature that is off in the runtime/TCB build) and emits the JSON with `serde_json`.
  The schema is a **pure export of the parser**, so it cannot describe a field the parser lacks or omit
  one it has — drift is **structurally impossible, not test-guarded**. The hand table
  (`gen-schema/src/model.rs`), the hand JSON writer (`json.rs`), and the emitter (`emit.rs`) are
  **deleted**. The cross-check test collapses to two mechanical checks: regenerating is **idempotent**
  (committed file equals a fresh regen) and **every in-tree template parses with the real parser**
  (`kennel-lib-compile/tests/schema_parser_crosscheck.rs`).
- **Why:** the hand table was a second source of truth for the most load-bearing artifact in the
  system, kept honest only by a test — and that test's `templates ⊆ model` direction made a forgotten
  entry in a doc-generation mirror **fail a parser-valid template** (`[[fs.write.add]]`). Deriving from
  the one source removes the duplicate, the babysitter test, and the inverted authority. No new
  vendored crate, no TCB-closure change.
- **Source:** the corpus-templates-fragments PR (#142).

## 2026-06-30 — drop template/fragment *versioning*: identity is the name, integrity is the signature (rides schema v3)

- **Target:** the templates chapter (design §5.10 "Signing, versioned references, and includes" and
  §5.11 the upgrade flow), the config-schema chapter (`template_base`/`template_version`/`include`
  reference grammar), and the lockfile/provenance model. In the frozen trees:
  docs/archive/design/05-templates.md, docs/archive/architecture/02-2-config-schema.md.
- **Change (as-built to capture in the rewrite) — this OVERRIDES §5.10:** there is **no version axis**
  on templates or fragments. A reference is a **bare name** (`template_base = "base-confined"`,
  `include = ["core-shell"]`, `[[spawn.allow]] template = "net-fetch"`); the `@vN` suffix, the
  `template_version` field, the `meta.toml` `version`, the reference-grammar version validator, the
  settled `ResolvedArtifact.version`, and the lockfile `version` key are all removed.
  - **Identity is the name; integrity is the signature.** §5.10 held that version-pinned references
    were a supply-chain control inseparable from signing. As-built, the **signature alone** is the
    content commitment: the lockfile pins each `name` → its ed25519 signature and hard-errors on
    drift (re-pointed/re-signed bytes change the signature and are caught); the dynamic-spawn
    content-pin (§7.12.8) likewise verifies the recorded *signature*, not a version label. The
    version string added no enforcement (resolution never cross-checked it, and the whole corpus was
    `@v1`), so it was theatre by the project's own no-theatre rule.
  - **Coexisting "versions" are coexisting names.** When a base template needs a breaking change,
    author a new **named** template (e.g. `base-confined-v2`) and point `template_base` at it
    deliberately — a reviewed edit, not an automatic bump. The `kennel policy upgrade` command (and
    its version-ordering module) is therefore **removed**; there is no "newest version" to detect.
  - Rides the existing **`SETTLED_SCHEMA_VERSION` 3** (the settled `ResolvedArtifact` loses `version`).
- **Why:** a control must move a real, named threat; an unenforced version string did not. Name +
  signature is the whole supply-chain control, and it is simpler and honestly enforced.
- **Source:** the corpus-templates-fragments PR (#142).

## 2026-06-30 — remove the `[binder]` service section + two invariant-only schema keys (rides schema v3)

- **Target:** the binder chapter (design §7.1, the user-defined service registry), the config-schema
  chapter (the `[binder]`, `[fs.proc]`, and `[unix]` tables), and the procfs/AF_UNIX construction. In
  the frozen trees: docs/archive/design/07-1-binder.md, docs/archive/architecture/02-2-config-schema.md,
  docs/archive/architecture/02-4-binder.md.
- **Change (as-built to capture in the rewrite):**
  - The **`[binder]` user-defined service section is removed** — `[[binder.provide]]` /
    `[[binder.consume]]`, the settled `BinderRuntime`, and `kenneld`'s node-0 service `Registry`
    (the `addService`/`getService` gate, plus the `GET_SERVICE`/`IS_DECLARED`/`LIST_SERVICES`
    verbs). It was a wired-but-unused mechanism with zero corpus/test usage, superseded by the
    cross-kennel capability **mesh** (`[[provides]]`/`[[consumes]]` → `MeshRuntime` → the
    `SVC_CONNECT` broker). Drop any framing of `[binder]` as the way to publish a service. The
    binder **transport** is untouched: `kenneld` still owns node 0 (the `Manager`/lifecycle), the
    per-kennel binder *device* is still the universal control plane, and `ADD_SERVICE` survives as
    the mesh-bus registration verb.
  - **`fs.proc.visibility` is removed.** Procfs is always self-only (`hidepid` such that the
    workload sees only its own tree); the field's only legal value was `self`, enforced as a
    framework invariant. The invariant-only key was theatre — procfs is now structurally self-only
    with no knob, and the `proc.visibility` framework-invariant marker is dropped. `[fs.proc]` keeps
    `hidepid`.
  - **`unix.default` is removed.** Default-deny is structural (the AF_UNIX shim contains only what is
    bound in); the field's only legal value was `deny` (`allow` was a hard compile error). `[unix]`
    keeps `abstract` (the real deny/allow escape hatch) and `[[unix.allow]]`.
  - These ride the existing **`SETTLED_SCHEMA_VERSION` 3** (no new bump — one v3 absorbs the whole
    schema cleanup); the settled `SettledPolicy` loses its `binder` field and `ProcPolicy.visibility`.
- **Why:** the schema should carry only fields that express a real choice against a real adversary.
  `[binder]` was unbuilt-in-practice dead weight (a TCB-shrinking removal of ~250 SLOC across the
  three TCB crates); `fs.proc.visibility` and `unix.default` were invariant-only keys whose single
  legal value made them cruft.
- **Source:** the corpus-templates-fragments PR (#142).

## 2026-06-30 — `[fs.tmp]`: `private` → `writable`, drop the DAC-mode knob (settled schema v3)

- **Target:** the config-schema chapter (the `[fs.tmp]` section) and the filesystem chapter's
  `/tmp` construction. In the frozen trees: docs/archive/architecture/02-2-config-schema.md and
  docs/archive/design/07-4-filesystem.md.
- **Change (as-built to capture in the rewrite):**
  - `[fs.tmp].private` is renamed **`writable`** — that is what it always was: the Landlock write
    grant on `/tmp`. `/tmp` is *always* a fresh per-kennel tmpfs in the constructed view; `writable =
    true` lets the workload use it, absent/false leaves it read-only. Drop the stale claim that
    `private = false` "bind-mounts the host `/tmp`" — it never did; it only withholds the write grant.
  - `[fs.tmp].mode` is **removed**. The tmpfs lives in the workload's own mount namespace and is owned
    by the workload uid, so a per-policy DAC mode gated no real adversary (the host can't reach it
    across the namespace; the kennel is single-uid). The mount now fixes `0700` internally — owner =
    the workload, private-and-usable. The octal-mode validation (an option-injection guard for a knob
    that no longer exists) is gone with it.
  - The settled `TmpPolicy` loses `mode` and renames `private` → `writable`; this bumps
    **`SETTLED_SCHEMA_VERSION` 2 → 3** (and `MIN` → 3): a pre-v3 settled carries the old shape and must
    be recompiled. The spawn plan wire format drops `tmp_mode` accordingly.
- **Why:** `private`/`mode` were a misleading name and security theatre; the schema should say what
  the field does (grant write) and not offer a knob that isn't a real choice.
- **Source:** the schema-fs-tmp-writable PR.

## 2026-06-30 — one policy type: list fields replace *or* increment at the same key

- **Target:** the templates chapter, design §5.2-5.3 (the composition model) and the config-schema
  chapter, architecture §the policy schema / the leaf-policy delta form. In the frozen trees:
  docs/archive/design/05-templates.md and docs/archive/architecture/02-2-config-schema.md.
- **Change (as-built to capture in the rewrite):** there is **one** source-policy type. The
  separate `LeafPolicy` (the delta-only `[[*.add]]` / `[[*.remove]]` form) and `SourcePolicy` (the
  bare-list "set" form) are unified — drop any framing that a leaf is a distinct type, or that the
  delta operators are a leaf-only increment applied after the chain fold. The as-built rule:
  - **Every list field replaces *or* increments at the same key.** A bare sequence
    (`fs.read = ["…"]`, `[[unix.allow]]`) *replaces* the inherited list (the SSH `Ciphers = …` set
    form); an `{ add, remove }` table (`[[fs.read.add]]` / `[[unix.allow.remove]]`) *increments* it
    (the `+=` / `-=` form). The deserializer picks by TOML shape. This holds for every list a leaf
    could previously delta: `fs.read`/`write`/`deny`, `exec.allow`, `unix.allow`, `net.proxy.allow`,
    `net.proxy.deny.policy`, `net.bpf.*.allow`/`deny`, `ssh.destinations`, `fs.dev.passthrough`.
  - **A *template* can now increment**, not only replace — which is the point: the shipped corpus is
    the teachable shape, so the increment form must be available wherever a list lives, not only in a leaf.
  - The chain fold applies the increments (`resolve`), so the **effective** policy always carries
    concrete `Set` lists; there is no separate post-fold delta pass.
  - Identity, not type, tells the three roles apart: a **template** has `template_name`; a runnable
    **leaf** has `name` + `template_base`; a composable **fragment** has `name`, no `template_base`,
    and is additive-only. A leaf may not declare `[[net.proxy.deny.invariant]]` (template/fragment only).
  - Mechanism: `kennel-lib-compile::source::{PathField, ListField, Delta}` (untagged set-or-delta);
    `resolve::fold` applies set-then-increment; `apply_fragment` folds an additive include. Removed:
    the `leaf` module (`LeafPolicy`, `compile_leaf`, `parse_leaf`, `sign_leaf`, `canonical_leaf`).
- **Why:** the two-type split forced a template to *replace* a list it wanted to extend (it could not
  `.add`), so the shipped reference corpus could not demonstrate the increment shape it teaches.
- **Source:** the unify-source-leaf-policy PR.

## 2026-06-30 — reserved-namespace authority is compile-only and tier-based

- **Target:** the service-catalogue chapter, design §7.13.4 / §7.13.5 (the reserved-namespace gate)
  and §7.13.5a (host `[[reserved]]`). In the frozen trees: docs/archive/design/07-13-service-catalog.md.
- **Change (as-built to capture in the rewrite):** the reserved-namespace authority is resolved
  **entirely at compile**, **tier-based**, and sealed into the settled policy's signature. There is
  **no runtime gate**. Drop the §7.13.4/§7.13.5 framing of a "runtime backstop / authoritative
  catalogue gate" where "a reserved provide's settled *signature* must be a maintainer key", and the
  per-entry `ReservedNamespace.keys` allowlist for host names. The as-built rule:
  - A reserved name has a *required tier*: `org.projectkennel.*` → **vendor** (the key dir
    `/usr/lib/kennel/keys`); a host `[[reserved]]` prefix (`system.toml`) → **host** (`/etc/kennel/keys`).
    Tiers order `User < Host < Vendor`; the gate checks the **declaring tier ≥ required**.
  - **The authority is the tier, not the identity — any key at a tier is equivalent.** The declaring
    tier is the verified tier of the ancestor *template* that supplied the `[[provides]]`
    (ancestor-origin), or the output `--key`'s tier when the leaf authored them itself (entry-origin).
    So a **host-signed** settled may provide `org.projectkennel.wayland` legitimately when it derives a
    **vendor-signed** template that declares it — which is what lets the installer host-compile the
    reference providers (no maintainer private key on the target host).
  - The daemon does **not** re-derive this. It loads only a settled policy whose signature verifies
    against the trust store (`verify_settled_signed`); that trusted signature is the whole boundary.
    The old runtime signer-tier check was **security theatre** against the trust root: a holder of any
    trusted key can re-sign a forged settled, and its only reach is that operator's own per-user daemon.
  - Mechanism: `kennel-lib-compile::mesh::ReservedAuthority` (the sole authorizer) + a tier-aware
    `source_sig::Trust` (`Tier`, `tier_of`); `resolve::ProvidesOrigin::Ancestor { tier }`. Removed:
    `kenneld::catalogue::{provide_authorized, first_unauthorized_provide}` and the daemon's
    `vendor_key_ids` / host-`reserved` plumbing.
- **Why:** the runtime gate forced reserved providers to be maintainer-signed *settled* artefacts —
  un-shippable across arches (settled pins arch loaders) and un-buildable on a target host (no
  maintainer key), while adding no real security. Moving the (already-existing) compile fail-fast to be
  the tier-aware sole authority unblocks host-compiled reference providers with zero shortcut.
- **Source:** branch fix/reserved-namespace-tier-gate.

## 2026-06-29 — D-Bus brokering is opt-in per consumer; host-dbus retained

- **Target:** the D-Bus mediation chapter (design §7.7) and the mesh chapter (§7.13.2,
  `dbus-name` shape). In the frozen trees: docs/archive/design/07-7-dbus.md, docs/archive/design/07-13-mesh.md.
- **Change (as-built to capture in the rewrite):** brokered D-Bus is **opt-in per consumer**, not
  a wholesale replacement of the `host-dbus` delegate. A kennel is routed over the standing
  `dbus-broker@v1` only when it declares **both** `[dbus.session]` **and** a `[[consumes]]` of a
  `dbus-name` capability (`org.projectkennel.dbus`); `[dbus.session]` alone keeps the legacy
  per-consumer `host-dbus` operator delegate. The two coexist (the two-declaration contract
  documented in `dbus-brokered/consumer.toml`). Drop any "host-dbus is retired / decommissioned"
  framing — that retirement is **deferred past 0.5.0** (decision 2026-06-29: keep the host facade
  for now). kenneld gates this on `loaded.consumes` carrying a `Shape::DbusName` entry.
- **Why:** the broker consolidates mediation onto the mesh; it does not yet subsume the
  non-consuming `[dbus.session]` case, which `host-dbus` still serves.
- **Source:** #136 (`brokered_dbus` gated on a dbus-name consume) + the 2026-06-29 decision;
  ROADMAP-0.5.0 W1 exit reconciled.

## 2026-06-28 — Signature format → SSHSIG (OpenSSH detached signatures)

- **Target:** book ch16.3 (Audits — the commitment); the settled-policy chapter (the
  user's §17.1, "signature over the canonical serialisation"); the keys chapter (the user's
  §18). In the frozen trees: docs/archive/architecture/02-2-config-schema.md (§Signatures),
  docs/archive/design/05-templates.md (§5.10 trust store), docs/archive/architecture/04-trust-boundaries.md,
  docs/archive/architecture/02-10-dynamic-spawn.md (the spawn content-pin).
- **Change (as-built to capture in the rewrite):**
  - **The on-disk signature is now an SSHSIG** (OpenSSH detached signature, `PROTOCOL.sshsig`),
    not a bare Ed25519 signature over the canonical bytes. The `[signature]` envelope's
    `algorithm` is `"sshsig"`; `signature` holds the armored `-----BEGIN SSH SIGNATURE-----`
    blob verbatim. Authoring signs via **`ssh-keygen -Y sign`** (so a key in a file, an
    ssh-agent, or a hardware token are all transparent — the framework writes no agent client).
  - **Verification is in-process** for Ed25519 keys (`kennel_lib_policy::sshsig`): de-armor →
    check the namespace → require the embedded key to equal the trust-store key → recompute
    `SHA-512(canonical)` → rebuild the SSHSIG preimage → one Ed25519 check. It never execs
    `ssh-keygen` (the trust root stays self-contained, `refuse-to-start`/`rule-of-1`). A real
    settled policy passes **both** `ssh-keygen -Y verify` and the in-process verifier — a
    cross-check test asserts it (`tests/sshsig_crosscheck.rs`).
  - **Domain separation:** the SSHSIG `namespace` is `policy.v1@projectkennel.org`. A signature
    minted for SSH authentication or git commits carries a different namespace and cannot be
    replayed as a kennel-policy signature, even with the same key — which matters now that an
    operator may sign with their ordinary SSH key.
  - **The commitment changed (ch16.3 — drop the "no sha2" line).** It was "the signature *is*
    the content commitment, no hashing." It is now "we pin the SSHSIG; it commits to
    `SHA-512(canonical)`." Still deterministic (Ed25519, RFC 8032) and collision-bound, one
    layer deeper. **SHA-512 is load-bearing in the commitment** (it was incidental inside
    Ed25519 before). The lockfile/spawn content-pin is unchanged in *role* — it still pins the
    `[signature]` string; that string is now the armor.
  - **Schema bump:** `settled_schema_version` is **2**. A v1 (pre-SSHSIG) settled policy is
    refused with `ObsoleteSchemaVersion` whose fix is "recompile" — single-format, no permanent
    dual verifier in the hot path. The shipped template/fragment corpus (28 files) was re-signed
    SSHSIG in the same change.
  - **Trust model UNCHANGED:** the three-tier store and precedence, the set of signed artefacts,
    compile-time ancestor verification against the system-only tiers, and the daemon's SPAWN
    re-verification of the content-pin all hold — only *what a "signature" is, byte-for-byte*,
    changed at each existing checkpoint. The key chapter (§18) gains one sentence: signatures are
    now SSH-verifiable, not merely SSH-shaped keys.
  - **New dependency:** `hmac-sha512` 1.1.12 (bare unkeyed SHA-512, `default-features = false`,
    zero transitive deps, same author as `ed25519-compact`). The SHA-512 inside `ed25519-compact`
    is private; exposing it would be a forbidden feature-add patch (`src/vendor/patches/README.md`)
    and would break that crate's byte-identical-to-upstream provenance, so a dedicated crate is the
    policy-conformant choice. Recorded in CHECKSUMS.toml / DEPENDENCIES.md / cargo-vet.
- **OWED (designed, not yet landed):**
  - **FIDO `sk-` signers** verify via an `ssh-keygen -Y verify` breakout (fixed argv, an
    allowed-signers file built from the **trust store** never the artefact, construction-path
    only, never a fallback after a failed in-process check). The verifier already detects `sk-`
    keys structurally and returns `HardwareKeyRequiresExternalVerify`; signing rejects `sk-` with a
    clear message. The breakout itself, the trust-store `sk-` entry shape (application string +
    authenticator flags alongside the 32 bytes), and `kennel policy risks` surfacing
    "signer is a hardware token" are owed.
- **THREATS (owed catalogue line):** the signature format is security-load-bearing; the SSHSIG
  namespace is the control that prevents cross-protocol signature reuse once an operator's SSH key
  doubles as their policy-signing key. A `T*` id for "cross-protocol signature reuse — mitigated by
  the SSHSIG namespace" should be minted by the catalogue owner (not invented here).
- **Why:** docs/design + docs/architecture are frozen; this lands the format change with no doc edits.
- **Source:** branch feat/w5-key-location (SSHSIG migration), PR #134.

---

## 2026-06-26 — W1: connector-shape mesh bus + dbus-broker@v1 standing service

- **Target:** docs/design §7.7 (D-Bus mediation), §7.13.4a (connector shapes / service catalogue),
  02-4-binder.md (node 0); docs/architecture 01-process-model / 02-8-internal-api / 03-crate-decomposition.
- **Change (as-built to capture in the rewrite):**
  - **binder-connector mesh bus** — `kenneld` runs a `MeshBus` controller as node 0 of a shared binder
    bus; providers acquire a node handle via `ADD_SERVICE` and consumers receive it via `SVC_CONNECT`.
    New binder primitive: `Reply::Handle(u32)` / `reply_with_handle()` (kennel-lib-binder).
  - **dbus-broker@v1** — a standing **service kennel** (`templates/dbus-broker/`, new crate
    `kennel-dbus-broker`) replacing the per-consumer `host-dbus` delegate. It `ADD_SERVICE`s one
    **control node** on the D-Bus mesh bus (`org.projectkennel.dbus-broker`), which only kenneld
    holds. The single control verb (kennel-lib-binder `service.rs::broker`) is **`ACCEPT_SESSION`**
    `[bus | talk | call | broadcast | own | deny_talk]`: kenneld tells the broker to accept one
    session and apply that filter; the broker mints a **per-session node**, stores the filter
    against the node's cookie, and replies with the node. Consumer→broker is then direct
    (`DBUS_SEND`/`RECV`/`CLOSE` on the session node, mediated by the reused `host-dbus::mediate`
    engine); the session is reclaimed on the node's `Br::Release`. kenneld never relays frames.
  - **Mesh-bus caller identity** — the D-Bus mesh bus's node-0 handler resolves a connecting
    consumer **fresh, per `SVC_CONNECT`**: kernel-attested `sender_pid` → `/proc/<pid>/cgroup` →
    `kennel-<ctx>` → that ctx's one settled `[dbus]` filter (`kenneld` holds a ctx→filter map,
    populated when a brokered kennel is prepared, dropped when its ctx is released). No cookie, no
    session table, no facade-pid keying — the cgroup is the restart-invariant kennel name and the
    only standing state is the policy. The handler then issues `ACCEPT_SESSION` as a *nested*
    transaction on its own context-manager connection and returns the session node via
    `Reply::Handle`. Distinct per-bus capability names carry the bus selector
    (`org.projectkennel.dbus` = session, `org.projectkennel.dbus-system` = system).
  - **dbus-name handoff is a pure locator** (`svc_connect_handoff`, `Shape::DbusName`): on the
    *per-kennel* bus kenneld replies `[OK][mesh-device-path]` when D-Bus is brokered (the facade
    then opens the mesh bus and connects there) or `[OK]` when not (legacy `host-dbus` route). It
    resolves no identity and mints no session — that is the mesh handler's job.
    `Shape::BinderConnector` replies `UNAVAILABLE` (connector transactions happen on the mesh bus).
  - **MeshBusGuard** — RAII guard that decrements participant refcounts and unmounts the per-mesh
    binderfs on the last participant's exit (both normal teardown and bring-up failure).
- **Why:** docs/design + docs/architecture are frozen; W1 ships this architecture with no doc updates.
- **Source:** PR (W1 integration) — branch feat/w1-integration. Supersedes the earlier draft of this
  entry (the `REGISTER_CONSUMER`/`UNREGISTER_CONSUMER`/`RELAY_FRAME` relay model and the startup-time
  filter registration were replaced before merge by the per-session `ACCEPT_SESSION` + cgroup-identity
  shape above; those verbs and the stub frame-relay no longer exist).

---

## 2026-06-29 — W1: mesh binderfs mountable unprivileged + exposed into views; binder handle-ref fix

- **Target:** docs/design §7.13.4a (connector mesh bus), §7.7 (D-Bus mediation), 02-4-binder.md (node 0
  / handle refs), 07-2 (kennel-bin-init role); docs/architecture 01-process-model / 02-8-internal-api.
- **Change (as-built to capture in the rewrite):**
  - **Unprivileged mesh-bus mount holder (§7.13.4a)** — the shared connector binderfs is mounted by a
    **forked, not exec'd** child of `kenneld` (`kenneld::mesh_holder`) under kenneld's own AppArmor
    profile (which carries the `userns` grant across the fork but NOT an exec). The holder creates a
    user namespace with a single-uid **self-map `0 <kenneld-uid> 1`** (unprivileged — no `cap_setuid`,
    no subuids) and mounts the binderfs there; nodes are owned by kenneld's own uid, so kenneld serves
    node 0 by opening the device via `/proc/<holder>/root`. **No privhelper, no host privilege** —
    the privhelper construct protocol, the boot-sync handshake, and the view construction are all
    UNTOUCHED. (A privhelper that *holds* a namespace would be a long-lived privileged process — the
    drift this deliberately avoids.)
  - **Mount handoff is fd-based, not path-based.** A kennel cannot reach the holder's mount by path
    (its construction has its own PID namespace, so `/proc/<holder>/root` does not resolve there), and
    only the holder — the namespace that *has* the mount — may `open_tree(OPEN_TREE_CLONE)` it. So the
    holder **serves clone requests**: on demand it clones a detached, movable binderfs mount and hands
    the fd back over `SCM_RIGHTS`. `kenneld` relays each detached fd into the kennel over a
    **connectionless `AF_UNIX` datagram** the init binds at a fixed in-view path (`RENDEZVOUS_SOCK`,
    on the writable `/dev` tmpfs), reached via `/proc/<init>/root` after boot-sync READY.
    `kennel-bin-init` `move_mount`s each clone into the view (`/dev/binderfs-mesh`) and adds the device
    to the **workload's Landlock ruleset** — all *before* it forks the workload, so the broker/facade
    open the device by path unchanged. `open_tree(CLONE)` shares the binderfs superblock/inode (same
    binder context), so cross-userns object translation works (verified by root probe: the mount/clone/
    userns are not the constraint). New primitives: `kennel_lib_syscall::namespace::{fork_mount_holder,
    open_tree_clone, move_mount_fd}`, `kennel_lib_scm::{bind_dgram, send_to_with_fds}`,
    `kennel_lib_spawn::mesh_rendezvous` (frame + `RENDEZVOUS_SOCK`). `Spec.mesh_mounts` carries the
    detached fds + in-view targets from `kenneld`'s plan into `bring_up`.
  - **Binder handle ref-acquire (correctness fix, 02-4 / 07-7).** `Connection::transact_handle` now
    **acquires a strong ref on the returned handle before freeing the reply buffer** — binder drops a
    transaction's object refs on `BC_FREE_BUFFER`, so without this the returned handle was already
    dangling (the node's refcount hit zero, its owner got `BR_RELEASE`, and the first transaction on
    the handle failed `BR_FAILED_REPLY`). This is what made the brokered D-Bus `ACCEPT_SESSION` handoff
    work end to end (latent until W1 first exercised it). New `Reply::HandleOnce(u32)`: forward a
    handle then **release the endpoint's own ref** — for the per-session node `kenneld` only relays
    (so the broker reclaims the session when the consumer disconnects), distinct from `Reply::Handle`
    (a persistent provider node the node-0 endpoint keeps).
  - **Brokered-consumer mesh-bus tier** — the consumer's brokered-D-Bus path resolves the broker's
    tier **from the catalogue** (not a hardcoded `Host`), so consumer and broker key the *same* mesh
    binderfs instance (a user-enabled broker is `User`-tier). A tier mismatch put them on separate
    buses and `ACCEPT_SESSION` failed closed with the broker's control node "not registered".
  - **Mesh-bus audit is durable** — the `MeshBus` uses a real journal-backed daemon writer
    (`audit::daemon_writer`, `stdout` sink → kenneld's journal), not a noop drain: every
    `SVC_CONNECT` / `ACCEPT_SESSION` / provider-death verdict on the most-trusted cross-kennel
    mediation path is recorded.
- **Why:** docs/design + docs/architecture are frozen; this lands the W1 mountability + the binder
  ref-lifetime correctness with no doc edits. e2e `dbus-brokered` round-trips `GetId` end to end.
- **Source:** branch feat/w1-integration.
