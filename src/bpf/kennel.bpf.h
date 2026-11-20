/*
 * Project Kennel shared BPF inline helpers.
 *
 * Factors the per-kennel metadata lookup, the deny-first allow/deny LPM
 * evaluation, and the audit-ringbuf emit so each program stays small and the
 * decision logic lives in one reviewed place. Not an ABI surface — an
 * implementation detail of the programs in this directory.
 *
 * STATUS: verifier-clean on Linux 6.8.0 (2026-05-30). See bpf/README.md.
 *
 * Assumes (in this order, from the including .bpf.c):
 *     #include <linux/bpf.h>
 *     #include <bpf/bpf_helpers.h>
 *     #include <bpf/bpf_endian.h>
 *     #include "maps.h"
 *     #include "audit_events.h"
 */
#ifndef KENNEL_BPF_H
#define KENNEL_BPF_H

/*
 * Address-family and protocol constants. Defined here rather than relied upon
 * from the kernel UAPI, whose exported symbol set varies by kernel.
 */
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/* cgroup hook verdicts: 1 allows the operation, 0 denies it. */
#define KENNEL_ALLOW 1
#define KENNEL_DENY 0

/* Fetch the per-kennel metadata (array index 0). NULL if absent/misbuilt. */
static __always_inline struct kennel_meta *kennel_meta_get(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&kennel_meta_map, &zero);
}

/* Count an audit event that could not be reserved (the ringbuf is full). */
static __always_inline void kennel_audit_lost(void)
{
	__u32 zero = 0;
	__u64 *lost = bpf_map_lookup_elem(&audit_lost, &zero);
	if (lost)
		__sync_fetch_and_add(lost, 1);
}

/*
 * Copy the 16-byte IPv6 daddr out of a bpf_sock_addr. The fields user_ip6[0..3]
 * are read individually: each is a direct context access the verifier rewrites,
 * whereas a memcpy through &ctx->user_ip6 is rejected as a "dereference of
 * modified ctx ptr" (the verifier disallows reading through an offset-adjusted
 * context pointer). Confirmed against the 6.8 verifier.
 */
static __always_inline void
kennel_ctx_load_ip6(const struct bpf_sock_addr *ctx, __u8 out[16])
{
	__u32 w[4];
	w[0] = ctx->user_ip6[0];
	w[1] = ctx->user_ip6[1];
	w[2] = ctx->user_ip6[2];
	w[3] = ctx->user_ip6[3];
	__builtin_memcpy(out, w, 16);
}

/*
 * Store a 16-byte IPv6 address back into a bpf_sock_addr (the bind6 rewrite
 * path), writing each word as a direct context access for the same reason as
 * the load above.
 */
static __always_inline void
kennel_ctx_store_ip6(struct bpf_sock_addr *ctx, const __u8 in[16])
{
	__u32 w[4];
	__builtin_memcpy(w, in, 16);
	ctx->user_ip6[0] = w[0];
	ctx->user_ip6[1] = w[1];
	ctx->user_ip6[2] = w[2];
	ctx->user_ip6[3] = w[3];
}

/* Populate the common audit header. */
static __always_inline void
kennel_audit_hdr(struct audit_hdr *hdr, __u16 kind, __u16 length, const struct kennel_meta *meta)
{
	hdr->magic = KENNEL_AUDIT_MAGIC;
	hdr->version = KENNEL_AUDIT_VERSION;
	hdr->kind = kind;
	hdr->ts_ns = bpf_ktime_get_ns();
	hdr->ctx_byte = meta->ctx_byte;
	hdr->length = length;
	hdr->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	/* comm is a fixed-size buffer; the helper takes an explicit size. */
	bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

/*
 * Emit a connect/sendmsg audit event. addr points at a 4-byte v4 address or a
 * 16-byte v6 address depending on family. port is network byte order.
 */
static __always_inline void
kennel_audit_connect(__u16 kind, __u8 family, __u8 protocol, __u16 port_be, const void *addr,
		     const struct kennel_meta *meta)
{
	struct audit_event_connect *ev =
		bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*ev), 0);
	if (!ev) {
		kennel_audit_lost(); /* ringbuf full: the event is dropped, and counted */
		return;
	}
	kennel_audit_hdr(&ev->hdr, kind, (__u16)sizeof(*ev), meta);
	ev->body.family = family;
	ev->body.protocol = protocol;
	ev->body.port = port_be;
	__builtin_memset(&ev->body.addr, 0, sizeof(ev->body.addr));
	if (family == AF_INET6)
		__builtin_memcpy(ev->body.addr.v6, addr, 16);
	else
		__builtin_memcpy(&ev->body.addr.v4, addr, 4);
	bpf_ringbuf_submit(ev, 0);
}

/*
 * True if any rule in `entry` covers `protocol` on `port_host`. Used for both
 * directions: on an allow entry it means "permitted", on a deny entry "denied".
 */
static __always_inline int
kennel_entry_matches(const struct allow_entry *entry, __u8 protocol, __u16 port_host)
{
	for (int i = 0; i < KENNEL_ENTRY_RULES; i++) {
		if (i >= entry->n_rules)
			break;
		const struct port_rule *r = &entry->rules[i];
		if (r->protocol != KENNEL_PROTO_ANY && r->protocol != protocol)
			continue;
		if (port_host >= r->port_min && port_host <= r->port_max)
			return 1;
	}
	return 0;
}

/* True if the 16-byte address is the unspecified address (::). */
static __always_inline int kennel_is_unspecified6(const __u8 a[16])
{
	for (int i = 0; i < 16; i++) {
		if (a[i] != 0)
			return 0;
	}
	return 1;
}

/* True if the 16-byte address is IPv4-mapped (::ffff:a.b.c.d). */
static __always_inline int kennel_is_v4mapped(const __u8 a[16])
{
	for (int i = 0; i < 10; i++) {
		if (a[i] != 0)
			return 0;
	}
	return a[10] == 0xff && a[11] == 0xff;
}

/*
 * IPv4 connect/sendmsg decision. daddr_be and port_be are network byte order.
 * Deny-first: the invariant deny trie is consulted before the allow trie, so
 * an allow rule can never cover an invariant-denied range.
 */
static __always_inline int
kennel_decide_v4(__u32 daddr_be, __u16 port_be, __u8 protocol, __u16 deny_kind, __u16 allow_kind,
		 const struct kennel_meta *meta)
{
	/* A connect to the unspecified address is routed to this host's loopback, so that is the
	 * destination the ACL must judge: otherwise 0.0.0.0 walks past a deny of 127.0.0.0/8. */
	if (daddr_be == 0)
		daddr_be = bpf_htonl(0x7f000001);
	struct lpm_v4_key key = { .prefixlen = 32, .addr = daddr_be };
	__u16 port_host = bpf_ntohs(port_be);

	struct allow_entry *denied = bpf_map_lookup_elem(&deny_v4, &key);
	if (denied && kennel_entry_matches(denied, protocol, port_host)) {
		kennel_audit_connect(deny_kind, AF_INET, protocol, port_be, &daddr_be, meta);
		return KENNEL_DENY;
	}
	struct allow_entry *entry = bpf_map_lookup_elem(&allow_v4, &key);
	if (entry && kennel_entry_matches(entry, protocol, port_host)) {
		kennel_audit_connect(allow_kind, AF_INET, protocol, port_be, &daddr_be, meta);
		return KENNEL_ALLOW;
	}
	kennel_audit_connect(deny_kind, AF_INET, protocol, port_be, &daddr_be, meta);
	return KENNEL_DENY;
}

/*
 * IPv6 connect/sendmsg decision. daddr_in points at 16 bytes; port_be is net order.
 *
 * Two addresses are not what they look like, and are judged as what the kernel will dial:
 *   - IPv4-mapped (::ffff:a.b.c.d): an AF_INET6 socket makes an IPv4 connection to a.b.c.d, and
 *     only this hook sees it — so the IPv4 tries decide. Without this, every IPv4 deny (the
 *     metadata address, RFC1918, an author's CIDR) is skipped whenever an allow covers ::/0.
 *   - the unspecified address (::): routed to this host's loopback, so it is judged as ::1.
 */
static __always_inline int
kennel_decide_v6(const __u8 daddr_in[16], __u16 port_be, __u8 protocol, __u16 deny_kind,
		 __u16 allow_kind, const struct kennel_meta *meta)
{
	__u8 daddr[16];
	__builtin_memcpy(daddr, daddr_in, 16);

	if (kennel_is_v4mapped(daddr)) {
		__u32 v4_be;
		__builtin_memcpy(&v4_be, daddr + 12, 4);
		return kennel_decide_v4(v4_be, port_be, protocol, deny_kind, allow_kind, meta);
	}
	if (kennel_is_unspecified6(daddr))
		daddr[15] = 1;

	struct lpm_v6_key key = { .prefixlen = 128 };
	__u16 port_host = bpf_ntohs(port_be);

	__builtin_memcpy(key.addr, daddr, 16);

	struct allow_entry *denied = bpf_map_lookup_elem(&deny_v6, &key);
	if (denied && kennel_entry_matches(denied, protocol, port_host)) {
		kennel_audit_connect(deny_kind, AF_INET6, protocol, port_be, daddr, meta);
		return KENNEL_DENY;
	}
	struct allow_entry *entry = bpf_map_lookup_elem(&allow_v6, &key);
	if (entry && kennel_entry_matches(entry, protocol, port_host)) {
		kennel_audit_connect(allow_kind, AF_INET6, protocol, port_be, daddr, meta);
		return KENNEL_ALLOW;
	}
	kennel_audit_connect(deny_kind, AF_INET6, protocol, port_be, daddr, meta);
	return KENNEL_DENY;
}

/* Emit a bind audit event. requested/rewritten point at 16-byte buffers
 * (v4 addresses occupy the first 4 bytes, zero-padded). */
static __always_inline void
kennel_audit_bind(__u16 kind, __u8 family, __u16 port_be, const __u8 requested[16],
		  const __u8 rewritten[16], const struct kennel_meta *meta)
{
	struct audit_event_bind *ev = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*ev), 0);
	if (!ev) {
		kennel_audit_lost();
		return;
	}
	kennel_audit_hdr(&ev->hdr, kind, (__u16)sizeof(*ev), meta);
	ev->body.family = family;
	ev->body._pad = 0;
	ev->body.port = port_be;
	__builtin_memcpy(ev->body.requested, requested, 16);
	__builtin_memcpy(ev->body.rewritten, rewritten, 16);
	bpf_ringbuf_submit(ev, 0);
}

/*
 * IPv4 bind ACL decision (§7.5.7), deny-first over the dedicated bind_{deny,allow}_v4 tries.
 * `addr_be` is the address actually being bound (network byte order, AFTER any INADDR_ANY
 * rewrite); `port_be` is network order. Default-deny: a bind that misses the allow trie (or
 * whose port the matching entry forbids) is denied. requested/rewritten are the 16-byte audit
 * buffers the caller already built. Returns KENNEL_ALLOW / KENNEL_DENY.
 */
static __always_inline int
kennel_bind_decide_v4(__u32 addr_be, __u16 port_be, __u8 protocol, const __u8 requested[16],
		      const __u8 rewritten[16], const struct kennel_meta *meta)
{
	struct lpm_v4_key key = { .prefixlen = 32, .addr = addr_be };
	__u16 port_host = bpf_ntohs(port_be);

	struct allow_entry *denied = bpf_map_lookup_elem(&bind_deny_v4, &key);
	if (denied && kennel_entry_matches(denied, protocol, port_host)) {
		kennel_audit_bind(AUDIT_NET_BIND_DENY, AF_INET, port_be, requested, rewritten, meta);
		return KENNEL_DENY;
	}
	struct allow_entry *entry = bpf_map_lookup_elem(&bind_allow_v4, &key);
	if (entry && kennel_entry_matches(entry, protocol, port_host)) {
		kennel_audit_bind(AUDIT_NET_BIND_ALLOW, AF_INET, port_be, requested, rewritten, meta);
		return KENNEL_ALLOW;
	}
	kennel_audit_bind(AUDIT_NET_BIND_DENY, AF_INET, port_be, requested, rewritten, meta);
	return KENNEL_DENY;
}

/* IPv6 bind ACL decision (§7.5.7), deny-first over bind_{deny,allow}_v6. `addr` points at the
 * 16 bytes actually being bound (post-rewrite); `port_be` is network order. */
static __always_inline int
kennel_bind_decide_v6(const __u8 addr[16], __u16 port_be, __u8 protocol, const __u8 requested[16],
		      const __u8 rewritten[16], const struct kennel_meta *meta)
{
	struct lpm_v6_key key = { .prefixlen = 128 };
	__u16 port_host = bpf_ntohs(port_be);

	__builtin_memcpy(key.addr, addr, 16);

	struct allow_entry *denied = bpf_map_lookup_elem(&bind_deny_v6, &key);
	if (denied && kennel_entry_matches(denied, protocol, port_host)) {
		kennel_audit_bind(AUDIT_NET_BIND_DENY, AF_INET6, port_be, requested, rewritten, meta);
		return KENNEL_DENY;
	}
	struct allow_entry *entry = bpf_map_lookup_elem(&bind_allow_v6, &key);
	if (entry && kennel_entry_matches(entry, protocol, port_host)) {
		kennel_audit_bind(AUDIT_NET_BIND_ALLOW, AF_INET6, port_be, requested, rewritten, meta);
		return KENNEL_ALLOW;
	}
	kennel_audit_bind(AUDIT_NET_BIND_DENY, AF_INET6, port_be, requested, rewritten, meta);
	return KENNEL_DENY;
}

#ifndef SOCK_STREAM
#define SOCK_STREAM 1
#endif
#ifndef SOCK_DGRAM
#define SOCK_DGRAM 2
#endif

/*
 * Verdict-only forms of the ACL lookups, for the ingress program: it runs per packet, in softirq
 * context, so it emits no allow events and has no current task to name. Same tries, same
 * deny-first order as the kennel_*_decide_* functions above.
 */
static __always_inline int kennel_acl_v4(void *deny, void *allow, __u32 addr_be, __u16 port_be,
					 __u8 protocol)
{
	struct lpm_v4_key key = { .prefixlen = 32, .addr = addr_be };
	__u16 port_host = bpf_ntohs(port_be);
	struct allow_entry *denied = bpf_map_lookup_elem(deny, &key);
	if (denied && kennel_entry_matches(denied, protocol, port_host))
		return KENNEL_DENY;
	struct allow_entry *entry = bpf_map_lookup_elem(allow, &key);
	if (entry && kennel_entry_matches(entry, protocol, port_host))
		return KENNEL_ALLOW;
	return KENNEL_DENY;
}

static __always_inline int kennel_acl_v6(void *deny, void *allow, const __u8 addr[16],
					 __u16 port_be, __u8 protocol)
{
	struct lpm_v6_key key = { .prefixlen = 128 };
	__u16 port_host = bpf_ntohs(port_be);
	__builtin_memcpy(key.addr, addr, 16);
	struct allow_entry *denied = bpf_map_lookup_elem(deny, &key);
	if (denied && kennel_entry_matches(denied, protocol, port_host))
		return KENNEL_DENY;
	struct allow_entry *entry = bpf_map_lookup_elem(allow, &key);
	if (entry && kennel_entry_matches(entry, protocol, port_host))
		return KENNEL_ALLOW;
	return KENNEL_DENY;
}

/* The port half of the bind policy (§7.3.7): the floor, then the allowlist when one is set. */
static __always_inline int kennel_bind_port_ok(const struct kennel_meta *meta,
					       const struct bind_subnet *bs, __u16 port_host)
{
	if (meta->bind_port_min != 0 && port_host < meta->bind_port_min)
		return 0;
	if (bs->n_ports == 0)
		return 1;
	int allowed = 0;
	for (int i = 0; i < 8; i++) {
		if (i < bs->n_ports && bs->allowed_ports[i] == port_host)
			allowed = 1;
	}
	return allowed;
}

/* Audit header for an event raised outside any task's context: no pid, no comm. */
static __always_inline void kennel_audit_hdr_packet(struct audit_hdr *hdr, __u16 kind, __u16 length,
						    const struct kennel_meta *meta)
{
	hdr->magic = KENNEL_AUDIT_MAGIC;
	hdr->version = KENNEL_AUDIT_VERSION;
	hdr->kind = kind;
	hdr->ts_ns = bpf_ktime_get_ns();
	hdr->ctx_byte = meta->ctx_byte;
	hdr->length = length;
	hdr->pid = 0;
	__builtin_memset(&hdr->comm, 0, sizeof(hdr->comm));
}

/* Emit a socket-creation deny audit event. */
static __always_inline void
kennel_audit_sock(__u16 family, __u16 type, const struct kennel_meta *meta)
{
	struct audit_event_sock *ev = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*ev), 0);
	if (!ev) {
		kennel_audit_lost();
		return;
	}
	kennel_audit_hdr(&ev->hdr, AUDIT_NET_SOCK_DENY, (__u16)sizeof(*ev), meta);
	ev->body.family = family;
	ev->body.type = type;
	bpf_ringbuf_submit(ev, 0);
}

/* Emit a setsockopt-forced audit event. */
static __always_inline void
kennel_audit_sockopt(__s32 level, __s32 optname, const struct kennel_meta *meta)
{
	struct audit_event_sockopt *ev = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*ev), 0);
	if (!ev) {
		kennel_audit_lost();
		return;
	}
	kennel_audit_hdr(&ev->hdr, AUDIT_NET_SETSOCKOPT_FORCED, (__u16)sizeof(*ev), meta);
	ev->body.level = level;
	ev->body.optname = optname;
	bpf_ringbuf_submit(ev, 0);
}

#endif /* KENNEL_BPF_H */
