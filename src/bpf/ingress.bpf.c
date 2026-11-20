// SPDX-License-Identifier: GPL-2.0
/*
 * Program: cgroup_skb/ingress
 * Purpose: The inbound half of the bind policy. The bind hooks judge a bind()
 *          call, but a socket can receive without one that the policy saw:
 *            - listen() on an unbound TCP socket binds it to the wildcard
 *              address on a kernel-chosen port, with no hook on the way;
 *            - a bind to port 0 is admitted without the address ACL or the
 *              wildcard rewrite (an outbound socket needs it), and the socket
 *              can then receive, or listen, on the port the kernel picks.
 *          Either is a reachable service the policy never admitted. There is
 *          no cgroup hook on listen(), so the check is made where the traffic
 *          arrives:
 *            - a packet for a TCP *listener* is dropped unless the listener's
 *              own address and port pass the bind policy. A listener on the
 *              wildcard address never passes: a bind the policy saw is
 *              rewritten to the kennel's loopback, so a wildcard listener is
 *              one it did not see.
 *            - a datagram for a UDP socket is delivered if the socket's own
 *              address and port pass the bind policy (a service the policy
 *              admits), or if the sender is a peer the kennel may send to (a
 *              reply). Anything else is dropped.
 *          Packets for connected TCP sockets pass: the connect hook, or the
 *          listener check on the handshake, already judged the flow.
 * Verifier complexity budget: ~600 instructions.
 * Maps used: kennel_meta_map, bind_subnet_map, bind_{deny,allow}_v{4,6},
 *          {deny,allow}_v{4,6}, audit_ringbuf, audit_lost.
 * Failure mode: returns 0, which drops the packet; a deny audit event is
 *          emitted (no pid/comm: there is no task in this context). A datagram
 *          whose headers cannot be read is dropped.
 * Threat bearing: T6 (an unadmitted listening surface in host mode).
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"
#include "audit_events.h"
#include "kennel.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define KENNEL_ETH_P_IP 0x0800
#define KENNEL_ETH_P_IPV6 0x86DD
#define KENNEL_TCP_LISTEN 10 /* BPF_TCP_LISTEN */

/* A listener (or UDP service) refused: bind body, `requested` = the socket's own address. */
static __always_inline void ingress_audit_local(__u8 family, __u16 port_be, const __u8 local[16],
						const struct kennel_meta *meta)
{
	struct audit_event_bind *ev = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*ev), 0);
	if (!ev) {
		kennel_audit_lost();
		return;
	}
	kennel_audit_hdr_packet(&ev->hdr, AUDIT_NET_LISTEN_DENY, (__u16)sizeof(*ev), meta);
	ev->body.family = family;
	ev->body._pad = 0;
	ev->body.port = port_be;
	__builtin_memcpy(ev->body.requested, local, 16);
	__builtin_memset(ev->body.rewritten, 0, 16);
	bpf_ringbuf_submit(ev, 0);
}

/* A datagram refused: connect body, the sender's address and port. */
static __always_inline void ingress_audit_peer(__u8 family, __u16 port_be, const void *addr,
					       const struct kennel_meta *meta)
{
	struct audit_event_connect *ev = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*ev), 0);
	if (!ev) {
		kennel_audit_lost();
		return;
	}
	kennel_audit_hdr_packet(&ev->hdr, AUDIT_NET_INGRESS_DENY, (__u16)sizeof(*ev), meta);
	ev->body.family = family;
	ev->body.protocol = IPPROTO_UDP;
	ev->body.port = port_be;
	__builtin_memset(&ev->body.addr, 0, sizeof(ev->body.addr));
	if (family == AF_INET6)
		__builtin_memcpy(ev->body.addr.v6, addr, 16);
	else
		__builtin_memcpy(&ev->body.addr.v4, addr, 4);
	bpf_ringbuf_submit(ev, 0);
}

/*
 * Whether the socket's own address and port pass the bind policy: a specific (non-wildcard)
 * address the bind ACL admits, on a port the floor and allowlist admit. `local` receives the
 * address for the audit event (v4 in the first four bytes).
 */
static __always_inline int ingress_local_ok(const struct bpf_sock *sk, __u8 protocol,
					    const struct kennel_meta *meta,
					    const struct bind_subnet *bs, __u8 local[16],
					    __u8 *family)
{
	__u16 port_host = (__u16)sk->src_port; /* host byte order */
	__u16 port_be = bpf_htons(port_host);

	if (!kennel_bind_port_ok(meta, bs, port_host))
		return 0;
	if (sk->family == AF_INET) {
		__u32 addr = sk->src_ip4;
		*family = AF_INET;
		__builtin_memcpy(local, &addr, 4);
		if (addr == 0)
			return 0;
		return kennel_acl_v4(&bind_deny_v4, &bind_allow_v4, addr, port_be, protocol);
	}
	__u32 w[4];
	w[0] = sk->src_ip6[0];
	w[1] = sk->src_ip6[1];
	w[2] = sk->src_ip6[2];
	w[3] = sk->src_ip6[3];
	__builtin_memcpy(local, w, 16);
	*family = AF_INET6;
	/* The bind hook refuses a mapped bind and rewrites the wildcard, so neither is admitted. */
	if (kennel_is_unspecified6(local) || kennel_is_v4mapped(local))
		return 0;
	return kennel_acl_v6(&bind_deny_v6, &bind_allow_v6, local, port_be, protocol);
}

SEC("cgroup_skb/ingress")
int kennel_ingress(struct __sk_buff *skb)
{
	const struct kennel_meta *meta = kennel_meta_get();
	if (!meta)
		return KENNEL_DENY; /* fail closed */

	struct bpf_sock *sk = skb->sk;
	if (!sk)
		return KENNEL_ALLOW;
	sk = bpf_sk_fullsock(sk);
	if (!sk)
		return KENNEL_ALLOW; /* a request or timewait socket: an existing flow */

	__u8 tcp = sk->protocol == IPPROTO_TCP;
	if (tcp && sk->state != KENNEL_TCP_LISTEN)
		return KENNEL_ALLOW; /* a connected socket: the flow was judged when it was made */
	if (!tcp && sk->protocol != IPPROTO_UDP)
		return KENNEL_ALLOW; /* no other socket kind exists here (sock_create) */

	__u32 zero = 0;
	const struct bind_subnet *bs = bpf_map_lookup_elem(&bind_subnet_map, &zero);
	if (!bs)
		return KENNEL_DENY;

	__u8 local[16] = {};
	__u8 family = AF_INET;
	if (ingress_local_ok(sk, tcp ? IPPROTO_TCP : IPPROTO_UDP, meta, bs, local, &family))
		return KENNEL_ALLOW;
	if (tcp) {
		ingress_audit_local(family, bpf_htons((__u16)sk->src_port), local, meta);
		return KENNEL_DENY;
	}

	/* UDP, and not a service the bind policy admits: deliver only a reply, that is, a
	 * datagram from a peer the kennel is allowed to send to. Read the sender from the packet
	 * (the socket is unconnected, so it does not say). */
	if (skb->protocol == bpf_htons(KENNEL_ETH_P_IP)) {
		__u8 ip[20];
		if (bpf_skb_load_bytes(skb, 0, ip, sizeof(ip)) < 0)
			return KENNEL_DENY;
		__u32 ihl = (__u32)(ip[0] & 0x0f) * 4;
		if (ihl < 20 || ip[9] != IPPROTO_UDP)
			return KENNEL_DENY;
		__u32 saddr;
		__builtin_memcpy(&saddr, ip + 12, 4);
		__u16 sport_be;
		if (bpf_skb_load_bytes(skb, ihl, &sport_be, sizeof(sport_be)) < 0)
			return KENNEL_DENY;
		if (kennel_acl_v4(&deny_v4, &allow_v4, saddr, sport_be, IPPROTO_UDP))
			return KENNEL_ALLOW;
		ingress_audit_peer(AF_INET, sport_be, &saddr, meta);
		return KENNEL_DENY;
	}
	if (skb->protocol == bpf_htons(KENNEL_ETH_P_IPV6)) {
		__u8 ip6[40];
		if (bpf_skb_load_bytes(skb, 0, ip6, sizeof(ip6)) < 0)
			return KENNEL_DENY;
		if (ip6[6] != IPPROTO_UDP)
			return KENNEL_DENY; /* extension headers: the sender's port is not where we can read it */
		__u8 saddr6[16];
		__builtin_memcpy(saddr6, ip6 + 8, 16);
		__u16 sport_be;
		if (bpf_skb_load_bytes(skb, 40, &sport_be, sizeof(sport_be)) < 0)
			return KENNEL_DENY;
		if (kennel_acl_v6(&deny_v6, &allow_v6, saddr6, sport_be, IPPROTO_UDP))
			return KENNEL_ALLOW;
		ingress_audit_peer(AF_INET6, sport_be, saddr6, meta);
		return KENNEL_DENY;
	}
	return KENNEL_DENY;
}
