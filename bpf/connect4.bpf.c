// SPDX-License-Identifier: GPL-2.0
/*
 * Program: cgroup/connect4
 * Purpose: Enforce the IPv4 egress policy. Every connect() from the workload
 *          is checked deny-first against the invariant deny trie, then against
 *          the allow trie (which includes the kennel's SOCKS5 proxy entry). A
 *          connect to anything else is denied at the kernel, so the proxy is
 *          unbypassable from inside the kennel.
 * Verifier complexity budget: ~2k instructions (two LPM lookups, a meta
 *          lookup, one ringbuf emit). Well under the 10k review ceiling.
 * Maps used: kennel_meta_map (proxy/ctx), deny_v4, allow_v4 (decision),
 *          audit_ringbuf (event).
 * Failure mode: returns 0, which fails the connect() (ECONNREFUSED/EPERM); a
 *          deny audit event is emitted. Fails closed: if metadata is missing,
 *          the connect is denied.
 * Threat bearing: T1 (exfiltration to an unlisted destination), T6 (lateral
 *          movement to RFC1918/loopback), T9 (unexpected destination surfaced
 *          in the audit log).
 *
 * STATUS: UNBUILT / UNVERIFIED. See bpf/README.md.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"
#include "audit_events.h"
#include "kennel.bpf.h"

char LICENSE[] SEC("license") = "GPL";

SEC("cgroup/connect4")
int kennel_connect4(struct bpf_sock_addr *ctx)
{
	const struct kennel_meta *meta = kennel_meta_get();
	if (!meta)
		return KENNEL_DENY; /* fail closed */

	__u32 daddr = ctx->user_ip4;	    /* network byte order */
	/* BYTE ORDER VERIFY: bpf_sock_addr.user_port packing must be confirmed
	 * against the kernel before this is trusted; treated here as the be16
	 * port in the low 16 bits. */
	__u16 port_be = (__u16)ctx->user_port;
	__u8 proto = (__u8)ctx->protocol;

	return kennel_decide_v4(daddr, port_be, proto, AUDIT_NET_CONNECT_DENY,
				AUDIT_NET_CONNECT_ALLOW, meta);
}
