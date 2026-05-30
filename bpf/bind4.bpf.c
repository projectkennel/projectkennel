// SPDX-License-Identifier: GPL-2.0
/*
 * Program: cgroup/bind4
 * Purpose: Keep IPv4 dev-server binds inside the kennel. A bind to INADDR_ANY
 *          (0.0.0.0) is rewritten to the kennel's private loopback address, so
 *          the half of the JS ecosystem that defaults to 0.0.0.0 works but is
 *          only reachable from inside the kennel. A bind already within the
 *          kennel subnet is allowed; anything else is denied.
 * Verifier complexity budget: ~1k instructions (two array lookups, a masked
 *          compare, one ringbuf emit).
 * Maps used: kennel_meta_map, bind_subnet_map, audit_ringbuf.
 * Failure mode: rewrite + allow (return 1) for wildcard/in-subnet; deny
 *          (return 0, bind fails) otherwise. Fails closed if metadata or the
 *          bind subnet is missing.
 * Threat bearing: T6 (a dev server bound to 0.0.0.0 would otherwise be exposed
 *          to the LAN/host; rewriting confines it to the kennel).
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

/* /24 network mask in network byte order. */
#define KENNEL_V4_MASK24 bpf_htonl(0xFFFFFF00u)

SEC("cgroup/bind4")
int kennel_bind4(struct bpf_sock_addr *ctx)
{
	const struct kennel_meta *meta = kennel_meta_get();
	if (!meta)
		return KENNEL_DENY;

	__u32 zero = 0;
	const struct bind_subnet *bs = bpf_map_lookup_elem(&bind_subnet_map, &zero);
	if (!bs)
		return KENNEL_DENY;

	__u32 addr = ctx->user_ip4;	       /* network byte order */
	__u16 port_be = (__u16)ctx->user_port; /* see BYTE ORDER VERIFY in connect4 */

	__u8 requested[16] = {};
	__u8 rewritten[16] = {};
	__builtin_memcpy(requested, &addr, 4);

	if (addr == 0) { /* INADDR_ANY: rewrite to the kennel loopback */
		ctx->user_ip4 = bs->v4_addr;
		__builtin_memcpy(rewritten, &bs->v4_addr, 4);
		kennel_audit_bind(AUDIT_NET_BIND_REWRITE, AF_INET, port_be, requested,
				  rewritten, meta);
		return KENNEL_ALLOW;
	}

	if ((addr & KENNEL_V4_MASK24) == (bs->v4_addr & KENNEL_V4_MASK24)) {
		/* Already inside the kennel's /24: allow unchanged. */
		return KENNEL_ALLOW;
	}

	kennel_audit_bind(AUDIT_NET_BIND_DENY, AF_INET, port_be, requested, rewritten, meta);
	return KENNEL_DENY;
}
