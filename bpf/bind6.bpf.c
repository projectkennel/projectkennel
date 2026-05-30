// SPDX-License-Identifier: GPL-2.0
/*
 * Program: cgroup/bind6
 * Purpose: IPv6 counterpart of bind4. A bind to in6addr_any (::) is rewritten
 *          to the kennel's private ULA loopback address; a bind already within
 *          the kennel /64 is allowed; anything else is denied.
 * Verifier complexity budget: ~1k instructions (a 64-bit prefix compare over
 *          the first 8 address bytes, plus the array lookups).
 * Maps used: kennel_meta_map, bind_subnet_map, audit_ringbuf.
 * Failure mode: rewrite + allow / allow / deny, as bind4. Fails closed.
 * Threat bearing: T6 (confines wildcard dev-server binds to the kennel).
 *
 * STATUS: verifier-clean on Linux 6.8.0 (2026-05-30). See bpf/README.md.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"
#include "audit_events.h"
#include "kennel.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* True iff the two 16-byte addresses share their first 8 bytes (a /64). */
static __always_inline int kennel_same_v64(const __u8 a[16], const __u8 b[16])
{
	for (int i = 0; i < 8; i++) {
		if (a[i] != b[i])
			return 0;
	}
	return 1;
}

/* True iff all 16 bytes are zero (in6addr_any). */
static __always_inline int kennel_is_any6(const __u8 a[16])
{
	for (int i = 0; i < 16; i++) {
		if (a[i] != 0)
			return 0;
	}
	return 1;
}

SEC("cgroup/bind6")
int kennel_bind6(struct bpf_sock_addr *ctx)
{
	const struct kennel_meta *meta = kennel_meta_get();
	if (!meta)
		return KENNEL_DENY;

	__u32 zero = 0;
	const struct bind_subnet *bs = bpf_map_lookup_elem(&bind_subnet_map, &zero);
	if (!bs)
		return KENNEL_DENY;

	__u8 addr[16];
	kennel_ctx_load_ip6(ctx, addr);
	__u16 port_be = (__u16)ctx->user_port; /* be16 port in low 16 bits; see connect4 */

	__u8 rewritten[16] = {};

	if (kennel_is_any6(addr)) {
		kennel_ctx_store_ip6(ctx, bs->v6_addr);
		__builtin_memcpy(rewritten, bs->v6_addr, 16);
		kennel_audit_bind(AUDIT_NET_BIND_REWRITE, AF_INET6, port_be, addr, rewritten,
				  meta);
		return KENNEL_ALLOW;
	}

	if (kennel_same_v64(addr, bs->v6_addr))
		return KENNEL_ALLOW;

	kennel_audit_bind(AUDIT_NET_BIND_DENY, AF_INET6, port_be, addr, rewritten, meta);
	return KENNEL_DENY;
}
