// SPDX-License-Identifier: GPL-2.0
/*
 * Program: cgroup/bind6
 * Purpose: IPv6 counterpart of bind4. A bind to in6addr_any (::) is rewritten to
 *          the kennel's private ULA loopback address first, then the rewritten
 *          address is gated by the [net.bpf].bind ACL (§7.5.7), deny-first and
 *          default-deny, exactly as bind4.
 * Verifier complexity budget: ~1k instructions (meta + subnet lookups, the port
 *          floor/allowlist, two LPM lookups, one ringbuf emit).
 * Maps used: kennel_meta_map, bind_subnet_map, bind_deny_v6, bind_allow_v6,
 *          audit_ringbuf.
 * Failure mode: rewrite wildcard, then ALLOW iff the address misses bind_deny and
 *          hits bind_allow; deny otherwise. Fails closed.
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

	/* The bind floor (§7.3.7): deny a bind below `bind_port_min` before the address
	 * logic — the privileged-port protection (T6), mirroring bind4. 0 = no floor. */
	if (meta->bind_port_min != 0 && bpf_ntohs(port_be) < meta->bind_port_min) {
		kennel_audit_bind(AUDIT_NET_BIND_DENY, AF_INET6, port_be, addr, rewritten, meta);
		return KENNEL_DENY;
	}

	/* The bind-port allowlist (§7.3.7): when `n_ports` is set, the port must be one of
	 * the listed ports. Bounded loop over the fixed array, mirroring bind4. */
	if (bs->n_ports != 0) {
		__u16 hport = bpf_ntohs(port_be);
		int allowed = 0;
		for (int i = 0; i < 8; i++) {
			if (i < bs->n_ports && bs->allowed_ports[i] == hport)
				allowed = 1;
		}
		if (!allowed) {
			kennel_audit_bind(AUDIT_NET_BIND_DENY, AF_INET6, port_be, addr, rewritten,
					  meta);
			return KENNEL_DENY;
		}
	}

	/* in6addr_any: rewrite to the kennel loopback FIRST, then gate the rewritten address by the
	 * ACL — a wildcard bind must still satisfy [net.bpf].bind (deny-first). `effective` carries
	 * the address actually being bound. */
	__u8 effective[16];
	__builtin_memcpy(effective, addr, 16);
	if (kennel_is_any6(addr)) {
		kennel_ctx_store_ip6(ctx, bs->v6_addr);
		__builtin_memcpy(effective, bs->v6_addr, 16);
		__builtin_memcpy(rewritten, bs->v6_addr, 16);
		kennel_audit_bind(AUDIT_NET_BIND_REWRITE, AF_INET6, port_be, addr, rewritten,
				  meta);
	}

	/* The inbound BIND ACL (§7.5.7), deny-first, default-deny (mirror of bind4). */
	return kennel_bind_decide_v6(effective, port_be, (__u8)ctx->protocol, addr, rewritten, meta);
}
