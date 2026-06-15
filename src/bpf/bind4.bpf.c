// SPDX-License-Identifier: GPL-2.0
/*
 * Program: cgroup/bind4
 * Purpose: Gate IPv4 binds by the [net.bpf].bind ACL (§7.5.7), deny-first. A bind
 *          to INADDR_ANY (0.0.0.0) is rewritten to the kennel's private loopback
 *          address first (so the JS ecosystem's 0.0.0.0 default works but is only
 *          reachable inside the kennel), then the rewritten address is gated by the
 *          ACL like any other. The ACL is default-deny; kenneld seeds it with the
 *          kennel's own loopback /28 so an in-subnet/wildcard bind stays allowed by
 *          default, while an author deny (or an out-of-set bind) is refused.
 * Verifier complexity budget: ~1k instructions (meta + subnet lookups, the port
 *          floor/allowlist, two LPM lookups, one ringbuf emit).
 * Maps used: kennel_meta_map, bind_subnet_map, bind_deny_v4, bind_allow_v4,
 *          audit_ringbuf.
 * Failure mode: rewrite wildcard, then ALLOW iff the address misses bind_deny and
 *          hits bind_allow; deny (return 0, bind fails) otherwise. Fails closed if
 *          metadata or the bind subnet is missing.
 * Threat bearing: T6 (a dev server bound to 0.0.0.0 would otherwise be exposed
 *          to the LAN/host; rewriting confines it to the kennel).
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
	__u16 port_be = (__u16)ctx->user_port; /* be16 port in low 16 bits; see connect4 */

	__u8 requested[16] = {};
	__u8 rewritten[16] = {};
	__builtin_memcpy(requested, &addr, 4);

	/* The bind floor (§7.3.7): a bind below `bind_port_min` is denied — the
	 * privileged-port protection (T6). Checked before the address logic, since a
	 * too-low port is refused regardless of which address it targets. 0 = no floor. */
	if (meta->bind_port_min != 0 && bpf_ntohs(port_be) < meta->bind_port_min) {
		kennel_audit_bind(AUDIT_NET_BIND_DENY, AF_INET, port_be, requested, rewritten, meta);
		return KENNEL_DENY;
	}

	/* The bind-port allowlist (§7.3.7): when `n_ports` is set, the port must be one
	 * of the listed ports. Bounded loop over the fixed array (verifier-friendly);
	 * `n_ports` caps the valid entries. Also address-independent, so checked here. */
	if (bs->n_ports != 0) {
		__u16 hport = bpf_ntohs(port_be);
		int allowed = 0;
		for (int i = 0; i < 8; i++) {
			if (i < bs->n_ports && bs->allowed_ports[i] == hport)
				allowed = 1;
		}
		if (!allowed) {
			kennel_audit_bind(AUDIT_NET_BIND_DENY, AF_INET, port_be, requested,
					  rewritten, meta);
			return KENNEL_DENY;
		}
	}

	/* INADDR_ANY: rewrite to the kennel loopback FIRST, then gate the rewritten address by
	 * the ACL — a wildcard bind must still satisfy [net.bpf].bind (deny-first). */
	__u32 effective = addr;
	if (addr == 0) {
		ctx->user_ip4 = bs->v4_addr;
		effective = bs->v4_addr;
		__builtin_memcpy(rewritten, &bs->v4_addr, 4);
		kennel_audit_bind(AUDIT_NET_BIND_REWRITE, AF_INET, port_be, requested,
				  rewritten, meta);
	}

	/* The inbound BIND ACL (§7.5.7), deny-first, default-deny. kenneld seeds the kennel's own
	 * loopback /28 into bind_allow, so an in-subnet or wildcard-rewritten bind stays allowed by
	 * default; an author deny (or a bind outside the allow set) is refused. */
	return kennel_bind_decide_v4(effective, port_be, (__u8)ctx->protocol, requested, rewritten,
				     meta);
}
