// SPDX-License-Identifier: GPL-2.0
/*
 * Program: cgroup/connect6
 * Purpose: IPv6 counterpart of connect4. Deny-first against deny_v6, then
 *          allow_v6. Denies any connect that does not match an allow entry.
 * Verifier complexity budget: ~2k instructions.
 * Maps used: kennel_meta_map, deny_v6, allow_v6, audit_ringbuf.
 * Failure mode: returns 0 (connect fails); deny audit emitted. Fails closed.
 * Threat bearing: T1, T6, T9 (as connect4); also the IPv6 metadata address
 *          fd00:ec2::254 case via the deny trie.
 *
 * STATUS: verifier-clean on Linux 6.8.0 (2026-05-30). See bpf/README.md.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "maps.h"
#include "audit_events.h"
#include "kennel.bpf.h"

char LICENSE[] SEC("license") = "GPL";

SEC("cgroup/connect6")
int kennel_connect6(struct bpf_sock_addr *ctx)
{
	const struct kennel_meta *meta = kennel_meta_get();
	if (!meta)
		return KENNEL_DENY; /* fail closed */

	__u8 daddr[16];
	/* user_ip6 is __u32[4] in network byte order; read word-by-word as
	 * direct ctx accesses (see kennel_ctx_load_ip6). */
	kennel_ctx_load_ip6(ctx, daddr);

	__u16 port_be = (__u16)ctx->user_port; /* be16 port in low 16 bits; see connect4 */
	__u8 proto = (__u8)ctx->protocol;

	return kennel_decide_v6(daddr, port_be, proto, AUDIT_NET_CONNECT_DENY,
				AUDIT_NET_CONNECT_ALLOW, meta);
}
