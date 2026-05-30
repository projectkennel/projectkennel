// SPDX-License-Identifier: GPL-2.0
/*
 * Program: cgroup/sendmsg6
 * Purpose: IPv6 counterpart of sendmsg4. Connectionless IPv6 datagrams are
 *          checked deny-first then against the allow trie, forcing UDP/53 and
 *          other datagram egress through the proxy.
 * Verifier complexity budget: ~2k instructions.
 * Maps used: kennel_meta_map, deny_v6, allow_v6, audit_ringbuf.
 * Failure mode: returns 0 (the send fails); deny audit emitted. Fails closed.
 * Threat bearing: T7, T1, T6.
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

SEC("cgroup/sendmsg6")
int kennel_sendmsg6(struct bpf_sock_addr *ctx)
{
	const struct kennel_meta *meta = kennel_meta_get();
	if (!meta)
		return KENNEL_DENY; /* fail closed */

	__u8 daddr[16];
	kennel_ctx_load_ip6(ctx, daddr);
	__u16 port_be = (__u16)ctx->user_port; /* be16 port in low 16 bits; see connect4 */

	return kennel_decide_v6(daddr, port_be, IPPROTO_UDP, AUDIT_NET_SENDMSG_DENY,
				AUDIT_NET_CONNECT_ALLOW, meta);
}
