// SPDX-License-Identifier: GPL-2.0
/*
 * Program: cgroup/sendmsg4
 * Purpose: Apply the egress policy to connectionless IPv4 datagrams
 *          (sendto/sendmsg on unconnected UDP), which bypass connect4. The
 *          principal case is DNS: the workload may not send UDP/53 anywhere
 *          except the proxy, so DNS resolution is forced through the proxy's
 *          allowlist rather than done directly by the workload.
 * Verifier complexity budget: ~2k instructions (same shape as connect4).
 * Maps used: kennel_meta_map, deny_v4, allow_v4, audit_ringbuf.
 * Failure mode: returns 0 (the send fails); deny audit emitted. Fails closed.
 * Threat bearing: T7 (DNS exfiltration — the workload cannot make direct DNS
 *          queries), T1, T6.
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

SEC("cgroup/sendmsg4")
int kennel_sendmsg4(struct bpf_sock_addr *ctx)
{
	const struct kennel_meta *meta = kennel_meta_get();
	if (!meta)
		return KENNEL_DENY; /* fail closed */

	__u32 daddr = ctx->user_ip4;
	__u16 port_be = (__u16)ctx->user_port; /* see BYTE ORDER VERIFY in connect4 */

	return kennel_decide_v4(daddr, port_be, IPPROTO_UDP, AUDIT_NET_SENDMSG_DENY,
				AUDIT_NET_CONNECT_ALLOW, meta);
}
