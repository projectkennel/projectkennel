// SPDX-License-Identifier: GPL-2.0-only
/*
 * Program: cgroup/sock_create
 * Purpose: Socket allowlist. The workload may create TCP and UDP sockets in
 *          AF_INET and AF_INET6, and nothing else. The address ACL lives in
 *          the connect/sendmsg/bind hooks, which exist for TCP and UDP only:
 *          any other socket in these families (an ICMP "ping" datagram
 *          socket, a raw socket, SCTP, MPTCP, UDP-Lite) would carry data to
 *          an address the ACL never judged, with no audit event.
 *
 *          This hook runs only for AF_INET and AF_INET6 sockets (the kernel
 *          calls it from inet_create/inet6_create). It does NOT see, and so
 *          cannot refuse, AF_PACKET, AF_NETLINK or any other family: those are
 *          not this program's to stop. AF_PACKET needs CAP_NET_RAW, which the
 *          workload does not hold. The final branch below is therefore only a
 *          fail-closed default for a family this hook should never be given.
 * Verifier complexity budget: ~100 instructions.
 * Maps used: kennel_meta_map, audit_ringbuf.
 * Failure mode: returns 0 for a disallowed socket, which fails socket(); a
 *          deny audit event is emitted. AF_UNIX is out of scope here (handled
 *          by the filesystem/Landlock shim, not this hook).
 * Threat bearing: T6 (raw sockets / netlink as a lateral-movement or recon
 *          surface).
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

SEC("cgroup/sock_create")
int kennel_sock_create(struct bpf_sock *ctx)
{
	if (ctx->family == AF_INET || ctx->family == AF_INET6) {
		/* `protocol` is the resolved one: socket(AF_INET, SOCK_STREAM, 0) reads as TCP. */
		if (ctx->type == SOCK_STREAM && ctx->protocol == IPPROTO_TCP)
			return KENNEL_ALLOW;
		if (ctx->type == SOCK_DGRAM && ctx->protocol == IPPROTO_UDP)
			return KENNEL_ALLOW;
	}

	const struct kennel_meta *meta = kennel_meta_get();
	if (meta)
		kennel_audit_sock((__u16)ctx->family, (__u16)ctx->type, meta);
	return KENNEL_DENY;
}
