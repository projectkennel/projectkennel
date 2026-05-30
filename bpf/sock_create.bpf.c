// SPDX-License-Identifier: GPL-2.0
/*
 * Program: cgroup/sock_create
 * Purpose: Socket-family allowlist. The workload may create AF_INET and
 *          AF_INET6 sockets (its egress goes through the proxy, gated by the
 *          connect programs). Other families — AF_PACKET (raw packet capture/
 *          injection), AF_NETLINK (kernel configuration interfaces) — are
 *          denied at creation.
 * Verifier complexity budget: ~100 instructions.
 * Maps used: kennel_meta_map, audit_ringbuf.
 * Failure mode: returns 0 for a disallowed family, which fails socket(); a
 *          deny audit event is emitted. AF_UNIX is out of scope here (handled
 *          by the filesystem/Landlock shim, not this hook).
 * Threat bearing: T6 (raw sockets / netlink as a lateral-movement or recon
 *          surface).
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

SEC("cgroup/sock_create")
int kennel_sock_create(struct bpf_sock *ctx)
{
	if (ctx->family == AF_INET || ctx->family == AF_INET6)
		return KENNEL_ALLOW;

	const struct kennel_meta *meta = kennel_meta_get();
	if (meta)
		kennel_audit_sock((__u16)ctx->family, (__u16)ctx->type, meta);
	return KENNEL_DENY;
}
