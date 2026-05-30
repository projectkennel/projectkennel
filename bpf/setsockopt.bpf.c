// SPDX-License-Identifier: GPL-2.0
/*
 * Program: cgroup/setsockopt
 * Purpose: Force IPV6_V6ONLY = 1. A dual-stack socket (V6ONLY=0) accepts IPv4
 *          traffic on an IPv6 socket; if only the IPv6 bind path were rewritten
 *          (bind6), the IPv4 fallback would escape isolation. This program
 *          rewrites any setsockopt(IPPROTO_IPV6, IPV6_V6ONLY) to value 1
 *          regardless of what the workload requested.
 * Verifier complexity budget: ~300 instructions. The optval read is bounds-
 *          checked against optval_end before dereference (§4.1).
 * Maps used: kennel_meta_map, audit_ringbuf.
 * Failure mode: returns 1 (proceed) with the value forced to 1. Unrelated
 *          setsockopt calls pass through unchanged. If optval cannot be read
 *          within bounds, the call proceeds unmodified.
 * Threat bearing: T6 (dual-stack escape of loopback isolation).
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

#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41
#endif
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 26
#endif

SEC("cgroup/setsockopt")
int kennel_setsockopt(struct bpf_sockopt *ctx)
{
	if (ctx->level != IPPROTO_IPV6 || ctx->optname != IPV6_V6ONLY)
		return 1; /* not our concern; proceed unchanged */

	__u8 *optval = ctx->optval;
	__u8 *optval_end = ctx->optval_end;
	/* Bounds check before dereference: optval must hold at least one byte. */
	if (optval + 1 > optval_end)
		return 1; /* cannot inspect the value; let the kernel proceed */

	if (*optval != 1) {
		*optval = 1;
		ctx->optlen = 1;
		const struct kennel_meta *meta = kennel_meta_get();
		if (meta)
			kennel_audit_sockopt(IPPROTO_IPV6, IPV6_V6ONLY, meta);
	}
	return 1;
}
