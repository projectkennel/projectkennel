/*
 * Project Kennel BPF map ABI — single source of truth for map layouts.
 *
 * The Rust loader (kennel-bpf) mirrors these layouts by hand in its KENNEL_MAPS
 * table (it does not read BTF); these definitions are authoritative for both
 * sides and the two must be kept in lockstep (architecture/02-7-bpf-abi.md).
 *
 * STATUS: verifier-clean on Linux 6.8.0 (2026-05-30); the map layouts were
 * validated by bpftool's BTF-driven decode of live map contents (the LPM key,
 * allow_entry, and kennel_meta layouts round-trip). See bpf/README.md.
 *
 * Include order in every .bpf.c:
 *     #include <linux/bpf.h>
 *     #include <bpf/bpf_helpers.h>
 *     #include "maps.h"
 *     #include "audit_events.h"
 *     #include "kennel.bpf.h"
 * This header assumes <linux/bpf.h> and bpf_helpers.h are already included.
 */
#ifndef KENNEL_MAPS_H
#define KENNEL_MAPS_H

/* Sentinels (architecture/02-7). */
#define KENNEL_META_MAGIC 0x4B4E454Cu /* "KNEL" */
#define KENNEL_ABI_VERSION 1

/* allow_entry.flags bits. */
#define KENNEL_ALLOW_FLAG_PROXY 0x01u /* this entry is the kennel's SOCKS5 proxy */

/* allow_entry.protocol sentinel for "any protocol". */
#define KENNEL_PROTO_ANY 0u

/*
 * Per-kennel metadata. Single-element array, populated by the loader at kennel
 * start and marked read-only (BPF_F_RDONLY_PROG) thereafter. Read by every
 * program at every invocation. Reserved padding keeps the layout deterministic
 * across the C and Rust sides.
 */
struct kennel_meta {
	__u32 magic;	      /* KENNEL_META_MAGIC */
	__u16 abi_version;    /* KENNEL_ABI_VERSION */
	__u16 ctx_byte;	      /* the kennel's <ctx> */
	__u32 proxy_addr_v4;  /* network byte order */
	__u16 proxy_port;     /* network byte order */
	__u16 bind_port_min;  /* host byte order; lowest bindable port (§7.3.7), 0 = no floor */
	__u8 proxy_addr_v6[16];
	__u8 policy_hash[32]; /* SHA-256 of the resolved policy */
};

/*
 * Value type for the allow/deny LPM tries. The v4 and v6 tries share this
 * value layout; they differ only in key width.
 */
struct allow_entry {
	__u16 port_min;	  /* inclusive, host byte order */
	__u16 port_max;	  /* inclusive, host byte order */
	__u8 protocol;	  /* IPPROTO_TCP / IPPROTO_UDP, or KENNEL_PROTO_ANY */
	__u8 flags;	  /* KENNEL_ALLOW_FLAG_* */
	__u8 _pad[2];
};

/* LPM trie keys. addr fields are in network byte order. */
struct lpm_v4_key {
	__u32 prefixlen;
	__u32 addr;
};

struct lpm_v6_key {
	__u32 prefixlen;
	__u8 addr[16];
};

/*
 * Per-kennel bind subnet, for INADDR_ANY/in6addr_any rewriting. Single-element
 * array. The kennel binds dev servers to this loopback address rather than to
 * a wildcard that would expose them beyond the kennel.
 */
struct bind_subnet {
	__u32 v4_addr;	  /* network byte order */
	__u32 v4_prefix;  /* host order, expected 24 */
	__u8 v6_addr[16];
	__u8 v6_prefix;	  /* expected 64 */
	__u8 n_ports;	  /* valid entries in allowed_ports (0 = any port >= the floor) */
	__u16 allowed_ports[8]; /* host order; if n_ports>0 the bind port must be one (§7.3.7) */
};

/* ------------------------------------------------------------------ maps */

/* Per-kennel metadata (index 0). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kennel_meta);
} kennel_meta_map SEC(".maps");

/* Invariant deny CIDRs (cloud metadata, RFC1918, link-local). Deny-first. */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__type(key, struct lpm_v4_key);
	__type(value, struct allow_entry);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} deny_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__type(key, struct lpm_v6_key);
	__type(value, struct allow_entry);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} deny_v6 SEC(".maps");

/* Per-destination allowlist (includes the proxy entry, flagged). */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key, struct lpm_v4_key);
	__type(value, struct allow_entry);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allow_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key, struct lpm_v6_key);
	__type(value, struct allow_entry);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} allow_v6 SEC(".maps");

/* Inbound BIND ACL (§7.5.7), deny-first, dedicated maps (independent of the connect
 * allow/deny tries above). A bind to <addr>:<port> is permitted iff it misses bind_deny
 * and hits bind_allow; default-deny otherwise. kenneld seeds bind_allow with the kennel's
 * own loopback /28 so a wildcard-rewritten or in-subnet bind stays allowed by default. */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__type(key, struct lpm_v4_key);
	__type(value, struct allow_entry);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} bind_deny_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 256);
	__type(key, struct lpm_v6_key);
	__type(value, struct allow_entry);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} bind_deny_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key, struct lpm_v4_key);
	__type(value, struct allow_entry);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} bind_allow_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 1024);
	__type(key, struct lpm_v6_key);
	__type(value, struct allow_entry);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} bind_allow_v6 SEC(".maps");

/* Bind subnet (index 0). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct bind_subnet);
} bind_subnet_map SEC(".maps");

/* Shared audit ringbuf (drained by kenneld). 1 MiB default. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} audit_ringbuf SEC(".maps");

#endif /* KENNEL_MAPS_H */
