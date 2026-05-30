/*
 * Project Kennel BPF audit-event ABI (architecture/02-5-bpf-abi.md).
 *
 * Events are packed structs written to the shared audit ringbuf. kenneld
 * drains them, resolves the kennel from ctx_byte, sanitises any strings, and
 * writes the JSONL audit events of architecture/02-3-audit-schema.md.
 *
 * STATUS: UNBUILT / UNVERIFIED. See bpf/README.md.
 *
 * Assumes vmlinux.h is already included (for the __uN types).
 */
#ifndef KENNEL_AUDIT_EVENTS_H
#define KENNEL_AUDIT_EVENTS_H

#define KENNEL_AUDIT_MAGIC 0x4145564Eu /* "AEVN" */
#define KENNEL_AUDIT_VERSION 1

enum audit_kind {
	AUDIT_NET_CONNECT_DENY = 1,
	AUDIT_NET_CONNECT_ALLOW = 2,
	AUDIT_NET_BIND_REWRITE = 3,
	AUDIT_NET_BIND_DENY = 4,
	AUDIT_NET_SOCK_DENY = 5,
	AUDIT_NET_SETSOCKOPT_FORCED = 6,
	AUDIT_NET_SENDMSG_DENY = 7,
};

/* Common header at the front of every event. */
struct audit_hdr {
	__u32 magic;	 /* KENNEL_AUDIT_MAGIC */
	__u16 version;	 /* KENNEL_AUDIT_VERSION */
	__u16 kind;	 /* enum audit_kind */
	__u64 ts_ns;	 /* CLOCK_MONOTONIC */
	__u16 ctx_byte;	 /* kennel context byte */
	__u16 length;	 /* total event length incl. header */
	__u32 pid;	 /* workload pid */
	__u8 comm[16];	 /* task->comm, null-padded */
};

/* connect / sendmsg bodies. addr in network byte order; v4 in addr.v4. */
struct audit_payload_connect {
	__u8 family;	/* AF_INET / AF_INET6 */
	__u8 protocol;	/* IPPROTO_TCP / IPPROTO_UDP */
	__u16 port;	/* network byte order */
	union {
		__u32 v4;
		__u8 v6[16];
	} addr;
};

/* bind body: the requested wildcard and what it was rewritten to. */
struct audit_payload_bind {
	__u8 family;
	__u8 _pad;
	__u16 port;	      /* network byte order */
	__u8 requested[16];   /* the address the workload asked to bind */
	__u8 rewritten[16];   /* what the kennel substituted (rewrite case) */
};

/* sock_create body. */
struct audit_payload_sock {
	__u16 family;
	__u16 type;
};

/* setsockopt-forced body. */
struct audit_payload_sockopt {
	__s32 level;
	__s32 optname;
};

/* Combined events reserved on the ringbuf as a unit. */
struct audit_event_connect {
	struct audit_hdr hdr;
	struct audit_payload_connect body;
};

struct audit_event_bind {
	struct audit_hdr hdr;
	struct audit_payload_bind body;
};

struct audit_event_sock {
	struct audit_hdr hdr;
	struct audit_payload_sock body;
};

struct audit_event_sockopt {
	struct audit_hdr hdr;
	struct audit_payload_sockopt body;
};

#endif /* KENNEL_AUDIT_EVENTS_H */
