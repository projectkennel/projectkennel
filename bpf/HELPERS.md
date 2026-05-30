# Permitted BPF helper functions

CODING-STANDARDS.md §4.1 restricts BPF helper usage to a whitelist with a
documented rationale per helper. Adding a helper to this list requires the same
two-maintainer review as adding an `unsafe` block. A program calling a helper
not on this list is rejected at review.

This list is the *intended* set for the current programs. It has not yet been
checked against a real build (see `README.md`: the programs are UNBUILT); a
helper may prove unavailable on the kernel floor and need substitution.

## Whitelist

| Helper | Used by | Rationale | Verifier note |
|---|---|---|---|
| `bpf_map_lookup_elem` | all | Read per-kennel maps: `kennel_meta`, the allow/deny LPM tries, `bind_subnet`. The core of every decision. | Returns NULL-able pointer; the result is always null-checked before deref. |
| `bpf_ringbuf_reserve` | all (audit path) | Reserve space for an audit event in the shared ringbuf. | Returns NULL-able pointer; null-checked before write. Reserve+submit pair, never reserve without submit/discard on every path. |
| `bpf_ringbuf_submit` | all (audit path) | Commit a reserved audit event. | Paired with every successful reserve. |
| `bpf_ringbuf_discard` | all (audit path) | Discard a reserved event on an error path so no reserve leaks. | Paired alternative to submit. |
| `bpf_ktime_get_ns` | all (audit path) | Timestamp (`CLOCK_MONOTONIC`) for `audit_hdr.ts_ns`. | Pure; no pointer. |
| `bpf_get_current_pid_tgid` | all (audit path) | Workload PID for `audit_hdr.pid`. | Pure; no pointer. |
| `bpf_get_current_comm` | all (audit path) | `task->comm` for `audit_hdr.comm`. | Writes into a fixed-size buffer with an explicit size argument. |

## Explicitly not used

- `bpf_probe_read_*` — the programs read only from the verifier-checked context
  struct and from map values, never from arbitrary kernel/user pointers, so no
  probe-read is needed. If a future program needs one, it uses the `_str`
  variant with an explicit length bound and is added here with justification.
- `bpf_printk` — debug only; forbidden in shipped programs and stripped before
  release (§4.1).
- Any helper that writes to the network packet, redirects, or tail-calls — out
  of scope for these cgroup attach points.
