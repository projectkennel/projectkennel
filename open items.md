The retry loop inside `kennel-init` exists solely to resolve a startup race condition between the host and the sandbox namespaces.

### Why the Loop Exists Now

The race stems from how the `binderfs` instance is shared across the boundary:

1. The `privhelper` child process creates the fresh namespace, mounts a private `binderfs` instance, and then executes `fexecve` to start `kennel-init` as PID 1.
2. `kennel-init` boots instantly and opens `/dev/binderfs/binder`, immediately attempting to transmit `GET_SANDBOX_PLAN` to Node 0 (the context manager).
3. Meanwhile, on the host, `kenneld` has *just* learned the supervisor's host PID from the `privhelper` parent. It must open `/proc/<init_host_pid>/root/dev/binderfs/binder` and issue the `ioctl` to register itself as the Node 0 Context Manager.

Because these two paths run concurrently, `kennel-init` often hits the binder driver before `kenneld` has completed its host-side registration. Without the loop, the binder driver would throw an immediate `BR_DEAD_REPLY` error because there is no context manager listening yet, causing the container to fail-closed and crash.

---

### How to Delete the Loop Natively (True "Do Less")

You can completely remove this retry loop and its associated constants (`PULL_RETRIES`, `PULL_BACKOFF`) without breaking the separation of concerns. Instead of making the guest supervisor poll blindly, the synchronization can be handled entirely on the host side using the existing `SOCK_SEQPACKET` communication channel (`chan`) between `kenneld` and the `privhelper` parent process.

By altering the host-side launch sequence, execution follows a deterministic order:

```
[ Parent Factory (Host Root) ]                      [ kenneld (Host Operator) ]
  Writes identity mappings 
  Drops privileges to operator
  Sends init_pid over wire ───────────────────────► Receives init_pid datagram
                                                    Opens /proc/<pid>/root/dev/binderfs/binder
                                                    Registers as Context Manager (Node 0)
  Blocks on recv_ack() <─── (Sends Wire Token) ─────┘
            │
            ▼
  Releases handshake pipe (ready_w)
            │
            ▼
[ Child Factory (Trapped) ]
  build_view_and_pivot()
  fexecve(kennel_init_fd)
            │
            ▼
[ kennel-init (PID 1) ]
  Opens /dev/binderfs/binder
  Invokes transact() ──► Guaranteed to succeed on first pass (Node 0 is already live)

```

### The Concrete Code Simplification

In `kennel-privhelper/src/construct.rs`, adjust the handshake order so the parent holds the child back until `kenneld` confirms Node 0 is live:

```rust
    // 4. Write maps and permanently drop privileges to the operator identity
    write_identity_maps(init_pid, op_uid, op_gid, &granted)?;
    kennel_syscall::unistd::set_gid(op_gid)?;
    kennel_syscall::unistd::set_uid(op_uid)?;

    // Transmit the anchor host PID to kenneld first
    send_with_fds(chan, &init_pid.to_le_bytes(), &[])?;

    // DO LESS: Synchronous Host Bus Gate
    // Block here until kenneld replies back over the control socket 
    // confirming it has successfully claimed Node 0 of the new instance.
    let mut bus_ready_token = [0u8; 1];
    let _ = kennel_syscall::handshake::recv_ack(chan)?; 

    // Node 0 is verified live on the host. Release the child to exec.
    send_ack(ready_w.as_fd(), ACK_PROCEED)?;
    drop(ready_w);

    // 5. Exit immediately (or drop into your unprivileged reap loop)
    Ok(0)

```

### The Architectural Result

1. **Deletes Guest Code Paths:** The `pull_plan` function inside `kennel-init/src/main.rs` shrinks to a single, non-blocking transaction. The entire retry loop, the tracking of `last` errors, the parsing of `BR_DEAD_REPLY` string metrics, and the `std::thread::sleep` invocations are **completely erased** from the sandbox memory footprint.
2. **Preserves Separation of Concerns:** `privhelper` remains blind to the workload configuration bytes. It does not look at the supervision plan; it simply blocks for a fraction of a millisecond on its existing control pipe to ensure the communication bus it constructed is plugged in before launching the supervisor.
3. **Eliminites Startup Jitter:** The sandbox supervisor boots deterministically, fetches its plan on the first clock cycle, and spawns the workload instantly.


----

kennel-syscall is way too big - 53% of the codebase!

We should at a minimum split between the unsafe and safe functions - and probably shift out every function that's only used by privhelper.

----

Major Soundness Bugs in unsafe Wrappers

kennel-binder/src/sys.rs: pub fn write_read(fd, bwr: &mut BinderWriteRead) is exposed as a safe function, but the BinderWriteRead struct contains raw u64 pointers to buffers. This means a caller in safe Rust can pass garbage pointers to the kernel and corrupt memory. Additionally, pub fn own_fd(raw: i32) relies on the caller verifying raw >= 0, but doesn't mark the function unsafe.
kennel-bpf/src/sys.rs: pub fn map_update(..., key: &[u8], value: &[u8]) is marked safe, but casts key.as_ptr() straight to the kernel. If a caller provides a slice shorter than the BPF map's key_size, the kernel will perform an out-of-bounds read on the process's memory.
These functions must be marked unsafe fn since they require the caller to uphold memory-safety invariants to avoid Undefined Behavior.

---- 

Dead Code (YAGNI Violations)
kennel-syscall/src/handshake.rs is Completely Redundant
Smell: As noted in 08-as-built-notes.md, the deferred-gid map handshake (§7.4.8) has been completely subsumed because the constructor now fully writes the maps before kennel-init starts.
Violation: Despite this, the entire handshake.rs file (a custom anonymous-pipe exchange mechanism with poll/pipe2) is still in the kennel-syscall crate.
Recommendation: Delete handshake.rs entirely. It is 100% obsolete dead code.
Unbuilt Features in kennel-policy
The 08-as-built-notes.md documents several features that are "designed, not built" (e.g., fs.scrub, fs.home.sanitise, [container], [dbus], [x11]).

Smell: Instead of removing these features from the parser until they are actually built, kennel-policy keeps thousands of lines of parser code, AST structs (FsScrub, ContainerSection, ContainerPort, X11Section), and merge resolution logic (resolve.rs) for them. It merely spits out a "not enforced" compile warning.
Recommendation: Strip out the AST nodes, parsing, and merging logic for unbuilt features. They are currently dead weight and increase the surface area of the policy engine for no runtime benefit.


----

we urgently need to rework IPC, based on the new binder framework and implement the afunix facade and frontend.



