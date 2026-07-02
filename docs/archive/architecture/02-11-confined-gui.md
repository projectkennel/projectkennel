# Confined GUI — the compositor-broker and the two display legs

> **Status: the display path is built.** This chapter is the implementation contract for the confined-GUI
> feature designed in [`../design/07-14-confined-gui.md`](../design/07-14-confined-gui.md) (§7.14). As
> built: a GUI-service kennel holds the host-Wayland leg and `/dev/dri`, runs the **`compositor-broker`**
> workload, and serves one nested compositor (cage / Weston / sway) **per app connection** over the mesh;
> each leg is an AF_UNIX brokered connect that forwards `SCM_RIGHTS` fds; the compositor is killed and its
> window folds the moment the app disconnects. The **interactive file broker** (§7.14.7) and the other
> Kennel-native desktop brokers (screenshot / open-URL / notifications, §7.14.8) remain designed, not
> built — confined GUI today is the *display* leg. Where this contract and the code diverge, the divergence
> is owed to the code.

A graphical workload reaches a display the way every other reachable capability arrives: the GUI-service
kennel is constructed holding one host-compositor connection and the GPU render node, and brokers a nested
compositor to each consuming app over the §7.13 service mesh. The app talks to *that* compositor; the host
compositor is absent from its view. This is the §4.3 interposition fd-handoff pointed at the display, with
no Wayland parser anywhere in the trusted path.

## Stability commitment

**Internal-stable** (per [`02-0-overview.md`](02-0-overview.md)). The `compositor-broker` argv contract and
the per-connection runtime-dir layout are coordinated within a release and carry no external commitment.
The **workload-facing** surface — the `[[provides]]`/`[[consumes]]` grammar, the `[[unix.allow]]` host leg,
the `[[fs.dev.passthrough]]` render-node grant, and `[fs.tmp]` — is the *policy schema*, **stable** and
specified in [`02-2-config-schema.md`](02-2-config-schema.md). A third party writes policy against those
grants; nothing outside Project Kennel writes the broker's wire.

## The compositor-broker — one nested compositor per connection

The GUI-service kennel runs no standing compositor. Its workload is
[`compositor-broker`](../../src/crates/kennel-facade/src/bin/compositor-broker.rs)
(`compositor-broker <listen-socket> <compositor> [compositor-args…]`), which:

1. **listens** on the kennel-to-kennel socket — the `[[provides]]` endpoint (a stable listening socket,
   always available to `accept`, so the mesh broker's connect to it always yields a real fd);
2. on each accepted connection, **spawns a fresh** nested compositor with a private `XDG_RUNTIME_DIR`
   (`/tmp/compositor-broker/<n>`), so that compositor's auto-named `wayland-N` display socket sits at a
   known, unique path — concurrent connections never collide;
3. waits for that display socket to appear, **connects** to it, and **`splice_with_fds`-relays** the
   accepted connection into it (the app's Wayland traffic, fds and all);
4. when the relay returns — the app disconnected, the compositor dropped the client and closed the socket —
   **kills that compositor**, folding its window, and removes the runtime dir.

The broker is compositor-agnostic: the compositor command is its argv, and the only convention it relies on
is the wlroots/libwayland one of naming the display socket `wayland-N` inside `XDG_RUNTIME_DIR`. Backend
selection (e.g. `WLR_BACKENDS=wayland`) and the host-leg `WAYLAND_DISPLAY` are inherited from the kennel's
policy env; the broker overrides only the per-connection runtime dir. The compositor's *own* exit behaviour
is irrelevant — cage exits with its launched child and has no exit-on-last-client mode, so the broker, not
the compositor, owns the kill. The window's life is exactly the connection's; the GUI-service kennel keeps
standing for the next connect.

## The two legs — both AF_UNIX brokered connect

Both legs ride [`facade-afunix`](../../src/crates/kennel-facade/src/bin/facade-afunix.rs) (the §7.6
brokered connect), and both forward fds:

- **Inner-compositor → host (eager).** The GUI-service kennel declares a `[[unix.allow]]` for the host
  Wayland socket (`real = /run/user/<uid>/wayland-<n>`, a shim path, `env = WAYLAND_DISPLAY`). The nested
  compositor opens the shim; `kenneld` brokers each connect to the host compositor. The shim names the
  *facade*, not the host — the host socket's own pathname is absent from the view. "Eager" because the host
  compositor is always up, so the connect succeeds the moment the compositor starts.
- **App → inner-compositor (lazy, socket-activated).** The app kennel declares a `[[consumes]]` for the GUI
  capability with an `at` socket bound to `WAYLAND_DISPLAY`. The app's connect drives mesh activation
  (§7.13.4): `kenneld` brings up the GUI-service kennel (if not already up) and connects the app to the
  broker's listening socket, which accepts and spawns that app's dedicated compositor.

## The fd-forwarding relay

Wayland passes fds — the keymap, shm pools, dmabuf buffers — as `SCM_RIGHTS` ancillary data. A byte-only
copy drops them (`file descriptor expected` → a dead client), so the relay on both legs is
[`kennel_lib_scm::splice::splice_with_fds`](../../src/crates/kennel-lib-scm/src/splice.rs): the
fd-forwarding sibling of the byte-only `splice`, AF_UNIX-only, forwarding bytes and fds together in order
and **never parsing the protocol** — it stays a transport, not an interposer. `facade-afunix` and
`compositor-broker` share the one copy. The relay is the only fd-passing surface either binary touches; the
single line of `unsafe` it rests on (adopting a `recvmsg`'d raw fd into an `OwnedFd`, with no safe `std`
equivalent) is isolated in `kennel-lib-scm`, which both binaries `#![forbid(unsafe_code)]` against.

## `/dev/shm` — the POSIX-shm requirement

wlroots allocates client buffers with `shm_open`, which is POSIX `/dev/shm`; absent from the minimal `/dev`
it is `ENOENT` and the compositor has no buffers. Each kennel with a private tmpfs (`[fs.tmp].private`)
therefore gets a private `/dev/shm` tmpfs, sealed in
[`kennel-lib-spawn`](../../src/crates/kennel-lib-spawn/src/lib.rs) `seal_view_tail` (beside `/tmp`)
with the matching `write_access()` Landlock grant in
[`plan.rs`](../../src/crates/kennel-lib-spawn/src/plan.rs) `Plan::from_policy`. Ephemeral, per-kennel, no
leak — the same shape as `/tmp`, and a default many graphical applications need (Chromium among them).

## The GUI-service kennel's policy surface

The GUI-service kennel is an ordinary confined kennel whose grants are the worked instance of the
service-kennel multi-leg exemption (§7.13.5 / §7.14.10):

- `[workload].argv = ["…/compositor-broker", "<listen>", "<compositor>", …]` and `exec.allow` for the
  broker, the compositor, and `/bin/sh`;
- `[[provides]]` the GUI capability (`org.projectkennel.wayland`, the reserved name only an operator-signed
  reserved-name kennel may provide, §7.13) with `endpoint = <listen>`;
- `[[unix.allow]]` for the host Wayland leg, with the required `reason` that `kennel policy risks` surfaces
  as the one bounded host-reach (§7.14.6);
- `[[fs.dev.passthrough]]` for `/dev/dri/renderD128` (the GL renderer + gbm allocator), tagged with its
  exposure threat;
- `[env.set]` for the compositor backend (`WLR_BACKENDS = "wayland"`) and `XDG_RUNTIME_DIR`.

The consuming app kennel declares only `[[consumes]]` the capability with its `at`/`WAYLAND_DISPLAY` — it
holds no display leg, no host reach, and no GPU grant; it has a display server, and that display server is
the GUI-service kennel's.

## Not built

The display leg is built; the rest of §7.14 is designed, not built:

- the **interactive file broker** (§7.14.7) — one consented file → one fd;
- **screenshot / open-URL / notification** brokers (§7.14.8) — though notifications already have a path via
  the D-Bus facade (§7.7);
- a **mediated clipboard / drag-and-drop** bridge (§7.14.9) — isolated by default until deliberately
  granted.
