# gui-mesh — the confined-GUI display path, end to end (§7.14)

The confined-GUI display leg on real kennels, headless. A self-driving case (`run.sh`):
the mesh needs a **provider** and a **consumer** plus enablement, and the provider is the
GUI-service kennel, so the hook owns the flow.

- **provider.toml** — an ondemand GUI-service kennel whose workload is `compositor-broker`:
  it listens on its `[[provides]]` endpoint and, per accepted connection, spawns a fresh
  nested compositor and relays the consumer into it.
- **consumer.toml** — a graphical app kennel that `[[consumes]]` the capability at an `at`
  socket (where a real app points `WAYLAND_DISPLAY`); its workload connects and exits 0 iff
  it reads `pong` back through the broker→compositor relay.
- **run.sh** — compiles + signs the provider, enables it ondemand, `daemon-reload`s the
  catalogue, then runs the consumer. The consumer's exit is the verdict.

Proves: `at` materialisation → the af-unix facade → CONNECT_AFUNIX dispatch to the broker →
catalogue resolve → ondemand socket-activation (W6) → reach the provider's endpoint through
`/proc/<pid>/root` → **`compositor-broker` accepts → spawns a compositor with a private
`XDG_RUNTIME_DIR` → relays the connection into its `wayland-0`** → round-trip → the broker
kills that compositor when the connection closes.

Headless by design: the **broker and the mesh** are what this case tests, not the renderer.
The "compositor" is `facade-mesh-probe serve-display` — a stand-in that binds the
broker-assigned `$XDG_RUNTIME_DIR/wayland-0` and echoes, with no GPU or display (staged via
`--with-test-bins`; never shipped). A real GUI kennel swaps in `cage` and adds the
host-Wayland `[[unix.allow]]` leg + the `/dev/dri` passthrough (see `02-11-confined-gui.md`);
that renderer leg is proven by hand on a live desktop, not in this headless case.
