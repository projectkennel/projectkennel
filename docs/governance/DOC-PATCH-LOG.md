# Design / Architecture patch log

`docs/design/**` and `docs/architecture/**` are **frozen** pending a clean-sheet rewrite.
While the freeze is in effect, do not edit those trees. Any change that would normally land
as an as-built update to a design or architecture chapter is recorded here instead, to be
ingested into the rewrite.

Each entry: the **target** (chapter / §, best guess — the rewrite may restructure), the
**as-built fact** the docs should reflect (or the stale claim to drop), the **why**, and the
**source** (PR / commit). Newest first.

---

<!-- Template:
## YYYY-MM-DD — <short title>
- **Target:** docs/<design|architecture>/<chapter>.md §<x> (approx)
- **Change:** <what is now true as-built / what is stale and should be dropped>
- **Why:** <one line>
- **Source:** #<PR> / <commit>
-->

## 2026-06-26 — W1: connector-shape mesh bus + dbus-broker@v1 standing service

- **Target:** docs/design §7.7 (D-Bus mediation), §7.13.4a (connector shapes / service catalogue),
  02-4-binder.md (node 0); docs/architecture 01-process-model / 02-8-internal-api / 03-crate-decomposition.
- **Change (as-built to capture in the rewrite):**
  - **binder-connector mesh bus** — `kenneld` runs a `MeshBus` controller as node 0 of a shared binder
    bus; providers acquire a node handle via `ADD_SERVICE` and consumers receive it via `SVC_CONNECT`.
    New binder primitive: `Reply::Handle(u32)` / `reply_with_handle()` (kennel-lib-binder).
  - **dbus-broker@v1** — a new standing **service kennel** (`templates/dbus-broker/`, new crate
    `kennel-dbus-broker`) is the intended replacement for the per-consumer `host-dbus` delegate:
    `kenneld` pushes per-consumer D-Bus filter sets over the mesh and relays frames for mediation.
    New node-0 verbs (kennel-lib-binder `service.rs`): `REGISTER_CONSUMER`, `UNREGISTER_CONSUMER`,
    `RELAY_FRAME`. `DbusRelay` routes to the broker if a transactor is configured, else falls back to
    the legacy `host-dbus` delegate.
  - **dbus-name / binder-connector handoff** (`svc_connect_handoff`): `Shape::DbusName` replies `OK`
    (filter set already registered at startup); `Shape::BinderConnector` replies `UNAVAILABLE`
    (connector transactions happen directly on the mesh bus).
  - **MeshBusGuard** — RAII guard that decrements participant refcounts and unmounts the per-mesh
    binderfs on the last participant's exit (both normal teardown and bring-up failure).
  - **⚠ NOT-yet-built:** the broker's **frame relay is a stub** — `handle_relay` registers the filter
    and the wire path but does NOT parse/filter/forward frames to the real D-Bus bus. D-Bus mediation
    currently flows through the legacy `host-dbus` delegate; the broker is dormant unless selected. The
    rewrite should describe the broker as the *designed* mediation path with the relay as a known gap.
- **Why:** docs/design + docs/architecture are frozen; W1 ships this architecture with no doc updates.
- **Source:** PR (W1 integration) — branch feat/w1-integration; agent branch feat/w1-connector-shapes.
