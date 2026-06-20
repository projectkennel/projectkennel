# oci-substrate — boot an OCI image as a confined kennel root (§7.11)

The only policy-suite case driven by `kennel oci run` rather than `kennel run`: an `[rootfs]`
policy is the OCI substrate model, which the universal `kennel run` verb refuses by the grammar
partition. So this case ships a **`run.sh` hook** the suite driver invokes (passing the installed
`kennel`, the suite key, and a scratch dir); the hook fetches a real image, builds a store entry,
boots it, and self-checks the slice from inside, exiting 0 iff every assertion holds.

It is **self-contained** (its own `XDG_DATA_HOME` store under the scratch dir — it never touches
the operator's real image store) and **skips cleanly** (exit 77) when `skopeo` is absent or the
image pull fails offline — a missing prerequisite is reported, never a silent pass.

What it proves end to end on the real installed stack:

- an unpacked OCI image (upstream `busybox`) boots as a **layered-overlay root** (§7.11.4a) and its
  entrypoint runs — exercising the static in-kennel binaries (the launcher + facades must load in
  an alien image root) and the `kennel-etc : image : scaffold` overlay;
- the **persona uid is imposed** — the image ships a non-root `config.User` (`12345`, a uid the
  persona map does not contain), and the workload runs as the persona, not `12345` (residual C:
  `User` is read at build for the lock decision, but not honored as a runtime uid);
- **closure-lock** (§7.11.4c) is derived at `oci build` from the non-root `config.User` (the FHS
  closure) and enforced by the spawn as Landlock: `/usr` is **read-only** (a write is denied) while
  staying read+execute (the image still runs);
- the constructed **`/tmp` is writable** by the persona (the DAC chown), and **Kennel's `/etc`**
  wins by layer precedence (`resolv.conf` present).

The non-root image is the interesting one: it activates the closure-lock the all-root smoke path
leaves off. An all-root image (no derived lock, writable substrate) is the other posture and is
left to manual testing — the suite proves the lock *holds*, which is the security-load-bearing
direction.
