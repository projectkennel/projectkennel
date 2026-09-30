# Vendored-crate patches

Project Kennel vendors every dependency as a byte-exact `.crate` under `src/vendor/`
(CODING-STANDARDS.md §5.5). The standing rule is that a vendored crate is identical
to the upstream release it names — a post-audit registry compromise cannot change
our build, because the on-disk `.crate` is authoritative and `verify-checksums.sh`
enforces it.

A patch in this directory is the **single, audited exception**: a vendored crate
whose bytes are upstream-plus-one-recorded-hunk. We carry a local patch only when
all three hold:

1. The hunk fixes a real defect reachable on our threat surface (not a feature add).
2. The standard mitigation is closed to us — e.g. the release profile is
   `panic = "abort"` (§8.5), so a reachable `panic!`/`unreachable!()` on untrusted
   input cannot be caught; it must be removed at the source.
3. The change is also submitted upstream, so the patch is temporary: it is dropped
   the moment a fixed upstream release is vendored.

Each patch is reproducible: extract the named upstream `.crate`, apply the `.patch`
at `-p1`, repackage, and the result is the vendored `.crate` recorded in
`supply-chain/CHECKSUMS.toml`. The CHECKSUMS `verified-against` entry records the
divergence and the recorded sha256 is the **patched** artifact's, not upstream's.

No patches are currently carried: every vendored `.crate` is byte-identical to the
upstream release it names.

(The one patch carried to date — `mini-sansio-dbus-5.0.1-header-field-panic.patch`,
a wire-reachable `unreachable!()` in the D-Bus header-field decoder found by the
kennel-fuzz harness — was merged upstream and shipped in mini-sansio-dbus 6.0.1;
the patch was dropped when 6.0.1 was vendored. Git history has the full record.)
