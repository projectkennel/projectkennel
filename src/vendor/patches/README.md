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

## mini-sansio-dbus-5.0.1-header-field-panic.patch

**Crate:** `mini-sansio-dbus` 5.0.1 (the D-Bus wire marshalling for `facade-dbus`, §7.7).

**Defect:** `incoming/header_fields.rs` decodes each D-Bus header field by mapping its
code byte through `HeaderFieldCode::from`, where any byte outside `1..=9` becomes
`HeaderFieldCode::Invalid`. The match arm for `Invalid` is `unreachable!()` — but it
is reachable: the code byte comes straight off the wire. A workload's in-kennel bus
client sends a method call with one bogus header-field code and the decoder panics.
The crate author already wrote the graceful path — the *caller* (`HeaderFields::cut`)
has an `HeaderField::Invalid => Err(MalformedHeaderField)` arm — but it is dead code,
because `HeaderField::cut` panics before returning.

**Why this surface matters:** `facade-dbus` runs in-kennel and decodes fully
workload-controlled bytes. Under `panic = "abort"` a panic there aborts the facade
process — a one-byte denial of service against the workload's own D-Bus access, and
exactly the class of robustness bug the §10.6 fuzz target exists to catch. The
`kennel-fuzz` harness (`dbus_incoming_never_panics_on_mutated_messages`) found this
before `facade-dbus` was built.

**Fix:** return the error the caller already expects instead of panicking:

```rust
-            HeaderFieldCode::Invalid => unreachable!(),
+            HeaderFieldCode::Invalid => Err(DBusError::MalformedHeaderField),
```

(The vendored hunk carries an explanatory comment; the upstream submission is the
bare one-line change.)

**Upstream:** reported to `github.com/iliabylich/mini-sansio-dbus` as the same
one-line change. Drop this patch and restore byte-identical vendoring when a release
carrying the fix is vendored.
