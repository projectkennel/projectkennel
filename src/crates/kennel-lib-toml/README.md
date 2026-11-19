# kennel-lib-toml

Project Kennel's in-tree TOML (de)serializer for Serde: [basic-toml] 0.1.10 by Alex Crichton
and David Tolnay, brought in as a first-party crate when upstream was archived
(RUSTSEC-2026-0374, #221). The first commit imported upstream's `src/`, `tests/`, licences and
README byte-for-byte from the audited vendored `.crate`; every later change is in git history.

Licensed, as upstream, under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

[basic-toml]: https://github.com/dtolnay/basic-toml
