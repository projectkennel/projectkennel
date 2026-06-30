# Generated policy schema

`policy.toml.schema` is a [JSON Schema](https://json-schema.org/) (draft-07) for a
Project Kennel **authored policy** (`policy.toml`: a template, fragment, or leaf). Host
editors read it for completion, hover documentation, and inline validation — see
[`editors/vscode`](../editors/vscode).

**It is generated — do not edit by hand.** It is emitted by the `gen-schema` tool
**directly from the `kennel-lib-compile` source structs** via `#[derive(SchemaType)]` — a
pure export of the parser, with no hand-kept copy that could drift. To regenerate after a
struct change:

```sh
cargo run -p gen-schema -- --out schema/policy.toml.schema
```

Because the schema is *derived* from the parser structs, it cannot describe a field the
parser lacks or omit one it has — drift is structurally impossible, not test-guarded.
`kennel-lib-compile`'s `tests/schema_parser_crosscheck.rs` asserts that regenerating is
**idempotent** (this committed file equals a fresh regen) and that every in-tree template
parses with the real parser. CI also re-runs `gen-schema` and fails on any diff against
this committed file.
