# Generated policy schema

`policy.toml.schema` is a [JSON Schema](https://json-schema.org/) (draft-07) for a
Project Kennel **authored policy** (`policy.toml`: a template, fragment, or leaf). Host
editors read it for completion, hover documentation, and inline validation — see
[`editors/vscode`](../editors/vscode).

**It is generated — do not edit by hand.** It is emitted by the `gen-schema` tool from a
data table ([`src/tools/gen-schema/src/model.rs`](../src/tools/gen-schema/src/model.rs))
that mirrors the `kennel-lib-compile` source structs. To regenerate after a schema
change:

```sh
cargo run -p gen-schema -- --out schema/policy.toml.schema
```

The table cannot silently drift from the parser: `kennel-lib-compile`'s
`tests/schema_parser_crosscheck.rs` builds a document exercising every field the schema
declares and asserts the real parser accepts it (and that the parser rejects an
undeclared field, and that every in-tree template's tables/keys are schema-declared). CI
also re-runs `gen-schema` and fails on any diff against this committed file. So a parser
field added without the matching `model.rs` entry — or a stale committed schema — fails
the build.
