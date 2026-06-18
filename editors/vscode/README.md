# Project Kennel policy — VS Code support

Completion, hover documentation, and inline validation for Project Kennel
`policy.toml` files, against the generated JSON Schema
([`schema/policy.toml.schema`](../../schema/policy.toml.schema)) — the same schema the
`kennel` compiler enforces (the schema is cross-checked against the parser in CI, so it
cannot drift).

The actual TOML language intelligence is provided by
[**Even Better TOML**](https://marketplace.visualstudio.com/items?itemName=tamasfe.even-better-toml)
(the `taplo` language server); this extension is a thin layer that points it at the
Kennel policy schema. It is declared as an `extensionDependency`, so installing this
extension pulls Even Better TOML in.

## Two ways to get it

**Editing policies inside this repository** — nothing to install but Even Better TOML.
The repo ships a [`.taplo.toml`](../../.taplo.toml) that associates every `policy.toml`
with the local generated schema. Open a policy file and you get validation immediately,
fully offline, against the working-tree schema.

**Editing policies anywhere else** — install this extension. It contributes a default
`evenBetterToml.schema.associations` entry mapping `policy.toml` (and `*.policy.toml`)
files to the published schema URL (the schema's `$id`,
`https://projectkennel.org/schema/policy.toml.schema.json`). For offline use outside the
repo, drop a `#:schema ./path/to/policy.toml.schema` directive on the first line of your
policy file, or add a local `.taplo.toml` like the one in this repo.

## Status

The schema generation, the schema↔parser cross-check, the CI no-drift gate, and the
`.taplo.toml` association are complete and verified. This packaged extension is
declarative (no extension code — it only contributes the schema association and the Even
Better TOML dependency); publishing it to the Marketplace (`vsce package` / `vsce
publish`) and the final live-editor smoke test are a release-time step, gated on the
schema URL being served (the repository is not yet public).
