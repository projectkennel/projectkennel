# Man pages

These groff `man(7)` pages are **generated and committed**. Do not edit the
`*.1` / `*.5` / `*.8` files here by hand — they are overwritten on the next
regeneration and a CI check (`git diff --exit-code man/`) will fail.

## Editing

The single source is the data table in
[`src/tools/gen-man/src/pages.rs`](../src/tools/gen-man/src/pages.rs). Edit the
relevant `Page` (or the `helper(...)` entry for a terse helper page), then
regenerate:

```sh
cargo run -p gen-man -- --out man
```

`gen-man` is a std-only, build-only tool (not shipped). It also accepts
`--list` and a single `NAME.SECTION` argument (printing one page to stdout).

## What stays in sync, and how

The `kennel(1)` and `kennel-policy(1)` command synopses are kept byte-identical
to the CLI's own `COMMANDS` / `POLICY_VERBS` tables. `gen-man` holds a checked
copy (`SYNC_COMMANDS` / `SYNC_POLICY`), and the `man_pages_in_sync_with_cli_tables`
test in `kenneld`'s `kennel` binary asserts the two match — so a CLI change that
isn't mirrored into the page data fails the build before the pages can drift.

## The pages

| Page | Section | Subject |
|---|---|---|
| `kennel` | 1 | the CLI |
| `kennel-policy` | 1 | the `kennel policy` authoring sub-verbs |
| `kenneld` | 8 | the supervisor daemon |
| `policy.toml` | 5 | the policy file format |
| `system.toml` | 5 | deployment config (integrity-sensitive) |
| `config.toml` | 5 | user CLI config |
| `subkennel` | 5 | the `/etc/kennel/subkennel` allocation file |
| `host-netproxy`, `host-inetd`, `facade-socks5`, `facade-client`, `facade-afunix`, `facade-ssh`, `kennel-akc`, `kennel-bin-init`, `kennel-privhelper` | 8 | the internal helper binaries kenneld forks (terse — each notes it is not invoked directly) |

`install.sh` installs every `man/*.<section>` into `$mandir/man<section>`
(default `/usr/share/man`, override with `--mandir`).
