# keys/

The project's **public** signing keys — `<key_id>.pub`, each the base64 of a
32-byte Ed25519 public key. These verify the signed reference templates
(`templates/*/policy.toml` carry a matching `[signature]`) and signed release
artefacts. The register, holders, and rotation policy are in
[MAINTAINERS.md](../docs/governance/MAINTAINERS.md).

`install.sh` deploys every `*.pub` here into the **vendor** trust store at
`/usr/lib/kennel/keys/`: the project's own key is vendor-provenance, the authority
for the built-in `org.projectkennel.*` reserved namespace, so it belongs in the
vendor layer rather than the admin one. An org or customer adds their own `*.pub`
under `/etc/kennel/keys/`; the CLI also reads `~/.config/kennel/keys/`.

**Private seeds never live here.** A signing seed (`<key_id>.key`, base64 of the
Ed25519 seed) stays only in its holder's `~/.config/kennel/keys/`, mode `0600`.
The repo carries public material only; `.gitignore` blocks `*.key` as a backstop.

Verify a template against this store:

```sh
kennel validate templates/ai-coding-strict/policy.toml \
    --template-dir templates --require-signed --trust-dir keys
```
