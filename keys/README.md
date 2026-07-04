# keys/

The project's **public** signing keys — `<key_id>.pub`, each an OpenSSH
public-key line (`ssh-ed25519 <base64-blob> <comment>`, as `ssh-keygen` and
`kennel keygen` write; the raw-base64 legacy encoding was removed in 0.6.0).
These verify the signed reference templates (`templates/*/policy.toml` carry a
matching `[signature]`) and signed release artefacts. The register, holders,
and rotation policy are in [MAINTAINERS.md](../docs/governance/MAINTAINERS.md).

`install.sh` deploys every `*.pub` here into the **vendor** trust store at
`/usr/lib/kennel/keys/`: the project's own key is vendor-provenance, the authority
for the built-in `org.projectkennel.*` reserved namespace, so it belongs in the
vendor layer rather than the admin one. An org or customer adds their own `*.pub`
under `/etc/kennel/keys/`; the CLI also reads `~/.config/kennel/keys/`.

**Private keys never live here.** A signing key (`<key_id>`, an unencrypted
OpenSSH Ed25519 private key, no extension) stays only in its holder's
`~/.config/kennel/keys/`, mode `0600`. The repo carries public material only;
`.gitignore` blocks `*.key` as a backstop against the pre-0.6.0 legacy layout.

Verify a template against this store:

```sh
kennel validate templates/ai-coding-strict/policy.toml \
    --template-dir templates --require-signed --trust-dir keys
```
