# Control-pack signing

The bundled `control-sets/*.yaml` packs are signed. The `.signing/` directory
(gitignored -- the private key itself is never committed) holds the RSA
private key used to sign them; see `scripts/generate-signing-key.sh` and
`scripts/sign-control-pack.sh`.

The matching public key is embedded in `config.yaml.example` under
`security.public_key`, so a freshly cloned or packaged copy of the agent can
verify the bundled packs out of the box with `security.require_signatures`
left at its default (`true`, fail closed).

## This is a development key, not a production key

`.signing/dev-private-key.pem` (once generated) is a plain RSA key sitting on
disk with no access control beyond filesystem permissions. That's fine for
making the standalone/free package work correctly out of the box, and for
local development. It is **not** an appropriate way to protect a real release
signing key, because:

- Anyone who can read that directory can sign arbitrary control packs the
  agent will trust.
- There's no audit trail of who signed what, or when.
- Key rotation means regenerating and re-signing everything by hand.

## Before a real production release

Replace this with a key managed by your release infrastructure:

- Generate the release keypair in CI (or better, an HSM / cloud KMS key that
  never leaves the signing service), not on a laptop.
- Store the private key as a CI secret (or reference to the KMS key), never
  as a file in the repo or a shared drive.
- Sign release control packs as a CI step using that secret, and update
  `config.yaml.example`'s `security.public_key` (and any customer-facing
  documentation of the public key) from the same pipeline.
- Track who has permission to trigger a signing run the same way you'd
  track access to any other release-signing credential.

See `RELEASE.md`'s "Control-Pack Signing" section for what this means for the
release checklist.
