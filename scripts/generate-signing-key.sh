#!/bin/bash
# generate-signing-key.sh
# Generates the RSA keypair used to sign bundled control-set YAML files
# (see scripts/sign-control-pack.sh). The private key stays in the
# gitignored .signing/ directory; the public key is what gets embedded in
# config.yaml.example so a packaged binary can verify the packs it ships
# with.
#
# For a real production release, generate the key in CI (or an HSM) and
# store the private key as a CI secret instead of this repo-local file --
# see .signing/README.md.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SIGNING_DIR="$REPO_ROOT/.signing"
KEY_PATH="$SIGNING_DIR/dev-private-key.pem"

if [[ -e "$KEY_PATH" ]]; then
    echo "Refusing to overwrite existing key: $KEY_PATH"
    echo "Delete it first if you really want to generate a new one (this invalidates all existing signatures)."
    exit 1
fi

mkdir -p "$SIGNING_DIR"
openssl genrsa -out "$KEY_PATH" 2048
chmod 600 "$KEY_PATH"

echo "Generated dev signing key: $KEY_PATH"
echo "Next: run scripts/sign-control-pack.sh to sign the bundled control-sets/*.yaml with it."
