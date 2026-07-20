#!/bin/bash
# sign-control-pack.sh
# Signs every control-set YAML in control-sets/ (in place) with the given RSA
# private key, using the same canonical payload / RSA-PKCS1v15-SHA256 scheme
# the agent verifies against (see pkg/controlset/signing.go). Run this any
# time a bundled control pack's evidence-capture SQL, procedures, or
# compatibility metadata changes -- the old signature will fail verification
# otherwise, and the agent fails closed on an invalid signature by default.
#
# Usage: scripts/sign-control-pack.sh [key-path] [control-sets-dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KEY_PATH="${1:-$REPO_ROOT/.signing/dev-private-key.pem}"
CONTROL_SETS_DIR="${2:-$REPO_ROOT/control-sets}"

if [[ ! -f "$KEY_PATH" ]]; then
    echo "Signing key not found: $KEY_PATH"
    echo "Run scripts/generate-signing-key.sh first, or pass a different key path as \$1."
    exit 1
fi

cd "$REPO_ROOT"

SIGNED_COUNT=0
for yaml_file in "$CONTROL_SETS_DIR"/*.yaml "$CONTROL_SETS_DIR"/*.yml; do
    [[ -e "$yaml_file" ]] || continue
    [[ "$yaml_file" == *.bak ]] && continue

    echo "Signing $(basename "$yaml_file")..."
    go run ./cmd/sign-controlset -key "$KEY_PATH" -in "$yaml_file"
    ((SIGNED_COUNT += 1))
done

echo ""
echo "Signed $SIGNED_COUNT control pack(s)."
echo ""
echo "=== Public key (base64 PKIX DER) for config.yaml security.public_key ==="
openssl rsa -in "$KEY_PATH" -pubout -outform DER 2>/dev/null | base64 | tr -d '\n'
echo ""
