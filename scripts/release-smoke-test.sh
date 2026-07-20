#!/bin/bash
# release-smoke-test.sh
# Runs the actual packaged binary against the actual packaged configuration
# and control sets, end to end, against a throwaway local SQLite database.
# This exists because a packaged release can build fine, pass unit tests,
# and even pass `--version`, while still being unusable out of the box if
# the bundled control packs aren't signed with the key embedded in
# config.yaml.example (security.require_signatures defaults to true / fail
# closed) -- exactly the gap this test is meant to catch before it ships.
#
# Usage: scripts/release-smoke-test.sh <package-dir> [binary-name]
#
# <package-dir> must contain the packaged binary, config.yaml.example, and a
# control-sets/ directory (i.e. the staged release directory, post
# package-free-controls.sh).

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PKG_DIR="${1:?usage: release-smoke-test.sh <package-dir> [binary-name]}"
BINARY_NAME="${2:-basecheck-agent}"

PKG_DIR="$(cd "$PKG_DIR" && pwd)"
BINARY="$PKG_DIR/$BINARY_NAME"

if [[ ! -x "$BINARY" ]]; then
    echo -e "${RED}ERROR: binary not found or not executable: $BINARY${NC}"
    exit 1
fi

if [[ ! -f "$PKG_DIR/config.yaml.example" ]]; then
    echo -e "${RED}ERROR: config.yaml.example not found in $PKG_DIR${NC}"
    exit 1
fi

if [[ ! -d "$PKG_DIR/control-sets" ]]; then
    echo -e "${RED}ERROR: control-sets/ not found in $PKG_DIR${NC}"
    exit 1
fi

WORK_DIR="$(mktemp -d "$PKG_DIR/.release-smoke.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

# Pull the public key straight out of the packaged config.yaml.example so
# this test proves the actual shipped key/signature pairing works, not a
# hand-copied one.
PUBLIC_KEY="$(grep -E "^[[:space:]]*public_key:" "$PKG_DIR/config.yaml.example" | head -1 | sed -E 's/^[[:space:]]*public_key:[[:space:]]*//' | tr -d '"'"'"'')"

if [[ -z "$PUBLIC_KEY" ]]; then
    echo -e "${RED}ERROR: config.yaml.example has no security.public_key set${NC}"
    exit 1
fi

CONFIG_PATH="$WORK_DIR/config.yaml"
OUTPUT_PATH="$WORK_DIR/output.json"

# The SQLite driver opens in mode=ro (read-only), so create a valid database
# first. A zero-byte file is not a portable read-only SQLite fixture.
go run ./examples/siem-demo/fixture -path "$WORK_DIR/smoke.db"

cat > "$CONFIG_PATH" <<EOF
agent:
  name: "release-smoke-test"
  token_file: ".agent_token"

control_sets:
  source: "local"
  local_path: "../control-sets"
  cache_path: "cache"

databases:
  - name: "smoke-sqlite"
    type: "sqlite"
    database: "smoke.db"

output:
  mode: "file"
  file:
    path: "output.json"
    format: "json"

security:
  require_signatures: true
  public_key: "$PUBLIC_KEY"
EOF

echo "=== Release Smoke Test ==="
echo "Package: $PKG_DIR"
echo "Binary:  $BINARY"
echo ""

if ! ( cd "$WORK_DIR" && "$BINARY" --config "$CONFIG_PATH" ); then
    echo -e "${RED}FAIL: packaged binary exited non-zero against packaged config + control sets${NC}"
    exit 1
fi

if [[ ! -s "$OUTPUT_PATH" ]]; then
    echo -e "${RED}FAIL: no output produced at $OUTPUT_PATH -- control sets likely failed to load/verify${NC}"
    exit 1
fi

echo -e "${GREEN}PASS: packaged binary ran the packaged (signed) control sets against a live database and produced output${NC}"
