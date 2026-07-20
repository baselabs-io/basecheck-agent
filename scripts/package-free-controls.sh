#!/bin/bash
# package-free-controls.sh
# Copies free-tier control packs to the release directory.
# Fails if public source contains paid or enterprise YAML.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTROL_SETS_DIR="$REPO_ROOT/control-sets"
OUTPUT_DIR="${1:-$REPO_ROOT/release/control-sets}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo "=== Free Control Pack Packaging ==="
echo "Source: $CONTROL_SETS_DIR"
echo "Output: $OUTPUT_DIR"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Clear existing control sets in output
rm -f "$OUTPUT_DIR"/*.yaml "$OUTPUT_DIR"/*.yml 2>/dev/null || true

FREE_COUNT=0
ERRORS=0

for yaml_file in "$CONTROL_SETS_DIR"/*.yaml "$CONTROL_SETS_DIR"/*.yml; do
    # Skip if no files match
    [[ -e "$yaml_file" ]] || continue

    # Skip backup files
    [[ "$yaml_file" == *.bak ]] && continue

    filename=$(basename "$yaml_file")

    # Extract tier from metadata section only (before "controls:" line)
    # This avoids false matches from tier values inside control definitions
    tier=$(sed -n '/^metadata:/,/^controls:/p' "$yaml_file" | grep -E "^\s+tier:" | head -1 | awk '{print $2}' | tr -d '"' | tr -d "'")

    if [[ -z "$tier" ]]; then
        echo -e "${RED}ERROR${NC} $filename has no tier metadata (fail-closed)"
        ((ERRORS += 1))
        continue
    fi

    # Normalize tier to lowercase
    tier_lower=$(echo "$tier" | tr '[:upper:]' '[:lower:]')

    case "$tier_lower" in
        free)
            # Fail closed: a pack shipped without a signature (or with an
            # empty one) cannot be loaded by a packaged binary whose default
            # config has security.require_signatures: true, so catch that
            # here rather than shipping a release the standalone package
            # can't actually run against.
            signature_b64=$(sed -n '/^metadata:/,/^controls:/p' "$yaml_file" | grep -E "^[[:space:]]+signature_b64:" | head -1 | sed -E 's/^[[:space:]]*signature_b64:[[:space:]]*//' | tr -d '"'"'"'')
            if [[ -z "$signature_b64" ]]; then
                echo -e "${RED}ERROR${NC} $filename has no signature_b64 (fail-closed) -- run scripts/sign-control-pack.sh"
                ((ERRORS += 1))
                continue
            fi

            cp "$yaml_file" "$OUTPUT_DIR/"
            echo -e "${GREEN}INCLUDE${NC} $filename (tier: free, signed)"
            ((FREE_COUNT += 1))
            ;;
        paid|enterprise)
            echo -e "${RED}ERROR${NC} $filename is $tier_lower content in public source"
            ((ERRORS += 1))
            ;;
        *)
            echo -e "${RED}ERROR${NC} $filename has unknown tier: $tier_lower (fail-closed)"
            ((ERRORS += 1))
            ;;
    esac
done

echo ""
echo "=== Summary ==="
echo -e "Included (free):  ${GREEN}$FREE_COUNT${NC}"
echo -e "Errors:           ${RED}$ERRORS${NC}"
echo ""

# Fail on any tier errors
if [[ $ERRORS -gt 0 ]]; then
    echo -e "${RED}FAIL: $ERRORS control pack(s) have missing or unknown tier${NC}"
    exit 1
fi

# Verify no paid packs leaked
if grep -l "tier: paid\|tier: enterprise" "$OUTPUT_DIR"/*.yaml "$OUTPUT_DIR"/*.yml 2>/dev/null; then
    echo -e "${RED}ERROR: Paid packs found in output directory!${NC}"
    exit 1
fi

echo -e "${GREEN}Free artifact packaging complete.${NC}"
echo "Output: $OUTPUT_DIR"
