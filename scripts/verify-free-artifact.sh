#!/bin/bash
# verify-free-artifact.sh
# Verifies that a free release artifact contains only free-tier control packs.
# Run this after packaging to ensure no paid content leaks into public releases.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_DIR="${1:-$SCRIPT_DIR/../release/control-sets}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo "=== Free Artifact Verification ==="
echo "Checking: $ARTIFACT_DIR"
echo ""

if [[ ! -d "$ARTIFACT_DIR" ]]; then
    echo -e "${RED}ERROR: Directory not found: $ARTIFACT_DIR${NC}"
    exit 1
fi

ERRORS=0
FREE_COUNT=0
TOTAL_COUNT=0

echo "--- Scanning for tier: paid/enterprise in any file ---"
if grep -l "tier: paid\|tier: enterprise" "$ARTIFACT_DIR"/*.yaml "$ARTIFACT_DIR"/*.yml 2>/dev/null; then
    echo -e "${RED}ERROR: Found paid tier metadata in artifact!${NC}"
    ((ERRORS += 1))
else
    echo -e "${GREEN}OK${NC} No paid tier metadata found in artifact"
fi

echo ""
echo "--- Verifying all included packs are tier: free ---"

for yaml_file in "$ARTIFACT_DIR"/*.yaml "$ARTIFACT_DIR"/*.yml; do
    [[ -e "$yaml_file" ]] || continue
    ((TOTAL_COUNT += 1))

    filename=$(basename "$yaml_file")

    # Extract tier from metadata section only (before "controls:" line)
    tier=$(sed -n '/^metadata:/,/^controls:/p' "$yaml_file" | grep -E "^\s+tier:" | head -1 | awk '{print $2}' | tr -d '"' | tr -d "'" | tr '[:upper:]' '[:lower:]')

    if [[ "$tier" == "free" ]]; then
        signature_b64=$(sed -n '/^metadata:/,/^controls:/p' "$yaml_file" | grep -E "^[[:space:]]+signature_b64:" | head -1 | sed -E 's/^[[:space:]]*signature_b64:[[:space:]]*//' | tr -d '"'"'"'')
        if [[ -z "$signature_b64" ]]; then
            echo -e "${RED}ERROR${NC} $filename (tier: free) has no signature_b64 -- a release binary with require_signatures: true cannot execute it"
            ((ERRORS += 1))
        else
            echo -e "${GREEN}OK${NC} $filename (tier: free, signed)"
            ((FREE_COUNT += 1))
        fi
    elif [[ -z "$tier" ]]; then
        echo -e "${RED}ERROR${NC} $filename has no tier metadata"
        ((ERRORS += 1))
    else
        echo -e "${RED}ERROR${NC} $filename is tier: $tier (expected: free)"
        ((ERRORS += 1))
    fi
done

echo ""
echo "--- Artifact Summary ---"
echo "Total packs: $TOTAL_COUNT"
echo "Free packs:  $FREE_COUNT"

if [[ $TOTAL_COUNT -eq 0 ]]; then
    echo -e "${RED}ERROR: No control packs found in artifact (fail-closed)${NC}"
    ((ERRORS += 1))
fi

echo ""
echo "=== Verification Result ==="
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}PASS: Free artifact is valid (all $FREE_COUNT packs are tier: free)${NC}"
    exit 0
else
    echo -e "${RED}FAIL: $ERRORS error(s) found${NC}"
    exit 1
fi
