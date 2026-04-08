#!/bin/bash

# Proof Audit Script for rescript-dom-mounter
# Systematically identifies where detailed proofs are needed

echo "=== PROOF AUDIT FOR rescript-dom-mounter ==="
echo ""

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if Idris2 is available for proof checking
if command -v idris2 &> /dev/null; then
    echo -e "${GREEN}✓ Idris2 found - can compile and check proofs${NC}"
    IDRIS_AVAILABLE=true
else
    echo -e "${YELLOW}⚠ Idris2 not found - will skip proof compilation checks${NC}"
    IDRIS_AVAILABLE=false
fi

echo ""
echo "=== FUNCTION INVENTORY ==="

# List all public functions that need proofs
FUNCTIONS=(
    "mount"
    "mountParsed"
    "mountString"
    "mountStringParsed"
    "mountSafe"
    "mountBatch"
    "mountWhenReady"
    "unmount"
    "remount"
    "mountWithNonce"
    "initTrustedTypes"
    "safetyDiagnostics"
)

echo "Public functions requiring proofs:"
for func in "${FUNCTIONS[@]}"; do
    echo "  - $func"
done

echo ""
echo "=== CURRENT PROOF COVERAGE ==="

# Check what proofs currently exist
PROOF_DIR="/var/mnt/eclipse/repos/rescript-dom-mounter/verification/proofs/idris2"

if [ -d "$PROOF_DIR" ]; then
    echo -e "${GREEN}✓ Proof directory exists: $PROOF_DIR${NC}"
    
    # List existing proof files
    echo "Existing proof files:"
    find "$PROOF_DIR" -name "*.idr" | while read file; do
        echo "  - ${file#$PROOF_DIR/}"
    done
    
    # Check if main proof file exists
    if [ -f "$PROOF_DIR/SafeDOMProofs.idr" ]; then
        echo -e "${GREEN}✓ Main proof file exists${NC}"
        
        # Count proof functions
        PROOF_COUNT=$(grep -c "^public export" "$PROOF_DIR/SafeDOMProofs.idr" || echo "0")
        echo "  Found $PROOF_COUNT exported proof functions"
        
        # Check for certificate definitions
        CERT_COUNT=$(grep -c "Cert\|cert" "$PROOF_DIR/SafeDOMProofs.idr" || echo "0")
        echo "  Found $CERT_COUNT certificate-related definitions"
    else
        echo -e "${RED}✗ Main proof file missing${NC}"
    fi
else
    echo -e "${RED}✗ Proof directory missing${NC}"
    echo "Create it with: mkdir -p $PROOF_DIR"
fi

echo ""
echo "=== PROOF GAP ANALYSIS ==="

# Analyze what's missing
MISSING_PROOFS=()

# Check for function-level proofs
for func in "${FUNCTIONS[@]}"; do
    if ! grep -q "${func}FunctionProof\|${func}SafetyProof" "$PROOF_DIR/SafeDOMProofs.idr" 2>/dev/null; then
        MISSING_PROOFS+=("Function-level proof for $func")
    fi
done

# Check for sanitisation proofs
if ! grep -q "regexBlocksScriptTags\|regexBlocksEventHandlers\|regexBlocksDangerousURLs" "$PROOF_DIR/SafeDOMProofs.idr" 2>/dev/null; then
    MISSING_PROOFS+=("Sanitisation effectiveness proofs")
fi

# Check for tag nesting proofs
if ! grep -q "stackValidatorSound\|stackValidatorComplete" "$PROOF_DIR/SafeDOMProofs.idr" 2>/dev/null; then
    MISSING_PROOFS+=("Tag nesting correctness proofs")
fi

# Check for defence-in-depth proofs
if ! grep -q "defenceInDepthRedundancy\|trustedTypesBackup" "$PROOF_DIR/SafeDOMProofs.idr" 2>/dev/null; then
    MISSING_PROOFS+=("Defence-in-depth redundancy proofs")
fi

# Check for atomicity proofs
if ! grep -q "batchOperationsAtomic\|remountAtomic" "$PROOF_DIR/SafeDOMProofs.idr" 2>/dev/null; then
    MISSING_PROOFS+=("Atomicity proofs for batch operations")
fi

if [ ${#MISSING_PROOFS[@]} -eq 0 ]; then
    echo -e "${GREEN}✓ No obvious proof gaps detected${NC}"
else
    echo -e "${YELLOW}Missing proofs (${#MISSING_PROOFS[@]} items):${NC}"
    for gap in "${MISSING_PROOFS[@]}"; do
        echo "  - $gap"
    done
fi

echo ""
echo "=== PROOF QUALITY CHECKS ==="

if [ "$IDRIS_AVAILABLE" = true ] && [ -f "$PROOF_DIR/SafeDOMProofs.idr" ]; then
    echo "Checking proof compilation..."
    
    # Try to compile the proofs
    cd "$PROOF_DIR"
    if idris2 --check "SafeDOMProofs.idr" 2>&1; then
        echo -e "${GREEN}✓ Proofs compile successfully${NC}"
    else
        echo -e "${RED}✗ Proof compilation failed${NC}"
        echo "Compilation output:"
        idris2 --check "SafeDOMProofs.idr" 2>&1 | head -20
    fi
    cd - > /dev/null
else
    echo -e "${YELLOW}⚠ Skipping compilation check (Idris2 not available)${NC}"
fi

echo ""
echo "=== PRIORITIZATION RECOMMENDATIONS ==="

echo "High Priority (Security Critical):"
echo "  1. Function-level proofs for mount, mountParsed, mountString"
echo "  2. Sanitisation effectiveness proofs (XSS prevention)"
echo "  3. Tag nesting correctness proofs"

echo ""
echo "Medium Priority (Defence-in-Depth):"
echo "  4. Defence-in-depth redundancy proofs"
echo "  5. Atomicity proofs for batch operations"

echo ""
echo "Low Priority (Completeness):"
echo "  6. Proofs for utility functions (unmount, remount)"
echo "  7. Proofs for diagnostic functions"

echo ""
echo "=== AUDIT COMPLETE ==="

if [ ${#MISSING_PROOFS[@]} -gt 0 ]; then
    echo -e "${YELLOW}Action Required: ${#MISSING_PROOFS[@]} proof gaps identified${NC}"
    echo "See PROOF-AUDIT.md for detailed implementation guidance"
else
    echo -e "${GREEN}All proof requirements appear to be met${NC}"
fi