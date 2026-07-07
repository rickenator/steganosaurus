#!/bin/bash
# JPEG Robustness Test - measures BER at different quality levels

BINARY="./turtlefft"
COVER="../../test_images/emu.png"
SECRET="hello jpeg robustness test"
PASS="test"
ITER=10000
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

echo "=== JPEG Robustness Test ==="
echo "Cover: $COVER"
echo "Secret: '$SECRET'"
echo ""

# Embed once into PNG
$BINARY embed --in "$COVER" --out "$TMPDIR/stego.png" \
    --secret "$SECRET" --pass "$PASS" --pbkdf2_iter $ITER 2>/dev/null

echo "Embedding complete. Testing JPEG degradation at various quality levels..."
echo ""
printf "%-10s %-10s\n" "Quality" "Status"
echo "------------------------"

for q in 100 95 90 85 80 75 70 60 50 40 30; do
    # Create JPEG from PNG
    $BINARY embed --in "$COVER" --out "$TMPDIR/out.png" \
        --secret "$SECRET" --pass "$PASS" --pbkdf2_iter $ITER \
        --jpeg-out $q 2>/dev/null | grep -v DEBUG || true
    
    # Extract from JPEG
    result=$($BINARY extract --in "$TMPDIR/out.jpg" --pass "$PASS" --pbkdf2_iter $ITER 2>&1) || true
    
    if echo "$result" | grep -q "^$SECRET"; then
        status="PASS ✓"
    else
        status="FAIL ✗"
    fi
    
    printf "%-10s %-10s\n" "Q$q" "$status"
done

echo ""
echo "=== Test complete ==="
