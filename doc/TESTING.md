# TurtleFFT Hardening Test Suite

This directory contains automated tests for validating the security hardening improvements to TurtleFFT.

## Test Files

### 1. `test_hardening.sh`
**Purpose**: Comprehensive functional testing of hardened features

**Tests**:
- Basic round-trip embed/extract
- Long message handling
- Wrong password detection
- Custom KDF iteration counts
- Experimental features (adaptive alpha, cover-dependent path)

**Usage**:
```bash
cd steganosaurus
./test_hardening.sh
```

**Expected Output**:
- ✓ Test 1: Basic round-trip (12 bytes)
- ✓ Test 2: Long message (60 bytes)
- ✓ Test 3: Wrong password detection
- ✓ Test 4: Custom iterations
- ⚠ Test 5: Experimental features (may fail)

### 2. `test_kdf_timing.sh`
**Purpose**: Validate key derivation timing meets security requirements

**Tests**:
- Default settings (600k iterations) - expects ~6s
- Original settings (200k iterations) - expects ~2s
- Minimum iterations threshold - finds ~10k for 100ms
- Wrong password timing - expects <1s fast failure

**Usage**:
```bash
cd steganosaurus
./test_kdf_timing.sh
```

**Expected Output**:
```
✓ Default (600k): ~6s (60x above requirement)
✓ Original (200k): ~2s (21x above requirement)
✓ Wrong password: ~0.13s (fast failure)
```

## Manual Testing

### Basic Embed/Extract
```bash
cd steganosaurus/build

# Generate test image
g++ -std=c++17 -O2 ../tools/gen_png.cpp -o gen_png
./gen_png

# Embed
time ./turtlefft embed --in host.png --out stego.png \
  --secret "Test message" --pass "SecurePass123"

# Extract
time ./turtlefft extract --in stego.png --pass "SecurePass123"
```

### Test with Different Iterations
```bash
# Fast (testing only - NOT secure)
./turtlefft embed --in host.png --out stego.png \
  --secret "test" --pass "test" --pbkdf2_iter 10000

# Default (production - secure)
./turtlefft embed --in host.png --out stego.png \
  --secret "test" --pass "test" --pbkdf2_iter 600000

# Very secure (slower)
./turtlefft embed --in host.png --out stego.png \
  --secret "test" --pass "test" --pbkdf2_iter 1000000
```

### Test Experimental Features
```bash
# Adaptive alpha (experimental - may fail)
./turtlefft embed --in host.png --out stego.png \
  --secret "test" --pass "test" \
  --pbkdf2_iter 50000 --adaptive_alpha 1

# Cover-dependent path (experimental - may fail)
./turtlefft embed --in host.png --out stego.png \
  --secret "test" --pass "test" \
  --pbkdf2_iter 50000 --cover_dependent_path 1
```

## Performance Benchmarks

### Expected Timing (on modern CPU)

| Operation | Iterations | Time | Notes |
|-----------|------------|------|-------|
| Embed | 600,000 | ~6.0s | KDF dominates |
| Extract | 600,000 | ~5.9s | KDF dominates |
| Wrong password | N/A | ~0.13s | Magic check fails |

### Capacity Estimates

| Image Size | Approx Capacity | Test Image |
|------------|----------------|------------|
| 256×256 | ~150 bytes | Default gen_png |
| 512×512 | ~600 bytes | Typical photo |
| 1024×1024 | ~2.4 KB | High-res image |

## Debugging

### Enable Debug Output
```bash
cd steganosaurus/build
cmake .. -DCMAKE_CXX_FLAGS="-DDEBUG=1"
cmake --build .

./turtlefft embed --in host.png --out stego.png \
  --secret "test" --pass "test"
# Shows detailed phase/magnitude information
```

### Common Issues

**Issue**: "Message too large"
```
Solution: Use larger image or shorter message
Check: Capacity estimate in error message
```

**Issue**: "Magic not found"
```
Reason: Wrong password or corrupted data
Check: Verify password matches embed
Check: Verify same parameters (iter, density, etc.)
```

**Issue**: "Auth failed"
```
Reason: Wrong password or MAC mismatch
Check: PBKDF2 iterations match
Check: Image not corrupted
```

**Issue**: Extraction hangs or crashes
```
Reason: Bit errors in header causing huge clen
Solution: Use --pbkdf2_iter to match embed
Experimental features may cause this
```

## Security Testing

### Timing Attack Resistance
```bash
# Test multiple wrong passwords
for i in {1..10}; do
  time ./turtlefft extract --in stego.png --pass "wrong$i" 2>&1
done
# Should show consistent timing for MAC failures
```

### Brute-Force Resistance
```bash
# Measure single attempt time
time ./turtlefft extract --in stego.png --pass "wrong" 2>&1

# Calculate attempts per year
# (assuming KDF failure, not magic check)
```

## Validation Checklist

Before considering hardening complete, verify:

- [ ] Basic round-trip works (test_hardening.sh)
- [ ] KDF timing >100ms (test_kdf_timing.sh)
- [ ] Constant-time MAC (manual timing test)
- [ ] Wrong password detection (test_hardening.sh)
- [ ] CodeQL security scan passes
- [ ] Documentation complete
- [ ] Build succeeds without warnings
- [ ] Parameters documented in README

## Continuous Integration

To add these tests to CI:

```yaml
# .github/workflows/test.yml
name: Hardening Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build
        run: |
          cd steganosaurus
          mkdir build && cd build
          cmake ..
          cmake --build .
      - name: Run Tests
        run: |
          cd steganosaurus
          ./test_hardening.sh
          ./test_kdf_timing.sh
```

## Troubleshooting

### Build Issues
```bash
# Clean rebuild
cd steganosaurus
rm -rf build
mkdir build && cd build
cmake ..
cmake --build .
```

### Test Image Issues
```bash
# Regenerate test image
cd steganosaurus/build
g++ -std=c++17 -O2 ../tools/gen_png.cpp -o gen_png
./gen_png
ls -lh host.png  # Should be ~112KB
```

### Path Issues
```bash
# Tests expect to be run from steganosaurus/ directory
cd steganosaurus
./test_hardening.sh

# Or adjust paths in scripts
```

## Contributing

When adding new tests:
1. Follow existing test format
2. Add to test_hardening.sh if functional test
3. Add to test_kdf_timing.sh if timing test
4. Update this README
5. Verify all tests pass before committing

## References

- `doc/HARDENING.md` - Detailed security analysis
- `doc/SUMMARY.md` - Implementation summary
- `README.md` - User documentation
- `doc/ATTACKS.md` - Threat analysis
- `doc/TODO.md` - Future work

---

**Last Updated**: 2025-11-15  
**Status**: All tests passing ✅  
**Coverage**: Functional, Security, Performance
