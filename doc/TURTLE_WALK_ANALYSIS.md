# Turtle Walk Deep Dive: Algorithm, Failure Modes, and Improvements

**Date**: 2026-07-06  
**Author**: Steganosaurus Agent  
**Context**: Analysis of why phase-domain steganography fails on quiet images (selfie.jpg) and how to fix it.

---

## 1. How the Turtle Walk Works

### 1.1 Overview

The turtle walk is a deterministic pseudo-random path through the 2D FFT spectrum that selects which frequency bins will carry hidden data. It's the core mechanism that makes embedding/extracting reproducible without storing any location metadata.

### 1.2 Path Generation

```
path_key = SHA256(passphrase)                    // Deterministic from passphrase
walk_seed = SHA256("seed:HxW" || path_key)       // Binds walk to image dimensions
start_y = walk_seed[0] % H                       // Random starting position
start_x = walk_seed[1] % W                       // Random starting position  
start_plane = walk_seed[2] % 3                   // Random starting color plane
```

### 1.3 Movement Rules

The turtle moves using a keystream-derived opcode (3 bits, values 0-7):

| Opcode | Movement | Description |
|--------|----------|-------------|
| 0 | plane+1 | Switch to next RGB plane |
| 1 | x+1 | Move right |
| 2 | y+1 | Move down |
| 3 | x-1 | Move left |
| 4 | y-1 | Move up |
| 5 | x+1, y+1 | Diagonal down-right |
| 6 | x-1, y+1 | Diagonal down-left |
| 7 | stay | Stay in place (change plane only) |

### 1.4 Bin Selection Constraints

A bin is **valid** if ALL of the following are true:

1. **Not on axis**: y≠0, x≠0, y≠H/2, x≠W/2 (avoids DC and symmetry axes)
2. **Not DC**: (y,x) ≠ (0,0)
3. **Not visited**: This bin and its conjugate haven't been used
4. **In annulus**: rmin ≤ radius ≤ rmax (default: 5% to 45% of min(H,W))
5. **Density check**: `walk_keystream.next_byte() < density * 256` (controls sparsity)

### 1.5 Capacity Calculation

For a 2048×2048 padded image (from 1920×1080 source):
- Total bins: 2048² = 4,194,304
- Excluded (axes + DC): ~8,200
- Annulus (5%-45%): ~1,000,000 bins per plane
- Conjugate pairs: ~500,000 unique pairs per plane
- 3 planes: ~1,500,000 total unique bins
- At density=0.7: ~1,050,000 usable bins

**Actual capacity**: The turtle walk visits bins sequentially until all bits are embedded. For a 17-byte payload with Rep-3 + Rep-7 ECC:
- Header (38 bytes): 38×8×3 = 912 bits (Rep-3)
- Payload (33 bytes): 33×8×7 = 1,848 bits (Rep-7)
- **Total**: 2,760 bits

This is well within capacity for any image size.

### 1.6 Embedding Protocol

For each bit:
1. Turtle advances to next valid bin (skipping density-rejected candidates)
2. Phase is perturbed by ±α radians (default α=0.80)
3. Jitter is added from per-plane keystream
4. Bin and its conjugate are marked visited

### 1.7 Extraction Protocol

1. Re-compute FFT of the stego image
2. Turtle walk follows the **same deterministic path** (same pass, same dims)
3. Read phase at each bin: sign determines bit value
4. Repetition-3 decoding for header (majority vote of 3)
5. Repetition-7 decoding for payload (majority vote of 7)

---

## 2. Why It Fails on Quiet Images

### 2.1 The Root Cause: Magnitude-Blind Embedding

**The turtle walk selects bins purely by position, ignoring local FFT magnitude.**

This is the fundamental flaw. The embedding strength (±0.80 radians) is applied uniformly to ALL bins regardless of their magnitude. But bins with low FFT magnitudes cannot tolerate the same phase perturbation as high-magnitude bins.

### 2.2 The Physics: Why Magnitude Matters

When you perturb a complex number's phase by ±α:
```
v = |v| · e^(i·φ) → v' = |v| · e^(i·(φ±α))
```

The IFFT reconstructs the spatial domain from ALL frequency bins. The quantization noise introduced by phase perturbation is:

```
Δspatial ≈ |v| · sin(α)  (per bin contribution)
```

For bins with **low magnitude** (smooth image regions), this perturbation is a large fraction of the signal, causing:
1. **Clamping artifacts**: IFFT output values get clipped to [0,255]
2. **Quantization noise**: 8-bit PNG quantization introduces ±0.5 LSB error
3. **Phase distortion**: The perturbed phase is no longer recoverable

### 2.3 Evidence from Test Results

| Image | Median FFT Mag | Standard Mode | QIM 1.60 |
|-------|---------------|---------------|----------|
| host.png (256×256) | ~1,237 | ✅ PASS | ✅ PASS |
| large_test.png (1024×1024) | ~1,200 | ✅ PASS | ❌ 73% BER |
| selfie_converted.png (1920×1080) | ~480 | ❌ 69% BER | ❌ 71% BER |

**Key observation**: host.png works because its synthetic noise pattern creates high FFT magnitudes across the spectrum. The selfie image has low magnitudes because skin tones and sky are smooth (low-frequency content).

### 2.4 The Quantization Error Model

For a bin with magnitude M, after IFFT+clamp+quantize:
- Phase error ≈ arctan(quant_noise / M)
- For M=1237 (host.png): error ≈ arctan(0.5/1237) ≈ 0.023° → negligible
- For M=480 (selfie.jpg): error ≈ arctan(0.5/480) ≈ 0.060° → manageable
- But the **cumulative** effect across all bins is what matters

The real issue is that low-magnitude bins contribute less to the spatial domain signal, so their phase perturbation creates a larger relative error in the reconstructed image. When this error exceeds the Repetition-3 decoding threshold (needs >50% agreement), the header fails.

### 2.5 Why QIM Doesn't Help on Quiet Images

QIM replaces absolute ±α nudges with quantization to discrete phase bins. But the same magnitude problem applies:
- Low-magnitude bins → larger quantization noise relative to signal
- The periodic pattern in phase space is still destroyed by IFFT artifacts
- QIM step=1.60 works on host.png but fails on selfie.jpg for the same reason

---

## 3. Proposed Improvements

### 3.1 Improvement 1: Magnitude-Aware Bin Selection (Primary Fix)

**Concept**: Instead of random turtle walk, prefer high-magnitude bins.

**Implementation**:
```cpp
// Pre-compute magnitude ranking for each plane
vector<vector<double>> mag_rank(PH, vector<double>(PW));
for each bin: mag_rank[y][x] = log1p(abs(F[y][x]));

// Modified turtle walk: when advancing, prefer unvisited high-magnitude bins
void advance_to_valid_weighted() {
    // Sample N candidate bins from the walk keystream
    // Among candidates, pick the one with highest magnitude
    // This biases toward robust bins while maintaining determinism
}
```

**Expected improvement**: 10-50x better BER on quiet images by concentrating embedding in high-magnitude regions.

### 3.2 Improvement 2: Adaptive Embedding Strength (Secondary Fix)

**Concept**: Scale α by local magnitude ratio.

**Implementation**:
```cpp
double adaptive_alpha = base_alpha * min(3.0, max(0.3, mag / median_mag));
// High-magnitude bins: stronger embedding (up to 3x)
// Low-magnitude bins: weaker embedding (down to 0.3x)
```

**Expected improvement**: More uniform BER across the spectrum. Combined with #1, this should make quiet images viable.

### 3.3 Improvement 3: Magnitude-Weighted ECC (Tertiary Fix)

**Concept**: Use stronger ECC (more repetitions) for bits in low-magnitude bins.

**Implementation**:
```cpp
// Instead of uniform Rep-7, use variable repetition:
// High mag bins: Rep-5 (less overhead)
// Low mag bins: Rep-9 (more redundancy)
```

**Expected improvement**: Better error correction where it's needed most.

### 3.4 Improvement 4: Pre-processing Noise Injection (Fallback)

**Concept**: If the image is too smooth, add controlled noise before embedding.

**Implementation**:
```cpp
// Compute median FFT magnitude across all planes
// If below threshold, add Gaussian noise to spatial domain
// This boosts high-frequency content without visible degradation
if (median_mag < THRESHOLD) {
    add_noise(img, noise_level);
}
```

**Expected improvement**: Makes any image viable for embedding. Trade-off: slight visible quality change.

### 3.5 Improvement 6: Multi-Path Turtle Walk (Advanced)

**Concept**: Use multiple independent turtle walks and spread bits across them.

**Implementation**:
```cpp
// Derive 3 independent path keys from the same passphrase
// Each walk covers a different subset of bins
// Bits are distributed round-robin across paths
```

**Expected improvement**: Better spatial distribution, harder to detect statistically.

---

## 4. Recommended Implementation Order

1. **Magnitude-aware bin selection** (highest impact, lowest risk)
2. **Adaptive embedding strength** (complements #1)
3. **Pre-processing noise injection** (fallback for extreme cases)
4. **Magnitude-weighted ECC** (optimization, not required)

---

## 5. Expected Outcomes

With improvements #1 + #2:
- selfie.jpg should achieve <5% BER (vs current ~70%)
- Any image with median FFT magnitude >200 should work reliably
- host.png and similar images should maintain 0% BER

The key insight is that **the turtle walk needs to be magnitude-aware, not just position-based**. By preferring high-magnitude bins and scaling embedding strength by local magnitude, we can make phase-domain steganography work on any image.
