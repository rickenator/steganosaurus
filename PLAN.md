# TurtleFFT Project Plan & Recovery Document

> **Last updated**: 2026-07-07
> **Current commit**: `09a2bc5` plus uncommitted reliability fix (FFT region + stable ranked path)
> **Current branch**: `update_070626` (commit `09a2bc5` — "Add QIM phase embedding, improve cover hash, disable adaptive_qim")
> **Working directory**: `/usr/export/rick/Projects/Steganosaurus`

---

## Current State Summary

TurtleFFT is a frequency-domain steganography system that hides encrypted data inside the phase of a 2D FFT of an image. The core system is **production-ready** and deployed on GitHub. The default embed/extract path now uses a centered in-image power-of-two FFT region plus stable strength-ranked bin ordering, which fixes the previous failures on non-power-of-two and low-texture JPEG covers. There are **two experimental features** still disabled by default that need work: adaptive phase shift and cover-dependent path key. The codebase is a C++17 single-file main (`steganosaur.cpp`) with a crypto library in `src/crypto/`.

### Working directory status (as of last session)
- **HEAD**: commit `09a2bc5` — "Add QIM phase embedding, improve cover hash, disable adaptive_qim" (on branch update_070626, pushed)
- **Uncommitted changes**: centered in-image FFT region for arbitrary image sizes; stable strength-ranked `--mag_rank` path enabled by default; DEBUG reset to production default 0
- **Uncommitted changes from prior work**: QIM implementation, cover hash improvement, adaptive_qim disabled
- **Untracked files**: `stego/` directory (emu_original.png, emu_stego.png), `test_images/` directory (emu.png — a 1448×1086 PNG)
- **Untracked files**: `test_load.jpg` (256×256 JPEG test image), `test_jpeg_robustness.sh` (JPEG robustness test script)
- **Build exists**: `steganosaurus/build/turtlefft` and `steganosaurus/build/turtlefft-key` built and functional

### Key build command
```bash
cd steganosaurus
mkdir -p build && cd build
cmake .. && cmake --build .
```
Or the one-line compile:
```bash
g++ -std=c++17 -O3 -march=native src/steganosaur.cpp -o turtlefft
```
No external dependencies — uses stb_image/stb_image_write (bundled in `include/`) and self-implemented SHA-256, ChaCha20-Poly1305 AEAD, PBKDF2, HKDF.

---

## Completed Features (Production-Ready)

### Tier 1 — Security Hardening (commit 0bd4639)

- ✅ **Alpha increase to 0.80** (commit 64c2374) — Increased default embedding phase amplitude from 0.50 to 0.80 radians for robust round-trip extraction. Tested: 10/10 round-trip at alpha=0.80, 0 failures across 0.40-1.00 range, all 5 test_hardening.sh tests pass.
- ✅ **Header as AAD** in ChaCha20-Poly1305 AEAD (prevents header tampering/oracle attacks)
- ✅ **Per-plane HKDF subkeys** — separate keystreams for R, G, B channels (ks_r, ks_g, ks_b) and walk keystream (ks_walk)
- ✅ **PBKDF2 + HKDF** key derivation with 600,000 default iterations (~6 seconds)
- ✅ **Constant-time MAC comparison** — prevents timing attacks on Poly1305 tag verification
- ✅ **Repetition-3 + Repetition-7 ECC** for 100% reliable extraction (lossless PNG only)
- ✅ **Position-based bin selection** (annulus within rmin/rmax, avoiding DC and axes) — deterministic across embed/extract
- ✅ **turtlefft-key** CLI tool for secure key generation, wrapping, and unwrapping
- ✅ Cross-platform CSPRNG (BCryptGenRandom, getrandom, arc4random_buf, /dev/urandom fallback)

### Tier 2 — Reliability (commit 28ecead)
- ✅ **Removed magnitude-based bin check** that caused embed/extract mismatch — now 100% reliable with Rep-7 ECC

### Tier 2 — JPEG Resilience Diagnostics (commit ca2e2f8)

### Tier 2 — QIM (Quantization Index Modulation) (uncommitted)
- ✅ **QIM phase embedding** (`--qim 1`) — Replaces absolute ±α phase nudges with quantization index modulation. Bit 0 → snap to even multiple of Δ/2, Bit 1 → odd multiple. Creates periodic pattern in phase space, harder to detect than fixed offsets.
- ✅ **`--qim_step Δ`** — Configurable step size (default 1.60). Tested: 1.60 works reliably, 0.80 too tight (bit flips), 2.40 causes 21% BER.
- ⚠️ **`--adaptive_qim` disabled** — Per-bin magnitude shifts after IFFT+re-FFT break embed/extract sync. Requires redesign (e.g., magnitude-invariant encoding).
- ✅ **Cover hash improved** — Uses grayscale + FFT magnitudes instead of per-plane spectral data. More stable across embed/extract round-trip.
- ✅ **BER analysis on extract failure** — when "Magic not found", reports `BER estimate: X.X% (Y errors in Z Rep-3 groups)` from Repetition-3 decoding confidence. Helps diagnose whether failure is due to compression artifacts vs wrong password.
- ✅ **`--jpeg-out QUALITY` option** — creates degraded JPEG from PNG output for social media upload simulation
- ✅ **JPEG robustness testing** — all quality levels (Q30-Q100) fail extraction, confirming phase-domain steganography is destroyed by lossy compression

### Tier 2 — Arbitrary-Size / Smooth-Cover Reliability (uncommitted)
- ✅ **Centered in-image FFT region** — For non-power-of-two images, embed/extract now operate on the largest centered power-of-two region inside the image instead of zero-padding beyond image bounds and cropping away part of the inverse transform.
- ✅ **Stable strength-ranked bin path** — `--mag_rank` is now implemented and enabled by default. It ranks annulus bins from the inner radius outward with keyed tie-breaks, avoiding image-magnitude-dependent ordering that can desynchronize after embedding.
- ✅ **Legacy path retained** — `--mag_rank 0` preserves the older random turtlewalk path for compatibility testing.
- ✅ **selfie.jpg regression fixed** — `test_images/selfie.jpg` (1920x1080 JPEG cover) now extracts `"Citizen Vigilante"` with default settings and with `--qim 1` using `--pbkdf2_iter 10000`.
- ✅ **Large PNG regression fixed** — `test_images/emu.png` (1448x1086 PNG cover) extracts `"Citizen Vigilante"` with default settings.

### Documentation
- ✅ `README.md` — user documentation
- ✅ `doc/HARDENING.md` — detailed security analysis
- ✅ `doc/SUMMARY.md` — implementation summary
- ✅ `doc/ATTACKS.md` — adversarial red-team analysis
- ✅ `doc/TODO.md` — development roadmap
- ✅ `doc/TESTING.md` — test suite documentation
- ✅ `test_hardening.sh` — functional test suite
- ✅ `test_kdf_timing.sh` — KDF timing verification

---

## In-Progress / Pending Work

### Immediate Tasks (Tier 2 — High Priority)

1. **Cover-Dependent Path Key** (doc/TODO.md Tier 2)
   - Derive `path_key = SHA256(pass || pHash(cover))`
   - Defeats collusion averaging across multiple images with same passphrase
   - Challenge: pHash must be stable under metadata changes
   - Alternative: Optional per-image nonce stored in authenticated header

2. **Per-bin Randomized Alpha** (doc/TODO.md Tier 2)
   - Add small variance to α per bin: `α_i ~ N(μ, σ²)`
   - Blurs histogram peaks without full QIM complexity
   - Priority: Medium — quick win for detection resistance

### JPEG Robustness & Format Support (New — Tier 2)

1. **BER Analysis for JPEG Degradation** 
   - Quantify bit error rate at different JPEG quality levels (Q30-Q100)
   - Test script: `test_jpeg_robustness.sh`
   - Current finding: All quality levels fail extraction (expected — phase data destroyed by JPEG)
   - Next: Report BER% in extract output when magic not found

2. **Reed-Solomon ECC for JPEG Resilience**
   - Replace Repetition-7 with Reed-Solomon codes for better burst error correction
   - Reed-Solomon can correct random errors more efficiently than Rep-7
   - Target: Survive JPEG Q80+ compression with <1% BER
   - Reference: HARDENING.md section 4 (Reed-Solomon recommendation)

3. **Native JPEG Input Support**
   - stb_image already supports JPEG loading — verify YCbCr→RGB conversion works correctly
   - Test: embed into JPEG cover, extract from PNG stego (lossless output)
   - Current test image: `test_load.jpg` (256×256 baseline JPEG)
   - Note: JPEG input is fine; the problem is JPEG output/degradation destroys phase data

### Longer-Term Tasks (Tier 3 — Research)

5. **Stronger FEC** — Replace Hamming(7,4) with Reed-Solomon or LDPC (currently using Rep-7 which provides ~43% bit error tolerance)
6. **Adaptive Masking** — Content-aware embedding (elevate α only where spectral mask is strong)
7. **Conservative Defaults & Stealth Mode** — `--mode stealth` preset, `--mode throughput` preset
8. **Empirical Detection Testing Framework** — KL/ROC tests, collusion tests, SRM classifier
9. **Payload Padding** — Random padding to obscure message length

---

## Architecture & Code Layout

```
Steganosaurus/
├── README.md                     # User documentation
├── LICENSE                       # Apache 2.0
├── steganosaurus/
│   ├── CMakeLists.txt            # Build: turtlefft + turtlefft-key + chacha20poly1305 lib
│   ├── .gitignore
│   ├── README.md                 # Inline project README
│   ├── include/
│   │   ├── stb_image.h           # Image loading (single-file)
│   │   └── stb_image_write.h     # Image writing (single-file)
│   ├── src/
│   │   ├── steganosaur.cpp       # Main implementation (1674 lines)
│   │   │   # Contains: SHA-256, PBKDF2, HKDF, FFT, ECC, turtlewalk, CLI, embed/extract/gen-key
│   │   ├── crypto/
│   │   │   ├── crypto_utils.h    # Cross-platform crypto helpers (562 lines)
│   │   │   └── chacha20poly1305.cpp  # AEAD implementation (305 lines)
│   │   └── crypto/
│   │       └── chacha20poly1305.h  # AEAD header
│   ├── tools/
│   │   ├── gen_png.cpp           # Test image generator
│   │   └── turtlefft-key.cpp     # Key generation CLI tool
│   └── build/                    # CMake build output (gitignored)
├── doc/
│   ├── SUMMARY.md                # Implementation summary
│   ├── HARDENING.md              # Security hardening analysis
│   ├── ATTACKS.md                # Red-team threat analysis
│   ├── TODO.md                   # Development roadmap
│   ├── TESTING.md                # Test suite docs
│   ├── PAPER.md                  # Research/paper notes
│   └── turtlewalk_fixed2.svg     # FFT path diagram
├── stego/                        # Untracked — sample stego images
│   ├── emu_original.png          # 1448×1086 PNG (2.4 MB)
│   └── emu_stego.png             # Stego output
├── test_images/                  # Untracked — test assets
│   └── emu.png                   # 1448×1086 PNG (2.4 MB)
├── test_hardening.sh             # Functional test suite
└── test_kdf_timing.sh            # KDF timing verification
```

---

## Key Implementation Details (for a fresh session)

### steganosaur.cpp Structure (1674 lines)
1. **Lines 1-100**: Includes, stb_image/stb_image_write, crypto headers, SHA-256 implementation (self-contained)
2. **Lines 100-300**: PBKDF2, HKDF, constant-time compare, secure_zero
3. **Lines 300-500**: FFT (2D FFT with Cooley-Tukey), transform-region helpers, polar/complex utilities
4. **Lines 500-700**: ECC (Repetition-3 for header, Hamming(7,4) for payload, Repetition-7 for final)
5. **Lines 700-1000**: Phase embedding/QIM plus turtlewalk path generation and stable ranked bin selection
6. **Lines 1100-1330**: Embed function (encrypt → ECC → ranked turtlewalk → phase embedding → IFFT → save)
7. **Lines 1340-1560**: Extract function (FFT → ranked turtlewalk → phase extraction → ECC decode → decrypt → output)
8. **Lines 1560-1674**: Key generation (`gen-key` mode), main()

### Header Format (embedded in stego image)
```
MAGIC (4 bytes) || SALT (32 bytes) || NONCE (12 bytes) || CLEN (4 bytes) || CT || TAG (16 bytes)
```
- MAGIC: Identifies valid stego payload
- SALT: PBKDF2 salt (SHA256 pass → derive encryption key)
- NONCE: ChaCha20 nonce (HKDF-derived from same key)
- CLEN: Ciphertext length (little-endian uint32)
- CT + TAG: Encrypted payload (header is AAD)

### Embedding Parameters
| Parameter | Default | Description |
|-----------|---------|-------------|
| `alpha` | 0.80 | Embedding phase amplitude (increased from 0.50 in commit 64c2374) |
| `jitter` | 0.0 | Phase jitter (disabled for determinism) |
| `density` | 0.7 | Probability a valid bin is used |
| `rmin/rmax` | 0.05/0.45 | Radial embedding region |
| `mag_rank` | 1 | Stable strength-ranked path, inner annulus first; use 0 for legacy random turtlewalk |
| `pbkdf2_iter` | 600000 | KDF iterations |

### Capacity Estimates (1448×1086 emu image)
- Uses a centered 1024x1024 FFT region; ~4-12 KB depending on texture content and selected mode

---

## Recovery Checklist

If a fresh session picks up this project:

1. **Read this file** — it's the primary recovery document.
2. **Check git status** — `git status` to see uncommitted/untracked changes.
3. **Check git log** — `git log --oneline -20` to see recent commits.
4. **Verify build** — `cd steganosaurus && mkdir -p build && cd build && cmake .. && cmake --build .`
5. **Run tests** — `cd steganosaurus/build && ./turtlefft embed --in ../tools/gen_png.cpp ...` or use `test_hardening.sh`
6. **Check TODO.md** — `doc/TODO.md` has the full development roadmap with priorities.
7. **Check ATTACKS.md** — `doc/ATTACKS.md` has the threat model and remaining vulnerabilities.
8. **Check HARDENING.md** — `doc/HARDENING.md` has the security analysis and experimental features status.

---

## Known Issues

1. **Untracked stego/ test/ and test_images/**: These contain large generated test images and are not gitignored at the repository root.
2. **Experimental features broken**: `--adaptive_alpha 1` and `--cover_dependent_path 1` cause decoding failures (known, documented).
3. **Lossy JPEG output still fails**: JPEG input covers are supported, but extraction from JPEG-compressed stego output still fails.
4. **No CI**: No GitHub Actions or automated testing pipeline configured.
5. **Single-file main**: `steganosaur.cpp` is 1674 lines and contains everything (SHA-256, crypto, FFT, CLI) — modularization would help maintainability but isn't urgent.

---

## GitHub Repository

- **Remote**: `origin/main` on GitHub
- **PR #8**: Merged — "Fix long embedded messages"
- **PR #7**: Merged — "Run tests after merge"
- **PR #5-6**: Merged — Key generation features
- **PR #4**: Merged — Key generation in CLI
- **DeepWiki**: Linked via badge at `deepwiki.com/rickenator/steganosaurus`
