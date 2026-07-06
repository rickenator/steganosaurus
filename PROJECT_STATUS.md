# TurtleFFT Project Status

> **Last updated**: 2026-07-06  
> **Repository**: Steganosaurus (GitHub: rickenator/steganosaurus)  
> **Current commit**: `64c2374` — "Increase default alpha from 0.50 to 0.80"

---

## Project Overview

**TurtleFFT** is a frequency-domain steganography system that hides encrypted data inside the **phase** of a 2D FFT of an image. A keyed "turtle-walk" path selects which frequency bins to modify across RGB channels, making the embedded data difficult to detect or extract without the correct passphrase.

**The turtle carries the secret inside its shell:**
- Encryption protects the message (ChaCha20-Poly1305 AEAD)
- Phase embedding hides the message (visually imperceptible, PSNR >50dB)
- The turtlewalk conceals where the message is (keyed SHA256 path)

---

## Current Status: Production-Ready Core

| Area | Status | Notes |
|------|--------|-------|
| Encryption | ✅ Production | ChaCha20-Poly1305 AEAD, header as AAD |
| Key Derivation | ✅ Production | PBKDF2 (600k iterations) + HKDF |
| ECC / Reliability | ✅ Production | Rep-3 (header) + Rep-7 (payload), 100% extract rate |
| Turtlewalk | ✅ Production | Keyed path, per-plane subkeys |
| CLI Interface | ✅ Production | `embed`, `extract`, `gen-key` modes |
| Key Management | ✅ Production | `turtlefft-key` tool with wrapping/unwrapping |
| Build System | ✅ Production | CMake (preferred) + one-line g++ |
| Documentation | ✅ Complete | README, HARDENING, ATTACKS, TODO, TESTING |

---

## Security Posture

### ✅ Protected Against
1. **Passphrase brute-force** — 600k PBKDF2 iterations (~6s/attempt, ~5.3M attempts/year on single CPU)
2. **Timing attacks on MAC** — constant-time Poly1305 comparison
3. **Header tampering** — header authenticated as AAD in AEAD
4. **Chosen-ciphertext attacks** — ChaCha20-Poly1305 AEAD (IND-CCA2)
5. **Cross-channel coherence** — per-plane independent keystreams (ks_r, ks_g, ks_b)
6. **Statistical detection** — phase-domain embedding, density shaping, keyed path

### ⚠️ Remaining Vulnerabilities (Deferred)
1. **Phase histogram detectors** — absolute ±α nudges may create measurable bimodal peaks
2. **Collusion (multi-cover averaging)** — same pass across many images reveals hotspots
3. **Known-cover attacks** — unavoidable design constraint (documented)
4. **Lossy compression** — heavy JPEG destroys phase data (documented limitation)
5. **Weak passphrases** — KDF slows but doesn't prevent brute-force

### ❌ Not Protected Against
1. Adversary with original cover image (compute FFT difference)
2. Heavy JPEG compression or aggressive filtering
3. Physical side-channels (power, EM, cache timing beyond MAC)

---

## Feature Roadmap Status

### Completed (Production)
- [x] 2D FFT phase embedding
- [x] ChaCha20-Poly1305 AEAD encryption
- [x] PBKDF2 + HKDF key derivation
- [x] Keyed turtlewalk path (SHA256 passphrase)
- [x] Header as AAD (commit 0bd4639)
- [x] Per-plane HKDF subkeys (commit 0bd4639)
- [x] Constant-time MAC comparison
- [x] Repetition-3 + Hamming(7,4) + Repetition-7 ECC
- [x] Position-based bin selection for 100% reliability
- [x] turtlefft-key CLI tool
- [x] Cross-platform CSPRNG
- [x] Comprehensive documentation

### Deferred — Tier 2 (High Priority)
- [ ] **QIM / Relative Quantization** — Replace absolute ±α with relative quantization. #1 detectability fix.
- [ ] **Cover-Dependent Path** — `path_key = SHA256(pass || pHash(cover))`. Defeats collusion.
- [ ] **Per-bin Randomized Alpha** — `α_i ~ N(μ, σ²)`. Quick win for detection resistance.

### Deferred — Tier 3 (Research)
- [ ] **Stronger FEC** — Reed-Solomon or LDPC instead of current ECC
- [ ] **Adaptive Masking** — Content-aware embedding
- [ ] **Stealth Mode** — `--mode stealth` / `--mode throughput` presets
- [ ] **Detection Testing Framework** — KL/ROC sweeps, collusion tests
- [ ] **Payload Padding** — Random padding to obscure message length

### Broken (Experimental, Disabled by Default)
- [ ] `--adaptive_alpha 1` — Causes bit errors (magnitude changes during IFFT→clamp→FFT)
- [ ] `--cover_dependent_path 1` — Path mismatch after embedding modifies image

---

## Build & Test Status

### Build
| Target | Status | Output |
|--------|--------|--------|
| `turtlefft` | ✅ Built | `steganosaurus/build/turtlefft` (458 KB) |
| `turtlefft-key` | ✅ Built | `steganosaurus/build/turtlefft-key` (86 KB) |
| `gen_png` (test) | ✅ Available | `steganosaurus/tools/gen_png.cpp` |

### Tests
| Test | Status | Notes |
|------|--------|-------|
| Basic round-trip | ✅ Pass | 12 bytes, ~12s (embed+extract) |
| Long messages | ✅ Pass | ~80 bytes tested |
| Wrong password | ✅ Pass | Fast failure (~0.21s) |
| Custom KDF iterations | ✅ Pass | 50k iterations for testing |
| Experimental features | ⚠️ Expected fail | Documented limitation |
| KDF timing | ✅ Pass | 600k iterations = ~6s |
| CodeQL scan | ✅ Pass | 0 vulnerabilities |
| Alpha=0.80 reliability | ✅ Pass | 10/10 round-trips; 0 failures at 0.40-1.00 |

### Test Scripts
- `test_hardening.sh` — Functional tests (run from `steganosaurus/` directory)
- `test_kdf_timing.sh` — KDF timing verification
- `doc/TESTING.md` — Full test documentation

---

## Uncommitted / Untracked State

### Uncommitted Changes
| File | Change | Impact |
|------|--------|--------|
| *(none)* | All recent changes committed to `main` | — |

### Untracked Files
| Path | Content | Size |
|------|---------|------|
| `stego/emu_original.png` | 1448×1086 PNG test cover | 2.4 MB |
| `stego/emu_stego.png` | Stego output of emu_original.png | 3.5 MB |
| `test_images/emu.png` | Original 1448×1086 PNG | 2.4 MB |

### Git Status
```
On branch main
Your branch is up to date with 'origin/main'.
Latest commit: 64c2374 — "Increase default alpha from 0.50 to 0.80"
```

---

## Performance Metrics

### Default Settings (600k PBKDF2 iterations)

| Image Size | Embed Time | Extract Time | Capacity |
|------------|------------|--------------|----------|
| 256×256 | ~6.0s | ~5.9s | ~150 bytes |
| 512×512 | ~6.0s | ~5.9s | ~600 bytes |
| 1024×1024 | ~6.0s | ~5.9s | ~2.4 KB |
| 1448×1086 | ~6.0s | ~5.9s | ~4-12 KB |

**Note**: PBKDF2 key derivation dominates (~99% of total time). Embed/extract overhead is negligible.

### Fast Testing Mode (NOT secure)
```bash
./turtlefft embed --in cover.png --out stego.png \
  --secret "test" --pass "test" --pbkdf2_iter 10000
# ~0.5s per operation
```

---

## Code Metrics

| File | Lines | Description |
|------|-------|-------------|
| `steganosaurus/src/steganosaur.cpp` | 1427 | Main implementation (SHA-256, crypto, FFT, ECC, CLI) |
| `steganosaurus/src/crypto/crypto_utils.h` | 562 | Cross-platform crypto helpers |
| `steganosaurus/src/crypto/chacha20poly1305.cpp` | 305 | AEAD implementation |
| `steganosaurus/src/crypto/chacha20poly1305.h` | ~40 | AEAD header |
| `steganosaurus/CMakeLists.txt` | 25 | Build configuration |

**Total source code**: ~2,359 lines (excluding stb_image headers)
**External dependencies**: None (stb_image/stb_image_write are single-file public domain headers)

---

## Known Issues & Technical Debt

| # | Issue | Priority | Notes |
|---|-------|----------|-------|
| 1 | DEBUG=1 uncommitted in steganosaur.cpp | Low | Set to 0 for production release |
| 2 | Untracked stego/ and test_images/ directories | Low | Add to .gitignore if unwanted |
| 3 | Experimental features (`--adaptive_alpha`, `--cover_dependent_path`) break extraction | Medium | Documented; need QIM redesign |
| 4 | No CI/CD pipeline | Medium | Add GitHub Actions per TESTING.md |
| 5 | Single-file steganosaur.cpp (1427 lines) | Low | Modularization would help maintainability |
| 6 | No `.gitignore` for steganosaurus/ root | Low | Root-level .gitignore would clean up untracked files |
| 7 | Phase histogram detectability | High | Needs QIM implementation |
| 8 | Collusion vulnerability | Medium | Needs cover-dependent path |

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2025-11-15 | 600k PBKDF2 iterations | 60x above 100ms target; strong brute-force resistance |
| 2025-11-15 | Header as AAD | Prevents oracle attacks; authenticated alongside ciphertext |
| 2025-11-15 | Per-plane HKDF subkeys | Reduces cross-channel coherence detectability |
| 2026-02-28 | Rep-7 ECC for payload | ~43% bit error tolerance → 100% reliable with lossless PNG |
| 2026-02-28 | Remove magnitude-based bin check | Caused embed/extract mismatch; position-based is deterministic |
| 2026-03-19 | Adaptive alpha deferred | Magnitude changes during IFFT→clamp→FFT cause decoding errors |
| 2026-03-19 | Cover-dependent path deferred | Cover hash unstable after embedding; needs robust alternative |
| 2026-07-06 | Alpha increased to 0.80 | Default 0.50 was borderline robust against 8-bit PNG quantization. 0.80 provides comfortable margin with no visible quality loss. Verified: 10/10 round-trips at 0.80, 0 failures across 0.40-1.00 range. |
