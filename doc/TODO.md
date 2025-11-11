# TurtleFFT Development Roadmap

## Recently Completed (commit 0bd4639)

- [x] **Implement Header as AAD in AEAD (Tier 1)**
  - Header bytes (salt, nonce, clen) authenticated as AAD in ChaCha20-Poly1305
  - Prevents header tampering and oracle attacks
  - Test: Round-trip embed/extract passes, wrong password rejects cleanly

- [x] **Implement per-plane HKDF subkeys (Tier 1)**
  - Separate keystreams for R, G, B channels via HKDF-expand
  - Walk keystream (`ks_walk`) separate from per-plane jitter keystreams (`ks_r/g/b`)
  - Reduces cross-channel coherence detection
  - Test: Verified independent keystream operation

- [x] **Update documentation**
  - Added doc/ATTACKS.md with comprehensive red-team analysis
  - Added doc/TODO.md tracking roadmap
  - Updated README.md security section with detailed notes

## Deferred for Separate Work

### Tier 2 (Important - Near Term)

- [ ] **QIM/Relative Quantization**
  - Replace absolute ±α phase nudges with relative quantization (QIM or STDM)
  - Reduces fixed offset signature in global phase histogram
  - Requires: Testing framework for phase histogram analysis
  - Priority: High, but needs empirical validation setup first

- [ ] **Cover-Dependent Path Key**
  - Derive `path_key = SHA256(pass || pHash(cover))`
  - Defeats collusion averaging across multiple images with same passphrase
  - Challenge: pHash must be stable under metadata changes (EXIF strip, gamma adjustments)
  - Alternative approach: Optional per-image nonce stored in authenticated header
  - Priority: Medium, requires design discussion on extraction UX

- [ ] **Per-bin Randomized Alpha (simpler than full QIM)**
  - Add small variance to α per bin: `α_i ~ N(μ, σ²)`
  - Blurs histogram peaks without full QIM complexity
  - Priority: Medium, quick win for detection resistance

### Tier 3 (Research - Longer Term)

- [ ] **Stronger FEC (Reed-Solomon or LDPC)**
  - Replace Hamming(7,4) with RS or LDPC for better error correction
  - Add interleaving across turtle sequence to distribute burst errors
  - More resilient to noise and targeted bin corruption
  - Priority: Low, significant implementation effort

- [ ] **Adaptive Masking (Content-Aware Embedding)**
  - Compute local spectral contrast
  - Elevate α only where mask is strong (higher mag relative to median)
  - Hide changes in "busy" spectrum regions
  - Priority: Low, requires perceptual modeling

- [ ] **Conservative Defaults & Stealth Mode**
  - Document safe defaults: density ≤ 0.25, α ≤ 0.25 rad
  - Provide `--mode stealth` and `--mode throughput` presets
  - Add `--test` mode that computes PSNR/SSIM/KL before embedding
  - Priority: Medium, UX improvement

- [ ] **Empirical Detection Testing Framework**
  - Build KL/ROC test harness for phase histogram analysis
  - Implement collusion test (mean FFT across multiple images)
  - Cross-channel correlation tests
  - BER vs AWGN/JPEG robustness tests
  - SRM classifier integration (if feasible)
  - Priority: Low, but essential for research validation

- [ ] **Payload Padding**
  - Add random padding to ciphertext to obscure message length
  - Prevents metadata leakage via ciphertext size
  - Priority: Low, operational security improvement

## Research Questions (Future Work)

1. How small can Δ (relative quantization step) be while still enabling robust decoding at modest capacity?
2. How much does cover-dependence of the path reduce collusion detection AUC?
3. Which FEC + interleaving scheme provides best capacity vs reliability under spectral perturbations?
4. What is the minimal payload at which phase histogram detectors reach AUC>0.95 across a 10k image corpus?
5. How much does per-plane independent jitter reduce cross-channel correlation detectability? (Needs empirical measurement)

## Change Log

### 2025-11-11: Tier 1 Security Hardening (commit 0bd4639)
- Implemented header as AAD for AEAD authentication
- Implemented per-plane HKDF subkeys (ks_walk + ks_r/g/b)
- Added comprehensive documentation (ATTACKS.md, TODO.md)
- Updated README.md with enhanced security section
- Test results: Round-trip embed/extract working, wrong password rejection confirmed
4. What is the minimal payload at which phase histogram detectors reach AUC>0.95 across a 10k image corpus?

## Completed

- [x] ECC integration (Repetition-3 + Hamming(7,4))
- [x] Portable endian-safe crypto (load32_le/store32_le)
- [x] Path key from SHA256(pass) for salt-independence
- [x] DEBUG macro for conditional output
- [x] Comprehensive documentation
