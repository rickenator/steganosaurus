# TurtleFFT Status

**Repository**: Steganosaurus / TurtleFFT  
**Branch**: `update_070626`  
**Current HEAD**: `a2b774f` (`Fix arbitrary-size FFT reliability`)  
**Report date**: 2026-07-07

## Executive Summary

TurtleFFT is currently in a production-ready state for lossless PNG output and passphrase-based use. The current branch includes:

- ChaCha20-Poly1305 AEAD with authenticated header
- PBKDF2 + HKDF key derivation
- Repetition-3 header ECC and Repetition-7 payload ECC
- QIM phase embedding as an optional mode
- A centered in-image FFT region for non-power-of-two covers
- Stable strength-ranked turtle selection as the default bin-ordering path

The important operational result is that the system now extracts successfully on the previously failing smooth/non-power-of-two covers, including `test_images/selfie.jpg` and `test_images/emu.png`, without requiring special manual tuning beyond the normal passphrase and test iteration count.

## Theory Of Operation

### 1. Encrypt First

The secret is encrypted with ChaCha20-Poly1305.

- The payload is confidential because the ciphertext is protected by AEAD.
- The header is authenticated as AAD, so tampering with salt, nonce, or length fails verification.
- Wrong passwords fail at authentication rather than leaking plaintext.

### 2. Expand With ECC

The ciphertext is expanded with redundancy before embedding.

- Header bytes use Repetition-3.
- Payload bytes use Repetition-7.
- This trades capacity for stability, which is the right choice for phase-domain embedding in PNG output.

### 3. Map Bits To A Deterministic Turtle Path

The turtlewalk is keyed from the passphrase-derived path key.

- The walk is deterministic for embed and extract.
- The current default path is stable strength-ranked ordering within the annulus.
- `--mag_rank 0` keeps the legacy random-walk path available for compatibility tests.

### 4. Embed In FFT Phase

The payload bits modify the phase of selected complex FFT bins.

- Absolute mode uses `phi_new = phi_old +/- alpha`.
- QIM mode uses quantization on phase bins instead of fixed offsets.
- The default `alpha` is `0.80`.
- `--qim_step` defaults to `1.60`.

### 5. Preserve Real-Image Boundaries

For non-power-of-two images, the implementation now uses the largest centered power-of-two region inside the source image.

- This avoids zero-padding outside the real image and then cropping away inverse-transform energy.
- Pixels outside the FFT region are preserved in the output PNG.
- This is the fix that made the previously failing `selfie.jpg` and `emu.png` cases work.

## Current Feature Set

### Cryptography

- ChaCha20-Poly1305 AEAD
- Header as AAD
- PBKDF2 + HKDF
- Constant-time MAC verification
- Secure key generation and wrapping via `turtlefft-key`

### Embedding And Extraction

- FFT phase-domain embedding
- Repetition-3 header ECC
- Repetition-7 payload ECC
- QIM phase embedding via `--qim 1`
- Optional legacy absolute phase mode
- Stable strength-ranked default turtle path
- Legacy random turtle path via `--mag_rank 0`

### Cover Handling

- PNG input/output
- JPEG input covers supported through `stb_image`
- Centered in-image FFT region for arbitrary image dimensions
- Preservation of pixels outside the FFT region

### Diagnostics

- BER estimate on header failure
- JPEG degradation simulation via `--jpeg-out QUALITY`
- Functional hardening test suite
- KDF timing verification

## Working Tests And Outcomes

### Build

- `cmake --build build -j2` passes
- `turtlefft` and `turtlefft-key` build successfully

### Functional Suite

`../test_hardening.sh` from `steganosaurus/` passes:

- Basic round-trip: pass
- Long message: pass
- Wrong password detection: pass
- Custom KDF iterations: pass
- Experimental adaptive alpha: expected fail, as documented

### Targeted Regression Checks

These were run manually during the reliability fix:

- `host.png` default round-trip: pass
- `selfie.jpg` default round-trip: pass
- `selfie.jpg --qim 1` round-trip: pass
- `emu.png` default round-trip: pass

### JPEG Degradation Findings

The JPEG robustness work confirms that lossy compression still breaks extraction.

- All tested JPEG qualities from Q100 to Q30 failed extraction on the degraded output.
- This is expected for phase-domain embedding and remains a known limitation.
- The failure mode is useful as a stress test, but not a supported deployment path.

### Earlier `selfie.jpg` Baseline History

The saved report in `test/test-selfie-jpg.md` captured the old failure state before the reliability fix.

- Baseline / QIM / mag-rank variants all failed there.
- After the current reliability fix, the same cover now passes.
- Treat that report as historical evidence of the bug, not the current state.

## Operational Parameters

### Recommended Defaults

- `--pbkdf2_iter 600000`
- `--alpha 0.80`
- `--density 0.7`
- `--rmin 0.05`
- `--rmax 0.45`
- `--mag_rank 1`
- `--qim 0` for legacy absolute embedding, or `--qim 1` for QIM testing

### Practical Test Mode

For quick local verification, a reduced KDF count is acceptable:

- `--pbkdf2_iter 10000` for fast round-trip checks
- Keep the same passphrase between embed and extract
- Keep the same `--qim`, `--qim_step`, `--density`, and `--mag_rank` settings on both sides

### Typical Commands

```bash
cd steganosaurus
cmake --build build -j2

./build/turtlefft embed --in ../test_images/selfie.jpg --out ../test/selfie_check.png \
  --secret "Citizen Vigilante" --pass Hammer --pbkdf2_iter 10000

./build/turtlefft extract --in ../test/selfie_check.png --pass Hammer --pbkdf2_iter 10000
```

```bash
cd steganosaurus
../test_hardening.sh
```

## Current Known Limits

- Adaptive alpha is still broken and stays disabled by default.
- Cover-dependent path key is still deferred.
- JPEG-compressed stego output still fails extraction.
- Stronger FEC such as Reed-Solomon or LDPC is still research work.

## Why The Current Fix Matters

The previous failure mode on smooth or non-power-of-two covers came from treating the image as if a larger zero-padded FFT could be saved back without loss. That was not true in practice, because the inverse transform was cropped back down to the original image size.

The current fix changes two things:

1. The transform runs on a centered power-of-two region that actually exists in the source image.
2. The turtle path is ordered by a stable, deterministic strength ranking instead of live magnitude-dependent sorting.

That gives the system a usable default on real-world covers rather than only on synthetic square test images.

## Reference Files

- [PLAN.md](/usr/export/rick/Projects/Steganosaurus/PLAN.md)
- [PROJECT_STATUS.md](/usr/export/rick/Projects/Steganosaurus/PROJECT_STATUS.md)
- [README.md](/usr/export/rick/Projects/Steganosaurus/README.md)
- [doc/TESTING.md](/usr/export/rick/Projects/Steganosaurus/doc/TESTING.md)
- [test/test-selfie-jpg.md](/usr/export/rick/Projects/Steganosaurus/test/test-selfie-jpg.md)

