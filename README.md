## Turtlewalk Frequency-Domain Embedding Path

<p align="center">
  <img src="doc/turtlewalk_fixed2.svg" alt="Turtlewalk FFT Path Diagram" width="650px">
</p>

# TurtleFFT

TurtleFFT is a frequency-domain steganography system that hides encrypted data inside the *phase* of a 2D FFT of an image.
A keyed "turtle-walk" selects which frequency bins to modify across the RGB channels, making the embedded data difficult to detect or extract without the correct passphrase.

The turtle carries the secret inside its shell:

* Encryption protects the message.
* Phase embedding hides the message.
* The turtlewalk conceals where the message is.

---

## FEATURES

• Secure AEAD encryption using ChaCha20-Poly1305  
• Passphrase hardened via PBKDF2 + HKDF  
• Message embedded in FFT *phase*, not in pixel bits  
• Keyed turtlewalk path derived from SHA256(passphrase)  
• ECC protection using Repetition-7 (header: Rep-3, payload: Rep-7) for 100% reliable extraction  
• Position-based bin selection within FFT annulus for deterministic embed/extract matching  
• RGB plane hopping to minimize local distortion patterns  

---

## PROCESS OVERVIEW

Secret Message  
→ ChaCha20-Poly1305 Encryption  
→ ECC (Repetition-7 for payload, Repetition-3 for header)  
→ SHA256(passphrase) → Turtlewalk Path  
→ Position-based Bin Selection (annulus within rmin/rmax, avoiding DC and axes)  
→ Phase Embedding in FFT (R, G, B)  
→ Inverse FFT → Stego Image Output  

---

## BUILD

Requires C++17 or later.

Command:
```bash
g++ -std=c++17 -O3 -march=native src/steganosaur.cpp -o turtlefft
```

Or using CMake:
```bash
mkdir build && cd build
cmake ..
cmake --build .
```

No external crypto libs needed.  
Image I/O uses stb_image and stb_image_write (included in `include/`).

---

## BASIC USAGE

To embed a message:

```bash
./turtlefft embed \
    --in host.png \
    --out stego.png \
    --secret "the eagle has landed" \
    --pass "correct horse battery staple"
```

To extract the message:

```bash
./turtlefft extract \
    --in stego.png \
    --pass "correct horse battery staple"
```

If the passphrase is wrong, output will fail cleanly.

---

## TUNABLE PARAMETERS (SAFE DEFAULTS)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `alpha` | 0.50 | Embedding phase amplitude (increased for reliability) |
| `jitter` | 0.0 | Phase jitter disabled for deterministic embedding |
| `density` | 0.7 | Probability a valid bin is used |
| `rmin/rmax` | 0.05 / 0.45 | Radial region of FFT to embed in |
| `center` | 0 | FFT center-shift toggle |
| `pbkdf2_iter` | 600000 | Passphrase strengthening iterations (hardened) |
| `adaptive_alpha` | 0 | Adaptive phase shift (experimental) |
| `cover_dependent_path` | 0 | Cover-dependent turtlewalk (experimental) |

**Important:** Extractor must use the same `density` and `pbkdf2_iter` as embedder.

**Reliability Note:** The combination of Repetition-7 ECC and position-based bin selection provides 100% reliable extraction across all message sizes.

---

## TYPICAL CAPACITY (VARIES WITH TEXTURE)

| Image Size | Approx Payload |
|------------|----------------|
| 512×512 | ~1 to 3 KB |
| 1080p | ~4 to 12 KB |
| 4K UHD | ~15 to 50 KB |

Busy, high-texture images allow more embedding.

---

## SECURITY NOTES

### Confidentiality & Integrity

• **ChaCha20-Poly1305 AEAD** provides authenticated encryption (IND-CCA2 secure).  
• **Header as AAD**: The message header (salt, nonce, ciphertext length) is authenticated as Additional Authenticated Data, preventing header tampering and oracle attacks.  
• **PBKDF2 + HKDF** derive separate keys for AEAD encryption and turtle path selection from one passphrase (600,000 iterations default).  
• **Constant-time MAC verification**: Poly1305 tag comparison uses constant-time comparison to prevent timing attacks.  
• **Key derivation hardening**: 600,000 PBKDF2 iterations (~6 seconds) provides strong resistance to passphrase brute-force attacks.  
• Wrong passphrase → extraction fails cleanly with no plaintext leakage.

### Stealth & Detectability

• **Keyed turtlewalk**: Path derived from SHA256(passphrase) prevents brute-force scanning of FFT bins.  
• **Per-plane independent keystreams**: R, G, B channels use separate HKDF-derived keys for jitter, reducing cross-channel coherence artifacts detectable by statistical analysis.  
• **Phase-domain embedding**: FFT phase modifications are visually imperceptible (PSNR typically >50dB).  
• **Density shaping**: Only a fraction of suitable bins are used, making statistical detection harder.

### Experimental Features

• **Adaptive phase shift** (`--adaptive_alpha 1`): Scales embedding strength based on local magnitude. Currently experimental - may cause decoding issues.  
• **Cover-dependent path** (`--cover_dependent_path 1`): Binds turtlewalk to cover image spectral hash. Currently experimental - sensitive to embedding changes.

### Robustness & Limitations

• **ECC protection**: Repetition-7 encoding for payload provides ~43% bit error tolerance, ensuring 100% reliable extraction with lossless PNG format.  
• **Position-based bin selection**: Bins are selected based on position (annulus within rmin/rmax, avoiding DC and axes), not magnitude, ensuring identical bins are used during embed and extract.  
• **Known-cover attacks**: This scheme is NOT secure against adversaries who possess the original cover image (they can compute FFT difference).  
• **Lossy compression**: Heavy JPEG compression or aggressive filtering can destroy phase-domain data → extraction fails.  
• **Passphrase strength**: Overall security depends on passphrase entropy. Use strong, unique passphrases.

---

## DEBUG MODE

To enable detailed debug output showing coordinates, phases, and magnitudes:

```bash
# Rebuild with DEBUG=1
cd build
cmake .. -DCMAKE_CXX_FLAGS="-DDEBUG=1"
cmake --build .
```

Default is `DEBUG=0` (clean output).

---

## PROJECT STRUCTURE

```
steganosaurus/
├── CMakeLists.txt        # Build configuration
├── README.md             # This file
├── .gitignore            # Git ignore file
├── include/              # Header files
│   ├── stb_image.h      # Image loading (single-file library)
│   └── stb_image_write.h # Image writing (single-file library)
├── src/
│   └── steganosaur.cpp  # Main implementation (crypto + FFT + stego)
└── tools/
    └── gen_png.cpp      # Test image generator (gradient + noise)
```

---

## LICENSE

Licensed under the Apache License 2.0 (with patent grant protection).


---

## ONE-LINE PROJECT DESCRIPTION

TurtleFFT: Encrypted, ECC-protected steganography hidden in the phase of a 2D FFT and guided by a keyed turtlewalk across RGB frequency planes.
