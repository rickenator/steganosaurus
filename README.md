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
• ECC protection using Hamming(7,4) + Repetition-3  
• Density shaping and magnitude thresholding to reduce detectability  
• RGB plane hopping to minimize local distortion patterns  

---

## PROCESS OVERVIEW

Secret Message  
→ ChaCha20-Poly1305 Encryption  
→ ECC (Hamming + Repetition)  
→ SHA256(passphrase) → Turtlewalk Path  
→ Phase Quantization of FFT (R, G, B)  
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
| `alpha` | 0.22 | Embedding phase amplitude |
| `jitter` | 0.05 | Random phase noise for stealth |
| `density` | 0.7 | Probability a valid bin is used |
| `rmin/rmax` | 0.05 / 0.45 | Radial region of FFT to embed in |
| `magmin` | 0.01 | Minimum magnitude needed for embedding |
| `center` | 0 | FFT center-shift toggle |
| `pbkdf2_iter` | 200000 | Passphrase strengthening iterations |

**Important:** Extractor must use the same `density`, `magmin`, `jitter`, and `pbkdf2_iter` as embedder.

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
• **PBKDF2 + HKDF** derive separate keys for AEAD encryption and turtle path selection from one passphrase (200,000 iterations default).  
• Wrong passphrase → extraction fails cleanly with no plaintext leakage.

### Stealth & Detectability

• **Keyed turtlewalk**: Path derived from SHA256(passphrase) prevents brute-force scanning of FFT bins.  
• **Per-plane independent keystreams**: R, G, B channels use separate HKDF-derived keys for jitter, reducing cross-channel coherence artifacts detectable by statistical analysis.  
• **Phase-domain embedding**: FFT phase modifications are visually imperceptible (PSNR typically >50dB).  
• **Density shaping**: Only a fraction of suitable bins are used, making statistical detection harder.

### Robustness & Limitations

• **ECC protection**: Hamming(7,4) + Repetition-3 enables some robustness to light image transformations (resizing, compression, blur).  
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
