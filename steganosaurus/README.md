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

• Data is encrypted *and* authenticated: extraction with wrong passphrase yields no plaintext.  
• Turtlewalk path prevents brute-force scanning of FFT bins.  
• ECC enables some robustness to light resizing, compression, blur, etc.  
• Very heavy JPEG compression may destroy phase-domain data.  
• Strong passphrase is essential.  

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

This means:

* You allow others to use the method.
* If someone uses your work and then tries to sue you over related patents, their license automatically terminates.
* Permits commercial and non-commercial use.

---

## ONE-LINE PROJECT DESCRIPTION

TurtleFFT: Encrypted, ECC-protected steganography hidden in the phase of a 2D FFT and guided by a keyed turtlewalk across RGB frequency planes.
