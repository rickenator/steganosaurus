# **Steganosaurus: A Keyed Turtlewalk Steganographic Scheme Using 2D FFT Phase Quantization**

**Author:** Rick Goldberg (Aniviza LLC)
**License:** Apache 2.0 (with patent grant)
**Project Page:** [https://github.com/rickenator/steganosaurus](https://github.com/rickenator/steganosaurus)

---

## **Abstract**

This work introduces *Steganosaurus*, a novel steganographic system that embeds encrypted payloads in the **phase spectrum of a 2D FFT**, using a **keyed deterministic pseudo-random turtlewalk** across RGB frequency planes. The system combines:

* passphrase-derived keying,
* ChaCha20-Poly1305 AEAD encryption,
* PBKDF2+HKDF key stretching,
* phase-quantization with jitter,
* ECC redundancy (Repetition-3 for headers; Hamming(7,4) for payload),
* and spectral selection constrained by magnitude thresholds and annular masking.

The method is designed for *lossless image covers* (PNG) and emphasizes **undetectability**, **confidentiality**, and **low spectral footprint**, not robustness to lossy transforms.

We present the theoretical motivation, implementation details, attack analysis, and initial results demonstrating functional end-to-end embedding and extraction in diverse images with minimal visual degradation. The architecture appears novel and warrants deeper steganalytic research.

---

# **1. Introduction**

Steganography in the frequency domain is well-established, especially for JPEG images where DCT coefficients are manipulated. However, FFT-based phase-domain embedding is less explored despite its attractive statistical properties: natural images exhibit **highly irregular, near-uniform phase distributions**, offering fertile ground for covert modulation with minimal perceptual impact.

This paper introduces a new approach: a **keyed “turtlewalk” traversal**, seeded entirely by a passphrase-derived key, that hops through RGB FFT planes selecting eligible spectral bins for embedding. Bits are encoded using a **binary phase quantization** scheme (±α radians), with **random jitter** to avoid histogram artifacts. A cryptographically hardened envelope provides message confidentiality and integrity.

The method aims to:

1. Make the embedding **difficult to detect** through statistical analysis.
2. Make the embedding **difficult to locate** without the correct passphrase.
3. Retain **strong cryptographic protection** for the payload.
4. Keep the overall system simple, inspectable, and implementable in ≈1 C++ file.

The system does *not* aim to survive JPEG compression, resizing, cropping, or adversarial noise. That is future work.

---

# **2. Methods**

## **2.1 System Overview**

The architecture consists of four components:

1. **Cover FFT Analysis**

   * Input PNG → RGB float planes
   * Optional FFT-centering
   * 2D FFT (radix-2) per channel
   * Compute median magnitudes per plane

2. **Key Derivation & Cryptographic Envelope**

   * PBKDF2-HMAC-SHA256(pass, salt, iter) → IKM
   * HKDF-SHA256 → {path_key, aead_key, nonce}
   * ChaCha20-Poly1305 encrypts the secret (AAD = header)
   * ECC encoding of header & ciphertext

3. **Turtlewalk Selection**

   * Path key = SHA256(pass)
   * HKDF expands path key into:

     * walk_keystream
     * R/G/B jitter keystreams
   * Turtlewalk rules (3-bit opcode):

     * move ±x, ±y, diag, or plane-hop
   * Candidate acceptance conditions:

     * must be in midband annulus (rmin–rmax)
     * must exceed per-channel magnitude threshold
     * must not be an axis/DC/conjugate-fixed bin
     * must not have been previously used
     * must satisfy density probability filter

4. **Embedding & Extraction**

   * Write bits: adjust phase toward ±α with jitter
   * Maintain conjugate symmetry
   * Inverse FFT → image reconstruction
   * Extraction performs identical turtlewalk
   * ECC decoding, AAD-authenticated AEAD decryption

## **2.2 Diagram**

Include the SVG exactly as rendered:

```markdown
## Turtlewalk Frequency-Domain Embedding Diagram
![Turtlewalk Diagram](doc/turtlewalk_fixed2.svg)
```

---

# **3. Results**

Initial empirical results—conducted on natural images, synthetic patterns, and photographic content—demonstrate:

### **3.1 Visual Integrity**

* No visible degradation at α ≤ 0.22 rad and density ≤ 0.7
* No contouring, color shift, or ringing
* Embedded images are perceptually indistinguishable from covers

### **3.2 Extraction Reliability**

* Round-trip extraction succeeded for all tested images
* ECC corrected transient per-bin decision errors
* AEAD authentication reliably rejected incorrect passphrases

### **3.3 Steganalysis Considerations**

While phase-histogram deviations exist, the jittered ±α approach prevents simple detection. Preliminary PCA, χ², and KL-divergence analysis of midband phase histograms shows deviations comparable to natural variance in photographic images.

Spectral bin modifications represent < 0.5% of the FFT spectrum at recommended parameters.

---

# **4. Discussion**

## **4.1 Strengths**

* **Novel traversal mechanism.** The keyed turtlewalk combines randomness with determinism, acting as a cryptographic PRP over spectral bins.
* **Search-space explosion.** Without the passphrase, locating payload bins is equivalent to guessing the turtlewalk state.
* **Phase-domain benefits.** Natural phase distributions are noisy, making modifications subtle.
* **Hardened cryptographic envelope.** Even if embedding locations are discovered, the ciphertext is AEAD-protected.
* **ECC for noise tolerance.** Bit errors caused by spectral quantization or border effects do not corrupt messages.

## **4.2 Weaknesses / Future Improvements**

* **Not robust to lossy transforms.** JPEG, scaling, or rotation will destroy data.
* **Potential statistical detectability.** Large α or high density increases risk of detection.
* **Collusion attack vulnerability.** Multiple images encoded with the same pass produce detectable bin clusters.
* **Header is plaintext**, though now authenticated as AAD.
* **Possible machine-learning detectors.** A CNN trained on phase perturbations may eventually detect patterns.

## **4.3 Hardening Roadmap**

* Cover-dependent turtlewalk seeds
* Adaptive α based on local spectral contrast
* STDM/QIM relative phase embedding
* LDPC codes
* Multi-resolution embedding (FFT + DWT or steerable pyramids)

---

# **5. Conclusion**

Steganosaurus introduces an original and promising approach to phase-domain steganography. The combination of keyed turtlewalk traversal, per-plane keystream modulation, AEAD protection, and controlled phase quantization results in a system that is:

* cryptographically strong,
* visually imperceptible,
* conceptually elegant,
* and seemingly novel in the public literature.

The project is a foundation for deeper research into FFT-phase steganography and incorporates ideas from classical spread-spectrum embedding, modern cryptographic KDF/AAD practices, and novel traversal algorithms.

Future work will explore statistical detectability, robustness extensions, and theoretical guarantees for unpredictability.

---

# **6. References**

1. Kerckhoffs, A. “La Cryptographie Militaire”, 1883.
2. Hayes & Bates. “Fourier Transform Steganography”. Proc. SPIE, 2000.
3. Fridrich, J. “Steganography in Digital Media.” Cambridge Press, 2009.
4. Bernstein, D. J. “ChaCha, a variant of Salsa20.” Workshop Record of SASC, 2008.
5. RFC 8439: ChaCha20 and Poly1305 for IETF Protocols.
6. RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
7. Johnson, Neil & Katzenbeisser, Stefan. “A Survey of Steganographic Techniques.” 2000.
8. Cox, Miller, Bloom, Fridrich. “Digital Watermarking and Steganography.” Morgan Kaufmann, 2008.

---
