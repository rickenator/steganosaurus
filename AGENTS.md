# TurtleFFT Agent Guidelines

Instructions for working within the Steganosaurus project. These guidelines apply to all files under this directory and its subdirectories.

---

## Project Overview

**TurtleFFT** is a C++17 frequency-domain steganography system. It hides encrypted data inside the phase of a 2D FFT of an image, guided by a keyed "turtle-walk" path derived from SHA256(passphrase). The system uses self-implemented cryptography (no external libraries): ChaCha20-Poly1305 AEAD, PBKDF2, HKDF, SHA-256.

**Build**: CMake (preferred) or one-line `g++ -std=c++17 -O3 -march=native`
**Dependencies**: None (stb_image/stb_image_write are bundled single-file headers)
**License**: Apache 2.0 with patent grant

---

## Build Instructions

### Recommended (CMake)
```bash
cd steganosaurus
mkdir -p build && cd build
cmake ..
cmake --build .
# Produces: build/turtlefft and build/turtlefft-key
```

### Quick Compile
```bash
cd steganosaurus
g++ -std=c++17 -O3 -march=native src/steganosaur.cpp -o turtlefft
```

### With Debug Output
```bash
cd steganosaurus/build
cmake .. -DCMAKE_CXX_FLAGS="-DDEBUG=1"
cmake --build .
```

---

## Testing Instructions

### Run Functional Tests
```bash
cd steganosaurus
../test_hardening.sh
```

### Run KDF Timing Tests
```bash
cd steganosaurus
../test_kdf_timing.sh
```

### Manual Quick Test (fast, not secure)
```bash
cd steganosaurus/build
./turtlefft embed --in host.png --out stego.png \
  --secret "hello world" --pass "test" --pbkdf2_iter 10000
./turtlefft extract --in stego.png --pass "test" --pbkdf2_iter 10000
# Expected: prints "hello world"
```

### Test Wrong Password (should fail fast)
```bash
./turtlefft extract --in stego.png --pass "wrong" --pbkdf2_iter 10000
# Expected: "Magic not found" or "Auth failed" (~0.1s)
```

---

## Code Structure

```
steganosaurus/
├── CMakeLists.txt            # Build config (turtlefft + turtlefft-key + chacha20poly1305 lib)
├── include/
│   ├── stb_image.h           # Image loading (single-file, public domain)
│   └── stb_image_write.h     # Image writing (single-file, public domain)
├── src/
│   ├── steganosaur.cpp       # Main implementation (1674 lines)
│   │   # SHA-256 (self-implemented)
│   │   # PBKDF2-HMAC-SHA256 (self-implemented)
│   │   # HKDF (self-implemented)
│   │   # 2D FFT (Cooley-Tukey)
│   │   # ECC: Repetition-3 (header), Hamming(7,4), Repetition-7 (payload)
│   │   # Turtlewalk: SHA256(pass) → stable strength-ranked deterministic bin path
│   │   # FFT region: centered in-image power-of-two tile for non-power-of-two covers
│   │   # Embed/extract: encrypt → ECC → turtlewalk → phase embed → IFFT / reverse
│   │   # CLI: embed, extract, gen-key modes
│   ├── crypto/
│   │   ├── crypto_utils.h    # Cross-platform helpers (CSPRNG, endian, secure_zero)
│   │   └── chacha20poly1305.cpp  # AEAD: ChaCha20 stream cipher + Poly1305 MAC
│   │   └── chacha20poly1305.h
│   └── tools/
│       ├── gen_png.cpp       # Test image generator (gradient + noise)
│       └── turtlefft-key.cpp # Key generation/wrapping CLI
├── build/                    # CMake output (gitignored)
└── .gitignore
```

---

## Coding Conventions

### General
- **C++17** — Use `auto`, `std::array`, `std::vector`, range-based for
- **Namespace `aead`** — All AEAD functions in `aead::` namespace
- **Namespace `crypto_utils`** — All crypto helpers in `crypto_utils::` namespace
- **No external dependencies** — Everything must be self-contained (no OpenSSL, Botan, etc.)
- **Single-file main** — `steganosaur.cpp` is intentionally one file; don't split it unless requested
- **GNU extensions OK** — Uses `<bits/stdc++.h>` and `__asm__` for secure zero (acceptable for crypto)

### Security
- **No external crypto libraries** — All crypto must be self-implemented and auditable
- **Secure memory wiping** — Use `crypto_utils::secure_zero()` for keys/nonces after use
- **Constant-time compare** — Use `crypto_utils::constant_time_compare()` for MAC verification
- **No `memcpy` for secrets** — Use `secure_zero` to wipe sensitive buffers
- **CSPRNG only** — Use `crypto_utils::get_random_bytes()` for all randomness
- **No debug output in production** — `#define DEBUG 0` in production builds

### Naming
- **Functions**: `snake_case` (e.g., `aead_chacha20_poly1305_encrypt`)
- **Types**: `PascalCase` (not currently used heavily)
- **Variables**: `snake_case` (e.g., `master_key`, `phase_amplitude`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `WRAPPED_KEY_MAGIC`)
- **Header guards**: `UPPER_CASE_H` (e.g., `CHACHA20POLY1305_H`)

### Crypto Implementation Rules
- **SHA-256**: Self-implemented in `steganosaur.cpp` — do not change unless fixing a bug
- **PBKDF2**: Self-implemented — only change iteration counts or salt handling
- **HKDF**: Self-implemented — use for key derivation; do not alter PRF or extract/expand
- **ChaCha20**: RFC 8439 compliant — quarter_round and block functions must not be changed
- **Poly1305**: RFC 8439 compliant — clamping and MAC computation must match RFC spec
- **Key format**: Always 32 bytes for ChaCha20 key, 12 bytes for nonce
- **Endianness**: Little-endian everywhere (load32_le, store32_le, store64_le)

### Embedding Protocol
- **Header**: `MAGIC(4) || SALT(32) || NONCE(12) || CLEN(4) || CT || TAG(16)`
- **ECC**: Repetition-3 for header bytes, Repetition-7 for payload bytes
- **Turtlewalk**: Stable strength-ranked bin path from SHA256(passphrase), annulus rmin=0.05, rmax=0.45; `--mag_rank 0` selects the legacy random walk
- **FFT region**: Non-power-of-two images use the largest centered power-of-two region inside the image; pixels outside that region are preserved in the PNG output
- **Phase embedding**: `φ_new = φ_old ± α` (absolute, default α=0.80) or QIM-relative (future)
- **RGB channels**: Independent keystreams (ks_r, ks_g, ks_b) with same bin path
- **Output format**: PNG (lossless) — JPEG destroys phase data

---

## File-Specific Notes

### `steganosaurus/src/steganosaur.cpp`
- **1674 lines** — the entire application in one file (QIM, cover hash, centered FFT region, stable ranked path)
- Contains: SHA-256, PBKDF2, HKDF, FFT, ECC, turtlewalk/ranked selection, embed, extract, CLI, gen-key
- **Line ranges** (for reference):
  - 1-100: Includes, stb_image/stb_image_write, SHA-256
  - 100-300: PBKDF2, HKDF, constant-time compare
  - 300-500: 2D FFT, transform-region helpers, complex number utilities
  - 500-700: ECC encoding/decoding (Rep-3, Hamming(7,4), Rep-7)
  - 700-870: Phase embedding and QIM (Quantization Index Modulation)
  - 870-1010: Turtlewalk path generation and stable strength-ranked bin selection
  - 1110-1330: `do_embed()` — FFT region, encrypt, ECC, phase embed, IFFT, save
  - 1340-1560: `do_extract()` — FFT region, extract phases, ECC decode, decrypt
  - 1560-1674: `do_gen_key()`, `main()`
- **DEBUG macro** (top of file): Defaults to 0 for production. Compile with `-DDEBUG=1` for verbose output.

### `steganosaurus/src/crypto/chacha20poly1305.cpp`
- **305 lines** — RFC 8439 ChaCha20-Poly1305 AEAD
- **Do not change** unless fixing a protocol bug
- Uses counter=0 for Poly1305 key generation, counter=1 for stream encryption
- AAD is authenticated alongside ciphertext via Poly1305 MAC

### `steganosaurus/src/crypto/crypto_utils.h`
- **562 lines** — cross-platform crypto helpers
- CSPRNG: Windows→BCryptGenRandom, Linux→getrandom(), macOS/BSD→arc4random_buf(), fallback→/dev/urandom
- Contains: `secure_zero()`, `load32_le()`, `store32_le()`, `load64_le()`, `store64_le()`, `get_random_bytes()`, `constant_time_compare()`, `base64_encode()`, `pbkdf2_hmac_sha256()`

### `steganosaurus/CMakeLists.txt`
- **25 lines** — defines 3 targets: `chacha20poly1305` (static lib), `turtlefft` (main), `turtlefft-key` (key tool)
- C++17 required

---

## Documentation

| File | Purpose |
|------|---------|
| `README.md` | User-facing documentation (build, usage, parameters) |
| `PLAN.md` | Development plan and recovery document (fresh sessions start here) |
| `PROJECT_STATUS.md` | Current project state, security posture, test results |
| `AGENTS.md` | Instructions for working within this project (this file) |
| `doc/SUMMARY.md` | Implementation summary (features, testing results) |
| `doc/HARDENING.md` | Security hardening analysis (detailed) |
| `doc/ATTACKS.md` | Adversarial red-team analysis (threat model) |
| `doc/TODO.md` | Development roadmap with priorities |
| `doc/TESTING.md` | Test suite documentation |
| `doc/PAPER.md` | Research/paper notes |

---

## Synchronous Documents — **MANDATORY**

**Every major step must update these documents. This is a hard requirement, not a suggestion.**

After every commit or significant change, update all of the following:
1. **PLAN.md** — Update status of completed/pending items; add to "Completed" section; update last-modified date
2. **PROJECT_STATUS.md** — Update test results, code metrics, known issues; update last-modified date and current commit hash
3. **doc/TODO.md** — Move completed items to "Recently Completed" section if applicable

Failure to keep these in sync is considered a defect. A fresh session **must** be able to reconstruct the full project state from these three files alone.

### Document Update Checklist
- [ ] `PLAN.md` — `Last updated` date, completed section, current commit, working directory status
- [ ] `PROJECT_STATUS.md` — `Last updated` date, current commit, test results, build status, code metrics
- [ ] `doc/TODO.md` — Completed items moved to "Recently Completed"
- [ ] `AGENTS.md` — Updated any defaults, line counts, or conventions that changed

### Branch & Sync Workflow
- **Branch naming**: Use `update_YYMMDD` format for feature branches (e.g., `update_070626`)
- **Sync before push**: After every commit, update PLAN.md, PROJECT_STATUS.md, and doc/TODO.md
- **Push to origin**: Always push new branches with `-u origin <branch>` so GitHub PR can be created
- **PR creation**: Use the remote URL provided by `git push` output (e.g., `https://github.com/rickenator/steganosaurus/pull/new/update_070626`)
- **Current branch**: `update_070626` — JPEG robustness and arbitrary-size reliability workflow (HEAD `09a2bc5`, uncommitted FFT-region/ranked-path fix)

---

## Recovery Guide (If Session Crashes)

A fresh session should:
1. Read **PLAN.md** first — it contains the full project state, recovery checklist, and next steps
2. Read **PROJECT_STATUS.md** — security posture, build/test status, known issues
3. Read **AGENTS.md** — coding conventions, code structure, file-specific notes
4. Run `git status` — check uncommitted/untracked changes
5. Run `git log --oneline -20` — check recent commits
6. Verify build: `cd steganosaurus && mkdir -p build && cd build && cmake .. && cmake --build .`
7. Run tests: `cd steganosaurus && ../test_hardening.sh`

---

## Common Tasks

### Fix a bug in steganosaur.cpp
1. Read the relevant section (see line ranges above)
2. Make targeted fix — do not reformat or refactor unrelated code
3. Build: `cd steganosaurus/build && cmake --build .`
4. Test: manual embed/extract round-trip with `--pbkdf2_iter 10000`
5. Run full test suite: `../test_hardening.sh` from `steganosaurus/`
6. Update PROJECT_STATUS.md and PLAN.md if needed

### Add a new CLI option
1. Add to `Args` struct (around line ~1300)
2. Add to `parse_args()` (around line ~1340)
3. Implement in the relevant handler (`do_embed`, `do_extract`, or `do_gen_key`)
4. Update README.md with documentation
5. Add test to `test_hardening.sh`

### Modify crypto code
1. **Never** change the public API of `chacha20poly1305.cpp` unless fixing a bug
2. Changes to crypto must be validated against RFC 8439
3. Run test_wrong_password to verify authentication still works
4. Run timing test to verify constant-time behavior is preserved

### Add a test image
1. Place in `test_images/` directory
2. Note dimensions and approximate capacity in PROJECT_STATUS.md
3. Test embed/extract with the image
