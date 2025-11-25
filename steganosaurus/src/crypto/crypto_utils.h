// crypto_utils.h - Portable, dependency-free cryptographic utilities
// Single-header library providing:
// - OS CSPRNG access (get_random_bytes)
// - SHA-256, HMAC-SHA256, HKDF (RFC 5869)
// - PBKDF2-HMAC-SHA256
// - Base64 encode/decode
// - Utility helpers (secure_zero, sha256_hex)
//
// Uses only standard C/C++ and OS APIs (no third-party libraries)

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>
#include <vector>
#include <string>
#include <algorithm>
#include <stdexcept>

// Platform detection for CSPRNG
#if defined(_WIN32) || defined(_WIN64)
#define CRYPTO_UTILS_WINDOWS
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__linux__)
#define CRYPTO_UTILS_LINUX
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
#include <sys/random.h>
#define CRYPTO_UTILS_HAS_GETRANDOM
#endif
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#define CRYPTO_UTILS_BSD
#include <stdlib.h>
#endif

namespace crypto_utils {

// ============================================================================
// Secure memory operations
// ============================================================================

/**
 * Securely zeroes memory to prevent sensitive data leakage.
 * Uses volatile to prevent compiler optimization.
 */
inline void secure_zero(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;
}

/**
 * Constant-time comparison to prevent timing attacks.
 */
inline bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    return diff == 0;
}

// ============================================================================
// Endian helpers (portable)
// ============================================================================

inline uint32_t load32_le(const void* p) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    return static_cast<uint32_t>(b[0]) |
           (static_cast<uint32_t>(b[1]) << 8) |
           (static_cast<uint32_t>(b[2]) << 16) |
           (static_cast<uint32_t>(b[3]) << 24);
}

inline void store32_le(uint32_t v, void* p) {
    uint8_t* b = static_cast<uint8_t*>(p);
    b[0] = static_cast<uint8_t>(v & 0xFF);
    b[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    b[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    b[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

inline uint64_t load64_le(const void* p) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    return static_cast<uint64_t>(b[0]) |
           (static_cast<uint64_t>(b[1]) << 8) |
           (static_cast<uint64_t>(b[2]) << 16) |
           (static_cast<uint64_t>(b[3]) << 24) |
           (static_cast<uint64_t>(b[4]) << 32) |
           (static_cast<uint64_t>(b[5]) << 40) |
           (static_cast<uint64_t>(b[6]) << 48) |
           (static_cast<uint64_t>(b[7]) << 56);
}

inline void store64_le(uint64_t v, void* p) {
    uint8_t* b = static_cast<uint8_t*>(p);
    for (int i = 0; i < 8; i++) {
        b[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
    }
}

// ============================================================================
// OS CSPRNG - Cryptographically Secure Random Number Generator
// ============================================================================

/**
 * Fills the buffer with cryptographically secure random bytes.
 * Uses OS-provided CSPRNG:
 * - Windows: BCryptGenRandom
 * - Linux: getrandom() syscall (or /dev/urandom fallback)
 * - macOS/BSD: arc4random_buf
 * 
 * @param buf Output buffer to fill with random bytes
 * @param len Number of random bytes to generate
 * @return true on success, false on failure
 */
inline bool get_random_bytes(uint8_t* buf, size_t len) {
    if (len == 0) return true;
    if (!buf) return false;

#if defined(CRYPTO_UTILS_WINDOWS)
    // Windows: Use BCryptGenRandom
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        buf,
        static_cast<ULONG>(len),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    return BCRYPT_SUCCESS(status);

#elif defined(CRYPTO_UTILS_BSD)
    // macOS, FreeBSD, OpenBSD: arc4random_buf never fails
    arc4random_buf(buf, len);
    return true;

#elif defined(CRYPTO_UTILS_LINUX)
    // Linux: Try getrandom() first, then fall back to /dev/urandom
#if defined(CRYPTO_UTILS_HAS_GETRANDOM)
    // Use glibc wrapper if available
    ssize_t result = getrandom(buf, len, 0);
    if (result == static_cast<ssize_t>(len)) {
        return true;
    }
#elif defined(SYS_getrandom)
    // Try syscall directly
    ssize_t result = syscall(SYS_getrandom, buf, len, 0);
    if (result == static_cast<ssize_t>(len)) {
        return true;
    }
#endif
    // Fallback to /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    size_t total = 0;
    while (total < len) {
        ssize_t r = read(fd, buf + total, len - total);
        if (r <= 0) {
            close(fd);
            return false;
        }
        total += static_cast<size_t>(r);
    }
    close(fd);
    return true;

#else
    // Unknown platform: try /dev/urandom as last resort
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) return false;
    bool ok = (fread(buf, 1, len, f) == len);
    fclose(f);
    return ok;
#endif
}

/**
 * Convenience overload for std::array
 */
template<size_t N>
inline bool get_random_bytes(std::array<uint8_t, N>& buf) {
    return get_random_bytes(buf.data(), N);
}

/**
 * Convenience overload for std::vector (fills entire vector)
 */
inline bool get_random_bytes(std::vector<uint8_t>& buf) {
    return get_random_bytes(buf.data(), buf.size());
}

// ============================================================================
// SHA-256 Implementation (FIPS 180-4)
// ============================================================================

namespace sha256_impl {

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t bsig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint32_t bsig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
inline uint32_t ssig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
inline uint32_t ssig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

} // namespace sha256_impl

/**
 * Computes SHA-256 hash of input data.
 * @param data Input data
 * @param len Length of input data
 * @return 32-byte hash
 */
inline std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len) {
    using namespace sha256_impl;
    
    // Padding
    std::vector<uint8_t> m(data, data + len);
    uint64_t bitlen = static_cast<uint64_t>(len) * 8;
    m.push_back(0x80);
    while ((m.size() + 8) % 64 != 0) m.push_back(0);
    for (int i = 7; i >= 0; --i) m.push_back(static_cast<uint8_t>(bitlen >> (8 * i)));
    
    // Initial hash values
    uint32_t H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    // Process each 512-bit block
    for (size_t off = 0; off < m.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(m[off + 4*i]) << 24) |
                   (static_cast<uint32_t>(m[off + 4*i + 1]) << 16) |
                   (static_cast<uint32_t>(m[off + 4*i + 2]) << 8) |
                   static_cast<uint32_t>(m[off + 4*i + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = ssig1(w[i-2]) + w[i-7] + ssig0(w[i-15]) + w[i-16];
        }
        
        uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
        uint32_t e = H[4], f = H[5], g = H[6], h = H[7];
        
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + bsig1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = bsig0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        
        H[0] += a; H[1] += b; H[2] += c; H[3] += d;
        H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    
    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 8; ++i) {
        out[4*i + 0] = static_cast<uint8_t>((H[i] >> 24) & 0xFF);
        out[4*i + 1] = static_cast<uint8_t>((H[i] >> 16) & 0xFF);
        out[4*i + 2] = static_cast<uint8_t>((H[i] >> 8) & 0xFF);
        out[4*i + 3] = static_cast<uint8_t>(H[i] & 0xFF);
    }
    return out;
}

inline std::array<uint8_t, 32> sha256(const std::string& s) {
    return sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

inline std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& v) {
    return sha256(v.data(), v.size());
}

// ============================================================================
// HMAC-SHA-256 (RFC 2104)
// ============================================================================

/**
 * Computes HMAC-SHA-256.
 * @param key HMAC key
 * @param key_len Length of key
 * @param msg Message to authenticate
 * @param msg_len Length of message
 * @param out Output buffer (32 bytes)
 */
inline void hmac_sha256(const uint8_t* key, size_t key_len,
                        const uint8_t* msg, size_t msg_len,
                        uint8_t out[32]) {
    uint8_t k0[64] = {0};
    
    if (key_len > 64) {
        auto h = sha256(key, key_len);
        std::memcpy(k0, h.data(), 32);
    } else {
        std::memcpy(k0, key, key_len);
    }
    
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    
    std::vector<uint8_t> inner(64 + msg_len);
    std::memcpy(inner.data(), ipad, 64);
    std::memcpy(inner.data() + 64, msg, msg_len);
    auto hi = sha256(inner.data(), inner.size());
    
    uint8_t tmp[64 + 32];
    std::memcpy(tmp, opad, 64);
    std::memcpy(tmp + 64, hi.data(), 32);
    auto ho = sha256(tmp, 96);
    
    std::memcpy(out, ho.data(), 32);
    
    // Clean up sensitive data
    secure_zero(k0, sizeof(k0));
    secure_zero(ipad, sizeof(ipad));
    secure_zero(opad, sizeof(opad));
    secure_zero(inner.data(), inner.size());
    secure_zero(tmp, sizeof(tmp));
}

inline std::array<uint8_t, 32> hmac_sha256(const uint8_t* key, size_t key_len,
                                           const uint8_t* msg, size_t msg_len) {
    std::array<uint8_t, 32> out;
    hmac_sha256(key, key_len, msg, msg_len, out.data());
    return out;
}

// ============================================================================
// HKDF (RFC 5869) - HMAC-based Key Derivation Function
// ============================================================================

/**
 * HKDF-Extract: Extract a pseudorandom key from input keying material.
 * @param salt Optional salt (can be nullptr, defaults to all zeros)
 * @param salt_len Length of salt
 * @param ikm Input keying material
 * @param ikm_len Length of IKM
 * @param prk Output pseudorandom key (32 bytes)
 */
inline void hkdf_extract(const uint8_t* salt, size_t salt_len,
                         const uint8_t* ikm, size_t ikm_len,
                         uint8_t prk[32]) {
    uint8_t default_salt[32] = {0};
    if (salt == nullptr || salt_len == 0) {
        salt = default_salt;
        salt_len = 32;
    }
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

/**
 * HKDF-Expand: Expand the PRK to the desired length.
 * @param prk Pseudorandom key (32 bytes)
 * @param info Optional context info
 * @param info_len Length of info
 * @param out Output buffer
 * @param out_len Desired output length (max 255 * 32 = 8160 bytes)
 */
inline void hkdf_expand(const uint8_t prk[32],
                        const uint8_t* info, size_t info_len,
                        uint8_t* out, size_t out_len) {
    if (out_len > 255 * 32) {
        throw std::runtime_error("HKDF output too long");
    }
    
    uint8_t T[32];
    size_t T_len = 0;
    uint8_t ctr = 1;
    size_t pos = 0;
    
    while (pos < out_len) {
        std::vector<uint8_t> msg(T, T + T_len);
        if (info && info_len > 0) {
            msg.insert(msg.end(), info, info + info_len);
        }
        msg.push_back(ctr);
        hmac_sha256(prk, 32, msg.data(), msg.size(), T);
        T_len = 32;
        
        size_t need = std::min(static_cast<size_t>(32), out_len - pos);
        std::memcpy(out + pos, T, need);
        pos += need;
        ctr++;
    }
    
    secure_zero(T, sizeof(T));
}

/**
 * Combined HKDF (Extract + Expand).
 */
inline void hkdf(const uint8_t* salt, size_t salt_len,
                 const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len) {
    uint8_t prk[32];
    hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    hkdf_expand(prk, info, info_len, out, out_len);
    secure_zero(prk, sizeof(prk));
}

// ============================================================================
// PBKDF2-HMAC-SHA-256 (RFC 8018)
// ============================================================================

/**
 * PBKDF2 key derivation with HMAC-SHA-256.
 * @param password Password/passphrase
 * @param pass_len Password length
 * @param salt Salt value
 * @param salt_len Salt length
 * @param iterations Number of iterations (recommended: 600000+)
 * @param out Output derived key
 * @param dk_len Desired derived key length
 */
inline void pbkdf2_hmac_sha256(const uint8_t* password, size_t pass_len,
                               const uint8_t* salt, size_t salt_len,
                               uint32_t iterations,
                               uint8_t* out, size_t dk_len) {
    uint32_t blocks = static_cast<uint32_t>((dk_len + 31) / 32);
    std::vector<uint8_t> U(32), T(32);
    
    for (uint32_t i = 1; i <= blocks; i++) {
        // U1 = HMAC(password, salt || INT(i))
        std::vector<uint8_t> msg(salt, salt + salt_len);
        uint8_t be[4] = {
            static_cast<uint8_t>(i >> 24),
            static_cast<uint8_t>(i >> 16),
            static_cast<uint8_t>(i >> 8),
            static_cast<uint8_t>(i)
        };
        msg.insert(msg.end(), be, be + 4);
        hmac_sha256(password, pass_len, msg.data(), msg.size(), U.data());
        std::memcpy(T.data(), U.data(), 32);
        
        for (uint32_t j = 2; j <= iterations; j++) {
            hmac_sha256(password, pass_len, U.data(), 32, U.data());
            for (int k = 0; k < 32; k++) T[k] ^= U[k];
        }
        
        size_t off = static_cast<size_t>(i - 1) * 32;
        size_t need = std::min(static_cast<size_t>(32), dk_len - off);
        std::memcpy(out + off, T.data(), need);
    }
    
    secure_zero(U.data(), U.size());
    secure_zero(T.data(), T.size());
}

inline void pbkdf2_hmac_sha256(const std::string& password,
                               const std::vector<uint8_t>& salt,
                               uint32_t iterations,
                               uint8_t* out, size_t dk_len) {
    pbkdf2_hmac_sha256(
        reinterpret_cast<const uint8_t*>(password.data()), password.size(),
        salt.data(), salt.size(),
        iterations,
        out, dk_len
    );
}

// ============================================================================
// Base64 Encoding/Decoding (RFC 4648)
// ============================================================================

namespace base64_impl {
    static const char encode_table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    static const int8_t decode_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 0-15
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  // 16-31
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  // 32-47 (+, /)
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,  // 48-63 (0-9, =)
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  // 64-79 (A-O)
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  // 80-95 (P-Z)
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  // 96-111 (a-o)
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  // 112-127 (p-z)
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
}

/**
 * Encodes data to Base64.
 * @param data Input data
 * @param len Length of input data
 * @return Base64 encoded string
 */
inline std::string base64_encode(const uint8_t* data, size_t len) {
    using namespace base64_impl;
    std::string result;
    result.reserve(((len + 2) / 3) * 4);
    
    size_t i = 0;
    while (i + 2 < len) {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i+1]) << 8) |
                     static_cast<uint32_t>(data[i+2]);
        result += encode_table[(n >> 18) & 0x3F];
        result += encode_table[(n >> 12) & 0x3F];
        result += encode_table[(n >> 6) & 0x3F];
        result += encode_table[n & 0x3F];
        i += 3;
    }
    
    if (i + 1 == len) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        result += encode_table[(n >> 18) & 0x3F];
        result += encode_table[(n >> 12) & 0x3F];
        result += '=';
        result += '=';
    } else if (i + 2 == len) {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i+1]) << 8);
        result += encode_table[(n >> 18) & 0x3F];
        result += encode_table[(n >> 12) & 0x3F];
        result += encode_table[(n >> 6) & 0x3F];
        result += '=';
    }
    
    return result;
}

inline std::string base64_encode(const std::vector<uint8_t>& data) {
    return base64_encode(data.data(), data.size());
}

inline std::string base64_encode(const std::array<uint8_t, 32>& data) {
    return base64_encode(data.data(), data.size());
}

/**
 * Decodes Base64 string to binary data.
 * @param input Base64 encoded string
 * @param output Output vector for decoded data
 * @return true on success, false on invalid input
 */
inline bool base64_decode(const std::string& input, std::vector<uint8_t>& output) {
    using namespace base64_impl;
    
    if (input.empty()) {
        output.clear();
        return true;
    }
    
    // Check valid length
    if (input.size() % 4 != 0) {
        return false;
    }
    
    output.reserve((input.size() / 4) * 3);
    
    for (size_t i = 0; i < input.size(); i += 4) {
        int8_t a = decode_table[static_cast<uint8_t>(input[i])];
        int8_t b = decode_table[static_cast<uint8_t>(input[i+1])];
        int8_t c = decode_table[static_cast<uint8_t>(input[i+2])];
        int8_t d = decode_table[static_cast<uint8_t>(input[i+3])];
        
        // Invalid character check
        if (a == -1 || b == -1 || (c == -1 && input[i+2] != '=') || (d == -1 && input[i+3] != '=')) {
            return false;
        }
        
        // Handle padding
        if (c == -2) c = 0; // '=' padding
        if (d == -2) d = 0;
        
        uint32_t n = (static_cast<uint32_t>(a) << 18) |
                     (static_cast<uint32_t>(b) << 12) |
                     (static_cast<uint32_t>(c) << 6) |
                     static_cast<uint32_t>(d);
        
        output.push_back(static_cast<uint8_t>((n >> 16) & 0xFF));
        if (input[i+2] != '=') {
            output.push_back(static_cast<uint8_t>((n >> 8) & 0xFF));
        }
        if (input[i+3] != '=') {
            output.push_back(static_cast<uint8_t>(n & 0xFF));
        }
    }
    
    return true;
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Converts SHA-256 hash to hexadecimal string.
 * @param hash 32-byte hash
 * @return 64-character hex string
 */
inline std::string sha256_hex(const std::array<uint8_t, 32>& hash) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (uint8_t b : hash) {
        result += hex_chars[(b >> 4) & 0xF];
        result += hex_chars[b & 0xF];
    }
    return result;
}

/**
 * Computes SHA-256 hash and returns hex string.
 */
inline std::string sha256_hex(const uint8_t* data, size_t len) {
    return sha256_hex(sha256(data, len));
}

/**
 * Generates a key fingerprint (first 8 bytes of SHA-256 in hex).
 * @param key 32-byte key
 * @return 16-character hex fingerprint
 */
inline std::string key_fingerprint(const std::array<uint8_t, 32>& key) {
    auto hash = sha256(key.data(), key.size());
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(16);
    for (size_t i = 0; i < 8; i++) {
        result += hex_chars[(hash[i] >> 4) & 0xF];
        result += hex_chars[hash[i] & 0xF];
    }
    return result;
}

} // namespace crypto_utils

#endif // CRYPTO_UTILS_H
