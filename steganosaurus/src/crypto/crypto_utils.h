// crypto_utils.h
// Cross-platform crypto helpers for TurtleFFT
// Dependency-free, portable implementations

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>
#include <vector>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <stdlib.h>
#endif
#endif

namespace crypto_utils {

// ============================ Secure Zero ====================================
/**
 * Securely zero memory to prevent sensitive data leakage.
 * Uses volatile pointer to prevent compiler optimization.
 */
inline void secure_zero(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;
}

// ============================ Endian Helpers =================================
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

// ============================ OS CSPRNG ======================================
/**
 * Cross-platform cryptographically secure random bytes.
 * Uses:
 * - Windows: BCryptGenRandom
 * - Linux: getrandom()
 * - macOS/BSD: arc4random_buf()
 * - Fallback: /dev/urandom
 */
inline bool get_random_bytes(uint8_t* buf, size_t len) {
    if (len == 0) return true;
    
#ifdef _WIN32
    // Windows: Use BCryptGenRandom
    NTSTATUS status = BCryptGenRandom(
        NULL,
        buf,
        static_cast<ULONG>(len),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    return status == 0; // STATUS_SUCCESS
#elif defined(__linux__)
    // Linux: Use getrandom() syscall
    size_t remaining = len;
    uint8_t* ptr = buf;
    while (remaining > 0) {
        ssize_t result = getrandom(ptr, remaining, 0);
        if (result < 0) {
            // Fallback to /dev/urandom on error
            break;
        }
        remaining -= static_cast<size_t>(result);
        ptr += result;
    }
    if (remaining == 0) return true;
    // Fallback to /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    while (remaining > 0) {
        ssize_t result = read(fd, ptr, remaining);
        if (result <= 0) {
            close(fd);
            return false;
        }
        remaining -= static_cast<size_t>(result);
        ptr += result;
    }
    close(fd);
    return true;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    // macOS/BSD: Use arc4random_buf
    arc4random_buf(buf, len);
    return true;
#else
    // Fallback: /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    size_t remaining = len;
    uint8_t* ptr = buf;
    while (remaining > 0) {
        ssize_t result = read(fd, ptr, remaining);
        if (result <= 0) {
            close(fd);
            return false;
        }
        remaining -= static_cast<size_t>(result);
        ptr += result;
    }
    close(fd);
    return true;
#endif
}

// ============================ SHA-256 ========================================
namespace sha256_impl {

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t bs0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint32_t bs1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
inline uint32_t ss0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
inline uint32_t ss1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

} // namespace sha256_impl

/**
 * Compute SHA-256 hash of data.
 */
inline std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len) {
    using namespace sha256_impl;
    
    std::vector<uint8_t> m(data, data + len);
    uint64_t bitlen = static_cast<uint64_t>(len) * 8;
    m.push_back(0x80);
    while ((m.size() + 8) % 64) m.push_back(0);
    for (int i = 7; i >= 0; --i) {
        m.push_back(static_cast<uint8_t>(bitlen >> (8 * i)));
    }
    
    uint32_t H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    for (size_t off = 0; off < m.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(m[off + 4*i]) << 24) |
                   (static_cast<uint32_t>(m[off + 4*i + 1]) << 16) |
                   (static_cast<uint32_t>(m[off + 4*i + 2]) << 8) |
                   static_cast<uint32_t>(m[off + 4*i + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = ss1(w[i-2]) + w[i-7] + ss0(w[i-15]) + w[i-16];
        }
        
        uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
        uint32_t e = H[4], f = H[5], g = H[6], h = H[7];
        
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + bs1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = bs0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        
        H[0] += a; H[1] += b; H[2] += c; H[3] += d;
        H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    
    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 8; ++i) {
        out[4*i + 0] = (H[i] >> 24) & 0xFF;
        out[4*i + 1] = (H[i] >> 16) & 0xFF;
        out[4*i + 2] = (H[i] >> 8) & 0xFF;
        out[4*i + 3] = H[i] & 0xFF;
    }
    return out;
}

inline std::array<uint8_t, 32> sha256(const std::string& s) {
    return sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

/**
 * Convert SHA-256 hash to hexadecimal string.
 */
inline std::string sha256_hex(const uint8_t* data, size_t len) {
    auto hash = sha256(data, len);
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (uint8_t b : hash) {
        result.push_back(hex[b >> 4]);
        result.push_back(hex[b & 0x0F]);
    }
    return result;
}

inline std::string sha256_hex(const std::string& s) {
    return sha256_hex(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// ============================ HMAC-SHA256 ====================================
/**
 * HMAC-SHA256 (RFC 2104)
 */
inline void hmac_sha256(const uint8_t* key, size_t klen,
                        const uint8_t* msg, size_t mlen,
                        uint8_t out[32]) {
    uint8_t k0[64] = {0};
    
    if (klen > 64) {
        auto h = sha256(key, klen);
        std::memcpy(k0, h.data(), 32);
    } else {
        std::memcpy(k0, key, klen);
    }
    
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    
    std::vector<uint8_t> inner(64 + mlen);
    std::memcpy(inner.data(), ipad, 64);
    std::memcpy(inner.data() + 64, msg, mlen);
    auto hi = sha256(inner.data(), inner.size());
    
    uint8_t tmp[64 + 32];
    std::memcpy(tmp, opad, 64);
    std::memcpy(tmp + 64, hi.data(), 32);
    auto ho = sha256(tmp, 96);
    
    std::memcpy(out, ho.data(), 32);
    
    // Secure cleanup
    secure_zero(k0, sizeof(k0));
    secure_zero(ipad, sizeof(ipad));
    secure_zero(opad, sizeof(opad));
    secure_zero(inner.data(), inner.size());
    secure_zero(tmp, sizeof(tmp));
}

// ============================ HKDF (RFC 5869) ================================
/**
 * HKDF-Extract using HMAC-SHA256.
 * If salt is null, uses a string of zeros.
 */
inline void hkdf_extract(const uint8_t* salt, size_t salt_len,
                         const uint8_t* ikm, size_t ikm_len,
                         uint8_t prk[32]) {
    if (salt == nullptr || salt_len == 0) {
        uint8_t zero_salt[32] = {0};
        hmac_sha256(zero_salt, 32, ikm, ikm_len, prk);
    } else {
        hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    }
}

/**
 * HKDF-Expand using HMAC-SHA256.
 */
inline void hkdf_expand(const uint8_t prk[32],
                        const uint8_t* info, size_t info_len,
                        uint8_t* out, size_t out_len) {
    uint8_t T[32];
    size_t T_len = 0;
    uint8_t ctr = 1;
    size_t pos = 0;
    
    while (pos < out_len) {
        std::vector<uint8_t> msg(T, T + T_len);
        msg.insert(msg.end(), info, info + info_len);
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
 * Full HKDF (Extract + Expand).
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

// ============================ PBKDF2-HMAC-SHA256 =============================
/**
 * PBKDF2-HMAC-SHA256 (RFC 8018)
 */
inline void pbkdf2_hmac_sha256(const uint8_t* pass, size_t pass_len,
                               const uint8_t* salt, size_t salt_len,
                               uint32_t iterations,
                               uint8_t* out, size_t dk_len) {
    uint32_t blocks = static_cast<uint32_t>((dk_len + 31) / 32);
    std::vector<uint8_t> U(32), T(32);
    
    for (uint32_t i = 1; i <= blocks; i++) {
        // U1 = HMAC(pass, salt || INT(i))
        std::vector<uint8_t> msg(salt, salt + salt_len);
        uint8_t be[4] = {
            static_cast<uint8_t>(i >> 24),
            static_cast<uint8_t>(i >> 16),
            static_cast<uint8_t>(i >> 8),
            static_cast<uint8_t>(i)
        };
        msg.insert(msg.end(), be, be + 4);
        hmac_sha256(pass, pass_len, msg.data(), msg.size(), U.data());
        std::memcpy(T.data(), U.data(), 32);
        
        for (uint32_t j = 2; j <= iterations; j++) {
            hmac_sha256(pass, pass_len, U.data(), 32, U.data());
            for (int k = 0; k < 32; k++) {
                T[k] ^= U[k];
            }
        }
        
        size_t off = static_cast<size_t>(i - 1) * 32;
        size_t need = std::min(static_cast<size_t>(32), dk_len - off);
        std::memcpy(out + off, T.data(), need);
    }
    
    secure_zero(U.data(), U.size());
    secure_zero(T.data(), T.size());
}

inline void pbkdf2_hmac_sha256(const std::string& pass,
                               const std::vector<uint8_t>& salt,
                               uint32_t iterations,
                               uint8_t* out, size_t dk_len) {
    pbkdf2_hmac_sha256(
        reinterpret_cast<const uint8_t*>(pass.data()), pass.size(),
        salt.data(), salt.size(),
        iterations, out, dk_len
    );
}

// ============================ Base64 =========================================
namespace base64_impl {

constexpr char ENCODE_TABLE[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

constexpr int8_t DECODE_TABLE[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

} // namespace base64_impl

/**
 * Encode binary data to base64 string.
 */
inline std::string base64_encode(const uint8_t* data, size_t len) {
    using namespace base64_impl;
    
    std::string result;
    result.reserve(((len + 2) / 3) * 4);
    
    size_t i = 0;
    while (i + 2 < len) {
        uint32_t triplet = (static_cast<uint32_t>(data[i]) << 16) |
                           (static_cast<uint32_t>(data[i + 1]) << 8) |
                           static_cast<uint32_t>(data[i + 2]);
        result.push_back(ENCODE_TABLE[(triplet >> 18) & 0x3F]);
        result.push_back(ENCODE_TABLE[(triplet >> 12) & 0x3F]);
        result.push_back(ENCODE_TABLE[(triplet >> 6) & 0x3F]);
        result.push_back(ENCODE_TABLE[triplet & 0x3F]);
        i += 3;
    }
    
    if (i < len) {
        uint32_t triplet = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) {
            triplet |= static_cast<uint32_t>(data[i + 1]) << 8;
        }
        result.push_back(ENCODE_TABLE[(triplet >> 18) & 0x3F]);
        result.push_back(ENCODE_TABLE[(triplet >> 12) & 0x3F]);
        if (i + 1 < len) {
            result.push_back(ENCODE_TABLE[(triplet >> 6) & 0x3F]);
        } else {
            result.push_back('=');
        }
        result.push_back('=');
    }
    
    return result;
}

inline std::string base64_encode(const std::vector<uint8_t>& data) {
    return base64_encode(data.data(), data.size());
}

/**
 * Decode base64 string to binary data.
 * Returns empty vector on error.
 */
inline std::vector<uint8_t> base64_decode(const std::string& input) {
    using namespace base64_impl;
    
    std::vector<uint8_t> result;
    if (input.empty()) return result;
    
    // Calculate expected output size
    size_t padding = 0;
    if (!input.empty() && input[input.size() - 1] == '=') padding++;
    if (input.size() > 1 && input[input.size() - 2] == '=') padding++;
    
    result.reserve((input.size() / 4) * 3 - padding);
    
    uint32_t buffer = 0;
    int bits = 0;
    
    for (char c : input) {
        if (c == '=') break;
        
        int8_t val = DECODE_TABLE[static_cast<unsigned char>(c)];
        if (val < 0) {
            // Skip whitespace
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
            // Invalid character
            return std::vector<uint8_t>();
        }
        
        buffer = (buffer << 6) | static_cast<uint32_t>(val);
        bits += 6;
        
        if (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    
    return result;
}

// ============================ Constant-time Compare ==========================
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

} // namespace crypto_utils

#endif // CRYPTO_UTILS_H
