// crypto_utils.h - Portable, dependency-free cryptographic utilities for TurtleFFT
// Single-header implementation with OS CSPRNG, SHA-256, HMAC-SHA256, HKDF, PBKDF2, and Base64
// Copyright (c) 2024 TurtleFFT Project. Apache License 2.0.

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <array>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

// ============================ Platform Detection ============================
#if defined(_WIN32) || defined(_WIN64)
#define CRYPTO_UTILS_WINDOWS
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__linux__)
#define CRYPTO_UTILS_LINUX
#include <sys/random.h>
#include <unistd.h>
#include <fcntl.h>
#elif defined(__APPLE__)
#define CRYPTO_UTILS_APPLE
#include <stdlib.h>
#elif defined(__unix__)
#define CRYPTO_UTILS_UNIX
#include <unistd.h>
#include <fcntl.h>
#endif

namespace crypto {

// ============================ Secure Memory Zeroing =========================
/**
 * Securely wipe sensitive buffers to reduce the chance of key/nonce leakage.
 * Uses volatile pointer to prevent compiler optimization.
 */
inline void secure_zero(void* ptr, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;
}

// ============================ Endian Helpers (Portable) =====================
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

// ============================ CSPRNG - get_random_bytes =====================
/**
 * Get cryptographically secure random bytes using OS-provided CSPRNG.
 * Platform-specific implementations:
 * - Windows: BCryptGenRandom
 * - Linux: getrandom() syscall with /dev/urandom fallback
 * - macOS: arc4random_buf
 * - Other UNIX: /dev/urandom
 *
 * @param buf Output buffer
 * @param len Number of random bytes to generate
 * @return true on success, false on failure
 */
inline bool get_random_bytes(uint8_t* buf, size_t len) {
    if (len == 0) return true;
    if (!buf) return false;

#if defined(CRYPTO_UTILS_WINDOWS)
    // Windows: BCryptGenRandom (preferred over CryptGenRandom)
    NTSTATUS status = BCryptGenRandom(
        nullptr,
        buf,
        static_cast<ULONG>(len),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    return BCRYPT_SUCCESS(status);

#elif defined(CRYPTO_UTILS_LINUX)
    // Linux: getrandom() syscall (available since kernel 3.17)
    size_t remaining = len;
    uint8_t* ptr = buf;
    while (remaining > 0) {
        ssize_t ret = getrandom(ptr, remaining, 0);
        if (ret < 0) {
            // Fallback to /dev/urandom
            int fd = open("/dev/urandom", O_RDONLY);
            if (fd < 0) return false;
            while (remaining > 0) {
                ssize_t r = read(fd, ptr, remaining);
                if (r <= 0) {
                    close(fd);
                    return false;
                }
                ptr += r;
                remaining -= static_cast<size_t>(r);
            }
            close(fd);
            return true;
        }
        ptr += ret;
        remaining -= static_cast<size_t>(ret);
    }
    return true;

#elif defined(CRYPTO_UTILS_APPLE)
    // macOS/iOS: arc4random_buf (cryptographically secure, never fails)
    arc4random_buf(buf, len);
    return true;

#elif defined(CRYPTO_UTILS_UNIX)
    // Generic UNIX: /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    size_t remaining = len;
    uint8_t* ptr = buf;
    while (remaining > 0) {
        ssize_t r = read(fd, ptr, remaining);
        if (r <= 0) {
            close(fd);
            return false;
        }
        ptr += r;
        remaining -= static_cast<size_t>(r);
    }
    close(fd);
    return true;

#else
    // Unsupported platform
    (void)buf;
    (void)len;
    return false;
#endif
}

// ============================ SHA-256 Implementation ========================
namespace sha256 {

inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t bs0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint32_t bs1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
inline uint32_t ss0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
inline uint32_t ss1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/**
 * Compute SHA-256 hash of data.
 * @param data Input data
 * @param len Length of input data
 * @return 32-byte hash
 */
inline std::array<uint8_t, 32> hash(const uint8_t* data, size_t len) {
    std::vector<uint8_t> m(data, data + len);
    uint64_t bitlen = static_cast<uint64_t>(len) * 8;
    m.push_back(0x80);
    while ((m.size() + 8) % 64) m.push_back(0);
    for (int i = 7; i >= 0; --i) m.push_back(static_cast<uint8_t>(bitlen >> (8 * i)));

    uint32_t H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    for (size_t off = 0; off < m.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (m[off + 4 * i] << 24) | (m[off + 4 * i + 1] << 16) |
                   (m[off + 4 * i + 2] << 8) | (m[off + 4 * i + 3]);
        }
        for (int i = 16; i < 64; ++i)
            w[i] = ss1(w[i - 2]) + w[i - 7] + ss0(w[i - 15]) + w[i - 16];

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
        out[4 * i + 0] = (H[i] >> 24) & 0xFF;
        out[4 * i + 1] = (H[i] >> 16) & 0xFF;
        out[4 * i + 2] = (H[i] >> 8) & 0xFF;
        out[4 * i + 3] = H[i] & 0xFF;
    }
    return out;
}

inline std::array<uint8_t, 32> hash(const std::string& s) {
    return hash(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

inline std::array<uint8_t, 32> hash(const std::vector<uint8_t>& v) {
    return hash(v.data(), v.size());
}

} // namespace sha256

// ============================ HMAC-SHA256 ===================================
/**
 * Compute HMAC-SHA256.
 * @param key HMAC key
 * @param klen Key length
 * @param msg Message to authenticate
 * @param mlen Message length
 * @param out 32-byte output buffer
 */
inline void hmac_sha256(const uint8_t* key, size_t klen,
                        const uint8_t* msg, size_t mlen,
                        uint8_t out[32]) {
    uint8_t k0[64] = {0};
    if (klen > 64) {
        auto h = sha256::hash(key, klen);
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
    auto hi = sha256::hash(inner.data(), inner.size());

    uint8_t tmp[64 + 32];
    std::memcpy(tmp, opad, 64);
    std::memcpy(tmp + 64, hi.data(), 32);
    auto ho = sha256::hash(tmp, 96);
    std::memcpy(out, ho.data(), 32);

    secure_zero(k0, sizeof(k0));
    secure_zero(ipad, sizeof(ipad));
    secure_zero(opad, sizeof(opad));
}

// ============================ PBKDF2-HMAC-SHA256 ============================
/**
 * PBKDF2 key derivation using HMAC-SHA256 (RFC 8018).
 * @param pass Password
 * @param salt Salt vector
 * @param iters Number of iterations
 * @param out Output buffer
 * @param dkLen Desired key length in bytes
 */
inline void pbkdf2_hmac_sha256(const std::string& pass,
                               const std::vector<uint8_t>& salt,
                               uint32_t iters,
                               uint8_t* out, size_t dkLen) {
    uint32_t blocks = static_cast<uint32_t>((dkLen + 31) / 32);
    std::vector<uint8_t> U(32), T(32);

    for (uint32_t i = 1; i <= blocks; i++) {
        // U1 = HMAC(pass, salt || INT(i))
        std::vector<uint8_t> msg(salt.begin(), salt.end());
        uint8_t be[4] = {
            static_cast<uint8_t>(i >> 24),
            static_cast<uint8_t>(i >> 16),
            static_cast<uint8_t>(i >> 8),
            static_cast<uint8_t>(i)
        };
        msg.insert(msg.end(), be, be + 4);
        hmac_sha256(reinterpret_cast<const uint8_t*>(pass.data()), pass.size(),
                    msg.data(), msg.size(), U.data());
        std::memcpy(T.data(), U.data(), 32);

        for (uint32_t j = 2; j <= iters; j++) {
            hmac_sha256(reinterpret_cast<const uint8_t*>(pass.data()), pass.size(),
                        U.data(), 32, U.data());
            for (int k = 0; k < 32; k++) T[k] ^= U[k];
        }

        size_t off = static_cast<size_t>(i - 1) * 32;
        size_t need = std::min(static_cast<size_t>(32), dkLen - off);
        std::memcpy(out + off, T.data(), need);
    }

    secure_zero(U.data(), U.size());
    secure_zero(T.data(), T.size());
}

// ============================ HKDF (RFC 5869) ===============================
/**
 * HKDF-Extract using HMAC-SHA256.
 * @param salt Salt (can be nullptr if slen is 0)
 * @param slen Salt length
 * @param ikm Input keying material
 * @param ikmlen IKM length
 * @param prk 32-byte output pseudorandom key
 */
inline void hkdf_sha256_extract(const uint8_t* salt, size_t slen,
                                const uint8_t* ikm, size_t ikmlen,
                                uint8_t prk[32]) {
    if (salt == nullptr || slen == 0) {
        uint8_t zeros[32] = {0};
        hmac_sha256(zeros, 32, ikm, ikmlen, prk);
    } else {
        hmac_sha256(salt, slen, ikm, ikmlen, prk);
    }
}

/**
 * HKDF-Expand using HMAC-SHA256.
 * @param prk 32-byte pseudorandom key
 * @param info Context/application-specific info
 * @param infolen Info length
 * @param out Output buffer
 * @param L Desired output length
 */
inline void hkdf_sha256_expand(const uint8_t prk[32],
                               const uint8_t* info, size_t infolen,
                               uint8_t* out, size_t L) {
    uint8_t T[32];
    size_t Tlen = 0;
    uint8_t ctr = 1;
    size_t pos = 0;

    while (pos < L) {
        std::vector<uint8_t> msg(T, T + Tlen);
        msg.insert(msg.end(), info, info + infolen);
        msg.push_back(ctr);
        hmac_sha256(prk, 32, msg.data(), msg.size(), T);
        Tlen = 32;
        size_t need = std::min(static_cast<size_t>(32), L - pos);
        std::memcpy(out + pos, T, need);
        pos += need;
        ctr++;
    }

    secure_zero(T, sizeof(T));
}

// ============================ Base64 Encoding/Decoding ======================
namespace base64 {

constexpr char ENCODE_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Encode binary data to base64 string.
 * @param data Input data
 * @param len Data length
 * @return Base64-encoded string
 */
inline std::string encode(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(((len + 2) / 3) * 4);

    size_t i = 0;
    while (i + 2 < len) {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8) |
                     static_cast<uint32_t>(data[i + 2]);
        result += ENCODE_TABLE[(n >> 18) & 0x3F];
        result += ENCODE_TABLE[(n >> 12) & 0x3F];
        result += ENCODE_TABLE[(n >> 6) & 0x3F];
        result += ENCODE_TABLE[n & 0x3F];
        i += 3;
    }

    if (i + 1 == len) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        result += ENCODE_TABLE[(n >> 18) & 0x3F];
        result += ENCODE_TABLE[(n >> 12) & 0x3F];
        result += '=';
        result += '=';
    } else if (i + 2 == len) {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8);
        result += ENCODE_TABLE[(n >> 18) & 0x3F];
        result += ENCODE_TABLE[(n >> 12) & 0x3F];
        result += ENCODE_TABLE[(n >> 6) & 0x3F];
        result += '=';
    }

    return result;
}

inline std::string encode(const std::vector<uint8_t>& data) {
    return encode(data.data(), data.size());
}

inline std::string encode(const std::array<uint8_t, 32>& data) {
    return encode(data.data(), data.size());
}

/**
 * Decode base64 string to binary data.
 * @param str Base64-encoded string
 * @param out Output vector (cleared and resized)
 * @return true on success, false on invalid input
 */
inline bool decode(const std::string& str, std::vector<uint8_t>& out) {
    out.clear();
    if (str.empty()) return true;
    if (str.size() % 4 != 0) return false;

    // Build decode table
    int8_t decode_table[256];
    std::memset(decode_table, -1, sizeof(decode_table));
    for (int i = 0; i < 64; i++) {
        decode_table[static_cast<uint8_t>(ENCODE_TABLE[i])] = static_cast<int8_t>(i);
    }

    size_t padding = 0;
    if (str.size() >= 2) {
        if (str[str.size() - 1] == '=') padding++;
        if (str[str.size() - 2] == '=') padding++;
    }

    out.reserve((str.size() / 4) * 3 - padding);

    for (size_t i = 0; i < str.size(); i += 4) {
        int8_t a = decode_table[static_cast<uint8_t>(str[i])];
        int8_t b = decode_table[static_cast<uint8_t>(str[i + 1])];
        int8_t c = (str[i + 2] == '=') ? 0 : decode_table[static_cast<uint8_t>(str[i + 2])];
        int8_t d = (str[i + 3] == '=') ? 0 : decode_table[static_cast<uint8_t>(str[i + 3])];

        if (a < 0 || b < 0 || (str[i + 2] != '=' && c < 0) || (str[i + 3] != '=' && d < 0)) {
            out.clear();
            return false;
        }

        uint32_t n = (static_cast<uint32_t>(a) << 18) |
                     (static_cast<uint32_t>(b) << 12) |
                     (static_cast<uint32_t>(c) << 6) |
                     static_cast<uint32_t>(d);

        out.push_back(static_cast<uint8_t>((n >> 16) & 0xFF));
        if (str[i + 2] != '=') out.push_back(static_cast<uint8_t>((n >> 8) & 0xFF));
        if (str[i + 3] != '=') out.push_back(static_cast<uint8_t>(n & 0xFF));
    }

    return true;
}

} // namespace base64

// ============================ SHA256 Hex String =============================
/**
 * Convert SHA-256 hash to lowercase hex string.
 * @param hash 32-byte hash
 * @return 64-character hex string
 */
inline std::string sha256_hex(const std::array<uint8_t, 32>& hash) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (uint8_t b : hash) {
        result += hex[(b >> 4) & 0xF];
        result += hex[b & 0xF];
    }
    return result;
}

/**
 * Compute SHA-256 hash and return as hex string.
 * @param data Input data
 * @param len Data length
 * @return 64-character hex string
 */
inline std::string sha256_hex(const uint8_t* data, size_t len) {
    return sha256_hex(sha256::hash(data, len));
}

// ============================ Constant-time Comparison ======================
/**
 * Constant-time comparison to prevent timing attacks.
 * @param a First buffer
 * @param b Second buffer
 * @param len Length to compare
 * @return true if equal
 */
inline bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    return diff == 0;
}

} // namespace crypto

#endif // CRYPTO_UTILS_H
