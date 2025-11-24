// chacha20poly1305.cpp - ChaCha20-Poly1305 AEAD (RFC 8439) implementation
// Compact, portable, dependency-free
// Based on public domain reference implementations
// Copyright (c) 2024 TurtleFFT Project. Apache License 2.0.

#include "chacha20poly1305.h"

namespace {

using crypto::secure_zero;
using crypto::load32_le;
using crypto::store32_le;
using crypto::constant_time_compare;

// ============================ ChaCha20 Core =================================

/**
 * Left rotation for 32-bit integers.
 */
inline uint32_t rotl(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

/**
 * ChaCha20 quarter-round function.
 */
inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl(d, 16);
    c += d; b ^= c; b = rotl(b, 12);
    a += b; d ^= a; d = rotl(d, 8);
    c += d; b ^= c; b = rotl(b, 7);
}

/**
 * ChaCha20 state structure.
 */
struct ChaCha20State {
    uint32_t s[16];

    /**
     * Initialize ChaCha20 state with key, nonce, and counter.
     */
    void init(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter = 0) {
        // Constants: "expand 32-byte k"
        s[0] = 0x61707865; // "expa"
        s[1] = 0x3320646e; // "nd 3"
        s[2] = 0x79622d32; // "2-by"
        s[3] = 0x6b206574; // "te k"

        // Key
        for (int i = 0; i < 8; i++) {
            s[4 + i] = load32_le(key + 4 * i);
        }

        // Counter and nonce
        s[12] = counter;
        s[13] = load32_le(nonce);
        s[14] = load32_le(nonce + 4);
        s[15] = load32_le(nonce + 8);
    }

    /**
     * Generate one 64-byte keystream block.
     */
    void block(uint8_t out[64]) {
        uint32_t x[16];
        std::memcpy(x, s, 64);

        // 20 rounds (10 column rounds + 10 diagonal rounds)
        for (int i = 0; i < 10; i++) {
            // Column rounds
            quarter_round(x[0], x[4], x[8], x[12]);
            quarter_round(x[1], x[5], x[9], x[13]);
            quarter_round(x[2], x[6], x[10], x[14]);
            quarter_round(x[3], x[7], x[11], x[15]);
            // Diagonal rounds
            quarter_round(x[0], x[5], x[10], x[15]);
            quarter_round(x[1], x[6], x[11], x[12]);
            quarter_round(x[2], x[7], x[8], x[13]);
            quarter_round(x[3], x[4], x[9], x[14]);
        }

        // Add original state
        for (int i = 0; i < 16; i++) {
            x[i] += s[i];
        }

        // Serialize to little-endian bytes
        for (int i = 0; i < 16; i++) {
            store32_le(x[i], out + 4 * i);
        }

        // Increment counter
        s[12]++;
    }

    /**
     * XOR keystream with data in place.
     */
    void xor_stream(uint8_t* data, size_t len) {
        uint8_t keystream[64];
        size_t off = 0;

        while (off < len) {
            block(keystream);
            size_t n = (len - off < 64) ? (len - off) : 64;
            for (size_t i = 0; i < n; i++) {
                data[off + i] ^= keystream[i];
            }
            off += n;
        }

        secure_zero(keystream, sizeof(keystream));
    }
};

// ============================ Poly1305 Core =================================

/**
 * Compute Poly1305 MAC over a message.
 * Uses the one-time key (32 bytes: r || s).
 */
void poly1305_mac(uint8_t tag[16], const uint8_t* msg, size_t mlen, const uint8_t key[32]) {
    // Extract r (clamped) and s from key
    // r is the first 16 bytes, clamped per RFC 8439
    uint64_t r0 = load32_le(&key[0]) & 0x3ffffff;
    uint64_t r1 = (load32_le(&key[3]) >> 2) & 0x3ffff03;
    uint64_t r2 = (load32_le(&key[6]) >> 4) & 0x3ffc0ff;
    uint64_t r3 = (load32_le(&key[9]) >> 6) & 0x3f03fff;
    uint64_t r4 = (load32_le(&key[12]) >> 8) & 0x00fffff;

    // Precomputed 5*r values for modular reduction
    uint64_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    // Accumulator
    uint64_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

    const uint8_t* p = msg;
    size_t left = mlen;

    while (left > 0) {
        // Read up to 16 bytes into block
        size_t n = (left < 16) ? left : 16;
        uint8_t block[17] = {0};
        std::memcpy(block, p, n);

        // Add terminator byte
        block[n] = 0x01;

        // Convert block to radix 2^26 limbs
        uint64_t t0 = load32_le(&block[0]) & 0x3ffffff;
        uint64_t t1 = (load32_le(&block[3]) >> 2) & 0x3ffffff;
        uint64_t t2 = (load32_le(&block[6]) >> 4) & 0x3ffffff;
        uint64_t t3 = (load32_le(&block[9]) >> 6) & 0x3ffffff;
        uint64_t t4 = (load32_le(&block[12]) >> 8);

        // Add high bit if full block
        if (n == 16) {
            t4 |= (1ULL << 24);
        }

        // Add to accumulator
        h0 += t0;
        h1 += t1;
        h2 += t2;
        h3 += t3;
        h4 += t4;

        // Multiply by r and reduce mod 2^130 - 5
        uint64_t d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        uint64_t d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        uint64_t d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        uint64_t d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        uint64_t d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        // Partial reduction (carry propagation)
        uint64_t c;
        c = (d0 >> 26); h0 = d0 & 0x3ffffff;
        d1 += c; c = (d1 >> 26); h1 = d1 & 0x3ffffff;
        d2 += c; c = (d2 >> 26); h2 = d2 & 0x3ffffff;
        d3 += c; c = (d3 >> 26); h3 = d3 & 0x3ffffff;
        d4 += c; c = (d4 >> 26); h4 = d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        p += n;
        left -= n;
    }

    // Final reduction
    uint64_t c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    // Compute h - p to check if h >= p
    uint64_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint64_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint64_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint64_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint64_t g4 = h4 + c - (1ULL << 26);

    // Select h if h < p, else g = h - p
    uint64_t mask = (g4 >> 63) - 1;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    // Add s (second half of key)
    uint64_t k0 = load32_le(&key[16]);
    uint64_t k1 = load32_le(&key[20]);
    uint64_t k2 = load32_le(&key[24]);
    uint64_t k3 = load32_le(&key[28]);

    uint64_t f0 = ((h0) | (h1 << 26)) + k0;
    uint64_t f1 = ((h1 >> 6) | (h2 << 20)) + k1 + (f0 >> 32); f0 &= 0xffffffff;
    uint64_t f2 = ((h2 >> 12) | (h3 << 14)) + k2 + (f1 >> 32); f1 &= 0xffffffff;
    uint64_t f3 = ((h3 >> 18) | (h4 << 8)) + k3 + (f2 >> 32); f2 &= 0xffffffff;
    f3 &= 0xffffffff;

    store32_le(static_cast<uint32_t>(f0), &tag[0]);
    store32_le(static_cast<uint32_t>(f1), &tag[4]);
    store32_le(static_cast<uint32_t>(f2), &tag[8]);
    store32_le(static_cast<uint32_t>(f3), &tag[12]);
}

/**
 * Build the AAD || ciphertext || lengths structure for Poly1305.
 */
std::vector<uint8_t> build_poly1305_message(
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len) {

    std::vector<uint8_t> mac;
    mac.reserve(((aad_len + 15) / 16) * 16 + ((ct_len + 15) / 16) * 16 + 16);

    // AAD with padding to 16-byte boundary
    if (aad && aad_len > 0) {
        mac.insert(mac.end(), aad, aad + aad_len);
        while (mac.size() % 16 != 0) mac.push_back(0);
    }

    // Ciphertext with padding to 16-byte boundary
    if (ct && ct_len > 0) {
        mac.insert(mac.end(), ct, ct + ct_len);
        while (mac.size() % 16 != 0) mac.push_back(0);
    }

    // Little-endian lengths (8 bytes each)
    uint8_t aad_len_le[8], ct_len_le[8];
    for (int i = 0; i < 8; i++) {
        aad_len_le[i] = static_cast<uint8_t>((aad_len >> (8 * i)) & 0xFF);
        ct_len_le[i] = static_cast<uint8_t>((ct_len >> (8 * i)) & 0xFF);
    }
    mac.insert(mac.end(), aad_len_le, aad_len_le + 8);
    mac.insert(mac.end(), ct_len_le, ct_len_le + 8);

    return mac;
}

} // anonymous namespace

namespace aead {

bool aead_chacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* pt,
    size_t pt_len,
    uint8_t* ct_out,
    uint8_t tag_out[16]) {

    if (!key || !nonce || !ct_out || !tag_out) return false;
    if (pt_len > 0 && !pt) return false;
    if (aad_len > 0 && !aad) return false;

    // Generate one-time Poly1305 key using ChaCha20 with counter = 0
    uint8_t otk[64];
    ChaCha20State c0;
    c0.init(key, nonce, 0);
    c0.block(otk);

    // Encrypt plaintext with ChaCha20 (counter = 1)
    if (pt_len > 0) {
        std::memcpy(ct_out, pt, pt_len);
        ChaCha20State c;
        c.init(key, nonce, 1);
        c.xor_stream(ct_out, pt_len);
    }

    // Compute Poly1305 tag over AAD || pad || ciphertext || pad || lengths
    auto mac_input = build_poly1305_message(aad, aad_len, ct_out, pt_len);
    poly1305_mac(tag_out, mac_input.data(), mac_input.size(), otk);

    // Clean up sensitive data
    secure_zero(mac_input.data(), mac_input.size());
    secure_zero(otk, sizeof(otk));

    return true;
}

bool aead_chacha20_poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ct,
    size_t ct_len,
    const uint8_t tag[16],
    uint8_t* pt_out) {

    if (!key || !nonce || !tag || !pt_out) return false;
    if (ct_len > 0 && !ct) return false;
    if (aad_len > 0 && !aad) return false;

    // Generate one-time Poly1305 key using ChaCha20 with counter = 0
    uint8_t otk[64];
    ChaCha20State c0;
    c0.init(key, nonce, 0);
    c0.block(otk);

    // Compute expected tag over AAD || pad || ciphertext || pad || lengths
    auto mac_input = build_poly1305_message(aad, aad_len, ct, ct_len);
    uint8_t expected_tag[16];
    poly1305_mac(expected_tag, mac_input.data(), mac_input.size(), otk);

    // Constant-time tag comparison
    bool tags_match = constant_time_compare(expected_tag, tag, 16);

    // Clean up
    secure_zero(mac_input.data(), mac_input.size());
    secure_zero(otk, sizeof(otk));
    secure_zero(expected_tag, sizeof(expected_tag));

    if (!tags_match) {
        return false;
    }

    // Decrypt ciphertext
    if (ct_len > 0) {
        std::memcpy(pt_out, ct, ct_len);
        ChaCha20State c;
        c.init(key, nonce, 1);
        c.xor_stream(pt_out, ct_len);
    }

    return true;
}

} // namespace aead
