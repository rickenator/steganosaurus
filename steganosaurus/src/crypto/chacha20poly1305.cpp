// chacha20poly1305.cpp
// Compact ChaCha20-Poly1305 AEAD implementation
// RFC 8439 compliant, dependency-free

#include "chacha20poly1305.h"
#include "crypto_utils.h"
#include <cstring>
#include <vector>
#include <array>

namespace aead {

namespace {

// ============================ ChaCha20 Core ==================================
inline uint32_t rotl(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl(d, 16);
    c += d; b ^= c; b = rotl(b, 12);
    a += b; d ^= a; d = rotl(d, 8);
    c += d; b ^= c; b = rotl(b, 7);
}

class ChaCha20 {
public:
    void init(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter = 1) {
        // "expand 32-byte k" magic constant
        state_[0] = 0x61707865;
        state_[1] = 0x3320646e;
        state_[2] = 0x79622d32;
        state_[3] = 0x6b206574;
        
        // Key (words 4-11)
        for (int i = 0; i < 8; i++) {
            state_[4 + i] = crypto_utils::load32_le(key + 4 * i);
        }
        
        // Counter and nonce (words 12-15)
        state_[12] = counter;
        state_[13] = crypto_utils::load32_le(nonce);
        state_[14] = crypto_utils::load32_le(nonce + 4);
        state_[15] = crypto_utils::load32_le(nonce + 8);
    }
    
    void block(uint8_t out[64]) {
        uint32_t x[16];
        std::memcpy(x, state_, sizeof(x));
        
        // 20 rounds (10 double-rounds)
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
            x[i] += state_[i];
        }
        
        // Serialize as little-endian
        for (int i = 0; i < 16; i++) {
            crypto_utils::store32_le(x[i], out + 4 * i);
        }
        
        // Increment counter
        state_[12]++;
    }
    
    void xor_stream(uint8_t* data, size_t len) {
        uint8_t keystream[64];
        size_t off = 0;
        
        while (off < len) {
            block(keystream);
            size_t n = std::min(static_cast<size_t>(64), len - off);
            for (size_t i = 0; i < n; i++) {
                data[off + i] ^= keystream[i];
            }
            off += n;
        }
        
        crypto_utils::secure_zero(keystream, sizeof(keystream));
    }

private:
    uint32_t state_[16];
};

// ============================ Poly1305 MAC ===================================
void poly1305_mac(uint8_t tag[16], const uint8_t* msg, size_t mlen, const uint8_t key[32]) {
    // r (clamped)
    uint64_t r0 = crypto_utils::load32_le(&key[0]) & 0x3ffffff;
    uint64_t r1 = (crypto_utils::load32_le(&key[3]) >> 2) & 0x3ffff03;
    uint64_t r2 = (crypto_utils::load32_le(&key[6]) >> 4) & 0x3ffc0ff;
    uint64_t r3 = (crypto_utils::load32_le(&key[9]) >> 6) & 0x3f03fff;
    uint64_t r4 = (crypto_utils::load32_le(&key[12]) >> 8) & 0x00fffff;
    
    // Precomputed r * 5 values for reduction
    uint64_t sr1 = r1 * 5, sr2 = r2 * 5, sr3 = r3 * 5, sr4 = r4 * 5;
    
    // Accumulator
    uint64_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    
    const uint8_t* p = msg;
    size_t left = mlen;
    
    while (left > 0) {
        uint64_t t0, t1, t2, t3, t4;
        size_t n = std::min(left, static_cast<size_t>(16));
        uint8_t block[16] = {0};
        std::memcpy(block, p, n);
        p += n;
        left -= n;
        
        t0 = crypto_utils::load32_le(&block[0]) & 0x3ffffff;
        t1 = (crypto_utils::load32_le(&block[3]) >> 2) & 0x3ffffff;
        t2 = (crypto_utils::load32_le(&block[6]) >> 4) & 0x3ffffff;
        t3 = (crypto_utils::load32_le(&block[9]) >> 6) & 0x3ffffff;
        t4 = (crypto_utils::load32_le(&block[12]) >> 8);
        t4 |= (1ULL << 24);  // Poly1305 padding bit
        
        h0 += t0; h1 += t1; h2 += t2; h3 += t3; h4 += t4;
        
        // Multiply and reduce
        uint64_t d0 = h0*r0 + h1*sr4 + h2*sr3 + h3*sr2 + h4*sr1;
        uint64_t d1 = h0*r1 + h1*r0 + h2*sr4 + h3*sr3 + h4*sr2;
        uint64_t d2 = h0*r2 + h1*r1 + h2*r0 + h3*sr4 + h4*sr3;
        uint64_t d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*sr4;
        uint64_t d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0;
        
        // Partial reduction
        uint64_t c;
        c = (d0 >> 26); h0 = d0 & 0x3ffffff;
        d1 += c; c = (d1 >> 26); h1 = d1 & 0x3ffffff;
        d2 += c; c = (d2 >> 26); h2 = d2 & 0x3ffffff;
        d3 += c; c = (d3 >> 26); h3 = d3 & 0x3ffffff;
        d4 += c; c = (d4 >> 26); h4 = d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    }
    
    // Final reduction
    uint64_t c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    
    // Compute h + -p
    uint64_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint64_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint64_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint64_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint64_t g4 = h4 + c - (1ULL << 26);
    
    // Select h if h < p, else h - p
    uint64_t mask = (g4 >> 63) - 1;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = ((h4 & ~mask) | (g4 & mask)) + (1ULL << 26);
    
    // Add s (second half of key)
    uint64_t s0 = crypto_utils::load32_le(&key[16]);
    uint64_t s1 = crypto_utils::load32_le(&key[20]);
    uint64_t s2 = crypto_utils::load32_le(&key[24]);
    uint64_t s3 = crypto_utils::load32_le(&key[28]);
    
    uint64_t f0 = (h0) | (h1 << 26);
    f0 += s0;
    uint64_t f1 = (h1 >> 6) | (h2 << 20);
    f1 += s1 + (f0 >> 32); f0 &= 0xffffffff;
    uint64_t f2 = (h2 >> 12) | (h3 << 14);
    f2 += s2 + (f1 >> 32); f1 &= 0xffffffff;
    uint64_t f3 = (h3 >> 18) | (h4 << 8);
    f3 += s3 + (f2 >> 32); f2 &= 0xffffffff;
    f3 &= 0xffffffff;
    
    crypto_utils::store32_le(static_cast<uint32_t>(f0), &tag[0]);
    crypto_utils::store32_le(static_cast<uint32_t>(f1), &tag[4]);
    crypto_utils::store32_le(static_cast<uint32_t>(f2), &tag[8]);
    crypto_utils::store32_le(static_cast<uint32_t>(f3), &tag[12]);
}

// Build MAC input: aad || pad16 || ciphertext || pad16 || len(aad) || len(ct)
std::vector<uint8_t> build_mac_data(const uint8_t* aad, size_t aad_len,
                                     const uint8_t* ct, size_t ct_len) {
    std::vector<uint8_t> mac;
    size_t aad_padded = ((aad_len + 15) / 16) * 16;
    size_t ct_padded = ((ct_len + 15) / 16) * 16;
    mac.reserve(aad_padded + ct_padded + 16);
    
    if (aad && aad_len) {
        mac.insert(mac.end(), aad, aad + aad_len);
        while (mac.size() % 16) mac.push_back(0);
    }
    
    if (ct && ct_len) {
        mac.insert(mac.end(), ct, ct + ct_len);
        while (mac.size() % 16) mac.push_back(0);
    }
    
    // Little-endian lengths
    uint8_t le_aad_len[8], le_ct_len[8];
    crypto_utils::store64_le(aad_len, le_aad_len);
    crypto_utils::store64_le(ct_len, le_ct_len);
    mac.insert(mac.end(), le_aad_len, le_aad_len + 8);
    mac.insert(mac.end(), le_ct_len, le_ct_len + 8);
    
    return mac;
}

} // anonymous namespace

// ============================ Public API =====================================

bool aead_chacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct_out,
    uint8_t tag_out[16])
{
    // Generate one-time Poly1305 key (counter = 0)
    uint8_t otk[64];
    ChaCha20 c0;
    c0.init(key, nonce, 0);
    c0.block(otk);
    
    // Copy plaintext to output and encrypt with counter = 1
    std::memcpy(ct_out, pt, pt_len);
    ChaCha20 c;
    c.init(key, nonce, 1);
    c.xor_stream(ct_out, pt_len);
    
    // Compute authentication tag
    auto mac_data = build_mac_data(aad, aad_len, ct_out, pt_len);
    poly1305_mac(tag_out, mac_data.data(), mac_data.size(), otk);
    
    // Secure cleanup
    crypto_utils::secure_zero(otk, sizeof(otk));
    if (!mac_data.empty()) {
        crypto_utils::secure_zero(mac_data.data(), mac_data.size());
    }
    
    return true;
}

bool aead_chacha20_poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t tag[16],
    uint8_t* pt_out)
{
    // Generate one-time Poly1305 key (counter = 0)
    uint8_t otk[64];
    ChaCha20 c0;
    c0.init(key, nonce, 0);
    c0.block(otk);
    
    // Recompute tag over ciphertext
    auto mac_data = build_mac_data(aad, aad_len, ct, ct_len);
    uint8_t computed_tag[16];
    poly1305_mac(computed_tag, mac_data.data(), mac_data.size(), otk);
    
    // Constant-time tag comparison
    bool valid = crypto_utils::constant_time_compare(computed_tag, tag, 16);
    
    // Secure cleanup
    crypto_utils::secure_zero(otk, sizeof(otk));
    crypto_utils::secure_zero(computed_tag, sizeof(computed_tag));
    if (!mac_data.empty()) {
        crypto_utils::secure_zero(mac_data.data(), mac_data.size());
    }
    
    if (!valid) {
        // Zero output on authentication failure
        std::memset(pt_out, 0, ct_len);
        return false;
    }
    
    // Decrypt with counter = 1
    std::memcpy(pt_out, ct, ct_len);
    ChaCha20 c;
    c.init(key, nonce, 1);
    c.xor_stream(pt_out, ct_len);
    
    return true;
}

} // namespace aead
