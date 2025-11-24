// chacha20poly1305.cpp - ChaCha20-Poly1305 AEAD Implementation (RFC 8439)
// Compact, auditable, dependency-free implementation
//
// References:
// - RFC 8439: ChaCha20 and Poly1305 for IETF Protocols
// - RFC 7539: ChaCha20 and Poly1305 for TLS (predecessor)

#include "chacha20poly1305.h"
#include "crypto_utils.h"
#include <cstring>

namespace chacha20poly1305 {

// ============================================================================
// Internal helper functions
// ============================================================================

namespace {

using crypto_utils::secure_zero;
using crypto_utils::constant_time_compare;
using crypto_utils::load32_le;
using crypto_utils::store32_le;
using crypto_utils::store64_le;

// ChaCha20 quarter round
inline void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d << 8) | (d >> 24);
    c += d; b ^= c; b = (b << 7) | (b >> 25);
}

// ChaCha20 block function
// Takes 256-bit key, 96-bit nonce, 32-bit counter
// Outputs 64-byte keystream block
class ChaCha20 {
public:
    void init(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
        // "expand 32-byte k" constant
        state_[0] = 0x61707865;
        state_[1] = 0x3320646e;
        state_[2] = 0x79622d32;
        state_[3] = 0x6b206574;
        
        // Key (32 bytes = 8 words)
        for (int i = 0; i < 8; i++) {
            state_[4 + i] = load32_le(key + 4 * i);
        }
        
        // Counter (1 word)
        state_[12] = counter;
        
        // Nonce (3 words)
        state_[13] = load32_le(nonce + 0);
        state_[14] = load32_le(nonce + 4);
        state_[15] = load32_le(nonce + 8);
    }
    
    void block(uint8_t out[64]) {
        uint32_t x[16];
        std::memcpy(x, state_, 64);
        
        // 20 rounds (10 double rounds)
        for (int i = 0; i < 10; i++) {
            // Column rounds
            quarter_round(x[0], x[4], x[8],  x[12]);
            quarter_round(x[1], x[5], x[9],  x[13]);
            quarter_round(x[2], x[6], x[10], x[14]);
            quarter_round(x[3], x[7], x[11], x[15]);
            // Diagonal rounds
            quarter_round(x[0], x[5], x[10], x[15]);
            quarter_round(x[1], x[6], x[11], x[12]);
            quarter_round(x[2], x[7], x[8],  x[13]);
            quarter_round(x[3], x[4], x[9],  x[14]);
        }
        
        // Add original state
        for (int i = 0; i < 16; i++) {
            x[i] += state_[i];
        }
        
        // Serialize output (little-endian)
        for (int i = 0; i < 16; i++) {
            store32_le(x[i], out + 4 * i);
        }
        
        // Increment counter
        state_[12]++;
        
        // Clean working state
        secure_zero(x, sizeof(x));
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
        
        secure_zero(keystream, sizeof(keystream));
    }
    
private:
    uint32_t state_[16];
};

// Poly1305 MAC
// The r part of the key is clamped as per RFC 8439
void poly1305_mac(uint8_t tag[16], const uint8_t* msg, size_t msg_len, const uint8_t key[32]) {
    // Parse and clamp r
    uint64_t r0 = load32_le(&key[0]) & 0x0fffffff;
    uint64_t r1 = load32_le(&key[4]) & 0x0ffffffc;
    uint64_t r2 = load32_le(&key[8]) & 0x0ffffffc;
    uint64_t r3 = load32_le(&key[12]) & 0x0ffffffc;
    
    // r in 26-bit limbs
    uint64_t r0_26 = r0 & 0x3ffffff;
    uint64_t r1_26 = ((r0 >> 26) | (r1 << 6)) & 0x3ffffff;
    uint64_t r2_26 = ((r1 >> 20) | (r2 << 12)) & 0x3ffffff;
    uint64_t r3_26 = ((r2 >> 14) | (r3 << 18)) & 0x3ffffff;
    uint64_t r4_26 = (r3 >> 8);
    
    // Precompute 5*r for reduction
    uint64_t s1 = r1_26 * 5;
    uint64_t s2 = r2_26 * 5;
    uint64_t s3 = r3_26 * 5;
    uint64_t s4 = r4_26 * 5;
    
    // Accumulator
    uint64_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    
    // Process message in 16-byte blocks
    const uint8_t* p = msg;
    size_t remaining = msg_len;
    
    while (remaining > 0) {
        // Read block (up to 16 bytes)
        uint8_t block[17] = {0};
        size_t block_size = std::min(remaining, static_cast<size_t>(16));
        std::memcpy(block, p, block_size);
        
        // Append 0x01 byte (or nothing for final partial block)
        block[block_size] = 0x01;
        
        // Convert to 26-bit limbs and add to accumulator
        uint64_t t0 = load32_le(&block[0]) & 0x3ffffff;
        uint64_t t1 = (load32_le(&block[3]) >> 2) & 0x3ffffff;
        uint64_t t2 = (load32_le(&block[6]) >> 4) & 0x3ffffff;
        uint64_t t3 = (load32_le(&block[9]) >> 6) & 0x3ffffff;
        uint64_t t4 = (load32_le(&block[12]) >> 8);
        
        // Add the 2^128 bit for full blocks
        if (block_size == 16) {
            t4 |= (1ULL << 24);
        }
        
        h0 += t0;
        h1 += t1;
        h2 += t2;
        h3 += t3;
        h4 += t4;
        
        // Multiply by r and reduce
        uint64_t d0 = h0*r0_26 + h1*s4 + h2*s3 + h3*s2 + h4*s1;
        uint64_t d1 = h0*r1_26 + h1*r0_26 + h2*s4 + h3*s3 + h4*s2;
        uint64_t d2 = h0*r2_26 + h1*r1_26 + h2*r0_26 + h3*s4 + h4*s3;
        uint64_t d3 = h0*r3_26 + h1*r2_26 + h2*r1_26 + h3*r0_26 + h4*s4;
        uint64_t d4 = h0*r4_26 + h1*r3_26 + h2*r2_26 + h3*r1_26 + h4*r0_26;
        
        // Carry propagation
        uint64_t c;
        c = d0 >> 26; h0 = d0 & 0x3ffffff;
        d1 += c; c = d1 >> 26; h1 = d1 & 0x3ffffff;
        d2 += c; c = d2 >> 26; h2 = d2 & 0x3ffffff;
        d3 += c; c = d3 >> 26; h3 = d3 & 0x3ffffff;
        d4 += c; c = d4 >> 26; h4 = d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
        
        p += block_size;
        remaining -= block_size;
    }
    
    // Final reduction
    uint64_t c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    
    // Compute h + -p (where p = 2^130 - 5)
    uint64_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint64_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint64_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint64_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint64_t g4 = h4 + c - (1ULL << 26);
    
    // Select h or g based on carry out
    uint64_t mask = (g4 >> 63) - 1;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);
    
    // Add s (the second half of the key)
    uint64_t s0_val = load32_le(&key[16]);
    uint64_t s1_val = load32_le(&key[20]);
    uint64_t s2_val = load32_le(&key[24]);
    uint64_t s3_val = load32_le(&key[28]);
    
    // Convert h back to 32-bit limbs and add s
    uint64_t f0 = (h0 | (h1 << 26)) + s0_val;
    uint64_t f1 = ((h1 >> 6) | (h2 << 20)) + s1_val + (f0 >> 32);
    f0 &= 0xffffffff;
    uint64_t f2 = ((h2 >> 12) | (h3 << 14)) + s2_val + (f1 >> 32);
    f1 &= 0xffffffff;
    uint64_t f3 = ((h3 >> 18) | (h4 << 8)) + s3_val + (f2 >> 32);
    f2 &= 0xffffffff;
    f3 &= 0xffffffff;
    
    // Write output
    store32_le(static_cast<uint32_t>(f0), &tag[0]);
    store32_le(static_cast<uint32_t>(f1), &tag[4]);
    store32_le(static_cast<uint32_t>(f2), &tag[8]);
    store32_le(static_cast<uint32_t>(f3), &tag[12]);
}

// Build the AEAD construction MAC input
// Format: AAD || pad16(AAD) || ciphertext || pad16(ciphertext) || len(AAD) || len(ciphertext)
std::vector<uint8_t> build_mac_data(const uint8_t* aad, size_t aad_len,
                                     const uint8_t* ct, size_t ct_len) {
    std::vector<uint8_t> data;
    data.reserve(((aad_len + 15) / 16) * 16 + ((ct_len + 15) / 16) * 16 + 16);
    
    // AAD with padding
    if (aad && aad_len > 0) {
        data.insert(data.end(), aad, aad + aad_len);
        while (data.size() % 16 != 0) data.push_back(0);
    }
    
    // Ciphertext with padding
    if (ct && ct_len > 0) {
        data.insert(data.end(), ct, ct + ct_len);
        while (data.size() % 16 != 0) data.push_back(0);
    }
    
    // Length fields (little-endian 64-bit)
    uint8_t len_buf[16];
    store64_le(aad_len, len_buf);
    store64_le(ct_len, len_buf + 8);
    data.insert(data.end(), len_buf, len_buf + 16);
    
    return data;
}

} // anonymous namespace

// ============================================================================
// Public API Implementation
// ============================================================================

bool aead_chacha20_poly1305_encrypt(
    const uint8_t key[KEY_SIZE],
    const uint8_t nonce[NONCE_SIZE],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext_out,
    uint8_t tag_out[TAG_SIZE]
) {
    if (!key || !nonce || !tag_out) return false;
    if (pt_len > 0 && (!plaintext || !ciphertext_out)) return false;
    if (aad_len > 0 && !aad) return false;
    
    // Generate one-time Poly1305 key (ChaCha20 block with counter=0)
    uint8_t otk[64];
    ChaCha20 c0;
    c0.init(key, nonce, 0);
    c0.block(otk);
    
    // Copy plaintext to output and encrypt in place (ChaCha20 with counter=1)
    if (pt_len > 0) {
        std::memcpy(ciphertext_out, plaintext, pt_len);
        ChaCha20 c;
        c.init(key, nonce, 1);
        c.xor_stream(ciphertext_out, pt_len);
    }
    
    // Build MAC data and compute tag
    auto mac_data = build_mac_data(aad, aad_len, ciphertext_out, pt_len);
    poly1305_mac(tag_out, mac_data.data(), mac_data.size(), otk);
    
    // Clean up
    secure_zero(otk, sizeof(otk));
    if (!mac_data.empty()) secure_zero(mac_data.data(), mac_data.size());
    
    return true;
}

bool aead_chacha20_poly1305_decrypt(
    const uint8_t key[KEY_SIZE],
    const uint8_t nonce[NONCE_SIZE],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t tag[TAG_SIZE],
    uint8_t* plaintext_out
) {
    if (!key || !nonce || !tag) return false;
    if (ct_len > 0 && (!ciphertext || !plaintext_out)) return false;
    if (aad_len > 0 && !aad) return false;
    
    // Generate one-time Poly1305 key
    uint8_t otk[64];
    ChaCha20 c0;
    c0.init(key, nonce, 0);
    c0.block(otk);
    
    // Verify tag first (before decryption)
    auto mac_data = build_mac_data(aad, aad_len, ciphertext, ct_len);
    uint8_t computed_tag[16];
    poly1305_mac(computed_tag, mac_data.data(), mac_data.size(), otk);
    
    bool tag_ok = constant_time_compare(computed_tag, tag, 16);
    
    // Clean up MAC data
    secure_zero(otk, sizeof(otk));
    secure_zero(computed_tag, sizeof(computed_tag));
    if (!mac_data.empty()) secure_zero(mac_data.data(), mac_data.size());
    
    if (!tag_ok) {
        // Authentication failed - zero output to prevent leakage
        if (ct_len > 0) {
            secure_zero(plaintext_out, ct_len);
        }
        return false;
    }
    
    // Decrypt (ChaCha20 with counter=1)
    if (ct_len > 0) {
        std::memcpy(plaintext_out, ciphertext, ct_len);
        ChaCha20 c;
        c.init(key, nonce, 1);
        c.xor_stream(plaintext_out, ct_len);
    }
    
    return true;
}

// ============================================================================
// Convenience Wrappers
// ============================================================================

bool aead_encrypt(
    const std::array<uint8_t, KEY_SIZE>& key,
    const std::array<uint8_t, NONCE_SIZE>& nonce,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& plaintext,
    std::vector<uint8_t>& ciphertext_out,
    std::array<uint8_t, TAG_SIZE>& tag_out
) {
    ciphertext_out.resize(plaintext.size());
    return aead_chacha20_poly1305_encrypt(
        key.data(), nonce.data(),
        aad.empty() ? nullptr : aad.data(), aad.size(),
        plaintext.empty() ? nullptr : plaintext.data(), plaintext.size(),
        plaintext.empty() ? nullptr : ciphertext_out.data(),
        tag_out.data()
    );
}

bool aead_decrypt(
    const std::array<uint8_t, KEY_SIZE>& key,
    const std::array<uint8_t, NONCE_SIZE>& nonce,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& ciphertext,
    const std::array<uint8_t, TAG_SIZE>& tag,
    std::vector<uint8_t>& plaintext_out
) {
    plaintext_out.resize(ciphertext.size());
    return aead_chacha20_poly1305_decrypt(
        key.data(), nonce.data(),
        aad.empty() ? nullptr : aad.data(), aad.size(),
        ciphertext.empty() ? nullptr : ciphertext.data(), ciphertext.size(),
        tag.data(),
        ciphertext.empty() ? nullptr : plaintext_out.data()
    );
}

} // namespace chacha20poly1305
