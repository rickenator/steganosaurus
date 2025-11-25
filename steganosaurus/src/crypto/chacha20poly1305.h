// chacha20poly1305.h - ChaCha20-Poly1305 AEAD Implementation (RFC 8439)
// Compact, auditable, dependency-free implementation
//
// This file provides the public interface for ChaCha20-Poly1305 AEAD.
// Implementation is in chacha20poly1305.cpp.

#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>

namespace chacha20poly1305 {

// AEAD tag size in bytes
constexpr size_t TAG_SIZE = 16;

// Key size in bytes (256-bit)
constexpr size_t KEY_SIZE = 32;

// Nonce size in bytes (96-bit)
constexpr size_t NONCE_SIZE = 12;

/**
 * Encrypts plaintext using ChaCha20-Poly1305 AEAD.
 * 
 * @param key        32-byte encryption key
 * @param nonce      12-byte nonce (must be unique per key)
 * @param aad        Additional authenticated data (may be nullptr if aad_len is 0)
 * @param aad_len    Length of AAD
 * @param plaintext  Input plaintext (may be nullptr if pt_len is 0)
 * @param pt_len     Length of plaintext
 * @param ciphertext_out Output buffer for ciphertext (same size as plaintext)
 * @param tag_out    Output buffer for 16-byte authentication tag
 * @return true on success, false on failure
 * 
 * The ciphertext_out buffer must be at least pt_len bytes.
 * The plaintext and ciphertext_out buffers may overlap (in-place encryption).
 */
bool aead_chacha20_poly1305_encrypt(
    const uint8_t key[KEY_SIZE],
    const uint8_t nonce[NONCE_SIZE],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext_out,
    uint8_t tag_out[TAG_SIZE]
);

/**
 * Decrypts ciphertext using ChaCha20-Poly1305 AEAD.
 * 
 * @param key        32-byte encryption key
 * @param nonce      12-byte nonce (same as used for encryption)
 * @param aad        Additional authenticated data (same as used for encryption)
 * @param aad_len    Length of AAD
 * @param ciphertext Input ciphertext
 * @param ct_len     Length of ciphertext
 * @param tag        16-byte authentication tag to verify
 * @param plaintext_out Output buffer for decrypted plaintext
 * @return true on success (tag verified), false on failure (authentication failed)
 * 
 * The plaintext_out buffer must be at least ct_len bytes.
 * If authentication fails, plaintext_out is zeroed to prevent leakage.
 * The ciphertext and plaintext_out buffers may overlap (in-place decryption).
 */
bool aead_chacha20_poly1305_decrypt(
    const uint8_t key[KEY_SIZE],
    const uint8_t nonce[NONCE_SIZE],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t tag[TAG_SIZE],
    uint8_t* plaintext_out
);

/**
 * Convenience wrappers using std::array and std::vector.
 */

bool aead_encrypt(
    const std::array<uint8_t, KEY_SIZE>& key,
    const std::array<uint8_t, NONCE_SIZE>& nonce,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& plaintext,
    std::vector<uint8_t>& ciphertext_out,
    std::array<uint8_t, TAG_SIZE>& tag_out
);

bool aead_decrypt(
    const std::array<uint8_t, KEY_SIZE>& key,
    const std::array<uint8_t, NONCE_SIZE>& nonce,
    const std::vector<uint8_t>& aad,
    const std::vector<uint8_t>& ciphertext,
    const std::array<uint8_t, TAG_SIZE>& tag,
    std::vector<uint8_t>& plaintext_out
);

} // namespace chacha20poly1305

#endif // CHACHA20POLY1305_H
