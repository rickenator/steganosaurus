// chacha20poly1305.h - ChaCha20-Poly1305 AEAD (RFC 8439) for TurtleFFT
// Compact, portable, dependency-free implementation
// Copyright (c) 2024 TurtleFFT Project. Apache License 2.0.

#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <array>
#include <vector>
#include "crypto_utils.h"

namespace aead {

/**
 * ChaCha20-Poly1305 AEAD Encryption (RFC 8439).
 *
 * @param key 32-byte key
 * @param nonce 12-byte nonce
 * @param aad Additional authenticated data (may be nullptr if aad_len is 0)
 * @param aad_len Length of AAD
 * @param pt Plaintext to encrypt
 * @param pt_len Length of plaintext
 * @param ct_out Ciphertext output buffer (same size as plaintext)
 * @param tag_out 16-byte authentication tag output
 * @return true on success
 */
bool aead_chacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* pt,
    size_t pt_len,
    uint8_t* ct_out,
    uint8_t tag_out[16]);

/**
 * ChaCha20-Poly1305 AEAD Decryption (RFC 8439).
 *
 * @param key 32-byte key
 * @param nonce 12-byte nonce
 * @param aad Additional authenticated data (may be nullptr if aad_len is 0)
 * @param aad_len Length of AAD
 * @param ct Ciphertext to decrypt
 * @param ct_len Length of ciphertext
 * @param tag 16-byte authentication tag
 * @param pt_out Plaintext output buffer (same size as ciphertext)
 * @return true if authentication succeeded and decryption was performed
 */
bool aead_chacha20_poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ct,
    size_t ct_len,
    const uint8_t tag[16],
    uint8_t* pt_out);

} // namespace aead

#endif // CHACHA20POLY1305_H
