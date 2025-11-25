// chacha20poly1305.h
// Compact ChaCha20-Poly1305 AEAD implementation
// RFC 8439 compliant, dependency-free

#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <cstdint>
#include <cstddef>

namespace aead {

/**
 * ChaCha20-Poly1305 AEAD encryption.
 * 
 * @param key      32-byte encryption key
 * @param nonce    12-byte nonce (must be unique per key)
 * @param aad      Additional authenticated data (may be nullptr if aad_len is 0)
 * @param aad_len  Length of AAD
 * @param pt       Plaintext to encrypt
 * @param pt_len   Length of plaintext
 * @param ct_out   Output buffer for ciphertext (must be at least pt_len bytes)
 * @param tag_out  Output buffer for 16-byte authentication tag
 * @return         true on success, false on failure
 */
bool aead_chacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* pt, size_t pt_len,
    uint8_t* ct_out,
    uint8_t tag_out[16]
);

/**
 * ChaCha20-Poly1305 AEAD decryption.
 * 
 * @param key      32-byte encryption key
 * @param nonce    12-byte nonce
 * @param aad      Additional authenticated data (may be nullptr if aad_len is 0)
 * @param aad_len  Length of AAD
 * @param ct       Ciphertext to decrypt
 * @param ct_len   Length of ciphertext
 * @param tag      16-byte authentication tag to verify
 * @param pt_out   Output buffer for plaintext (must be at least ct_len bytes)
 * @return         true if authentication succeeds and decryption completed,
 *                 false if authentication fails (pt_out is zeroed)
 */
bool aead_chacha20_poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ct, size_t ct_len,
    const uint8_t tag[16],
    uint8_t* pt_out
);

} // namespace aead

#endif // CHACHA20POLY1305_H
