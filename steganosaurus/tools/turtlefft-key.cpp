// turtlefft-key.cpp
// Secure key generation and optional passphrase-wrapped key export tool for TurtleFFT
// Usage:
//   turtlefft-key --gen-key [--key-out FILE] [--wrap PASSPHRASE]
//   turtlefft-key --unwrap FILE --pass PASSPHRASE [--key-out FILE]
//   turtlefft-key --export-hex FILE [--pass PASSPHRASE]
//
// Default wrapping: PBKDF2-HMAC-SHA256 (16-byte salt, 200000 iterations) + ChaCha20-Poly1305 (12-byte nonce)

#include "../src/crypto/crypto_utils.h"
#include "../src/crypto/chacha20poly1305.h"

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <array>
#include <vector>

// Configuration constants
constexpr size_t KEY_SIZE = 32;           // 256-bit key
constexpr size_t SALT_SIZE = 16;          // 16-byte salt for PBKDF2
constexpr size_t NONCE_SIZE = 12;         // 12-byte nonce for ChaCha20-Poly1305
constexpr size_t TAG_SIZE = 16;           // 16-byte Poly1305 tag
constexpr uint32_t PBKDF2_ITERATIONS = 200000;  // Conservative PBKDF2 iteration count

// Wrapped key format: MAGIC(4) || VERSION(1) || SALT(16) || NONCE(12) || CIPHERTEXT(32) || TAG(16)
constexpr size_t WRAPPED_KEY_SIZE = 4 + 1 + SALT_SIZE + NONCE_SIZE + KEY_SIZE + TAG_SIZE;
constexpr uint8_t MAGIC[4] = {'T', 'F', 'K', 'W'};  // TurtleFFT Key Wrapped
constexpr uint8_t VERSION = 1;

namespace {

void print_usage() {
    std::cerr << "turtlefft-key: Secure key generation and management for TurtleFFT\n\n"
              << "Usage:\n"
              << "  turtlefft-key --gen-key [OPTIONS]\n"
              << "    Generate a new 256-bit key\n"
              << "    Options:\n"
              << "      --key-out FILE    Write key to FILE (default: stdout as base64)\n"
              << "      --wrap PASSPHRASE Wrap key with passphrase before output\n"
              << "      --hex             Output raw key as hex (only without --wrap)\n\n"
              << "  turtlefft-key --unwrap FILE --pass PASSPHRASE [OPTIONS]\n"
              << "    Unwrap a passphrase-protected key\n"
              << "    Options:\n"
              << "      --key-out FILE    Write unwrapped key to FILE (default: stdout as base64)\n"
              << "      --hex             Output as hex instead of base64\n\n"
              << "  turtlefft-key --export-hex FILE [--pass PASSPHRASE]\n"
              << "    Export key from FILE as hex\n"
              << "    Use --pass if the key is wrapped\n\n"
              << "Wrapped key format uses:\n"
              << "  - PBKDF2-HMAC-SHA256 with 16-byte salt and 200000 iterations\n"
              << "  - ChaCha20-Poly1305 AEAD with 12-byte nonce\n";
}

// Derive wrapping key from passphrase and salt
std::array<uint8_t, KEY_SIZE> derive_wrapping_key(const std::string& passphrase,
                                                    const uint8_t salt[SALT_SIZE]) {
    std::array<uint8_t, KEY_SIZE> wk{};
    crypto_utils::pbkdf2_hmac_sha256(
        reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size(),
        salt, SALT_SIZE,
        PBKDF2_ITERATIONS,
        wk.data(), wk.size()
    );
    return wk;
}

// Wrap a key with passphrase
std::vector<uint8_t> wrap_key(const uint8_t key[KEY_SIZE], const std::string& passphrase) {
    std::vector<uint8_t> wrapped(WRAPPED_KEY_SIZE);
    
    // Generate random salt and nonce
    uint8_t salt[SALT_SIZE];
    uint8_t nonce[NONCE_SIZE];
    if (!crypto_utils::get_random_bytes(salt, SALT_SIZE) ||
        !crypto_utils::get_random_bytes(nonce, NONCE_SIZE)) {
        return {};  // Return empty on CSPRNG failure
    }
    
    // Derive wrapping key
    auto wk = derive_wrapping_key(passphrase, salt);
    
    // Build header: MAGIC || VERSION || SALT || NONCE
    size_t offset = 0;
    std::memcpy(wrapped.data() + offset, MAGIC, 4); offset += 4;
    wrapped[offset++] = VERSION;
    std::memcpy(wrapped.data() + offset, salt, SALT_SIZE); offset += SALT_SIZE;
    std::memcpy(wrapped.data() + offset, nonce, NONCE_SIZE); offset += NONCE_SIZE;
    
    // Encrypt key with AEAD (header is AAD)
    uint8_t* ct_out = wrapped.data() + offset;
    uint8_t* tag_out = ct_out + KEY_SIZE;
    
    // AAD = MAGIC || VERSION || SALT || NONCE
    const uint8_t* aad = wrapped.data();
    size_t aad_len = 4 + 1 + SALT_SIZE + NONCE_SIZE;
    
    if (!aead::aead_chacha20_poly1305_encrypt(
            wk.data(), nonce,
            aad, aad_len,
            key, KEY_SIZE,
            ct_out, tag_out)) {
        crypto_utils::secure_zero(wk.data(), wk.size());
        return {};
    }
    
    crypto_utils::secure_zero(wk.data(), wk.size());
    return wrapped;
}

// Unwrap a key with passphrase
bool unwrap_key(const std::vector<uint8_t>& wrapped, const std::string& passphrase,
                uint8_t key_out[KEY_SIZE]) {
    if (wrapped.size() != WRAPPED_KEY_SIZE) {
        std::cerr << "Error: Invalid wrapped key size\n";
        return false;
    }
    
    // Verify magic and version
    if (std::memcmp(wrapped.data(), MAGIC, 4) != 0) {
        std::cerr << "Error: Invalid wrapped key format (bad magic)\n";
        return false;
    }
    if (wrapped[4] != VERSION) {
        std::cerr << "Error: Unsupported wrapped key version\n";
        return false;
    }
    
    // Extract salt and nonce
    const uint8_t* salt = wrapped.data() + 5;
    const uint8_t* nonce = salt + SALT_SIZE;
    const uint8_t* ct = nonce + NONCE_SIZE;
    const uint8_t* tag = ct + KEY_SIZE;
    
    // Derive wrapping key
    auto wk = derive_wrapping_key(passphrase, salt);
    
    // AAD = MAGIC || VERSION || SALT || NONCE
    const uint8_t* aad = wrapped.data();
    size_t aad_len = 4 + 1 + SALT_SIZE + NONCE_SIZE;
    
    // Decrypt and verify
    bool success = aead::aead_chacha20_poly1305_decrypt(
        wk.data(), nonce,
        aad, aad_len,
        ct, KEY_SIZE,
        tag, key_out
    );
    
    crypto_utils::secure_zero(wk.data(), wk.size());
    
    if (!success) {
        std::cerr << "Error: Authentication failed (wrong passphrase or corrupted key)\n";
    }
    
    return success;
}

// Convert bytes to hex string
std::string to_hex(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        result.push_back(hex[data[i] >> 4]);
        result.push_back(hex[data[i] & 0x0F]);
    }
    return result;
}

// Write binary data to file
bool write_file(const std::string& path, const uint8_t* data, size_t len) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        std::cerr << "Error: Cannot open file for writing: " << path << "\n";
        return false;
    }
    out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    return out.good();
}

// Read binary data from file
std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) {
        std::cerr << "Error: Cannot open file for reading: " << path << "\n";
        return {};
    }
    auto size = in.tellg();
    if (size <= 0) {
        std::cerr << "Error: File is empty or unreadable: " << path << "\n";
        return {};
    }
    std::vector<uint8_t> data(static_cast<size_t>(size));
    in.seekg(0);
    in.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }
    
    std::string mode;
    std::string key_out_path;
    std::string wrap_passphrase;
    std::string unwrap_file;
    std::string export_file;
    std::string passphrase;
    bool output_hex = false;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--gen-key") {
            mode = "gen-key";
        } else if (arg == "--unwrap") {
            mode = "unwrap";
            if (i + 1 < argc) {
                unwrap_file = argv[++i];
            }
        } else if (arg == "--export-hex") {
            mode = "export-hex";
            if (i + 1 < argc) {
                export_file = argv[++i];
            }
        } else if (arg == "--key-out") {
            if (i + 1 < argc) {
                key_out_path = argv[++i];
            }
        } else if (arg == "--wrap") {
            if (i + 1 < argc) {
                wrap_passphrase = argv[++i];
            }
        } else if (arg == "--pass") {
            if (i + 1 < argc) {
                passphrase = argv[++i];
            }
        } else if (arg == "--hex") {
            output_hex = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        } else {
            std::cerr << "Error: Unknown option: " << arg << "\n";
            print_usage();
            return 1;
        }
    }
    
    // Execute based on mode
    if (mode == "gen-key") {
        // Generate a new key
        std::array<uint8_t, KEY_SIZE> key{};
        if (!crypto_utils::get_random_bytes(key.data(), key.size())) {
            std::cerr << "Error: Failed to generate random key (CSPRNG failure)\n";
            return 1;
        }
        
        if (!wrap_passphrase.empty()) {
            // Wrap the key
            auto wrapped = wrap_key(key.data(), wrap_passphrase);
            crypto_utils::secure_zero(key.data(), key.size());
            
            if (wrapped.empty()) {
                std::cerr << "Error: Failed to wrap key\n";
                return 1;
            }
            
            if (!key_out_path.empty()) {
                // Write wrapped key to file
                if (!write_file(key_out_path, wrapped.data(), wrapped.size())) {
                    return 1;
                }
                std::cout << "Wrapped key written to: " << key_out_path << "\n";
            } else {
                // Output as base64 to stdout
                std::cout << crypto_utils::base64_encode(wrapped) << "\n";
            }
        } else {
            // Output raw key
            if (!key_out_path.empty()) {
                // Write raw key to file
                if (!write_file(key_out_path, key.data(), key.size())) {
                    crypto_utils::secure_zero(key.data(), key.size());
                    return 1;
                }
                crypto_utils::secure_zero(key.data(), key.size());
                std::cout << "Key written to: " << key_out_path << "\n";
            } else {
                // Output to stdout
                if (output_hex) {
                    std::cout << to_hex(key.data(), key.size()) << "\n";
                } else {
                    std::cout << crypto_utils::base64_encode(key.data(), key.size()) << "\n";
                }
                crypto_utils::secure_zero(key.data(), key.size());
            }
        }
        
    } else if (mode == "unwrap") {
        if (unwrap_file.empty()) {
            std::cerr << "Error: --unwrap requires a file path\n";
            return 1;
        }
        if (passphrase.empty()) {
            std::cerr << "Error: --unwrap requires --pass PASSPHRASE\n";
            return 1;
        }
        
        // Read wrapped key
        auto wrapped = read_file(unwrap_file);
        if (wrapped.empty()) {
            return 1;
        }
        
        // Unwrap
        std::array<uint8_t, KEY_SIZE> key{};
        if (!unwrap_key(wrapped, passphrase, key.data())) {
            return 1;
        }
        
        if (!key_out_path.empty()) {
            // Write unwrapped key to file
            if (!write_file(key_out_path, key.data(), key.size())) {
                crypto_utils::secure_zero(key.data(), key.size());
                return 1;
            }
            crypto_utils::secure_zero(key.data(), key.size());
            std::cout << "Unwrapped key written to: " << key_out_path << "\n";
        } else {
            // Output to stdout
            if (output_hex) {
                std::cout << to_hex(key.data(), key.size()) << "\n";
            } else {
                std::cout << crypto_utils::base64_encode(key.data(), key.size()) << "\n";
            }
            crypto_utils::secure_zero(key.data(), key.size());
        }
        
    } else if (mode == "export-hex") {
        if (export_file.empty()) {
            std::cerr << "Error: --export-hex requires a file path\n";
            return 1;
        }
        
        // Read key file
        auto data = read_file(export_file);
        if (data.empty()) {
            return 1;
        }
        
        std::array<uint8_t, KEY_SIZE> key{};
        
        if (data.size() == WRAPPED_KEY_SIZE) {
            // It's a wrapped key
            if (passphrase.empty()) {
                std::cerr << "Error: Wrapped key requires --pass PASSPHRASE\n";
                return 1;
            }
            if (!unwrap_key(data, passphrase, key.data())) {
                return 1;
            }
        } else if (data.size() == KEY_SIZE) {
            // It's a raw key
            std::memcpy(key.data(), data.data(), KEY_SIZE);
        } else {
            std::cerr << "Error: Invalid key file size (expected " << KEY_SIZE 
                      << " or " << WRAPPED_KEY_SIZE << " bytes)\n";
            return 1;
        }
        
        std::cout << to_hex(key.data(), key.size()) << "\n";
        crypto_utils::secure_zero(key.data(), key.size());
        
    } else {
        std::cerr << "Error: No valid mode specified\n";
        print_usage();
        return 1;
    }
    
    return 0;
}
