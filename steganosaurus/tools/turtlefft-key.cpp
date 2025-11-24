// turtlefft-key.cpp - CLI tool for key generation, wrapping, and export
// Demonstrates generate/wrap/unpack flows for TurtleFFT
// Copyright (c) 2024 TurtleFFT Project. Apache License 2.0.

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <vector>
#include <array>

#include "../src/crypto/crypto_utils.h"
#include "../src/crypto/chacha20poly1305.h"

namespace {

constexpr size_t KEY_SIZE = 32;
constexpr size_t SALT_SIZE = 16;
constexpr size_t NONCE_SIZE = 12;
constexpr size_t TAG_SIZE = 16;
constexpr uint32_t DEFAULT_PBKDF2_ITERS = 100000;

// File format magic for wrapped keys
constexpr char WRAPPED_KEY_MAGIC[] = "TFFTKEY1";
constexpr size_t MAGIC_SIZE = 8;

struct Args {
    bool gen_key = false;
    bool wrap = false;
    bool unwrap = false;
    std::string key_out;
    std::string key_in;
    std::string passphrase;
    uint32_t pbkdf2_iters = DEFAULT_PBKDF2_ITERS;
    bool help = false;
};

void print_usage() {
    std::cerr << R"(
turtlefft-key - Key generation and management for TurtleFFT

USAGE:
  turtlefft-key --gen-key [--key-out <file>]
  turtlefft-key --wrap --key-in <file> --key-out <file> --pass <passphrase>
  turtlefft-key --unwrap --key-in <file> --pass <passphrase>
  turtlefft-key --help

OPTIONS:
  --gen-key           Generate a new 256-bit (32-byte) master key
  --key-out <file>    Output file for key (default: stdout)
  --key-in <file>     Input key file
  --wrap              Wrap (encrypt) a key with a passphrase
  --unwrap            Unwrap (decrypt) a wrapped key file
  --pass <passphrase> Passphrase for key wrapping/unwrapping
  --pbkdf2-iters <n>  PBKDF2 iterations (default: 100000)
  --help              Show this help message

EXAMPLES:
  # Generate a new key and print to stdout
  turtlefft-key --gen-key

  # Generate a key and save to file
  turtlefft-key --gen-key --key-out master.key

  # Wrap a key with a passphrase
  turtlefft-key --wrap --key-in master.key --key-out master.wrapped --pass "my passphrase"

  # Unwrap a key
  turtlefft-key --unwrap --key-in master.wrapped --pass "my passphrase"

OUTPUT FORMAT:
  --gen-key outputs:
    Key (base64): <base64-encoded 32-byte key>
    Fingerprint:  <first 12 chars of SHA256 hex>
)" << std::endl;
}

bool parse_args(int argc, char* argv[], Args& args) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--gen-key") {
            args.gen_key = true;
        } else if (arg == "--wrap") {
            args.wrap = true;
        } else if (arg == "--unwrap") {
            args.unwrap = true;
        } else if (arg == "--key-out") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --key-out requires an argument" << std::endl;
                return false;
            }
            args.key_out = argv[++i];
        } else if (arg == "--key-in") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --key-in requires an argument" << std::endl;
                return false;
            }
            args.key_in = argv[++i];
        } else if (arg == "--pass") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --pass requires an argument" << std::endl;
                return false;
            }
            args.passphrase = argv[++i];
        } else if (arg == "--pbkdf2-iters") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --pbkdf2-iters requires an argument" << std::endl;
                return false;
            }
            unsigned long val = std::stoul(argv[++i]);
            // Validate iteration count bounds
            constexpr unsigned long MIN_ITERS = 1000;
            constexpr unsigned long MAX_ITERS = 10000000;
            if (val < MIN_ITERS || val > MAX_ITERS) {
                std::cerr << "Error: --pbkdf2-iters must be between " << MIN_ITERS << " and " << MAX_ITERS << std::endl;
                return false;
            }
            args.pbkdf2_iters = static_cast<uint32_t>(val);
        } else if (arg == "--help" || arg == "-h") {
            args.help = true;
        } else {
            std::cerr << "Error: Unknown argument: " << arg << std::endl;
            return false;
        }
    }
    
    return true;
}

/**
 * Generate a fingerprint from a key (first 12 hex chars of SHA256).
 */
std::string key_fingerprint(const std::array<uint8_t, KEY_SIZE>& key) {
    auto hash = crypto::sha256::hash(key.data(), key.size());
    std::string hex = crypto::sha256_hex(hash);
    return hex.substr(0, 12);
}

/**
 * Generate a new 256-bit master key.
 */
bool do_gen_key(const Args& args) {
    std::array<uint8_t, KEY_SIZE> key{};
    
    if (!crypto::get_random_bytes(key.data(), key.size())) {
        std::cerr << "Error: Failed to generate random bytes" << std::endl;
        return false;
    }
    
    std::string b64 = crypto::base64::encode(key.data(), key.size());
    std::string fingerprint = key_fingerprint(key);
    
    if (args.key_out.empty()) {
        // Print to stdout
        std::cout << "Key (base64): " << b64 << std::endl;
        std::cout << "Fingerprint:  " << fingerprint << std::endl;
    } else {
        // Write to file (base64 format)
        std::ofstream out(args.key_out);
        if (!out) {
            std::cerr << "Error: Cannot open output file: " << args.key_out << std::endl;
            crypto::secure_zero(key.data(), key.size());
            return false;
        }
        out << b64 << std::endl;
        out.close();
        
        std::cout << "Key saved to: " << args.key_out << std::endl;
        std::cout << "Fingerprint:  " << fingerprint << std::endl;
    }
    
    crypto::secure_zero(key.data(), key.size());
    return true;
}

/**
 * Read a key from file (base64 format).
 */
bool read_key_file(const std::string& path, std::array<uint8_t, KEY_SIZE>& key) {
    std::ifstream in(path);
    if (!in) {
        std::cerr << "Error: Cannot open key file: " << path << std::endl;
        return false;
    }
    
    std::string line;
    std::getline(in, line);
    in.close();
    
    // Trim whitespace
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' ')) {
        line.pop_back();
    }
    
    std::vector<uint8_t> decoded;
    if (!crypto::base64::decode(line, decoded)) {
        std::cerr << "Error: Invalid base64 in key file" << std::endl;
        return false;
    }
    
    if (decoded.size() != KEY_SIZE) {
        std::cerr << "Error: Key file has wrong size (expected " << KEY_SIZE << " bytes, got " << decoded.size() << ")" << std::endl;
        return false;
    }
    
    std::memcpy(key.data(), decoded.data(), KEY_SIZE);
    crypto::secure_zero(decoded.data(), decoded.size());
    return true;
}

/**
 * Wrap (encrypt) a key with a passphrase.
 * Format: MAGIC (8) || SALT (16) || NONCE (12) || CIPHERTEXT (32) || TAG (16)
 */
bool do_wrap_key(const Args& args) {
    if (args.key_in.empty()) {
        std::cerr << "Error: --key-in is required for --wrap" << std::endl;
        return false;
    }
    if (args.key_out.empty()) {
        std::cerr << "Error: --key-out is required for --wrap" << std::endl;
        return false;
    }
    if (args.passphrase.empty()) {
        std::cerr << "Error: --pass is required for --wrap" << std::endl;
        return false;
    }
    
    // Read the key to wrap
    std::array<uint8_t, KEY_SIZE> key{};
    if (!read_key_file(args.key_in, key)) {
        return false;
    }
    
    // Generate salt and nonce
    std::array<uint8_t, SALT_SIZE> salt{};
    std::array<uint8_t, NONCE_SIZE> nonce{};
    if (!crypto::get_random_bytes(salt.data(), salt.size()) ||
        !crypto::get_random_bytes(nonce.data(), nonce.size())) {
        std::cerr << "Error: Failed to generate random bytes" << std::endl;
        crypto::secure_zero(key.data(), key.size());
        return false;
    }
    
    // Derive wrapping key from passphrase using PBKDF2
    std::array<uint8_t, KEY_SIZE> wrapping_key{};
    crypto::pbkdf2_hmac_sha256(
        args.passphrase,
        std::vector<uint8_t>(salt.begin(), salt.end()),
        args.pbkdf2_iters,
        wrapping_key.data(),
        wrapping_key.size()
    );
    
    // Encrypt the key
    std::array<uint8_t, KEY_SIZE> ciphertext{};
    std::array<uint8_t, TAG_SIZE> tag{};
    
    // Use salt as AAD to bind it to the ciphertext
    if (!aead::aead_chacha20_poly1305_encrypt(
            wrapping_key.data(),
            nonce.data(),
            salt.data(),
            salt.size(),
            key.data(),
            key.size(),
            ciphertext.data(),
            tag.data())) {
        std::cerr << "Error: Encryption failed" << std::endl;
        crypto::secure_zero(key.data(), key.size());
        crypto::secure_zero(wrapping_key.data(), wrapping_key.size());
        return false;
    }
    
    // Build output: MAGIC || SALT || NONCE || CIPHERTEXT || TAG
    std::vector<uint8_t> output;
    output.insert(output.end(), WRAPPED_KEY_MAGIC, WRAPPED_KEY_MAGIC + MAGIC_SIZE);
    output.insert(output.end(), salt.begin(), salt.end());
    output.insert(output.end(), nonce.begin(), nonce.end());
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());
    output.insert(output.end(), tag.begin(), tag.end());
    
    // Write to file (base64)
    std::ofstream out(args.key_out);
    if (!out) {
        std::cerr << "Error: Cannot open output file: " << args.key_out << std::endl;
        crypto::secure_zero(key.data(), key.size());
        crypto::secure_zero(wrapping_key.data(), wrapping_key.size());
        return false;
    }
    out << crypto::base64::encode(output) << std::endl;
    out.close();
    
    std::cout << "Wrapped key saved to: " << args.key_out << std::endl;
    std::cout << "Original fingerprint: " << key_fingerprint(key) << std::endl;
    
    crypto::secure_zero(key.data(), key.size());
    crypto::secure_zero(wrapping_key.data(), wrapping_key.size());
    return true;
}

/**
 * Unwrap (decrypt) a wrapped key file.
 */
bool do_unwrap_key(const Args& args) {
    if (args.key_in.empty()) {
        std::cerr << "Error: --key-in is required for --unwrap" << std::endl;
        return false;
    }
    if (args.passphrase.empty()) {
        std::cerr << "Error: --pass is required for --unwrap" << std::endl;
        return false;
    }
    
    // Read the wrapped key file
    std::ifstream in(args.key_in);
    if (!in) {
        std::cerr << "Error: Cannot open wrapped key file: " << args.key_in << std::endl;
        return false;
    }
    
    std::string line;
    std::getline(in, line);
    in.close();
    
    // Trim whitespace
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' ')) {
        line.pop_back();
    }
    
    std::vector<uint8_t> data;
    if (!crypto::base64::decode(line, data)) {
        std::cerr << "Error: Invalid base64 in wrapped key file" << std::endl;
        return false;
    }
    
    constexpr size_t expected_size = MAGIC_SIZE + SALT_SIZE + NONCE_SIZE + KEY_SIZE + TAG_SIZE;
    if (data.size() != expected_size) {
        std::cerr << "Error: Wrapped key file has wrong size" << std::endl;
        return false;
    }
    
    // Parse the wrapped key
    if (std::memcmp(data.data(), WRAPPED_KEY_MAGIC, MAGIC_SIZE) != 0) {
        std::cerr << "Error: Invalid wrapped key file (bad magic)" << std::endl;
        return false;
    }
    
    const uint8_t* salt = data.data() + MAGIC_SIZE;
    const uint8_t* nonce = salt + SALT_SIZE;
    const uint8_t* ciphertext = nonce + NONCE_SIZE;
    const uint8_t* tag = ciphertext + KEY_SIZE;
    
    // Derive wrapping key from passphrase
    std::array<uint8_t, KEY_SIZE> wrapping_key{};
    crypto::pbkdf2_hmac_sha256(
        args.passphrase,
        std::vector<uint8_t>(salt, salt + SALT_SIZE),
        args.pbkdf2_iters,
        wrapping_key.data(),
        wrapping_key.size()
    );
    
    // Decrypt the key
    std::array<uint8_t, KEY_SIZE> key{};
    if (!aead::aead_chacha20_poly1305_decrypt(
            wrapping_key.data(),
            nonce,
            salt,
            SALT_SIZE,
            ciphertext,
            KEY_SIZE,
            tag,
            key.data())) {
        std::cerr << "Error: Decryption failed (wrong passphrase or corrupted file)" << std::endl;
        crypto::secure_zero(wrapping_key.data(), wrapping_key.size());
        return false;
    }
    
    std::string b64 = crypto::base64::encode(key.data(), key.size());
    std::string fingerprint = key_fingerprint(key);
    
    if (args.key_out.empty()) {
        // Print to stdout
        std::cout << "Key (base64): " << b64 << std::endl;
        std::cout << "Fingerprint:  " << fingerprint << std::endl;
    } else {
        // Write to file
        std::ofstream out(args.key_out);
        if (!out) {
            std::cerr << "Error: Cannot open output file: " << args.key_out << std::endl;
            crypto::secure_zero(key.data(), key.size());
            crypto::secure_zero(wrapping_key.data(), wrapping_key.size());
            return false;
        }
        out << b64 << std::endl;
        out.close();
        
        std::cout << "Key saved to: " << args.key_out << std::endl;
        std::cout << "Fingerprint:  " << fingerprint << std::endl;
    }
    
    crypto::secure_zero(key.data(), key.size());
    crypto::secure_zero(wrapping_key.data(), wrapping_key.size());
    return true;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    Args args;
    
    if (!parse_args(argc, argv, args)) {
        print_usage();
        return 1;
    }
    
    if (args.help) {
        print_usage();
        return 0;
    }
    
    // Count how many modes are selected
    int mode_count = (args.gen_key ? 1 : 0) + (args.wrap ? 1 : 0) + (args.unwrap ? 1 : 0);
    
    if (mode_count == 0) {
        std::cerr << "Error: No operation specified" << std::endl;
        print_usage();
        return 1;
    }
    
    if (mode_count > 1) {
        std::cerr << "Error: Only one operation can be specified at a time" << std::endl;
        return 1;
    }
    
    if (args.gen_key) {
        return do_gen_key(args) ? 0 : 1;
    }
    
    if (args.wrap) {
        return do_wrap_key(args) ? 0 : 1;
    }
    
    if (args.unwrap) {
        return do_unwrap_key(args) ? 0 : 1;
    }
    
    return 0;
}
