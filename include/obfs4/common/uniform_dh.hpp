#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>

namespace obfs4::common {

// RFC 3526 Group 5: 1536-bit MODP group
// Used by obfs3 and scramblesuit for key exchange.
// Public keys are zero-padded to 192 bytes for uniform distribution.
constexpr size_t UNIFORM_DH_KEY_LEN = 192;  // 1536 bits / 8

enum class UniformDHError {
    KeygenFailed,
    SharedSecretFailed,
    InvalidPublicKey,
    OpenSSLError,
};

[[nodiscard]] std::string uniform_dh_error_message(UniformDHError err);

struct UniformDHKeypair {
    std::array<uint8_t, UNIFORM_DH_KEY_LEN> public_key;   // Zero-padded to 192 bytes
    std::array<uint8_t, UNIFORM_DH_KEY_LEN> private_key;  // Zero-padded to 192 bytes
};

// Generate a new ephemeral DH keypair
[[nodiscard]] std::expected<UniformDHKeypair, UniformDHError>
uniform_dh_keygen();

// Compute shared secret from local private key and peer's public key
[[nodiscard]] std::expected<std::array<uint8_t, UNIFORM_DH_KEY_LEN>, UniformDHError>
uniform_dh_shared_secret(std::span<const uint8_t, UNIFORM_DH_KEY_LEN> private_key,
                         std::span<const uint8_t, UNIFORM_DH_KEY_LEN> public_key);

}  // namespace obfs4::common
