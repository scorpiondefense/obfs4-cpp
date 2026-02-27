#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

namespace obfs4::crypto {

enum class SecretboxError {
    InvalidKeyLength,
    InvalidNonceLength,
    DecryptionFailed,
    MessageTooShort,
};

[[nodiscard]] std::string secretbox_error_message(SecretboxError err);

// Low-level primitives (exposed for framing)
void salsa20_quarterround(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d);
void salsa20_core(uint8_t out[64], const uint8_t in[64]);
void hsalsa20(std::span<uint8_t, 32> out,
              std::span<const uint8_t, 32> key,
              std::span<const uint8_t, 16> nonce);
void xsalsa20_xor(std::span<uint8_t> data,
                   std::span<const uint8_t, 32> key,
                   std::span<const uint8_t, 24> nonce);
void xsalsa20_stream(std::span<uint8_t> stream,
                     std::span<const uint8_t, 32> key,
                     std::span<const uint8_t, 24> nonce);
void poly1305(std::span<uint8_t, 16> out,
              std::span<const uint8_t> message,
              std::span<const uint8_t, 32> key);
bool poly1305_verify(std::span<const uint8_t, 16> tag,
                     std::span<const uint8_t> message,
                     std::span<const uint8_t, 32> key);

// NaCl Secretbox: XSalsa20-Poly1305 AEAD
class Secretbox {
public:
    static constexpr size_t KEY_LEN = 32;
    static constexpr size_t NONCE_LEN = 24;
    static constexpr size_t TAG_LEN = 16;
    static constexpr size_t OVERHEAD = TAG_LEN;

    static std::vector<uint8_t> seal(
        std::span<const uint8_t, KEY_LEN> key,
        std::span<const uint8_t, NONCE_LEN> nonce,
        std::span<const uint8_t> plaintext);

    static std::expected<std::vector<uint8_t>, SecretboxError> open(
        std::span<const uint8_t, KEY_LEN> key,
        std::span<const uint8_t, NONCE_LEN> nonce,
        std::span<const uint8_t> ciphertext);
};

}  // namespace obfs4::crypto
