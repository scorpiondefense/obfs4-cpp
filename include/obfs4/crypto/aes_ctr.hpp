#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace obfs4::crypto {

enum class AesCtrError {
    InvalidKeyLength,
    InvalidIVLength,
    InitFailed,
    ProcessFailed,
    NotInitialized,
};

[[nodiscard]] std::string aes_ctr_error_message(AesCtrError err);

// AES-CTR stream cipher (128-bit or 256-bit key).
// Wraps OpenSSL EVP_CIPHER_CTX for streaming encryption/decryption.
// AES-CTR is symmetric: encrypt and decrypt are the same operation.
class AesCtrStream {
public:
    static constexpr size_t AES128_KEY_LEN = 16;
    static constexpr size_t AES256_KEY_LEN = 32;
    static constexpr size_t IV_LEN = 16;

    AesCtrStream();
    ~AesCtrStream();
    AesCtrStream(AesCtrStream&&) noexcept;
    AesCtrStream& operator=(AesCtrStream&&) noexcept;
    AesCtrStream(const AesCtrStream&) = delete;
    AesCtrStream& operator=(const AesCtrStream&) = delete;

    // Initialize with key (16 or 32 bytes) and IV (16 bytes)
    [[nodiscard]] std::expected<void, AesCtrError>
    init(std::span<const uint8_t> key, std::span<const uint8_t, IV_LEN> iv);

    // XOR data with keystream in-place (encrypt or decrypt)
    [[nodiscard]] std::expected<void, AesCtrError>
    process(std::span<uint8_t> data);

    // XOR data with keystream, returning result
    [[nodiscard]] std::expected<std::vector<uint8_t>, AesCtrError>
    process(std::span<const uint8_t> data);

    bool initialized() const { return initialized_; }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    bool initialized_ = false;
};

}  // namespace obfs4::crypto
