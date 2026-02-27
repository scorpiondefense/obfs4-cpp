#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace obfs4::crypto {

constexpr size_t SHA256_DIGEST_LEN = 32;
constexpr size_t SHA512_DIGEST_LEN = 64;

enum class HashError {
    InvalidLength,
    UpdateFailed,
    FinalizeFailed,
    OpenSSLError,
};

[[nodiscard]] std::string hash_error_message(HashError err);

// HMAC-SHA256
class HmacSha256 {
public:
    HmacSha256();
    ~HmacSha256();
    HmacSha256(HmacSha256&&) noexcept;
    HmacSha256& operator=(HmacSha256&&) noexcept;
    HmacSha256(const HmacSha256&) = delete;
    HmacSha256& operator=(const HmacSha256&) = delete;

    [[nodiscard]] std::expected<void, HashError> init(std::span<const uint8_t> key);
    [[nodiscard]] std::expected<void, HashError> update(std::span<const uint8_t> data);
    [[nodiscard]] std::expected<std::array<uint8_t, SHA256_DIGEST_LEN>, HashError> finalize();
    void reset();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// One-shot HMAC-SHA256
[[nodiscard]] std::expected<std::array<uint8_t, SHA256_DIGEST_LEN>, HashError>
hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> data);

// One-shot SHA-256
[[nodiscard]] std::expected<std::array<uint8_t, SHA256_DIGEST_LEN>, HashError>
sha256(std::span<const uint8_t> data);

// One-shot SHA-512
[[nodiscard]] std::expected<std::array<uint8_t, SHA512_DIGEST_LEN>, HashError>
sha512(std::span<const uint8_t> data);

// HKDF-SHA256 (RFC 5869)
[[nodiscard]] std::expected<std::vector<uint8_t>, HashError>
hkdf_sha256(std::span<const uint8_t> salt,
            std::span<const uint8_t> ikm,
            std::span<const uint8_t> info,
            size_t length);

// Hex encoding/decoding
[[nodiscard]] std::string to_hex(std::span<const uint8_t> data);
[[nodiscard]] std::expected<std::vector<uint8_t>, HashError> from_hex(const std::string& hex);

// Constant-time comparison
[[nodiscard]] bool constant_time_compare(std::span<const uint8_t> a,
                                          std::span<const uint8_t> b);

}  // namespace obfs4::crypto
