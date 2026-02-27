#include "obfs4/crypto/hash.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <cstring>

namespace obfs4::crypto {

// HmacSha256 implementation
struct HmacSha256::Impl {
    EVP_MAC* mac{nullptr};
    EVP_MAC_CTX* ctx{nullptr};
    std::vector<uint8_t> key;

    Impl() {
        mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    }

    ~Impl() {
        if (ctx) EVP_MAC_CTX_free(ctx);
        if (mac) EVP_MAC_free(mac);
    }
};

HmacSha256::HmacSha256() : impl_(std::make_unique<Impl>()) {}
HmacSha256::~HmacSha256() = default;
HmacSha256::HmacSha256(HmacSha256&&) noexcept = default;
HmacSha256& HmacSha256::operator=(HmacSha256&&) noexcept = default;

std::expected<void, HashError> HmacSha256::init(std::span<const uint8_t> key) {
    if (!impl_ || !impl_->mac) {
        return std::unexpected(HashError::OpenSSLError);
    }

    impl_->key.assign(key.begin(), key.end());

    if (impl_->ctx) EVP_MAC_CTX_free(impl_->ctx);
    impl_->ctx = EVP_MAC_CTX_new(impl_->mac);
    if (!impl_->ctx) return std::unexpected(HashError::OpenSSLError);

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_MAC_init(impl_->ctx, impl_->key.data(), impl_->key.size(), params) != 1) {
        return std::unexpected(HashError::OpenSSLError);
    }
    return {};
}

std::expected<void, HashError> HmacSha256::update(std::span<const uint8_t> data) {
    if (!impl_ || !impl_->ctx) return std::unexpected(HashError::OpenSSLError);
    if (EVP_MAC_update(impl_->ctx, data.data(), data.size()) != 1) {
        return std::unexpected(HashError::UpdateFailed);
    }
    return {};
}

std::expected<std::array<uint8_t, SHA256_DIGEST_LEN>, HashError> HmacSha256::finalize() {
    if (!impl_ || !impl_->ctx) return std::unexpected(HashError::OpenSSLError);

    std::array<uint8_t, SHA256_DIGEST_LEN> result;
    size_t len = result.size();

    if (EVP_MAC_final(impl_->ctx, result.data(), &len, result.size()) != 1) {
        return std::unexpected(HashError::FinalizeFailed);
    }

    // Reinitialize for reuse
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0);
    params[1] = OSSL_PARAM_construct_end();
    EVP_MAC_init(impl_->ctx, impl_->key.data(), impl_->key.size(), params);

    return result;
}

void HmacSha256::reset() {
    if (impl_ && impl_->ctx && !impl_->key.empty()) {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0);
        params[1] = OSSL_PARAM_construct_end();
        EVP_MAC_init(impl_->ctx, impl_->key.data(), impl_->key.size(), params);
    }
}

// One-shot HMAC-SHA256
std::expected<std::array<uint8_t, SHA256_DIGEST_LEN>, HashError>
hmac_sha256(std::span<const uint8_t> key, std::span<const uint8_t> data) {
    HmacSha256 hmac;
    auto init_result = hmac.init(key);
    if (!init_result) return std::unexpected(init_result.error());

    auto update_result = hmac.update(data);
    if (!update_result) return std::unexpected(update_result.error());

    return hmac.finalize();
}

// One-shot SHA-256
std::expected<std::array<uint8_t, SHA256_DIGEST_LEN>, HashError>
sha256(std::span<const uint8_t> data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return std::unexpected(HashError::OpenSSLError);

    std::array<uint8_t, SHA256_DIGEST_LEN> result;
    unsigned int len = result.size();

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, result.data(), &len) != 1) {
        EVP_MD_CTX_free(ctx);
        return std::unexpected(HashError::OpenSSLError);
    }

    EVP_MD_CTX_free(ctx);
    return result;
}

// One-shot SHA-512
std::expected<std::array<uint8_t, SHA512_DIGEST_LEN>, HashError>
sha512(std::span<const uint8_t> data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return std::unexpected(HashError::OpenSSLError);

    std::array<uint8_t, SHA512_DIGEST_LEN> result;
    unsigned int len = result.size();

    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, result.data(), &len) != 1) {
        EVP_MD_CTX_free(ctx);
        return std::unexpected(HashError::OpenSSLError);
    }

    EVP_MD_CTX_free(ctx);
    return result;
}

// HKDF-SHA256
std::expected<std::vector<uint8_t>, HashError>
hkdf_sha256(std::span<const uint8_t> salt,
            std::span<const uint8_t> ikm,
            std::span<const uint8_t> info,
            size_t length) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) return std::unexpected(HashError::OpenSSLError);

    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx) return std::unexpected(HashError::OpenSSLError);

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA256"), 0);
    params[1] = OSSL_PARAM_construct_octet_string("key",
        const_cast<uint8_t*>(ikm.data()), ikm.size());
    params[2] = OSSL_PARAM_construct_octet_string("salt",
        const_cast<uint8_t*>(salt.data()), salt.size());
    params[3] = OSSL_PARAM_construct_octet_string("info",
        const_cast<uint8_t*>(info.data()), info.size());
    params[4] = OSSL_PARAM_construct_end();

    std::vector<uint8_t> output(length);

    if (EVP_KDF_derive(ctx, output.data(), length, params) <= 0) {
        EVP_KDF_CTX_free(ctx);
        return std::unexpected(HashError::OpenSSLError);
    }

    EVP_KDF_CTX_free(ctx);
    return output;
}

// Hex encoding
std::string to_hex(std::span<const uint8_t> data) {
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t byte : data) {
        result.push_back(hex_chars[byte >> 4]);
        result.push_back(hex_chars[byte & 0x0F]);
    }
    return result;
}

std::expected<std::vector<uint8_t>, HashError> from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0) return std::unexpected(HashError::InvalidLength);

    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = 0;
        for (int j = 0; j < 2; ++j) {
            char c = hex[i + j];
            uint8_t nibble;
            if (c >= '0' && c <= '9') nibble = c - '0';
            else if (c >= 'a' && c <= 'f') nibble = 10 + (c - 'a');
            else if (c >= 'A' && c <= 'F') nibble = 10 + (c - 'A');
            else return std::unexpected(HashError::InvalidLength);
            byte = (byte << 4) | nibble;
        }
        result.push_back(byte);
    }
    return result;
}

// Constant-time comparison
bool constant_time_compare(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    if (a.size() != b.size()) return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

std::string hash_error_message(HashError err) {
    switch (err) {
        case HashError::InvalidLength: return "Invalid length";
        case HashError::UpdateFailed: return "Update failed";
        case HashError::FinalizeFailed: return "Finalize failed";
        case HashError::OpenSSLError: return "OpenSSL error";
        default: return "Unknown hash error";
    }
}

}  // namespace obfs4::crypto
