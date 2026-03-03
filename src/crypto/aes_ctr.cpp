#include "obfs4/crypto/aes_ctr.hpp"
#include <openssl/evp.h>
#include <cstring>

namespace obfs4::crypto {

std::string aes_ctr_error_message(AesCtrError err) {
    switch (err) {
        case AesCtrError::InvalidKeyLength: return "invalid key length (must be 16 or 32)";
        case AesCtrError::InvalidIVLength: return "invalid IV length (must be 16)";
        case AesCtrError::InitFailed: return "AES-CTR initialization failed";
        case AesCtrError::ProcessFailed: return "AES-CTR process failed";
        case AesCtrError::NotInitialized: return "AES-CTR stream not initialized";
    }
    return "unknown AES-CTR error";
}

struct AesCtrStream::Impl {
    EVP_CIPHER_CTX* ctx = nullptr;

    Impl() {
        ctx = EVP_CIPHER_CTX_new();
    }

    ~Impl() {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }

    Impl(Impl&& other) noexcept : ctx(other.ctx) {
        other.ctx = nullptr;
    }

    Impl& operator=(Impl&& other) noexcept {
        if (this != &other) {
            if (ctx) EVP_CIPHER_CTX_free(ctx);
            ctx = other.ctx;
            other.ctx = nullptr;
        }
        return *this;
    }
};

AesCtrStream::AesCtrStream() : impl_(std::make_unique<Impl>()) {}
AesCtrStream::~AesCtrStream() = default;
AesCtrStream::AesCtrStream(AesCtrStream&&) noexcept = default;
AesCtrStream& AesCtrStream::operator=(AesCtrStream&&) noexcept = default;

std::expected<void, AesCtrError>
AesCtrStream::init(std::span<const uint8_t> key, std::span<const uint8_t, IV_LEN> iv) {
    if (!impl_->ctx) {
        return std::unexpected(AesCtrError::InitFailed);
    }

    const EVP_CIPHER* cipher = nullptr;
    if (key.size() == AES128_KEY_LEN) {
        cipher = EVP_aes_128_ctr();
    } else if (key.size() == AES256_KEY_LEN) {
        cipher = EVP_aes_256_ctr();
    } else {
        return std::unexpected(AesCtrError::InvalidKeyLength);
    }

    if (EVP_EncryptInit_ex(impl_->ctx, cipher, nullptr, key.data(), iv.data()) != 1) {
        return std::unexpected(AesCtrError::InitFailed);
    }

    // Disable padding (CTR mode doesn't need it)
    EVP_CIPHER_CTX_set_padding(impl_->ctx, 0);

    initialized_ = true;
    return {};
}

std::expected<void, AesCtrError>
AesCtrStream::process(std::span<uint8_t> data) {
    if (!initialized_) {
        return std::unexpected(AesCtrError::NotInitialized);
    }

    int outlen = 0;
    if (EVP_EncryptUpdate(impl_->ctx, data.data(), &outlen,
                          data.data(), static_cast<int>(data.size())) != 1) {
        return std::unexpected(AesCtrError::ProcessFailed);
    }

    return {};
}

std::expected<std::vector<uint8_t>, AesCtrError>
AesCtrStream::process(std::span<const uint8_t> data) {
    if (!initialized_) {
        return std::unexpected(AesCtrError::NotInitialized);
    }

    std::vector<uint8_t> out(data.size());
    int outlen = 0;
    if (EVP_EncryptUpdate(impl_->ctx, out.data(), &outlen,
                          data.data(), static_cast<int>(data.size())) != 1) {
        return std::unexpected(AesCtrError::ProcessFailed);
    }

    return out;
}

}  // namespace obfs4::crypto
