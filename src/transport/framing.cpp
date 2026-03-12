#include "obfs4/transport/framing.hpp"
#include <cstring>

namespace obfs4::transport {

// --- Encoder ---

void Encoder::init(std::span<const uint8_t, 32> key,
                   std::span<const uint8_t, 16> nonce_prefix,
                   std::span<const uint8_t, 24> drbg_seed) {
    std::memcpy(key_.data(), key.data(), 32);
    std::memcpy(nonce_prefix_.data(), nonce_prefix.data(), 16);
    counter_ = 1;
    drbg_.init(drbg_seed);
}

std::array<uint8_t, 24> Encoder::make_nonce() const {
    std::array<uint8_t, 24> nonce{};
    std::memcpy(nonce.data(), nonce_prefix_.data(), 16);
    // Counter in last 8 bytes, big-endian
    nonce[16] = static_cast<uint8_t>(counter_ >> 56);
    nonce[17] = static_cast<uint8_t>(counter_ >> 48);
    nonce[18] = static_cast<uint8_t>(counter_ >> 40);
    nonce[19] = static_cast<uint8_t>(counter_ >> 32);
    nonce[20] = static_cast<uint8_t>(counter_ >> 24);
    nonce[21] = static_cast<uint8_t>(counter_ >> 16);
    nonce[22] = static_cast<uint8_t>(counter_ >> 8);
    nonce[23] = static_cast<uint8_t>(counter_);
    return nonce;
}

void Encoder::increment_counter() {
    ++counter_;
}

std::vector<uint8_t> Encoder::encode(std::span<const uint8_t> payload) {
    // Seal the payload with secretbox
    auto nonce = make_nonce();
    auto sealed = crypto::Secretbox::seal(key_, nonce, payload);
    increment_counter();

    // Obfuscate length
    uint16_t raw_len = static_cast<uint16_t>(sealed.size());
    uint16_t mask = drbg_.next_length_mask();
    uint16_t obfuscated = raw_len ^ mask;

    // Wire format: obfuscated_length[2] || sealed
    std::vector<uint8_t> output(2 + sealed.size());
    output[0] = static_cast<uint8_t>(obfuscated >> 8);
    output[1] = static_cast<uint8_t>(obfuscated & 0xff);
    std::memcpy(output.data() + 2, sealed.data(), sealed.size());

    return output;
}

// --- Decoder ---

void Decoder::init(std::span<const uint8_t, 32> key,
                   std::span<const uint8_t, 16> nonce_prefix,
                   std::span<const uint8_t, 24> drbg_seed) {
    std::memcpy(key_.data(), key.data(), 32);
    std::memcpy(nonce_prefix_.data(), nonce_prefix.data(), 16);
    counter_ = 1;
    drbg_.init(drbg_seed);
}

std::array<uint8_t, 24> Decoder::make_nonce() const {
    std::array<uint8_t, 24> nonce{};
    std::memcpy(nonce.data(), nonce_prefix_.data(), 16);
    nonce[16] = static_cast<uint8_t>(counter_ >> 56);
    nonce[17] = static_cast<uint8_t>(counter_ >> 48);
    nonce[18] = static_cast<uint8_t>(counter_ >> 40);
    nonce[19] = static_cast<uint8_t>(counter_ >> 32);
    nonce[20] = static_cast<uint8_t>(counter_ >> 24);
    nonce[21] = static_cast<uint8_t>(counter_ >> 16);
    nonce[22] = static_cast<uint8_t>(counter_ >> 8);
    nonce[23] = static_cast<uint8_t>(counter_);
    return nonce;
}

void Decoder::increment_counter() {
    ++counter_;
}

std::expected<Decoder::DecodeResult, FrameError>
Decoder::decode(std::span<const uint8_t> data) {
    DecodeResult result;

    buffer_.insert(buffer_.end(), data.begin(), data.end());

    while (true) {
        if (!pending_len_) {
            if (buffer_.size() < 2) break;

            uint16_t obfuscated = (static_cast<uint16_t>(buffer_[0]) << 8) |
                                   static_cast<uint16_t>(buffer_[1]);
            uint16_t mask = drbg_.next_length_mask();
            uint16_t raw_len = obfuscated ^ mask;

            // Validate: raw_len must be in [OVERHEAD, MAX_SEGMENT_LENGTH - 2]
            // (secretbox overhead = 16, so minimum sealed size is 16)
            if (raw_len < crypto::Secretbox::OVERHEAD ||
                raw_len > MAX_SEGMENT_LENGTH - 2) {
                // Length oracle mitigation: use a random length, then fail on tag
                auto block = drbg_.next_block();
                raw_len = (static_cast<uint16_t>(block[0]) << 8 |
                           static_cast<uint16_t>(block[1])) %
                          (MAX_SEGMENT_LENGTH - 2 - crypto::Secretbox::OVERHEAD) +
                          crypto::Secretbox::OVERHEAD;
            }

            pending_len_ = raw_len;
            buffer_.erase(buffer_.begin(), buffer_.begin() + 2);
            result.consumed += 2;
        }

        if (buffer_.size() < *pending_len_) break;

        // Decrypt frame
        auto nonce = make_nonce();
        auto ct = std::span<const uint8_t>(buffer_.data(), *pending_len_);
        auto pt = crypto::Secretbox::open(key_, nonce, ct);
        if (!pt) {
            return std::unexpected(FrameError::TagMismatch);
        }
        increment_counter();

        result.frames.push_back(DecodedFrame{std::move(*pt)});
        buffer_.erase(buffer_.begin(), buffer_.begin() + *pending_len_);
        result.consumed += *pending_len_;
        pending_len_.reset();
    }

    return result;
}

}  // namespace obfs4::transport
