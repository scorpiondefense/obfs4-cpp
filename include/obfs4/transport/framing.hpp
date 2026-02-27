#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <vector>
#include "obfs4/crypto/secretbox.hpp"
#include "obfs4/common/drbg.hpp"

namespace obfs4::transport {

constexpr size_t MAX_SEGMENT_LENGTH = 1448;
constexpr size_t FRAME_OVERHEAD = 2 + 16;  // length + secretbox tag
constexpr size_t MAX_FRAME_PAYLOAD = MAX_SEGMENT_LENGTH - FRAME_OVERHEAD;  // 1430
constexpr size_t KEY_MATERIAL_LENGTH = 32 + 16 + 24;  // 72 = key + nonce_prefix + drbg_seed

enum class FrameError {
    NeedMore,
    TagMismatch,
    InvalidLength,
};

struct DecodedFrame {
    std::vector<uint8_t> payload;
};

// Frame encoder
class Encoder {
public:
    void init(std::span<const uint8_t, 32> key,
              std::span<const uint8_t, 16> nonce_prefix,
              std::span<const uint8_t, 24> drbg_seed);

    std::vector<uint8_t> encode(std::span<const uint8_t> payload);

private:
    std::array<uint8_t, 32> key_{};
    std::array<uint8_t, 16> nonce_prefix_{};
    uint64_t counter_ = 1;  // Starts at 1, per spec
    common::HashDrbg drbg_;

    std::array<uint8_t, 24> make_nonce() const;
    void increment_counter();
};

// Frame decoder
class Decoder {
public:
    void init(std::span<const uint8_t, 32> key,
              std::span<const uint8_t, 16> nonce_prefix,
              std::span<const uint8_t, 24> drbg_seed);

    // Returns decoded frames and number of bytes consumed
    struct DecodeResult {
        std::vector<DecodedFrame> frames;
        size_t consumed = 0;
    };

    std::expected<DecodeResult, FrameError> decode(std::span<const uint8_t> data);

private:
    std::array<uint8_t, 32> key_{};
    std::array<uint8_t, 16> nonce_prefix_{};
    uint64_t counter_ = 1;
    common::HashDrbg drbg_;

    std::vector<uint8_t> buffer_;
    std::optional<uint16_t> pending_len_;

    std::array<uint8_t, 24> make_nonce() const;
    void increment_counter();
};

}  // namespace obfs4::transport
