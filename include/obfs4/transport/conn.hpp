#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <vector>
#include "obfs4/transport/framing.hpp"
#include "obfs4/transport/packet.hpp"
#include "obfs4/common/prob_dist.hpp"
#include "obfs4/common/drbg.hpp"

namespace obfs4::transport {

// IAT (Inter-Arrival Time) modes
enum class IATMode : int {
    None = 0,       // No IAT obfuscation
    Enabled = 1,    // IAT delays enabled
    Paranoid = 2,   // Paranoid IAT (split writes)
};

enum class ConnError {
    HandshakeIncomplete,
    EncodeFailed,
    DecodeFailed,
    PayloadTooLarge,
};

// obfs4 connection state (wraps framing + packet layers)
class Obfs4Conn {
public:
    Obfs4Conn() = default;

    // Initialize from handshake key material
    void init(std::span<const uint8_t, 72> encoder_km,
              std::span<const uint8_t, 72> decoder_km,
              IATMode iat_mode = IATMode::None);

    // Encode plaintext data into obfs4 wire format
    std::vector<uint8_t> write(std::span<const uint8_t> data);

    // Decode obfs4 wire data into plaintext
    struct ReadResult {
        std::vector<uint8_t> plaintext;
        size_t consumed = 0;
    };
    std::expected<ReadResult, ConnError> read(std::span<const uint8_t> data);

    // Update PRNG seed (received via PrngSeed packet)
    void update_prng_seed(const common::DrbgSeed& seed);

    bool initialized() const { return initialized_; }

private:
    Encoder encoder_;
    Decoder decoder_;
    IATMode iat_mode_ = IATMode::None;
    common::WeightedDist len_dist_;
    common::WeightedDist iat_dist_;
    bool initialized_ = false;
};

}  // namespace obfs4::transport
