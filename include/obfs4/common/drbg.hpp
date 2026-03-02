#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace obfs4::common {

// SipHash-2-4 inline implementation
uint64_t siphash_2_4(const uint8_t key[16], const uint8_t msg[8]);

// Seed = 24 bytes: SipHash key[16] + OFB initial state[8]
using DrbgSeed = std::array<uint8_t, 24>;

// SipHash-2-4 OFB DRBG
// Port of Go's common/drbg
// IMPORTANT: Uses streaming/accumulating SipHash state to match Go's hash.Hash
// interface where Write() calls accumulate internal state across NextBlock() calls.
class HashDrbg {
public:
    HashDrbg() = default;

    void init(const DrbgSeed& seed);
    void init(std::span<const uint8_t, 24> seed);

    // Generate next 8-byte block
    std::array<uint8_t, 8> next_block();

    // Get 16-bit length mask for frame obfuscation
    uint16_t next_length_mask();

    bool initialized() const { return initialized_; }

private:
    // Streaming SipHash-2-4 state that accumulates across next_block() calls.
    // This matches Go's hash.Hash64 interface where Write() modifies internal
    // state and Sum() finalizes on a copy without resetting.
    struct SipState {
        uint64_t v0{}, v1{}, v2{}, v3{};
        size_t total_len{0};
    };

    SipState sip_{};
    std::array<uint8_t, 8> ofb_{};
    bool initialized_ = false;
};

}  // namespace obfs4::common
