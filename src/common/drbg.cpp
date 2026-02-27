#include "obfs4/common/drbg.hpp"
#include <cstring>

namespace obfs4::common {

// --- SipHash-2-4 inline implementation ---

static inline uint64_t rotl64(uint64_t v, int n) {
    return (v << n) | (v >> (64 - n));
}

static inline void sipround(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3) {
    v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
    v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;
    v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;
    v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
}

static inline uint64_t le64(const uint8_t* p) {
    return static_cast<uint64_t>(p[0])
         | (static_cast<uint64_t>(p[1]) << 8)
         | (static_cast<uint64_t>(p[2]) << 16)
         | (static_cast<uint64_t>(p[3]) << 24)
         | (static_cast<uint64_t>(p[4]) << 32)
         | (static_cast<uint64_t>(p[5]) << 40)
         | (static_cast<uint64_t>(p[6]) << 48)
         | (static_cast<uint64_t>(p[7]) << 56);
}

static inline void put_le64(uint8_t* p, uint64_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
    p[4] = static_cast<uint8_t>(v >> 32);
    p[5] = static_cast<uint8_t>(v >> 40);
    p[6] = static_cast<uint8_t>(v >> 48);
    p[7] = static_cast<uint8_t>(v >> 56);
}

uint64_t siphash_2_4(const uint8_t key[16], const uint8_t msg[8]) {
    uint64_t k0 = le64(key);
    uint64_t k1 = le64(key + 8);

    uint64_t v0 = k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = k1 ^ 0x7465646279746573ULL;

    // Process single 8-byte block
    uint64_t m = le64(msg);
    v3 ^= m;
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    v0 ^= m;

    // Finalization: length byte (8) in high byte
    uint64_t b = static_cast<uint64_t>(8) << 56;
    v3 ^= b;
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    v0 ^= b;

    v2 ^= 0xff;
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);
    sipround(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

// --- HashDrbg ---

void HashDrbg::init(const DrbgSeed& seed) {
    std::memcpy(key_.data(), seed.data(), 16);
    std::memcpy(ofb_.data(), seed.data() + 16, 8);
    initialized_ = true;
}

void HashDrbg::init(std::span<const uint8_t, 24> seed) {
    std::memcpy(key_.data(), seed.data(), 16);
    std::memcpy(ofb_.data(), seed.data() + 16, 8);
    initialized_ = true;
}

std::array<uint8_t, 8> HashDrbg::next_block() {
    // OFB mode: ofb = SipHash-2-4(key, ofb)
    uint64_t output = siphash_2_4(key_.data(), ofb_.data());
    put_le64(ofb_.data(), output);

    std::array<uint8_t, 8> result;
    put_le64(result.data(), output);
    return result;
}

uint16_t HashDrbg::next_length_mask() {
    auto block = next_block();
    return static_cast<uint16_t>(block[0]) << 8 | static_cast<uint16_t>(block[1]);
}

}  // namespace obfs4::common
