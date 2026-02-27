#include <catch2/catch_test_macros.hpp>
#include "obfs4/transport/framing.hpp"
#include "obfs4/common/csrand.hpp"
#include <cstring>

using namespace obfs4::transport;

static void init_pair(Encoder& enc, Decoder& dec) {
    auto key = obfs4::common::random_array<32>();
    auto nonce_prefix = obfs4::common::random_array<16>();
    auto drbg_seed = obfs4::common::random_array<24>();

    enc.init(key, nonce_prefix, drbg_seed);
    dec.init(key, nonce_prefix, drbg_seed);
}

TEST_CASE("Framing encode-decode round-trip empty", "[framing]") {
    Encoder enc;
    Decoder dec;
    init_pair(enc, dec);

    std::vector<uint8_t> payload;
    auto encoded = enc.encode(payload);

    auto result = dec.decode(encoded);
    REQUIRE(result.has_value());
    REQUIRE(result->frames.size() == 1);
    REQUIRE(result->frames[0].payload.empty());
}

TEST_CASE("Framing encode-decode round-trip small", "[framing]") {
    Encoder enc;
    Decoder dec;
    init_pair(enc, dec);

    std::vector<uint8_t> payload = {1, 2, 3, 4, 5};
    auto encoded = enc.encode(payload);

    auto result = dec.decode(encoded);
    REQUIRE(result.has_value());
    REQUIRE(result->frames.size() == 1);
    REQUIRE(result->frames[0].payload == payload);
}

TEST_CASE("Framing encode-decode round-trip max payload", "[framing]") {
    Encoder enc;
    Decoder dec;
    init_pair(enc, dec);

    auto payload = obfs4::common::random_bytes(MAX_FRAME_PAYLOAD);
    auto encoded = enc.encode(payload);

    auto result = dec.decode(encoded);
    REQUIRE(result.has_value());
    REQUIRE(result->frames.size() == 1);
    REQUIRE(result->frames[0].payload == payload);
}

TEST_CASE("Framing multiple frames", "[framing]") {
    Encoder enc;
    Decoder dec;
    init_pair(enc, dec);

    std::vector<uint8_t> p1 = {10, 20, 30};
    std::vector<uint8_t> p2 = {40, 50, 60, 70};
    std::vector<uint8_t> p3 = {80};

    auto e1 = enc.encode(p1);
    auto e2 = enc.encode(p2);
    auto e3 = enc.encode(p3);

    // Concatenate all frames
    std::vector<uint8_t> wire;
    wire.insert(wire.end(), e1.begin(), e1.end());
    wire.insert(wire.end(), e2.begin(), e2.end());
    wire.insert(wire.end(), e3.begin(), e3.end());

    auto result = dec.decode(wire);
    REQUIRE(result.has_value());
    REQUIRE(result->frames.size() == 3);
    REQUIRE(result->frames[0].payload == p1);
    REQUIRE(result->frames[1].payload == p2);
    REQUIRE(result->frames[2].payload == p3);
}

TEST_CASE("Framing various payload sizes", "[framing]") {
    Encoder enc;
    Decoder dec;
    init_pair(enc, dec);

    for (size_t size = 0; size <= 100; ++size) {
        auto payload = obfs4::common::random_bytes(size);
        auto encoded = enc.encode(payload);

        auto result = dec.decode(encoded);
        REQUIRE(result.has_value());
        REQUIRE(result->frames.size() == 1);
        REQUIRE(result->frames[0].payload == payload);
    }
}
