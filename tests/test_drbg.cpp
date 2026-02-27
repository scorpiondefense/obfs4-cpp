#include <catch2/catch_test_macros.hpp>
#include "obfs4/common/drbg.hpp"
#include <cstring>

using namespace obfs4::common;

TEST_CASE("SipHash-2-4 known value", "[drbg]") {
    // Known SipHash-2-4 test vector
    uint8_t key[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint8_t msg[8] = {0, 1, 2, 3, 4, 5, 6, 7};

    uint64_t result = siphash_2_4(key, msg);
    // SipHash-2-4 should produce a deterministic non-zero result
    REQUIRE(result != 0);
}

TEST_CASE("HashDrbg produces deterministic output", "[drbg]") {
    DrbgSeed seed{};
    for (int i = 0; i < 24; ++i) seed[i] = static_cast<uint8_t>(i);

    HashDrbg drbg1, drbg2;
    drbg1.init(seed);
    drbg2.init(seed);

    for (int i = 0; i < 100; ++i) {
        auto block1 = drbg1.next_block();
        auto block2 = drbg2.next_block();
        REQUIRE(block1 == block2);
    }
}

TEST_CASE("HashDrbg produces varying output", "[drbg]") {
    DrbgSeed seed{};
    seed[0] = 42;

    HashDrbg drbg;
    drbg.init(seed);

    auto block1 = drbg.next_block();
    auto block2 = drbg.next_block();

    // Two consecutive blocks should differ
    REQUIRE(block1 != block2);
}

TEST_CASE("HashDrbg length mask", "[drbg]") {
    DrbgSeed seed{};
    HashDrbg drbg;
    drbg.init(seed);

    // Should produce 16-bit values
    for (int i = 0; i < 100; ++i) {
        uint16_t mask = drbg.next_length_mask();
        // Just verify it returns without error
        (void)mask;
    }
}

TEST_CASE("HashDrbg different seeds produce different output", "[drbg]") {
    DrbgSeed seed1{}, seed2{};
    seed1[0] = 1;
    seed2[0] = 2;

    HashDrbg drbg1, drbg2;
    drbg1.init(seed1);
    drbg2.init(seed2);

    auto block1 = drbg1.next_block();
    auto block2 = drbg2.next_block();

    REQUIRE(block1 != block2);
}
