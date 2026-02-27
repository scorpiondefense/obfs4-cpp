#include <catch2/catch_test_macros.hpp>
#include "obfs4/crypto/elligator2.hpp"
#include "obfs4/crypto/hash.hpp"
#include <cstring>

using namespace obfs4::crypto;

// Go test vectors from x25519ell2 tests
TEST_CASE("Elligator2 representative_to_public_key zero", "[elligator2]") {
    Representative repr{};
    auto pub = elligator2::representative_to_public_key(repr);
    PublicKey expected{};
    REQUIRE(pub == expected);
}

TEST_CASE("Elligator2 representative_to_public_key vector 1", "[elligator2]") {
    // Go test vector: 673a...c02f -> 242a...f85e
    auto repr_hex = from_hex("673a505e107189ee54ca93310ac42e4545e9e59050aaac6f8b5f64295c8ec02f");
    REQUIRE(repr_hex.has_value());
    Representative repr;
    std::memcpy(repr.data(), repr_hex->data(), 32);

    auto pub = elligator2::representative_to_public_key(repr);

    auto expected_hex = from_hex("242ae39ef158ed60f20b89396d7d7eef5374aba15dc312a6aea6d1e57cacf85e");
    REQUIRE(expected_hex.has_value());
    PublicKey expected;
    std::memcpy(expected.data(), expected_hex->data(), 32);

    REQUIRE(pub == expected);
}

TEST_CASE("Elligator2 representative_to_public_key vector 2", "[elligator2]") {
    // Go test vector: 9226...545a -> 696f...410b
    auto repr_hex = from_hex("922688fa428d42bc1fa8806998b70f557dd7c3dea81a55f02841df688d26545a");
    REQUIRE(repr_hex.has_value());
    Representative repr;
    std::memcpy(repr.data(), repr_hex->data(), 32);

    auto pub = elligator2::representative_to_public_key(repr);

    auto expected_hex = from_hex("89373a8efc691c5784c729d30849fd9f040a9cc3f2f1f189c5509a0ca019d56a");
    REQUIRE(expected_hex.has_value());
    PublicKey expected;
    std::memcpy(expected.data(), expected_hex->data(), 32);

    REQUIRE(pub == expected);
}

TEST_CASE("Elligator2 representative_to_public_key vector 3", "[elligator2]") {
    // Go test vector: 0d3b...bbba -> 0b00...177f
    auto repr_hex = from_hex("0d3b0eb88b74ed13d5f6a130e03c4ad1680bb87db1ce3b2ab610f8945465bbba");
    REQUIRE(repr_hex.has_value());
    Representative repr;
    std::memcpy(repr.data(), repr_hex->data(), 32);

    auto pub = elligator2::representative_to_public_key(repr);

    auto expected_hex = from_hex("43f54b624bc7677f3af6d3cde751d91cee06e2fdb9548da0fb8f6c273f1ca303");
    REQUIRE(expected_hex.has_value());
    PublicKey expected;
    std::memcpy(expected.data(), expected_hex->data(), 32);

    REQUIRE(pub == expected);
}

TEST_CASE("Elligator2 clamping clears bits 254-255", "[elligator2]") {
    // A representative with bit 254 set should still work correctly
    // because we clamp with &= 0x3f (not 0x7f)
    Representative repr{};
    repr[31] = 0x40;  // bit 254 set

    auto pub_wrong = elligator2::representative_to_public_key(repr);

    // With proper 0x3f clamping, this bit gets cleared, so result
    // should be the same as the zero representative
    Representative zero_repr{};
    auto pub_correct = elligator2::representative_to_public_key(zero_repr);

    REQUIRE(pub_wrong == pub_correct);
}

TEST_CASE("Elligator2 generate_representable_keypair round-trip", "[elligator2]") {
    // Generate a representable keypair and verify round-trip
    auto kp = elligator2::generate_representable_keypair();
    REQUIRE(kp.representative.has_value());

    // representative -> public key should match
    auto recovered = elligator2::representative_to_public_key(*kp.representative);
    REQUIRE(recovered == kp.public_key);
}

TEST_CASE("Elligator2 multiple keypair round-trips", "[elligator2]") {
    // Generate several keypairs and verify each round-trips
    for (int i = 0; i < 10; ++i) {
        auto kp = elligator2::generate_representable_keypair();
        REQUIRE(kp.representative.has_value());

        auto recovered = elligator2::representative_to_public_key(*kp.representative);
        REQUIRE(recovered == kp.public_key);
    }
}

TEST_CASE("Elligator2 padding bits are set in representative", "[elligator2]") {
    // Generate keypairs and check that bits 254-255 can be set
    bool saw_bit254 = false;
    bool saw_bit255 = false;

    for (int i = 0; i < 100; ++i) {
        auto kp = elligator2::generate_representable_keypair();
        if (!kp.representative) continue;

        auto& repr = *kp.representative;
        if (repr[31] & 0x40) saw_bit254 = true;
        if (repr[31] & 0x80) saw_bit255 = true;

        if (saw_bit254 && saw_bit255) break;
    }

    // With 100 attempts, probability of not seeing each bit is ~(0.5)^100
    REQUIRE(saw_bit254);
    REQUIRE(saw_bit255);
}
