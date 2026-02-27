#include <catch2/catch_test_macros.hpp>
#include "obfs4/crypto/field25519.hpp"
#include <cstring>

using namespace obfs4::crypto;

TEST_CASE("FieldElement zero", "[field25519]") {
    auto z = FieldElement::zero();
    auto bytes = z.to_bytes();
    for (int i = 0; i < 32; ++i) {
        REQUIRE(bytes[i] == 0);
    }
}

TEST_CASE("FieldElement one", "[field25519]") {
    auto one = FieldElement::one();
    auto bytes = one.to_bytes();
    REQUIRE(bytes[0] == 1);
    for (int i = 1; i < 32; ++i) {
        REQUIRE(bytes[i] == 0);
    }
}

TEST_CASE("FieldElement round-trip encode/decode", "[field25519]") {
    std::array<uint8_t, 32> input{};
    input[0] = 42;
    input[5] = 0xff;
    input[31] = 0x7f;

    auto fe = FieldElement::from_bytes(input);
    auto output = fe.to_bytes();

    REQUIRE(std::memcmp(input.data(), output.data(), 32) == 0);
}

TEST_CASE("FieldElement A constant", "[field25519]") {
    auto a = FieldElement::A();
    auto bytes = a.to_bytes();
    // 486662 = 0x76d06 in little-endian: 0x06, 0x6d, 0x07, 0x00...
    REQUIRE(bytes[0] == 0x06);
    REQUIRE(bytes[1] == 0x6d);
    REQUIRE(bytes[2] == 0x07);
    for (int i = 3; i < 32; ++i) {
        REQUIRE(bytes[i] == 0);
    }
}

TEST_CASE("FieldElement addition", "[field25519]") {
    auto one = FieldElement::one();
    auto two = one + one;
    auto bytes = two.to_bytes();
    REQUIRE(bytes[0] == 2);
}

TEST_CASE("FieldElement multiplication", "[field25519]") {
    auto three = FieldElement(3, 0, 0, 0, 0);
    auto four = FieldElement(4, 0, 0, 0, 0);
    auto twelve = three * four;
    auto bytes = twelve.to_bytes();
    REQUIRE(bytes[0] == 12);
}

TEST_CASE("FieldElement inversion", "[field25519]") {
    auto three = FieldElement(3, 0, 0, 0, 0);
    auto inv = three.invert();
    auto product = three * inv;
    REQUIRE(product == FieldElement::one());
}

TEST_CASE("FieldElement sqrt(-1)", "[field25519]") {
    auto i = FieldElement::sqrt_m1();
    auto i_sq = i.square();
    auto neg_one = -FieldElement::one();
    REQUIRE(i_sq == neg_one);
}

TEST_CASE("FieldElement sqrt", "[field25519]") {
    auto nine = FieldElement(9, 0, 0, 0, 0);
    auto [root, exists] = nine.sqrt();
    REQUIRE(exists);
    REQUIRE(root.square() == nine);
}

TEST_CASE("FieldElement conditional_negate", "[field25519]") {
    auto five = FieldElement(5, 0, 0, 0, 0);
    auto neg_five = five.conditional_negate(true);
    REQUIRE((five + neg_five) == FieldElement::zero());

    auto same = five.conditional_negate(false);
    REQUIRE(same == five);
}

TEST_CASE("FieldElement mul_small", "[field25519]") {
    auto seven = FieldElement(7, 0, 0, 0, 0);
    auto result = seven.mul_small(6);
    auto expected = FieldElement(42, 0, 0, 0, 0);
    REQUIRE(result == expected);
}
