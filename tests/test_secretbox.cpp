#include <catch2/catch_test_macros.hpp>
#include "obfs4/crypto/secretbox.hpp"
#include "obfs4/common/csrand.hpp"
#include <cstring>

using namespace obfs4::crypto;

TEST_CASE("Secretbox seal and open round-trip", "[secretbox]") {
    std::array<uint8_t, 32> key{};
    key[0] = 1;
    std::array<uint8_t, 24> nonce{};
    nonce[0] = 2;

    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5, 6, 7, 8};

    auto sealed = Secretbox::seal(key, nonce, plaintext);
    REQUIRE(sealed.size() == plaintext.size() + Secretbox::OVERHEAD);

    auto opened = Secretbox::open(key, nonce, sealed);
    REQUIRE(opened.has_value());
    REQUIRE(*opened == plaintext);
}

TEST_CASE("Secretbox open fails with wrong key", "[secretbox]") {
    std::array<uint8_t, 32> key{};
    key[0] = 1;
    std::array<uint8_t, 24> nonce{};

    std::vector<uint8_t> plaintext = {1, 2, 3};
    auto sealed = Secretbox::seal(key, nonce, plaintext);

    std::array<uint8_t, 32> wrong_key{};
    wrong_key[0] = 99;

    auto opened = Secretbox::open(wrong_key, nonce, sealed);
    REQUIRE(!opened.has_value());
}

TEST_CASE("Secretbox open fails with tampered ciphertext", "[secretbox]") {
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 24> nonce{};
    std::vector<uint8_t> plaintext = {10, 20, 30};

    auto sealed = Secretbox::seal(key, nonce, plaintext);
    sealed[sealed.size() - 1] ^= 0xff;  // Flip last byte

    auto opened = Secretbox::open(key, nonce, sealed);
    REQUIRE(!opened.has_value());
}

TEST_CASE("Secretbox empty plaintext", "[secretbox]") {
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 24> nonce{};
    std::vector<uint8_t> plaintext;

    auto sealed = Secretbox::seal(key, nonce, plaintext);
    REQUIRE(sealed.size() == Secretbox::OVERHEAD);

    auto opened = Secretbox::open(key, nonce, sealed);
    REQUIRE(opened.has_value());
    REQUIRE(opened->empty());
}

TEST_CASE("Secretbox various sizes", "[secretbox]") {
    auto key = obfs4::common::random_array<32>();
    auto nonce = obfs4::common::random_array<24>();

    for (size_t size : {1, 15, 16, 17, 63, 64, 65, 255, 1024}) {
        auto plaintext = obfs4::common::random_bytes(size);

        auto sealed = Secretbox::seal(key, nonce, plaintext);
        auto opened = Secretbox::open(key, nonce, sealed);
        REQUIRE(opened.has_value());
        REQUIRE(*opened == plaintext);
    }
}
