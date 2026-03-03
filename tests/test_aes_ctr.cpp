#include <catch2/catch_test_macros.hpp>
#include "obfs4/crypto/aes_ctr.hpp"
#include "obfs4/common/csrand.hpp"
#include <cstring>

using namespace obfs4::crypto;
using namespace obfs4::common;

TEST_CASE("AES-128-CTR encrypt/decrypt round trip", "[aes_ctr]") {
    auto key = random_array<AesCtrStream::AES128_KEY_LEN>();
    auto iv = random_array<AesCtrStream::IV_LEN>();

    std::vector<uint8_t> plaintext(256);
    for (size_t i = 0; i < plaintext.size(); ++i) {
        plaintext[i] = static_cast<uint8_t>(i);
    }

    // Encrypt
    AesCtrStream enc;
    REQUIRE(enc.init(key, iv).has_value());
    auto ciphertext = enc.process(std::span<const uint8_t>(plaintext));
    REQUIRE(ciphertext.has_value());
    REQUIRE(ciphertext->size() == plaintext.size());
    REQUIRE(*ciphertext != plaintext);

    // Decrypt (same key/iv, CTR is symmetric)
    AesCtrStream dec;
    REQUIRE(dec.init(key, iv).has_value());
    auto decrypted = dec.process(std::span<const uint8_t>(*ciphertext));
    REQUIRE(decrypted.has_value());
    REQUIRE(*decrypted == plaintext);
}

TEST_CASE("AES-256-CTR encrypt/decrypt round trip", "[aes_ctr]") {
    auto key = random_array<AesCtrStream::AES256_KEY_LEN>();
    auto iv = random_array<AesCtrStream::IV_LEN>();

    std::vector<uint8_t> plaintext(1024);
    random_bytes(plaintext);

    AesCtrStream enc;
    REQUIRE(enc.init(key, iv).has_value());
    auto ciphertext = enc.process(std::span<const uint8_t>(plaintext));
    REQUIRE(ciphertext.has_value());

    AesCtrStream dec;
    REQUIRE(dec.init(key, iv).has_value());
    auto decrypted = dec.process(std::span<const uint8_t>(*ciphertext));
    REQUIRE(decrypted.has_value());
    REQUIRE(*decrypted == plaintext);
}

TEST_CASE("AES-CTR streaming mode", "[aes_ctr]") {
    auto key = random_array<AesCtrStream::AES128_KEY_LEN>();
    auto iv = random_array<AesCtrStream::IV_LEN>();

    std::vector<uint8_t> data(100);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(i);
    }

    // Encrypt in one shot
    AesCtrStream enc1;
    REQUIRE(enc1.init(key, iv).has_value());
    auto ct_one_shot = enc1.process(std::span<const uint8_t>(data));
    REQUIRE(ct_one_shot.has_value());

    // Encrypt in chunks (streaming)
    AesCtrStream enc2;
    REQUIRE(enc2.init(key, iv).has_value());
    std::vector<uint8_t> ct_streaming;
    auto chunk1 = enc2.process(std::span<const uint8_t>(data.data(), 30));
    auto chunk2 = enc2.process(std::span<const uint8_t>(data.data() + 30, 70));
    REQUIRE(chunk1.has_value());
    REQUIRE(chunk2.has_value());
    ct_streaming.insert(ct_streaming.end(), chunk1->begin(), chunk1->end());
    ct_streaming.insert(ct_streaming.end(), chunk2->begin(), chunk2->end());

    REQUIRE(ct_streaming == *ct_one_shot);
}

TEST_CASE("AES-CTR in-place processing", "[aes_ctr]") {
    auto key = random_array<AesCtrStream::AES128_KEY_LEN>();
    auto iv = random_array<AesCtrStream::IV_LEN>();

    std::vector<uint8_t> original(64);
    random_bytes(original);
    auto data = original;

    AesCtrStream enc;
    REQUIRE(enc.init(key, iv).has_value());
    REQUIRE(enc.process(std::span<uint8_t>(data)).has_value());
    REQUIRE(data != original);

    AesCtrStream dec;
    REQUIRE(dec.init(key, iv).has_value());
    REQUIRE(dec.process(std::span<uint8_t>(data)).has_value());
    REQUIRE(data == original);
}

TEST_CASE("AES-CTR rejects invalid key length", "[aes_ctr]") {
    auto iv = random_array<AesCtrStream::IV_LEN>();
    auto bad_key = random_array<15>();

    AesCtrStream stream;
    auto result = stream.init(bad_key, iv);
    REQUIRE(!result.has_value());
    REQUIRE(result.error() == AesCtrError::InvalidKeyLength);
}

TEST_CASE("AES-CTR rejects uninitialized process", "[aes_ctr]") {
    std::vector<uint8_t> data(16);
    AesCtrStream stream;
    auto result = stream.process(std::span<uint8_t>(data));
    REQUIRE(!result.has_value());
    REQUIRE(result.error() == AesCtrError::NotInitialized);
}
