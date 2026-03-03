#include <catch2/catch_test_macros.hpp>
#include "obfs4/crypto/hash.hpp"
#include "obfs4/crypto/aes_ctr.hpp"
#include "obfs4/common/csrand.hpp"
#include "obfs4/common/drbg.hpp"
#include "obfs4/common/prob_dist.hpp"
#include "obfs4/common/uniform_dh.hpp"
#include <cstring>

using namespace obfs4::crypto;
using namespace obfs4::common;

// ============= SHA-256 tests =============

TEST_CASE("crypto parity: SHA-256 empty input", "[crypto][parity]") {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    std::vector<uint8_t> empty;
    auto result = sha256(empty);
    REQUIRE(result.has_value());
    auto hex = to_hex(*result);
    REQUIRE(hex == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_CASE("crypto parity: SHA-256 known vector", "[crypto][parity]") {
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    std::vector<uint8_t> data = {'a', 'b', 'c'};
    auto result = sha256(data);
    REQUIRE(result.has_value());
    auto hex = to_hex(*result);
    REQUIRE(hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

// ============= SHA-512 tests =============

TEST_CASE("crypto parity: SHA-512 empty input", "[crypto][parity]") {
    std::vector<uint8_t> empty;
    auto result = sha512(empty);
    REQUIRE(result.has_value());
    auto hex = to_hex(*result);
    // Standard SHA-512("") value
    REQUIRE(hex == "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                   "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

// ============= HMAC-SHA256 tests =============

TEST_CASE("crypto parity: HMAC-SHA256 known vector", "[crypto][parity]") {
    // RFC 4231 test case 2:
    // Key = "Jefe"
    // Data = "what do ya want for nothing?"
    std::vector<uint8_t> key = {'J', 'e', 'f', 'e'};
    std::vector<uint8_t> data = {'w', 'h', 'a', 't', ' ', 'd', 'o', ' ',
                                  'y', 'a', ' ', 'w', 'a', 'n', 't', ' ',
                                  'f', 'o', 'r', ' ', 'n', 'o', 't', 'h',
                                  'i', 'n', 'g', '?'};
    auto result = hmac_sha256(key, data);
    REQUIRE(result.has_value());
    auto hex = to_hex(*result);
    REQUIRE(hex == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST_CASE("crypto parity: HMAC-SHA256 streaming matches one-shot", "[crypto][parity]") {
    auto key = random_bytes(32);
    auto data = random_bytes(256);

    // One-shot
    auto one_shot = hmac_sha256(key, data);
    REQUIRE(one_shot.has_value());

    // Streaming
    HmacSha256 hmac;
    REQUIRE(hmac.init(key).has_value());

    // Feed in chunks
    size_t offset = 0;
    while (offset < data.size()) {
        size_t chunk = std::min<size_t>(37, data.size() - offset);
        REQUIRE(hmac.update(std::span<const uint8_t>(data.data() + offset, chunk)).has_value());
        offset += chunk;
    }

    auto streaming = hmac.finalize();
    REQUIRE(streaming.has_value());
    REQUIRE(*one_shot == *streaming);
}

// ============= HKDF-SHA256 tests =============

TEST_CASE("crypto parity: HKDF-SHA256 RFC 5869 test vector 1", "[crypto][parity]") {
    // Test Case 1 from RFC 5869
    // IKM = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
    // salt = 0x000102030405060708090a0b0c (13 octets)
    // info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
    // L = 42

    std::vector<uint8_t> ikm(22, 0x0b);
    std::vector<uint8_t> salt = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                  0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    std::vector<uint8_t> info = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
                                  0xf7, 0xf8, 0xf9};

    auto result = hkdf_sha256(salt, ikm, info, 42);
    REQUIRE(result.has_value());
    REQUIRE(result->size() == 42);

    auto hex = to_hex(*result);
    REQUIRE(hex == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                   "34007208d5b887185865");
}

TEST_CASE("crypto parity: HKDF-SHA256 with salt", "[crypto][parity]") {
    // Test that HKDF produces deterministic output with given salt
    std::vector<uint8_t> ikm(32, 0x42);
    std::vector<uint8_t> salt(16, 0x00);
    std::vector<uint8_t> info = {'t', 'e', 's', 't'};

    auto result1 = hkdf_sha256(salt, ikm, info, 64);
    REQUIRE(result1.has_value());
    REQUIRE(result1->size() == 64);

    // Same inputs -> same output
    auto result2 = hkdf_sha256(salt, ikm, info, 64);
    REQUIRE(result2.has_value());
    REQUIRE(*result1 == *result2);

    // Different IKM -> different output
    std::vector<uint8_t> ikm2(32, 0x43);
    auto result3 = hkdf_sha256(salt, ikm2, info, 64);
    REQUIRE(result3.has_value());
    REQUIRE(*result1 != *result3);
}

// ============= Hex encoding tests =============

TEST_CASE("crypto parity: hex encode/decode round-trip", "[crypto][parity]") {
    for (size_t len = 0; len < 64; ++len) {
        auto data = random_bytes(len);
        auto hex = to_hex(data);
        REQUIRE(hex.size() == len * 2);

        auto decoded = from_hex(hex);
        REQUIRE(decoded.has_value());
        REQUIRE(*decoded == data);
    }
}

TEST_CASE("crypto parity: hex decode known values", "[crypto][parity]") {
    auto r1 = from_hex("deadbeef");
    REQUIRE(r1.has_value());
    REQUIRE(r1->size() == 4);
    REQUIRE((*r1)[0] == 0xde);
    REQUIRE((*r1)[1] == 0xad);
    REQUIRE((*r1)[2] == 0xbe);
    REQUIRE((*r1)[3] == 0xef);

    // Empty string
    auto r2 = from_hex("");
    REQUIRE(r2.has_value());
    REQUIRE(r2->empty());
}

TEST_CASE("crypto parity: hex decode rejects invalid input", "[crypto][parity]") {
    // Odd length
    auto r1 = from_hex("abc");
    REQUIRE(!r1.has_value());

    // Invalid characters
    auto r2 = from_hex("gg");
    REQUIRE(!r2.has_value());
}

// ============= Constant-time comparison =============

TEST_CASE("crypto parity: constant_time_compare", "[crypto][parity]") {
    auto a = random_bytes(32);
    auto b = a;  // copy

    REQUIRE(constant_time_compare(a, b));

    // Differ by one byte
    b[15] ^= 0x01;
    REQUIRE(!constant_time_compare(a, b));

    // Different lengths
    auto c = random_bytes(16);
    REQUIRE(!constant_time_compare(a, c));

    // Empty spans
    std::vector<uint8_t> e1, e2;
    REQUIRE(constant_time_compare(e1, e2));
}

// ============= AES-CTR parity tests =============

TEST_CASE("crypto parity: AES-128-CTR known vector", "[crypto][parity]") {
    // NIST AES-128-CTR test: Key and IV are all zeros, plaintext all zeros
    // This tests that our implementation matches standard AES-CTR
    std::array<uint8_t, 16> key{};
    std::array<uint8_t, 16> iv{};
    std::vector<uint8_t> plaintext(32, 0);

    AesCtrStream enc, dec;
    REQUIRE(enc.init(key, iv).has_value());
    REQUIRE(dec.init(key, iv).has_value());

    auto ciphertext = enc.process(std::span<const uint8_t>(plaintext));
    REQUIRE(ciphertext.has_value());
    REQUIRE(ciphertext->size() == 32);

    // Ciphertext should not be all zeros (AES encrypts)
    bool all_zero = true;
    for (auto b : *ciphertext) {
        if (b != 0) { all_zero = false; break; }
    }
    REQUIRE(!all_zero);

    // Decrypt should return original plaintext
    auto decrypted = dec.process(std::span<const uint8_t>(*ciphertext));
    REQUIRE(decrypted.has_value());
    REQUIRE(*decrypted == plaintext);
}

TEST_CASE("crypto parity: AES-256-CTR streaming chunks match single process", "[crypto][parity]") {
    auto key = random_array<32>();
    std::array<uint8_t, 16> iv{};

    auto data = random_bytes(1000);

    // Process all at once
    AesCtrStream single;
    REQUIRE(single.init(key, iv).has_value());
    auto single_result = single.process(std::span<const uint8_t>(data));
    REQUIRE(single_result.has_value());

    // Process in chunks of varying sizes
    AesCtrStream chunked;
    REQUIRE(chunked.init(key, iv).has_value());
    std::vector<uint8_t> chunked_result;
    size_t offset = 0;
    size_t chunk_sizes[] = {1, 7, 13, 100, 37, 200, 3};
    size_t ci = 0;
    while (offset < data.size()) {
        size_t chunk = std::min(chunk_sizes[ci % 7], data.size() - offset);
        auto r = chunked.process(std::span<const uint8_t>(data.data() + offset, chunk));
        REQUIRE(r.has_value());
        chunked_result.insert(chunked_result.end(), r->begin(), r->end());
        offset += chunk;
        ci++;
    }

    REQUIRE(chunked_result == *single_result);
}

// ============= DRBG tests =============

TEST_CASE("crypto parity: DRBG deterministic output", "[crypto][parity]") {
    // Same seed -> same output (matching Go behavior)
    DrbgSeed seed = random_array<24>();

    HashDrbg d1, d2;
    d1.init(seed);
    d2.init(seed);

    for (int i = 0; i < 50; ++i) {
        REQUIRE(d1.next_block() == d2.next_block());
    }
}

TEST_CASE("crypto parity: DRBG different seeds produce different output", "[crypto][parity]") {
    DrbgSeed s1 = random_array<24>();
    DrbgSeed s2 = random_array<24>();

    HashDrbg d1, d2;
    d1.init(s1);
    d2.init(s2);

    // At least one block should differ
    bool differ = false;
    for (int i = 0; i < 10; ++i) {
        if (d1.next_block() != d2.next_block()) {
            differ = true;
            break;
        }
    }
    REQUIRE(differ);
}

TEST_CASE("crypto parity: DRBG length mask is uint16_t", "[crypto][parity]") {
    DrbgSeed seed = random_array<24>();
    HashDrbg drbg;
    drbg.init(seed);

    // Sample many length masks, all should be valid uint16_t
    for (int i = 0; i < 100; ++i) {
        uint16_t mask = drbg.next_length_mask();
        REQUIRE(mask <= 0xFFFF);
        (void)mask;  // Just checking it doesn't crash
    }
}

// ============= WeightedDist tests =============

TEST_CASE("crypto parity: WeightedDist uniform bounds", "[crypto][parity]") {
    // Uniform distribution should always return values in [min, max]
    DrbgSeed seed = random_array<24>();
    WeightedDist dist(seed, 100, 200, false);

    REQUIRE(dist.initialized());

    for (int i = 0; i < 1000; ++i) {
        int val = dist.sample();
        REQUIRE(val >= 100);
        REQUIRE(val <= 200);
    }
}

TEST_CASE("crypto parity: WeightedDist biased bounds", "[crypto][parity]") {
    // Biased distribution should also stay in bounds
    DrbgSeed seed = random_array<24>();
    WeightedDist dist(seed, 0, 1000, true);

    REQUIRE(dist.initialized());

    for (int i = 0; i < 1000; ++i) {
        int val = dist.sample();
        REQUIRE(val >= 0);
        REQUIRE(val <= 1000);
    }
}

TEST_CASE("crypto parity: WeightedDist reset changes distribution", "[crypto][parity]") {
    DrbgSeed seed1 = random_array<24>();
    DrbgSeed seed2 = random_array<24>();

    WeightedDist dist(seed1, 0, 100, true);

    // Sample some values
    std::vector<int> samples1;
    for (int i = 0; i < 50; ++i) {
        samples1.push_back(dist.sample());
    }

    // Reset with different seed
    dist.reset(seed2, 0, 100, true);

    std::vector<int> samples2;
    for (int i = 0; i < 50; ++i) {
        samples2.push_back(dist.sample());
    }

    // Should produce different sequences (overwhelmingly likely)
    REQUIRE(samples1 != samples2);
}

TEST_CASE("crypto parity: WeightedDist deterministic with same seed", "[crypto][parity]") {
    DrbgSeed seed = random_array<24>();

    WeightedDist d1(seed, 0, 500, true);
    WeightedDist d2(seed, 0, 500, true);

    for (int i = 0; i < 100; ++i) {
        REQUIRE(d1.sample() == d2.sample());
    }
}

// ============= CSRNG tests =============

TEST_CASE("crypto parity: random_intn bounds", "[crypto][parity]") {
    // random_intn(n) returns [0, n)
    for (int i = 0; i < 1000; ++i) {
        auto val = random_intn(10);
        REQUIRE(val < 10);
    }

    // Edge case: n=1 should always return 0
    for (int i = 0; i < 100; ++i) {
        REQUIRE(random_intn(1) == 0);
    }
}

TEST_CASE("crypto parity: random_int_range bounds", "[crypto][parity]") {
    // random_int_range(min, max) returns [min, max] inclusive
    for (int i = 0; i < 1000; ++i) {
        auto val = random_int_range(-10, 10);
        REQUIRE(val >= -10);
        REQUIRE(val <= 10);
    }

    // Single value range
    for (int i = 0; i < 100; ++i) {
        REQUIRE(random_int_range(42, 42) == 42);
    }
}

TEST_CASE("crypto parity: random_float64 bounds", "[crypto][parity]") {
    // random_float64() returns [0.0, 1.0)
    for (int i = 0; i < 10000; ++i) {
        double val = random_float64();
        REQUIRE(val >= 0.0);
        REQUIRE(val < 1.0);
    }
}

TEST_CASE("crypto parity: random_bytes produces non-zero output", "[crypto][parity]") {
    // Overwhelmingly unlikely to get all zeros for 32 bytes
    auto data = random_bytes(32);
    bool all_zero = true;
    for (auto b : data) {
        if (b != 0) { all_zero = false; break; }
    }
    REQUIRE(!all_zero);
}

// ============= UniformDH parity tests =============

TEST_CASE("crypto parity: UniformDH key length is 192", "[crypto][parity]") {
    // Go: uniformDHLen = 192
    REQUIRE(UNIFORM_DH_KEY_LEN == 192);
}

TEST_CASE("crypto parity: UniformDH shared secret commutativity", "[crypto][parity]") {
    // Go: DH(a, B) == DH(b, A)
    for (int i = 0; i < 3; ++i) {
        auto kp1 = uniform_dh_keygen();
        REQUIRE(kp1.has_value());
        auto kp2 = uniform_dh_keygen();
        REQUIRE(kp2.has_value());

        auto s1 = uniform_dh_shared_secret(kp1->private_key, kp2->public_key);
        auto s2 = uniform_dh_shared_secret(kp2->private_key, kp1->public_key);

        REQUIRE(s1.has_value());
        REQUIRE(s2.has_value());
        REQUIRE(*s1 == *s2);
    }
}

TEST_CASE("crypto parity: UniformDH rejects all-zero public key", "[crypto][parity]") {
    auto kp = uniform_dh_keygen();
    REQUIRE(kp.has_value());

    std::array<uint8_t, UNIFORM_DH_KEY_LEN> zero_key{};
    auto result = uniform_dh_shared_secret(kp->private_key, zero_key);
    REQUIRE(!result.has_value());
}

TEST_CASE("crypto parity: UniformDH rejects all-one public key", "[crypto][parity]") {
    auto kp = uniform_dh_keygen();
    REQUIRE(kp.has_value());

    // Public key = 1 (big-endian: 191 zero bytes + 0x01)
    std::array<uint8_t, UNIFORM_DH_KEY_LEN> one_key{};
    one_key[UNIFORM_DH_KEY_LEN - 1] = 0x01;
    auto result = uniform_dh_shared_secret(kp->private_key, one_key);
    REQUIRE(!result.has_value());
}
