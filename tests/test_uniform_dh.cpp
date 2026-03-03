#include <catch2/catch_test_macros.hpp>
#include "obfs4/common/uniform_dh.hpp"

using namespace obfs4::common;

TEST_CASE("UniformDH keygen produces valid keypair", "[uniform_dh]") {
    auto result = uniform_dh_keygen();
    REQUIRE(result.has_value());

    auto& kp = *result;
    // Public key should not be all zeros
    bool all_zero = true;
    for (auto b : kp.public_key) {
        if (b != 0) { all_zero = false; break; }
    }
    REQUIRE(!all_zero);
}

TEST_CASE("UniformDH shared secret agreement", "[uniform_dh]") {
    auto alice = uniform_dh_keygen();
    auto bob = uniform_dh_keygen();
    REQUIRE(alice.has_value());
    REQUIRE(bob.has_value());

    auto secret_a = uniform_dh_shared_secret(alice->private_key, bob->public_key);
    auto secret_b = uniform_dh_shared_secret(bob->private_key, alice->public_key);
    REQUIRE(secret_a.has_value());
    REQUIRE(secret_b.has_value());

    // Both parties should derive the same shared secret
    REQUIRE(*secret_a == *secret_b);
}

TEST_CASE("UniformDH different keypairs produce different secrets", "[uniform_dh]") {
    auto alice = uniform_dh_keygen();
    auto bob = uniform_dh_keygen();
    auto charlie = uniform_dh_keygen();
    REQUIRE(alice.has_value());
    REQUIRE(bob.has_value());
    REQUIRE(charlie.has_value());

    auto ab = uniform_dh_shared_secret(alice->private_key, bob->public_key);
    auto ac = uniform_dh_shared_secret(alice->private_key, charlie->public_key);
    REQUIRE(ab.has_value());
    REQUIRE(ac.has_value());
    REQUIRE(*ab != *ac);
}

TEST_CASE("UniformDH rejects trivial public key", "[uniform_dh]") {
    auto kp = uniform_dh_keygen();
    REQUIRE(kp.has_value());

    // Public key of 0 should be rejected
    std::array<uint8_t, UNIFORM_DH_KEY_LEN> zero_key{};
    auto result = uniform_dh_shared_secret(kp->private_key, zero_key);
    REQUIRE(!result.has_value());
}

TEST_CASE("UniformDH public keys are 192 bytes", "[uniform_dh]") {
    auto kp = uniform_dh_keygen();
    REQUIRE(kp.has_value());
    REQUIRE(kp->public_key.size() == 192);
    REQUIRE(kp->private_key.size() == 192);
}
