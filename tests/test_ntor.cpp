#include <catch2/catch_test_macros.hpp>
#include "obfs4/common/ntor.hpp"
#include "obfs4/crypto/elligator2.hpp"
#include "obfs4/common/csrand.hpp"

using namespace obfs4::common;
using namespace obfs4::crypto;

TEST_CASE("ntor handshake round-trip", "[ntor]") {
    // Generate identity keypair
    auto id_kp = elligator2::generate_representable_keypair();
    REQUIRE(id_kp.representative.has_value());

    // Generate server ephemeral keypair
    auto server_kp = elligator2::generate_representable_keypair();
    REQUIRE(server_kp.representative.has_value());

    // Generate client ephemeral keypair
    auto client_kp = elligator2::generate_representable_keypair();
    REQUIRE(client_kp.representative.has_value());

    // Node ID
    NodeID node_id{};
    for (int i = 0; i < 20; ++i) node_id[i] = static_cast<uint8_t>(i);

    // Server handshake
    auto server_result = server_handshake(
        client_kp.public_key, server_kp, id_kp, node_id);
    REQUIRE(server_result.has_value());

    auto& [server_key_seed, server_auth] = *server_result;

    // Client handshake
    auto client_result = client_handshake(
        client_kp, server_kp.public_key, id_kp.public_key, node_id);
    REQUIRE(client_result.has_value());

    auto& [client_key_seed, client_auth] = *client_result;

    // Key seeds must match
    REQUIRE(server_key_seed == client_key_seed);

    // Auth values must match
    REQUIRE(server_auth == client_auth);
}

TEST_CASE("ntor KDF produces expected length", "[ntor]") {
    KeySeed seed{};
    seed[0] = 42;

    auto okm = kdf(seed, 144);
    REQUIRE(okm.size() == 144);
}

TEST_CASE("ntor KDF is deterministic", "[ntor]") {
    KeySeed seed{};
    seed[0] = 1;
    seed[31] = 2;

    auto okm1 = kdf(seed, 72);
    auto okm2 = kdf(seed, 72);
    REQUIRE(okm1 == okm2);
}

TEST_CASE("X25519 DH works", "[ntor]") {
    // Generate two keypairs via Elligator2
    auto kp1 = elligator2::generate_representable_keypair();
    auto kp2 = elligator2::generate_representable_keypair();

    // DH should be commutative
    auto shared1 = x25519_dh(kp1.private_key, kp2.public_key);
    auto shared2 = x25519_dh(kp2.private_key, kp1.public_key);

    REQUIRE(shared1.has_value());
    REQUIRE(shared2.has_value());
    REQUIRE(*shared1 == *shared2);
}
