#include <catch2/catch_test_macros.hpp>
#include "obfs4/transport/handshake.hpp"
#include "obfs4/crypto/elligator2.hpp"
#include "obfs4/common/csrand.hpp"

using namespace obfs4::transport;
using namespace obfs4::crypto;
using namespace obfs4::common;

TEST_CASE("Wire handshake client/server round-trip", "[handshake]") {
    // Generate server identity keypair
    auto id_kp = elligator2::generate_representable_keypair();
    REQUIRE(id_kp.representative.has_value());

    // Node ID
    NodeID node_id{};
    for (int i = 0; i < 20; ++i) node_id[i] = static_cast<uint8_t>(i);

    // Replay filter
    ReplayFilter replay_filter;

    // Client generates hello
    ClientHandshake client(id_kp.public_key, node_id);
    auto client_hello = client.generate();
    REQUIRE(client_hello.size() >= REPRESENTATIVE_LENGTH + MARK_LENGTH + MAC_LENGTH);

    // Server processes client hello
    ServerHandshake server(id_kp, node_id, replay_filter);
    auto consume_result = server.consume(client_hello);
    REQUIRE(consume_result.has_value());
    REQUIRE(server.completed());

    // Server generates response
    auto server_hello = server.generate();
    REQUIRE(server_hello.has_value());
    REQUIRE(server_hello->size() >= REPRESENTATIVE_LENGTH + AUTH_LENGTH + MARK_LENGTH + MAC_LENGTH);

    // Client processes server response
    auto parse_result = client.parse_server_response(*server_hello);
    REQUIRE(parse_result.has_value());

    // Both sides should have matching key material
    auto& client_keys = client.keys();
    auto& server_keys = server.keys();

    // Client encoder == server decoder (and vice versa)
    REQUIRE(client_keys.encoder_key_material == server_keys.decoder_key_material);
    REQUIRE(client_keys.decoder_key_material == server_keys.encoder_key_material);
}

TEST_CASE("Handshake replay detection", "[handshake]") {
    auto id_kp = elligator2::generate_representable_keypair();
    NodeID node_id{};
    ReplayFilter replay_filter;

    ClientHandshake client(id_kp.public_key, node_id);
    auto hello = client.generate();

    // First attempt succeeds
    ServerHandshake server1(id_kp, node_id, replay_filter);
    auto result1 = server1.consume(hello);
    REQUIRE(result1.has_value());

    // Second attempt with same hello should fail (replay)
    ServerHandshake server2(id_kp, node_id, replay_filter);
    auto result2 = server2.consume(hello);
    REQUIRE(!result2.has_value());
    REQUIRE(result2.error() == HandshakeError::ReplayDetected);
}

TEST_CASE("Handshake mark/MAC validation", "[handshake]") {
    auto id_kp = elligator2::generate_representable_keypair();
    NodeID node_id{};
    ReplayFilter replay_filter;

    // Corrupt the hello
    ClientHandshake client(id_kp.public_key, node_id);
    auto hello = client.generate();

    // Corrupt a byte in the representative
    hello[15] ^= 0xff;

    ServerHandshake server(id_kp, node_id, replay_filter);
    auto result = server.consume(hello);

    // Should fail: either mark not found or MAC verification
    if (result.has_value()) {
        // If mark was somehow found by coincidence, MAC should still fail
        REQUIRE(false);
    }
}

TEST_CASE("Epoch hour calculation", "[handshake]") {
    auto hour = epoch_hour();
    // Should be a reasonable epoch hour (after 2020)
    REQUIRE(hour > 438000);  // ~2020 in epoch hours
}
