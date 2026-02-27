#include <catch2/catch_test_macros.hpp>
#include "obfs4/transport/conn.hpp"
#include "obfs4/transport/handshake.hpp"
#include "obfs4/transport/state.hpp"
#include "obfs4/crypto/elligator2.hpp"
#include "obfs4/common/csrand.hpp"

using namespace obfs4::transport;
using namespace obfs4::crypto;
using namespace obfs4::common;

TEST_CASE("Full obfs4 end-to-end: handshake + data exchange", "[obfs4]") {
    // Generate server identity
    auto id_kp = elligator2::generate_representable_keypair();
    REQUIRE(id_kp.representative.has_value());

    NodeID node_id{};
    for (int i = 0; i < 20; ++i) node_id[i] = static_cast<uint8_t>(i);

    ReplayFilter replay_filter;

    // --- Handshake ---
    ClientHandshake client_hs(id_kp.public_key, node_id);
    auto client_hello = client_hs.generate();

    ServerHandshake server_hs(id_kp, node_id, replay_filter);
    auto consume_result = server_hs.consume(client_hello);
    REQUIRE(consume_result.has_value());

    auto server_hello = server_hs.generate();
    REQUIRE(server_hello.has_value());

    auto parse_result = client_hs.parse_server_response(*server_hello);
    REQUIRE(parse_result.has_value());

    // --- Setup connections ---
    Obfs4Conn client_conn, server_conn;

    auto& client_keys = client_hs.keys();
    auto& server_keys = server_hs.keys();

    client_conn.init(
        std::span<const uint8_t, 72>(client_keys.encoder_key_material.data(), 72),
        std::span<const uint8_t, 72>(client_keys.decoder_key_material.data(), 72));
    server_conn.init(
        std::span<const uint8_t, 72>(server_keys.encoder_key_material.data(), 72),
        std::span<const uint8_t, 72>(server_keys.decoder_key_material.data(), 72));

    // --- Data exchange: client -> server ---
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ',
                                     'o', 'b', 'f', 's', '4', '!'};

    auto wire_data = client_conn.write(message);
    REQUIRE(!wire_data.empty());

    auto server_read = server_conn.read(wire_data);
    REQUIRE(server_read.has_value());
    REQUIRE(server_read->plaintext == message);

    // --- Data exchange: server -> client ---
    std::vector<uint8_t> reply = {'O', 'K'};
    auto wire_reply = server_conn.write(reply);

    auto client_read = client_conn.read(wire_reply);
    REQUIRE(client_read.has_value());
    REQUIRE(client_read->plaintext == reply);
}

TEST_CASE("Full obfs4 large data transfer", "[obfs4]") {
    auto id_kp = elligator2::generate_representable_keypair();
    NodeID node_id{};
    ReplayFilter replay_filter;

    ClientHandshake client_hs(id_kp.public_key, node_id);
    auto client_hello = client_hs.generate();

    ServerHandshake server_hs(id_kp, node_id, replay_filter);
    auto consume_result = server_hs.consume(client_hello);
    REQUIRE(consume_result.has_value());

    auto server_hello = server_hs.generate();
    REQUIRE(server_hello.has_value());

    auto parse_result = client_hs.parse_server_response(*server_hello);
    REQUIRE(parse_result.has_value());

    Obfs4Conn client_conn, server_conn;
    auto& ck = client_hs.keys();
    auto& sk = server_hs.keys();

    client_conn.init(
        std::span<const uint8_t, 72>(ck.encoder_key_material.data(), 72),
        std::span<const uint8_t, 72>(ck.decoder_key_material.data(), 72));
    server_conn.init(
        std::span<const uint8_t, 72>(sk.encoder_key_material.data(), 72),
        std::span<const uint8_t, 72>(sk.decoder_key_material.data(), 72));

    // Send 10KB of random data
    auto data = random_bytes(10240);
    auto wire = client_conn.write(data);

    auto read_result = server_conn.read(wire);
    REQUIRE(read_result.has_value());
    REQUIRE(read_result->plaintext == data);
}

TEST_CASE("Cert encode/decode round-trip", "[obfs4]") {
    NodeID node_id{};
    for (int i = 0; i < 20; ++i) node_id[i] = static_cast<uint8_t>(i);

    auto kp = elligator2::generate_representable_keypair();
    auto cert = encode_cert(node_id, kp.public_key);

    auto decoded = decode_cert(cert);
    REQUIRE(decoded.has_value());

    auto& [decoded_nid, decoded_pub] = *decoded;
    REQUIRE(decoded_nid == node_id);
    REQUIRE(decoded_pub == kp.public_key);
}
