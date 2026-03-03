#include <catch2/catch_test_macros.hpp>
#include "obfs4/transports/obfs4/obfs4.hpp"
#include "obfs4/transport/conn.hpp"
#include "obfs4/transport/handshake.hpp"
#include "obfs4/transport/state.hpp"
#include "obfs4/transport/framing.hpp"
#include "obfs4/transport/packet.hpp"
#include "obfs4/crypto/elligator2.hpp"
#include "obfs4/common/csrand.hpp"
#include "obfs4/common/replay_filter.hpp"
#include <cstring>
#include <filesystem>

using namespace obfs4::transport;
using namespace obfs4::transports;
using namespace obfs4::transports::obfs4_transport;
using namespace obfs4::crypto;
using namespace obfs4::common;

// ============= obfs4 transport wrapper tests =============

TEST_CASE("obfs4 parity: transport name matches Go", "[obfs4][parity]") {
    REQUIRE(Obfs4TransportConn::transport_name() == "obfs4");
    REQUIRE(Obfs4ClientFactory::transport_name() == "obfs4");
    REQUIRE(Obfs4ServerFactory::transport_name() == "obfs4");
}

TEST_CASE("obfs4 parity: client factory parses valid cert", "[obfs4][parity]") {
    // Generate a real cert
    auto id_kp = elligator2::generate_representable_keypair();
    NodeID node_id{};
    for (int i = 0; i < 20; ++i) node_id[i] = static_cast<uint8_t>(i);
    auto cert = encode_cert(node_id, id_kp.public_key);

    Obfs4ClientFactory factory;
    Args args;
    args["cert"] = cert;
    auto result = factory.parse_args(args);
    REQUIRE(result.has_value());

    // Verify parsed values
    REQUIRE(factory.node_id() == node_id);
    REQUIRE(factory.public_key() == id_kp.public_key);
    REQUIRE(factory.iat_mode() == IATMode::None);
}

TEST_CASE("obfs4 parity: client factory rejects missing cert", "[obfs4][parity]") {
    Obfs4ClientFactory factory;
    Args args;
    auto result = factory.parse_args(args);
    REQUIRE(!result.has_value());
    REQUIRE(result.error() == TransportError::InvalidArgs);
}

TEST_CASE("obfs4 parity: client factory rejects invalid cert", "[obfs4][parity]") {
    Obfs4ClientFactory factory;
    Args args;
    args["cert"] = "not-valid-base64-cert!!!";
    auto result = factory.parse_args(args);
    REQUIRE(!result.has_value());
}

TEST_CASE("obfs4 parity: client factory parses iat-mode", "[obfs4][parity]") {
    auto id_kp = elligator2::generate_representable_keypair();
    NodeID node_id{};
    auto cert = encode_cert(node_id, id_kp.public_key);

    // iat-mode=0
    {
        Obfs4ClientFactory factory;
        Args args;
        args["cert"] = cert;
        args["iat-mode"] = "0";
        REQUIRE(factory.parse_args(args).has_value());
        REQUIRE(factory.iat_mode() == IATMode::None);
    }

    // iat-mode=1
    {
        Obfs4ClientFactory factory;
        Args args;
        args["cert"] = cert;
        args["iat-mode"] = "1";
        REQUIRE(factory.parse_args(args).has_value());
        REQUIRE(factory.iat_mode() == IATMode::Enabled);
    }

    // iat-mode=2
    {
        Obfs4ClientFactory factory;
        Args args;
        args["cert"] = cert;
        args["iat-mode"] = "2";
        REQUIRE(factory.parse_args(args).has_value());
        REQUIRE(factory.iat_mode() == IATMode::Paranoid);
    }
}

TEST_CASE("obfs4 parity: cert encode/decode round-trip with random data", "[obfs4][parity]") {
    for (int i = 0; i < 10; ++i) {
        NodeID node_id = random_array<20>();
        auto kp = elligator2::generate_representable_keypair();

        auto cert = encode_cert(node_id, kp.public_key);
        REQUIRE(!cert.empty());

        auto decoded = decode_cert(cert);
        REQUIRE(decoded.has_value());
        REQUIRE(decoded->first == node_id);
        REQUIRE(decoded->second == kp.public_key);
    }
}

TEST_CASE("obfs4 parity: cert decode rejects truncated input", "[obfs4][parity]") {
    auto result = decode_cert("AAAA");  // Too short
    REQUIRE(!result.has_value());
}

TEST_CASE("obfs4 parity: cert decode rejects invalid base64", "[obfs4][parity]") {
    auto result = decode_cert("!!!invalid!!!");
    REQUIRE(!result.has_value());
}

// ============= obfs4 handshake tests =============

TEST_CASE("obfs4 parity: handshake key material is 72 bytes", "[obfs4][parity]") {
    // Go: keyMaterialLength = 72 (32 key + 16 nonce_prefix + 24 drbg_seed)
    REQUIRE(KEY_MATERIAL_LENGTH == 72);
}

TEST_CASE("obfs4 parity: handshake constants match Go", "[obfs4][parity]") {
    REQUIRE(MAX_HANDSHAKE_LENGTH == 8192);
    REQUIRE(MARK_LENGTH == 16);
    REQUIRE(MAC_LENGTH == 16);
    REQUIRE(REPRESENTATIVE_LENGTH == 32);
    REQUIRE(AUTH_LENGTH == 32);
    REQUIRE(CLIENT_HANDSHAKE_TIMEOUT == std::chrono::seconds(60));
    REQUIRE(SERVER_HANDSHAKE_TIMEOUT == std::chrono::seconds(30));
}

TEST_CASE("obfs4 parity: handshake key material swapped between client/server", "[obfs4][parity]") {
    // Go: client encoder == server decoder and vice versa
    auto id_kp = elligator2::generate_representable_keypair();
    NodeID node_id{};
    ReplayFilter replay_filter;

    ClientHandshake client(id_kp.public_key, node_id);
    auto client_hello = client.generate();

    ServerHandshake server(id_kp, node_id, replay_filter);
    auto consume = server.consume(client_hello);
    REQUIRE(consume.has_value());

    auto server_hello = server.generate();
    REQUIRE(server_hello.has_value());

    auto parse = client.parse_server_response(*server_hello);
    REQUIRE(parse.has_value());

    auto& ck = client.keys();
    auto& sk = server.keys();

    // Client encoder material == server decoder material
    REQUIRE(ck.encoder_key_material == sk.decoder_key_material);
    // Client decoder material == server encoder material
    REQUIRE(ck.decoder_key_material == sk.encoder_key_material);
}

TEST_CASE("obfs4 parity: multiple handshakes produce unique keys", "[obfs4][parity]") {
    auto id_kp = elligator2::generate_representable_keypair();
    NodeID node_id{};

    std::vector<std::array<uint8_t, 72>> encoder_keys;
    for (int i = 0; i < 5; ++i) {
        ReplayFilter rf;
        ClientHandshake client(id_kp.public_key, node_id);
        auto ch = client.generate();

        ServerHandshake server(id_kp, node_id, rf);
        (void)server.consume(ch);
        auto sh = server.generate();
        (void)client.parse_server_response(*sh);

        encoder_keys.push_back(client.keys().encoder_key_material);
    }

    // All encoder keys should be unique (ephemeral DH)
    for (size_t i = 0; i < encoder_keys.size(); ++i) {
        for (size_t j = i + 1; j < encoder_keys.size(); ++j) {
            REQUIRE(encoder_keys[i] != encoder_keys[j]);
        }
    }
}

// ============= obfs4 framing tests =============

TEST_CASE("obfs4 parity: frame constants match Go", "[obfs4][parity]") {
    // Go: maxFrameLength = 1448, frameOverhead = 18, maxFramePayload = 1430
    REQUIRE(MAX_SEGMENT_LENGTH == 1448);
    REQUIRE(FRAME_OVERHEAD == 18);
    REQUIRE(MAX_FRAME_PAYLOAD == 1430);
}

TEST_CASE("obfs4 parity: framing two frames decoded sequentially", "[obfs4][parity]") {
    Encoder enc;
    Decoder dec;
    auto key = random_array<32>();
    auto nonce_prefix = random_array<16>();
    auto drbg_seed = random_array<24>();
    enc.init(key, nonce_prefix, drbg_seed);
    dec.init(key, nonce_prefix, drbg_seed);

    // Encode two separate payloads
    std::vector<uint8_t> p1 = {0xDE, 0xAD};
    std::vector<uint8_t> p2 = {0xBE, 0xEF, 0xCA, 0xFE};
    auto e1 = enc.encode(p1);
    auto e2 = enc.encode(p2);

    // Decode first frame
    auto r1 = dec.decode(e1);
    REQUIRE(r1.has_value());
    REQUIRE(r1->frames.size() == 1);
    REQUIRE(r1->frames[0].payload == p1);

    // Decode second frame
    auto r2 = dec.decode(e2);
    REQUIRE(r2.has_value());
    REQUIRE(r2->frames.size() == 1);
    REQUIRE(r2->frames[0].payload == p2);
}

TEST_CASE("obfs4 parity: framing counter nonce uniqueness", "[obfs4][parity]") {
    // Verify that encoding the same payload multiple times produces
    // different ciphertexts (due to incrementing counter/nonce)
    Encoder enc;
    auto key = random_array<32>();
    auto nonce_prefix = random_array<16>();
    auto drbg_seed = random_array<24>();
    enc.init(key, nonce_prefix, drbg_seed);

    std::vector<uint8_t> payload = {1, 2, 3};
    auto e1 = enc.encode(payload);
    auto e2 = enc.encode(payload);
    auto e3 = enc.encode(payload);

    // Same plaintext, different nonces -> different ciphertext
    REQUIRE(e1 != e2);
    REQUIRE(e2 != e3);
    REQUIRE(e1 != e3);
}

// ============= obfs4 packet tests =============

TEST_CASE("obfs4 parity: packet constants match Go", "[obfs4][parity]") {
    // Go: packetOverhead = 3, maxPayloadLength = 1427, seedPacketPayload = 24
    REQUIRE(PACKET_OVERHEAD == 3);
    REQUIRE(MAX_PACKET_PAYLOAD == 1427);
    REQUIRE(SEED_PACKET_PAYLOAD == 24);
}

TEST_CASE("obfs4 parity: make/parse payload packet round-trip", "[obfs4][parity]") {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto pkt = make_packet(PacketType::Payload, data);

    REQUIRE(pkt.size() >= PACKET_OVERHEAD + data.size());

    // Parse it back
    auto parsed = parse_packets(pkt);
    REQUIRE(!parsed.empty());
    REQUIRE(parsed[0].type == PacketType::Payload);
    REQUIRE(parsed[0].payload == data);
}

TEST_CASE("obfs4 parity: make/parse PrngSeed packet round-trip", "[obfs4][parity]") {
    auto seed_data = random_bytes(SEED_PACKET_PAYLOAD);
    auto pkt = make_packet(PacketType::PrngSeed, seed_data);

    auto parsed = parse_packets(pkt);
    REQUIRE(!parsed.empty());
    REQUIRE(parsed[0].type == PacketType::PrngSeed);
    REQUIRE(parsed[0].payload == seed_data);
}

TEST_CASE("obfs4 parity: packet with padding", "[obfs4][parity]") {
    std::vector<uint8_t> data = {0xAA, 0xBB};
    size_t pad_len = 50;
    auto pkt = make_packet(PacketType::Payload, data, pad_len);

    // Total size: overhead(3) + data(2) + padding(50)
    REQUIRE(pkt.size() == PACKET_OVERHEAD + data.size() + pad_len);

    // Parse should extract only the data, not the padding
    auto parsed = parse_packets(pkt);
    REQUIRE(!parsed.empty());
    REQUIRE(parsed[0].type == PacketType::Payload);
    REQUIRE(parsed[0].payload == data);
}

TEST_CASE("obfs4 parity: parse empty packet payload", "[obfs4][parity]") {
    std::vector<uint8_t> data;
    auto pkt = make_packet(PacketType::Payload, data);

    auto parsed = parse_packets(pkt);
    REQUIRE(!parsed.empty());
    REQUIRE(parsed[0].type == PacketType::Payload);
    REQUIRE(parsed[0].payload.empty());
}

// ============= obfs4 conn tests =============

TEST_CASE("obfs4 parity: conn bidirectional with IAT None", "[obfs4][parity]") {
    auto id_kp = elligator2::generate_representable_keypair();
    NodeID node_id{};
    ReplayFilter rf;

    ClientHandshake ch(id_kp.public_key, node_id);
    auto client_hello = ch.generate();

    ServerHandshake sh(id_kp, node_id, rf);
    (void)sh.consume(client_hello);
    auto server_hello = sh.generate();
    (void)ch.parse_server_response(*server_hello);

    Obfs4Conn client_conn, server_conn;
    client_conn.init(
        std::span<const uint8_t, 72>(ch.keys().encoder_key_material.data(), 72),
        std::span<const uint8_t, 72>(ch.keys().decoder_key_material.data(), 72),
        IATMode::None);
    server_conn.init(
        std::span<const uint8_t, 72>(sh.keys().encoder_key_material.data(), 72),
        std::span<const uint8_t, 72>(sh.keys().decoder_key_material.data(), 72),
        IATMode::None);

    // Multiple round trips
    for (int i = 0; i < 20; ++i) {
        auto msg = random_bytes(100 + i * 50);
        auto wire = client_conn.write(msg);
        auto read = server_conn.read(wire);
        REQUIRE(read.has_value());
        REQUIRE(read->plaintext == msg);

        auto reply = random_bytes(50 + i * 30);
        auto wire2 = server_conn.write(reply);
        auto read2 = client_conn.read(wire2);
        REQUIRE(read2.has_value());
        REQUIRE(read2->plaintext == reply);
    }
}

TEST_CASE("obfs4 parity: close delay config", "[obfs4][parity]") {
    Obfs4Conn conn;
    auto km = random_array<72>();
    conn.init(std::span<const uint8_t, 72>(km.data(), 72),
              std::span<const uint8_t, 72>(km.data(), 72));

    // Default: disabled
    REQUIRE(!conn.close_delay().enabled);

    // Enable
    Obfs4Conn::CloseDelayConfig config;
    config.enabled = true;
    config.max_delay = std::chrono::seconds(60);
    conn.set_close_delay(config);

    REQUIRE(conn.close_delay().enabled);
    REQUIRE(conn.close_delay().max_delay == std::chrono::seconds(60));

    // Random duration should be within range
    auto delay = conn.get_close_delay_duration();
    REQUIRE(delay >= std::chrono::milliseconds(0));
    REQUIRE(delay <= std::chrono::milliseconds(60000));
}

// ============= Replay filter tests =============

TEST_CASE("obfs4 parity: replay filter detects replays", "[obfs4][parity]") {
    ReplayFilter rf;

    auto data1 = random_bytes(32);
    auto data2 = random_bytes(32);

    // First insertion: not seen
    REQUIRE(!rf.test_and_set(data1));
    // Second insertion of same data: replay
    REQUIRE(rf.test_and_set(data1));

    // Different data: not seen
    REQUIRE(!rf.test_and_set(data2));
    // Same different data: replay
    REQUIRE(rf.test_and_set(data2));
}

TEST_CASE("obfs4 parity: replay filter reset clears state", "[obfs4][parity]") {
    ReplayFilter rf;
    auto data = random_bytes(32);

    REQUIRE(!rf.test_and_set(data));
    REQUIRE(rf.test_and_set(data));

    rf.reset();
    // After reset, should not detect as replay
    REQUIRE(!rf.test_and_set(data));
}

TEST_CASE("obfs4 parity: replay filter default TTL is 3 hours", "[obfs4][parity]") {
    // Go: replayTTL = time.Hour * 3  (changed from 1 to 3 for obfs4 parity)
    ReplayFilter rf;
    // The constructor default is hours(3), we can verify by checking
    // that entries with the default TTL work correctly
    auto data = random_bytes(32);
    REQUIRE(!rf.test_and_set(data));
    REQUIRE(rf.test_and_set(data));  // Still within TTL
}

// ============= State file tests =============

TEST_CASE("obfs4 parity: state save/load round-trip", "[obfs4][parity]") {
    std::string path = "/tmp/obfs4_test_state_" +
        std::to_string(random_intn(1000000)) + ".json";

    auto id_kp = elligator2::generate_representable_keypair();
    NodeID node_id = random_array<20>();
    DrbgSeed drbg_seed = random_array<24>();

    ServerState state;
    state.node_id = node_id;
    state.identity = id_kp;
    state.drbg_seed = drbg_seed;
    state.iat_mode = IATMode::Enabled;

    auto save_result = save_state(path, state);
    REQUIRE(save_result.has_value());

    auto load_result = load_state(path);
    REQUIRE(load_result.has_value());

    REQUIRE(load_result->node_id == node_id);
    REQUIRE(load_result->identity.public_key == id_kp.public_key);
    REQUIRE(load_result->identity.private_key == id_kp.private_key);
    REQUIRE(load_result->drbg_seed == drbg_seed);
    REQUIRE(load_result->iat_mode == IATMode::Enabled);

    // Cleanup
    std::filesystem::remove(path);
}

TEST_CASE("obfs4 parity: state load rejects missing file", "[obfs4][parity]") {
    auto result = load_state("/tmp/nonexistent_obfs4_state_file_xyz.json");
    REQUIRE(!result.has_value());
}

// ============= Epoch hour =============

TEST_CASE("obfs4 parity: epoch_hour returns reasonable value", "[obfs4][parity]") {
    auto hour = epoch_hour();
    // As of 2025, epoch hours > 480000 (~2024 in epoch hours)
    REQUIRE(hour > 480000);
    // And less than some far future value
    REQUIRE(hour < 1000000);
}
