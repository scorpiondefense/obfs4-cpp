#include <catch2/catch_test_macros.hpp>
#include "obfs4/transports/obfs2/obfs2.hpp"
#include "obfs4/common/csrand.hpp"
#include <cstring>

using namespace obfs4::transports::obfs2;
using namespace obfs4::transports;
using namespace obfs4::common;

// Helper: complete a full obfs2 handshake between client and server
static void do_handshake(Obfs2Conn& client, Obfs2Conn& server) {
    client.init_client();
    server.init_server();
    auto ch = client.generate_handshake();
    auto sh = server.generate_handshake();
    (void)server.consume_handshake(ch);
    (void)client.consume_handshake(sh);
    REQUIRE(client.handshake_complete());
    REQUIRE(server.handshake_complete());
}

TEST_CASE("obfs2 parity: handshake size bounds", "[obfs2][parity]") {
    for (int i = 0; i < 20; ++i) {
        Obfs2Conn conn;
        conn.init_client();
        auto hs = conn.generate_handshake();
        // Must be at least SEED(16) + E(magic+padlen)(8)
        REQUIRE(hs.size() >= HANDSHAKE_HEADER_LEN);
        // Must be at most SEED(16) + E(8) + MAX_PADDING(8192)
        REQUIRE(hs.size() <= HANDSHAKE_HEADER_LEN + MAX_PADDING);
    }
}

TEST_CASE("obfs2 parity: multiple sequential messages", "[obfs2][parity]") {
    Obfs2Conn client, server;
    do_handshake(client, server);

    // Send 100 messages in each direction
    for (int i = 0; i < 100; ++i) {
        std::vector<uint8_t> msg(i + 1);
        for (size_t j = 0; j < msg.size(); ++j) {
            msg[j] = static_cast<uint8_t>((i + j) & 0xFF);
        }

        // Client -> server
        auto enc = client.write(msg);
        REQUIRE(enc.size() == msg.size());
        auto dec = server.read(enc);
        REQUIRE(dec.has_value());
        REQUIRE(dec->plaintext == msg);

        // Server -> client
        auto enc2 = server.write(msg);
        auto dec2 = client.read(enc2);
        REQUIRE(dec2.has_value());
        REQUIRE(dec2->plaintext == msg);
    }
}

TEST_CASE("obfs2 parity: empty message", "[obfs2][parity]") {
    Obfs2Conn client, server;
    do_handshake(client, server);

    std::vector<uint8_t> empty;
    auto enc = client.write(empty);
    REQUIRE(enc.empty());

    auto dec = server.read(enc);
    REQUIRE(dec.has_value());
    REQUIRE(dec->plaintext.empty());
}

TEST_CASE("obfs2 parity: single byte messages", "[obfs2][parity]") {
    Obfs2Conn client, server;
    do_handshake(client, server);

    for (int b = 0; b < 256; ++b) {
        std::vector<uint8_t> msg = {static_cast<uint8_t>(b)};
        auto enc = client.write(msg);
        auto dec = server.read(enc);
        REQUIRE(dec.has_value());
        REQUIRE(dec->plaintext == msg);
    }
}

TEST_CASE("obfs2 parity: corrupted handshake magic rejected", "[obfs2][parity]") {
    Obfs2Conn client, server;
    client.init_client();
    server.init_server();

    auto client_hello = client.generate_handshake();

    // Corrupt the encrypted header portion (after the seed)
    // Bytes [16..23] contain E(magic || padlen)
    client_hello[16] ^= 0xFF;
    client_hello[17] ^= 0xFF;

    auto result = server.consume_handshake(client_hello);
    REQUIRE(!result.has_value());
    REQUIRE(result.error() == TransportError::HandshakeFailed);
}

TEST_CASE("obfs2 parity: corrupted seed causes key mismatch", "[obfs2][parity]") {
    Obfs2Conn client, server;
    client.init_client();
    server.init_server();

    auto client_hello = client.generate_handshake();
    auto server_hello = server.generate_handshake();

    // Corrupt the client seed (first 16 bytes)
    client_hello[0] ^= 0xFF;

    // Server decrypts with wrong pad key -> magic mismatch
    auto result = server.consume_handshake(client_hello);
    REQUIRE(!result.has_value());
    REQUIRE(result.error() == TransportError::HandshakeFailed);
}

TEST_CASE("obfs2 parity: incremental handshake byte-by-byte", "[obfs2][parity]") {
    Obfs2Conn client, server;
    client.init_client();
    server.init_server();

    auto client_hello = client.generate_handshake();
    auto server_hello = server.generate_handshake();

    // Feed client hello byte-by-byte to server
    for (size_t i = 0; i < client_hello.size(); ++i) {
        auto result = server.consume_handshake(
            std::span<const uint8_t>(&client_hello[i], 1));
        if (i < client_hello.size() - 1) {
            // Not enough data yet, or we just finished
            if (server.handshake_complete()) break;
        }
    }
    REQUIRE(server.handshake_complete());

    // Feed server hello at once to client
    auto result = client.consume_handshake(server_hello);
    REQUIRE(result.has_value());
    REQUIRE(client.handshake_complete());

    // Verify data exchange works
    std::vector<uint8_t> msg = {1, 2, 3};
    auto enc = client.write(msg);
    auto dec = server.read(enc);
    REQUIRE(dec.has_value());
    REQUIRE(dec->plaintext == msg);
}

TEST_CASE("obfs2 parity: cipher stream continuity", "[obfs2][parity]") {
    // Verify that the AES-CTR stream is continuous across multiple writes.
    // This matches Go behavior where the cipher state is maintained.
    Obfs2Conn client, server;
    do_handshake(client, server);

    // Send data in two parts, then verify the decrypted content
    std::vector<uint8_t> part1 = {0x01, 0x02, 0x03};
    std::vector<uint8_t> part2 = {0x04, 0x05, 0x06};

    auto enc1 = client.write(part1);
    auto enc2 = client.write(part2);

    auto dec1 = server.read(enc1);
    REQUIRE(dec1.has_value());
    REQUIRE(dec1->plaintext == part1);

    auto dec2 = server.read(enc2);
    REQUIRE(dec2.has_value());
    REQUIRE(dec2->plaintext == part2);
}

TEST_CASE("obfs2 parity: symmetric encryption (different client/server keys)", "[obfs2][parity]") {
    // Verify client->server and server->client use different keys
    // (Go: initiator vs responder KDF strings)
    Obfs2Conn client, server;
    do_handshake(client, server);

    std::vector<uint8_t> msg = {0xAA, 0xBB, 0xCC};
    auto enc_c2s = client.write(msg);
    auto enc_s2c = server.write(msg);

    // Same plaintext, different ciphertexts (different keys)
    REQUIRE(enc_c2s != enc_s2c);

    // But each side can decrypt the other's data
    auto dec_c2s = server.read(enc_c2s);
    REQUIRE(dec_c2s.has_value());
    REQUIRE(dec_c2s->plaintext == msg);

    auto dec_s2c = client.read(enc_s2c);
    REQUIRE(dec_s2c.has_value());
    REQUIRE(dec_s2c->plaintext == msg);
}

TEST_CASE("obfs2 parity: transport name", "[obfs2][parity]") {
    REQUIRE(Obfs2Conn::transport_name() == "obfs2");
    REQUIRE(Obfs2ClientFactory::transport_name() == "obfs2");
    REQUIRE(Obfs2ServerFactory::transport_name() == "obfs2");
}

TEST_CASE("obfs2 parity: 256KB data transfer", "[obfs2][parity]") {
    Obfs2Conn client, server;
    do_handshake(client, server);

    auto data = random_bytes(262144);  // 256KB
    auto enc = client.write(data);
    auto dec = server.read(enc);
    REQUIRE(dec.has_value());
    REQUIRE(dec->plaintext == data);
}

TEST_CASE("obfs2 parity: independent sessions use different keys", "[obfs2][parity]") {
    // Two separate sessions should produce different ciphertext for same plaintext
    Obfs2Conn c1, s1, c2, s2;
    do_handshake(c1, s1);
    do_handshake(c2, s2);

    std::vector<uint8_t> msg = {1, 2, 3, 4, 5};
    auto enc1 = c1.write(msg);
    auto enc2 = c2.write(msg);

    // Different random seeds -> different keys -> different ciphertext
    REQUIRE(enc1 != enc2);

    // Both decrypt correctly
    auto dec1 = s1.read(enc1);
    auto dec2 = s2.read(enc2);
    REQUIRE(dec1.has_value());
    REQUIRE(dec2.has_value());
    REQUIRE(dec1->plaintext == msg);
    REQUIRE(dec2->plaintext == msg);
}
