#include <catch2/catch_test_macros.hpp>
#include "obfs4/transports/obfs2/obfs2.hpp"
#include <cstring>

using namespace obfs4::transports::obfs2;
using namespace obfs4::transports;

TEST_CASE("obfs2 client/server handshake and data exchange", "[obfs2]") {
    Obfs2Conn client, server;
    client.init_client();
    server.init_server();

    // Client generates handshake
    auto client_hello = client.generate_handshake();
    REQUIRE(client_hello.size() >= HANDSHAKE_HEADER_LEN);

    // Server generates handshake
    auto server_hello = server.generate_handshake();
    REQUIRE(server_hello.size() >= HANDSHAKE_HEADER_LEN);

    // Feed handshakes to each other
    auto server_result = server.consume_handshake(client_hello);
    REQUIRE(server_result.has_value());

    auto client_result = client.consume_handshake(server_hello);
    REQUIRE(client_result.has_value());

    REQUIRE(client.handshake_complete());
    REQUIRE(server.handshake_complete());

    // Data exchange: client -> server
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'o', 'b', 'f', 's', '2'};
    auto encrypted = client.write(message);
    REQUIRE(encrypted.size() == message.size());
    REQUIRE(encrypted != message);

    auto decrypted = server.read(encrypted);
    REQUIRE(decrypted.has_value());
    REQUIRE(decrypted->plaintext == message);

    // Data exchange: server -> client
    std::vector<uint8_t> response = {'O', 'K'};
    auto enc_resp = server.write(response);
    auto dec_resp = client.read(enc_resp);
    REQUIRE(dec_resp.has_value());
    REQUIRE(dec_resp->plaintext == response);
}

TEST_CASE("obfs2 incremental handshake", "[obfs2]") {
    Obfs2Conn client, server;
    client.init_client();
    server.init_server();

    auto client_hello = client.generate_handshake();
    auto server_hello = server.generate_handshake();

    // Feed server the client hello in small chunks
    size_t offset = 0;
    while (offset < client_hello.size()) {
        size_t chunk = std::min<size_t>(10, client_hello.size() - offset);
        auto result = server.consume_handshake(
            std::span<const uint8_t>(client_hello.data() + offset, chunk));
        if (result.has_value() && *result > 0) {
            break;  // handshake complete
        }
        offset += chunk;
    }
    REQUIRE(server.handshake_complete());

    // Feed client the server hello in one go
    auto result = client.consume_handshake(server_hello);
    REQUIRE(result.has_value());
    REQUIRE(client.handshake_complete());
}

TEST_CASE("obfs2 factory creates working connections", "[obfs2]") {
    Obfs2ClientFactory client_factory;
    Obfs2ServerFactory server_factory;

    REQUIRE(client_factory.parse_args({}).has_value());
    REQUIRE(server_factory.parse_args({}).has_value());

    auto client = client_factory.create();
    auto server = server_factory.create();

    auto ch = client.generate_handshake();
    auto sh = server.generate_handshake();
    server.consume_handshake(ch);
    client.consume_handshake(sh);

    REQUIRE(client.handshake_complete());
    REQUIRE(server.handshake_complete());
}

TEST_CASE("obfs2 large data transfer", "[obfs2]") {
    Obfs2Conn client, server;
    client.init_client();
    server.init_server();

    auto ch = client.generate_handshake();
    auto sh = server.generate_handshake();
    server.consume_handshake(ch);
    client.consume_handshake(sh);

    // Transfer 64KB of data
    std::vector<uint8_t> large_data(65536);
    for (size_t i = 0; i < large_data.size(); ++i) {
        large_data[i] = static_cast<uint8_t>(i & 0xFF);
    }

    auto enc = client.write(large_data);
    auto dec = server.read(enc);
    REQUIRE(dec.has_value());
    REQUIRE(dec->plaintext == large_data);
}
