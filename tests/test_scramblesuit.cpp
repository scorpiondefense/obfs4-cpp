#include <catch2/catch_test_macros.hpp>
#include "obfs4/transports/scramblesuit/scramblesuit.hpp"
#include "obfs4/transports/scramblesuit/ticket_store.hpp"
#include "obfs4/common/csrand.hpp"

using namespace obfs4::transports::scramblesuit;
using namespace obfs4::transports;
using namespace obfs4::common;

TEST_CASE("ScrambleSuit transport name", "[scramblesuit]") {
    REQUIRE(ScrambleSuitConn::transport_name() == "scramblesuit");
    REQUIRE(ScrambleSuitClientFactory::transport_name() == "scramblesuit");
}

TEST_CASE("ScrambleSuit factory parses password", "[scramblesuit]") {
    ScrambleSuitClientFactory factory;
    Args args;
    args["password"] = "testpassword123";
    auto result = factory.parse_args(args);
    REQUIRE(result.has_value());
}

TEST_CASE("ScrambleSuit factory rejects missing password", "[scramblesuit]") {
    ScrambleSuitClientFactory factory;
    Args args;
    auto result = factory.parse_args(args);
    REQUIRE(!result.has_value());
    REQUIRE(result.error() == TransportError::InvalidArgs);
}

TEST_CASE("ScrambleSuit generates handshake", "[scramblesuit]") {
    std::array<uint8_t, 20> server_id{};
    random_bytes(server_id);

    ScrambleSuitConn conn;
    conn.init(server_id);

    auto handshake = conn.generate_handshake();
    // At least PUBKEY_LEN + MARK_LEN
    REQUIRE(handshake.size() >= UNIFORM_DH_KEY_LEN + MARK_LEN);
}

TEST_CASE("SessionTicket validity", "[scramblesuit]") {
    SessionTicket ticket;
    ticket.issued = std::chrono::system_clock::now();
    REQUIRE(ticket.is_valid());

    // Expired ticket (8 days ago)
    ticket.issued = std::chrono::system_clock::now() - std::chrono::hours(8 * 24);
    REQUIRE(!ticket.is_valid());
}

TEST_CASE("TicketStore put and get", "[scramblesuit]") {
    TicketStore store;

    SessionTicket ticket;
    random_bytes(ticket.data);
    ticket.issued = std::chrono::system_clock::now();

    store.put("server1", ticket);

    auto retrieved = store.get("server1");
    REQUIRE(retrieved.has_value());
    REQUIRE(retrieved->data == ticket.data);

    // Non-existent server
    REQUIRE(!store.get("server2").has_value());
}

TEST_CASE("TicketStore prune removes expired", "[scramblesuit]") {
    TicketStore store;

    SessionTicket valid_ticket;
    random_bytes(valid_ticket.data);
    valid_ticket.issued = std::chrono::system_clock::now();

    SessionTicket expired_ticket;
    random_bytes(expired_ticket.data);
    expired_ticket.issued = std::chrono::system_clock::now() - std::chrono::hours(8 * 24);

    store.put("valid", valid_ticket);
    store.put("expired", expired_ticket);

    store.prune();

    REQUIRE(store.get("valid").has_value());
    REQUIRE(!store.get("expired").has_value());
}
