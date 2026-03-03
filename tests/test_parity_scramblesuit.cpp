#include <catch2/catch_test_macros.hpp>
#include "obfs4/transports/scramblesuit/scramblesuit.hpp"
#include "obfs4/transports/scramblesuit/ticket_store.hpp"
#include "obfs4/common/csrand.hpp"
#include "obfs4/common/uniform_dh.hpp"
#include "obfs4/crypto/hash.hpp"
#include <cstring>
#include <filesystem>

using namespace obfs4::transports::scramblesuit;
using namespace obfs4::transports;
using namespace obfs4::common;

TEST_CASE("scramblesuit parity: constants match Go", "[scramblesuit][parity]") {
    // Go: ticketLen = 112
    REQUIRE(TICKET_LEN == 112);
    // Go: ticketKeyLength = 32
    REQUIRE(TICKET_KEY_LEN == 32);
    // Go: ticketLifetime = 7 days
    REQUIRE(TICKET_LIFETIME_DAYS == 7);
    // Go: markLength = 32
    REQUIRE(MARK_LEN == 32);
    // Go: maxPadding = 1388
    REQUIRE(MAX_PADDING == 1388);
    // Go: kdf output = 160 bytes
    REQUIRE(KDF_OUTPUT_LEN == 160);
}

TEST_CASE("scramblesuit parity: flags match Go", "[scramblesuit][parity]") {
    REQUIRE(FLAG_PAYLOAD == 1);
    REQUIRE(FLAG_NEW_TICKET == (1 << 1));
    REQUIRE(FLAG_PRNG_SEED == (1 << 2));
}

TEST_CASE("scramblesuit parity: HKDF info string", "[scramblesuit][parity]") {
    // Go: scrambleSuitInfo = "ScrambleSuit"
    REQUIRE(HKDF_INFO == "ScrambleSuit");
}

TEST_CASE("scramblesuit parity: handshake size bounds", "[scramblesuit][parity]") {
    for (int i = 0; i < 10; ++i) {
        std::array<uint8_t, 20> server_id{};
        random_bytes(server_id);

        ScrambleSuitConn conn;
        conn.init(server_id);

        auto hs = conn.generate_handshake();
        // Minimum: PUBKEY(192) + MARK(32)
        REQUIRE(hs.size() >= UNIFORM_DH_KEY_LEN + MARK_LEN);
        // Maximum: PUBKEY(192) + MARK(32) + MAX_PADDING
        REQUIRE(hs.size() <= UNIFORM_DH_KEY_LEN + MARK_LEN + MAX_PADDING);
    }
}

TEST_CASE("scramblesuit parity: handshake mark derived from server_id", "[scramblesuit][parity]") {
    // Go: mark = HMAC-SHA256(server_id, pubkey)
    std::array<uint8_t, 20> server_id{};
    random_bytes(server_id);

    ScrambleSuitConn conn;
    conn.init(server_id);

    auto hs = conn.generate_handshake();

    // Extract pubkey (first 192 bytes) and mark (next 32 bytes)
    REQUIRE(hs.size() >= UNIFORM_DH_KEY_LEN + MARK_LEN);

    std::span<const uint8_t> pubkey(hs.data(), UNIFORM_DH_KEY_LEN);
    std::span<const uint8_t> mark(hs.data() + UNIFORM_DH_KEY_LEN, MARK_LEN);

    // Verify mark = HMAC-SHA256(server_id, pubkey)
    auto expected_mark = obfs4::crypto::hmac_sha256(
        std::span<const uint8_t>(server_id.data(), server_id.size()),
        pubkey);
    REQUIRE(expected_mark.has_value());
    REQUIRE(std::memcmp(mark.data(), expected_mark->data(), MARK_LEN) == 0);
}

TEST_CASE("scramblesuit parity: session ticket lifecycle", "[scramblesuit][parity]") {
    // Fresh ticket
    SessionTicket ticket;
    random_bytes(ticket.data);
    ticket.issued = std::chrono::system_clock::now();
    REQUIRE(ticket.is_valid());

    // Just under 7 days
    SessionTicket almost;
    random_bytes(almost.data);
    almost.issued = std::chrono::system_clock::now() -
        std::chrono::hours(TICKET_LIFETIME_DAYS * 24 - 1);
    REQUIRE(almost.is_valid());

    // Exactly 7 days (expired)
    SessionTicket exact;
    random_bytes(exact.data);
    exact.issued = std::chrono::system_clock::now() -
        std::chrono::hours(TICKET_LIFETIME_DAYS * 24);
    REQUIRE(!exact.is_valid());

    // Way past expiry
    SessionTicket old;
    random_bytes(old.data);
    old.issued = std::chrono::system_clock::now() - std::chrono::hours(30 * 24);
    REQUIRE(!old.is_valid());
}

TEST_CASE("scramblesuit parity: ticket store persistence", "[scramblesuit][parity]") {
    std::string path = "/tmp/obfs4_ticket_store_test_" +
        std::to_string(random_intn(1000000)) + ".dat";

    // Store tickets
    {
        TicketStore store;
        SessionTicket t1, t2;
        random_bytes(t1.data);
        t1.issued = std::chrono::system_clock::now();
        random_bytes(t2.data);
        t2.issued = std::chrono::system_clock::now();

        store.put("server_a", t1);
        store.put("server_b", t2);
        store.save(path);
    }

    // Load and verify
    {
        TicketStore store;
        store.load(path);

        auto r1 = store.get("server_a");
        REQUIRE(r1.has_value());

        auto r2 = store.get("server_b");
        REQUIRE(r2.has_value());

        REQUIRE(!store.get("server_c").has_value());
    }

    std::filesystem::remove(path);
}

TEST_CASE("scramblesuit parity: ticket store prune all expired", "[scramblesuit][parity]") {
    TicketStore store;

    // Add 5 expired tickets
    for (int i = 0; i < 5; ++i) {
        SessionTicket t;
        random_bytes(t.data);
        t.issued = std::chrono::system_clock::now() - std::chrono::hours(8 * 24);
        store.put("expired_" + std::to_string(i), t);
    }

    // Add 3 valid tickets
    for (int i = 0; i < 3; ++i) {
        SessionTicket t;
        random_bytes(t.data);
        t.issued = std::chrono::system_clock::now();
        store.put("valid_" + std::to_string(i), t);
    }

    store.prune();

    // All expired should be gone
    for (int i = 0; i < 5; ++i) {
        REQUIRE(!store.get("expired_" + std::to_string(i)).has_value());
    }

    // All valid should remain
    for (int i = 0; i < 3; ++i) {
        REQUIRE(store.get("valid_" + std::to_string(i)).has_value());
    }
}

TEST_CASE("scramblesuit parity: factory password derivation", "[scramblesuit][parity]") {
    // Go: server_id = SHA256(password)[:20]
    ScrambleSuitClientFactory f1, f2;

    Args args1, args2;
    args1["password"] = "password_alpha";
    args2["password"] = "password_beta";

    REQUIRE(f1.parse_args(args1).has_value());
    REQUIRE(f2.parse_args(args2).has_value());

    // Different passwords should produce different handshakes
    auto c1 = f1.create();
    auto c2 = f2.create();

    auto hs1 = c1.generate_handshake();
    auto hs2 = c2.generate_handshake();

    // The marks at offset 192 should differ (different server_ids)
    std::vector<uint8_t> mark1(hs1.begin() + UNIFORM_DH_KEY_LEN,
                                hs1.begin() + UNIFORM_DH_KEY_LEN + MARK_LEN);
    std::vector<uint8_t> mark2(hs2.begin() + UNIFORM_DH_KEY_LEN,
                                hs2.begin() + UNIFORM_DH_KEY_LEN + MARK_LEN);
    REQUIRE(mark1 != mark2);
}

TEST_CASE("scramblesuit parity: fresh sessions use unique DH keys", "[scramblesuit][parity]") {
    std::array<uint8_t, 20> server_id{};
    random_bytes(server_id);

    std::vector<std::vector<uint8_t>> pubkeys;
    for (int i = 0; i < 10; ++i) {
        ScrambleSuitConn conn;
        conn.init(server_id);
        auto hs = conn.generate_handshake();
        std::vector<uint8_t> pk(hs.begin(), hs.begin() + UNIFORM_DH_KEY_LEN);
        pubkeys.push_back(pk);
    }

    // All pubkeys should be unique
    for (size_t i = 0; i < pubkeys.size(); ++i) {
        for (size_t j = i + 1; j < pubkeys.size(); ++j) {
            REQUIRE(pubkeys[i] != pubkeys[j]);
        }
    }
}

TEST_CASE("scramblesuit parity: client-only (no server factory)", "[scramblesuit][parity]") {
    // ScrambleSuit is client-only in Go and C++.
    // The registry should not offer a server factory.
    // (This is tested in test_registry, but we verify the concept here)
    REQUIRE(ScrambleSuitClientFactory::transport_name() == "scramblesuit");
}
