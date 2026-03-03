#include <catch2/catch_test_macros.hpp>
#include "obfs4/proxy/socks5.hpp"
#include <cstring>

using namespace obfs4::proxy;

// ============= Method negotiation =============

TEST_CASE("socks5 parity: method negotiation single method", "[socks5][parity]") {
    std::vector<uint8_t> data = {0x05, 0x01, 0x00};  // NO AUTH only
    auto result = parse_method_negotiation(data);
    REQUIRE(result.has_value());
    REQUIRE(result->version == 5);
    REQUIRE(result->methods.size() == 1);
    REQUIRE(result->methods[0] == SOCKS5_AUTH_NONE);
}

TEST_CASE("socks5 parity: method negotiation all methods", "[socks5][parity]") {
    std::vector<uint8_t> data = {0x05, 0x03, 0x00, 0x01, 0x02};
    auto result = parse_method_negotiation(data);
    REQUIRE(result.has_value());
    REQUIRE(result->methods.size() == 3);
}

TEST_CASE("socks5 parity: method negotiation needs more data", "[socks5][parity]") {
    // Only version byte
    {
        std::vector<uint8_t> data = {0x05};
        auto r = parse_method_negotiation(data);
        REQUIRE(!r.has_value());
        REQUIRE(r.error() == Socks5Error::NeedMore);
    }

    // Version + nmethods but no methods
    {
        std::vector<uint8_t> data = {0x05, 0x02};
        auto r = parse_method_negotiation(data);
        REQUIRE(!r.has_value());
        REQUIRE(r.error() == Socks5Error::NeedMore);
    }

    // Version + nmethods + partial methods
    {
        std::vector<uint8_t> data = {0x05, 0x03, 0x00};
        auto r = parse_method_negotiation(data);
        REQUIRE(!r.has_value());
        REQUIRE(r.error() == Socks5Error::NeedMore);
    }
}

TEST_CASE("socks5 parity: method reply format", "[socks5][parity]") {
    // NO AUTH
    {
        auto reply = make_method_reply(SOCKS5_AUTH_NONE);
        REQUIRE(reply.size() == 2);
        REQUIRE(reply[0] == SOCKS5_VERSION);
        REQUIRE(reply[1] == SOCKS5_AUTH_NONE);
    }

    // USER/PASS
    {
        auto reply = make_method_reply(SOCKS5_AUTH_USER_PASS);
        REQUIRE(reply.size() == 2);
        REQUIRE(reply[0] == SOCKS5_VERSION);
        REQUIRE(reply[1] == SOCKS5_AUTH_USER_PASS);
    }

    // NO ACCEPTABLE
    {
        auto reply = make_method_reply(0xFF);
        REQUIRE(reply.size() == 2);
        REQUIRE(reply[0] == SOCKS5_VERSION);
        REQUIRE(reply[1] == 0xFF);
    }
}

// ============= User/Pass authentication =============

TEST_CASE("socks5 parity: auth with empty username and password", "[socks5][parity]") {
    // VER=1, ULEN=0, PLEN=0
    std::vector<uint8_t> data = {0x01, 0x00, 0x00};
    auto result = parse_user_pass_auth(data);
    REQUIRE(result.has_value());
    REQUIRE(result->username.empty());
    REQUIRE(result->password.empty());
}

TEST_CASE("socks5 parity: auth needs more data", "[socks5][parity]") {
    // Just version byte
    {
        std::vector<uint8_t> data = {0x01};
        auto r = parse_user_pass_auth(data);
        REQUIRE(!r.has_value());
        REQUIRE(r.error() == Socks5Error::NeedMore);
    }

    // Version + ulen but no username
    {
        std::vector<uint8_t> data = {0x01, 0x05};
        auto r = parse_user_pass_auth(data);
        REQUIRE(!r.has_value());
        REQUIRE(r.error() == Socks5Error::NeedMore);
    }
}

TEST_CASE("socks5 parity: auth reply format", "[socks5][parity]") {
    auto success = make_auth_reply(true);
    REQUIRE(success.size() == 2);
    REQUIRE(success[0] == 0x01);
    REQUIRE(success[1] == 0x00);

    auto fail = make_auth_reply(false);
    REQUIRE(fail.size() == 2);
    REQUIRE(fail[0] == 0x01);
    REQUIRE(fail[1] == 0x01);
}

// ============= CONNECT requests =============

TEST_CASE("socks5 parity: CONNECT IPv6 address", "[socks5][parity]") {
    // VER=5, CMD=CONNECT, RSV=0, ATYP=IPv6, ADDR=::1, PORT=8080
    std::vector<uint8_t> data = {0x05, 0x01, 0x00, 0x04,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                                  0x1F, 0x90};  // 8080
    auto result = parse_connect_request(data);
    REQUIRE(result.has_value());
    REQUIRE(result->command == SOCKS5_CMD_CONNECT);
    REQUIRE(result->address.type == SOCKS5_ATYP_IPV6);
    REQUIRE(result->address.port == 8080);
}

TEST_CASE("socks5 parity: CONNECT needs more data", "[socks5][parity]") {
    // Too short to parse header
    {
        std::vector<uint8_t> data = {0x05, 0x01, 0x00};
        auto r = parse_connect_request(data);
        REQUIRE(!r.has_value());
        REQUIRE(r.error() == Socks5Error::NeedMore);
    }

    // IPv4 but missing port
    {
        std::vector<uint8_t> data = {0x05, 0x01, 0x00, 0x01,
                                      127, 0, 0, 1};
        auto r = parse_connect_request(data);
        REQUIRE(!r.has_value());
        REQUIRE(r.error() == Socks5Error::NeedMore);
    }
}

TEST_CASE("socks5 parity: CONNECT reply with bind address", "[socks5][parity]") {
    Socks5Address addr;
    addr.type = SOCKS5_ATYP_IPV4;
    addr.host = "127.0.0.1";
    addr.port = 12345;

    auto reply = make_connect_reply(SOCKS5_REPLY_SUCCEEDED, addr);
    REQUIRE(reply.size() == 10);
    REQUIRE(reply[0] == SOCKS5_VERSION);
    REQUIRE(reply[1] == SOCKS5_REPLY_SUCCEEDED);
    REQUIRE(reply[3] == SOCKS5_ATYP_IPV4);
}

TEST_CASE("socks5 parity: CONNECT reply error codes", "[socks5][parity]") {
    auto r1 = make_connect_reply(SOCKS5_REPLY_GENERAL_FAILURE);
    REQUIRE(r1[1] == SOCKS5_REPLY_GENERAL_FAILURE);

    auto r2 = make_connect_reply(SOCKS5_REPLY_NOT_ALLOWED);
    REQUIRE(r2[1] == SOCKS5_REPLY_NOT_ALLOWED);

    auto r3 = make_connect_reply(SOCKS5_REPLY_NETWORK_UNREACHABLE);
    REQUIRE(r3[1] == SOCKS5_REPLY_NETWORK_UNREACHABLE);
}

TEST_CASE("socks5 parity: Socks5Address to_string", "[socks5][parity]") {
    Socks5Address addr;
    addr.type = SOCKS5_ATYP_IPV4;
    addr.host = "192.168.1.1";
    addr.port = 9050;

    auto str = addr.to_string();
    REQUIRE(str == "192.168.1.1:9050");
}

TEST_CASE("socks5 parity: domain address to_string", "[socks5][parity]") {
    Socks5Address addr;
    addr.type = SOCKS5_ATYP_DOMAIN;
    addr.host = "bridges.torproject.org";
    addr.port = 443;

    auto str = addr.to_string();
    REQUIRE(str == "bridges.torproject.org:443");
}

// ============= PT args =============

TEST_CASE("socks5 parity: PT args empty string", "[socks5][parity]") {
    auto result = PtArgs::parse("");
    REQUIRE(result.has_value());
    // Empty string should produce no args
}

TEST_CASE("socks5 parity: PT args single key-value", "[socks5][parity]") {
    auto result = PtArgs::parse("cert=AAAA+BBBB");
    REQUIRE(result.has_value());
    REQUIRE(result->get("cert").value() == "AAAA+BBBB");
}

TEST_CASE("socks5 parity: PT args multiple pairs", "[socks5][parity]") {
    auto result = PtArgs::parse("cert=AAAA;iat-mode=1;password=hunter2");
    REQUIRE(result.has_value());
    REQUIRE(result->get("cert").value() == "AAAA");
    REQUIRE(result->get("iat-mode").value() == "1");
    REQUIRE(result->get("password").value() == "hunter2");
}

TEST_CASE("socks5 parity: PT args backslash escaping", "[socks5][parity]") {
    // Escaped semicolon in value
    auto r1 = PtArgs::parse("key=val\\;ue;other=test");
    REQUIRE(r1.has_value());
    REQUIRE(r1->get("key").value() == "val;ue");
    REQUIRE(r1->get("other").value() == "test");

    // Escaped equals in value
    auto r2 = PtArgs::parse("key=val\\=ue");
    REQUIRE(r2.has_value());
    REQUIRE(r2->get("key").value() == "val=ue");

    // Escaped backslash
    auto r3 = PtArgs::parse("key=val\\\\ue");
    REQUIRE(r3.has_value());
    REQUIRE(r3->get("key").value() == "val\\ue");
}

TEST_CASE("socks5 parity: PT args missing value", "[socks5][parity]") {
    auto result = PtArgs::parse("nonexistent");
    // Should parse without crashing, but key lookup should fail
    if (result.has_value()) {
        REQUIRE(!result->get("nonexistent").has_value());
    }
}

TEST_CASE("socks5 parity: PT args trailing semicolon", "[socks5][parity]") {
    auto result = PtArgs::parse("key=value;");
    REQUIRE(result.has_value());
    REQUIRE(result->get("key").value() == "value");
}

// ============= Constants match Go =============

TEST_CASE("socks5 parity: SOCKS5 constants match RFC 1928", "[socks5][parity]") {
    REQUIRE(SOCKS5_VERSION == 0x05);
    REQUIRE(SOCKS5_AUTH_NONE == 0x00);
    REQUIRE(SOCKS5_AUTH_USER_PASS == 0x02);
    REQUIRE(SOCKS5_CMD_CONNECT == 0x01);
    REQUIRE(SOCKS5_ATYP_IPV4 == 0x01);
    REQUIRE(SOCKS5_ATYP_DOMAIN == 0x03);
    REQUIRE(SOCKS5_ATYP_IPV6 == 0x04);
    REQUIRE(SOCKS5_REPLY_SUCCEEDED == 0x00);
    REQUIRE(SOCKS5_REPLY_GENERAL_FAILURE == 0x01);
}
