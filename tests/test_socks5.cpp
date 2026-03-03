#include <catch2/catch_test_macros.hpp>
#include "obfs4/proxy/socks5.hpp"

using namespace obfs4::proxy;

TEST_CASE("SOCKS5 method negotiation parsing", "[socks5]") {
    // VER=5, NMETHODS=2, METHODS=[0x00, 0x02]
    std::vector<uint8_t> data = {0x05, 0x02, 0x00, 0x02};
    auto result = parse_method_negotiation(data);
    REQUIRE(result.has_value());
    REQUIRE(result->version == 5);
    REQUIRE(result->methods.size() == 2);
    REQUIRE(result->methods[0] == SOCKS5_AUTH_NONE);
    REQUIRE(result->methods[1] == SOCKS5_AUTH_USER_PASS);
}

TEST_CASE("SOCKS5 method negotiation rejects wrong version", "[socks5]") {
    std::vector<uint8_t> data = {0x04, 0x01, 0x00};  // SOCKS4
    auto result = parse_method_negotiation(data);
    REQUIRE(!result.has_value());
    REQUIRE(result.error() == Socks5Error::InvalidVersion);
}

TEST_CASE("SOCKS5 method reply", "[socks5]") {
    auto reply = make_method_reply(SOCKS5_AUTH_NONE);
    REQUIRE(reply.size() == 2);
    REQUIRE(reply[0] == 0x05);
    REQUIRE(reply[1] == 0x00);
}

TEST_CASE("SOCKS5 user/pass auth parsing", "[socks5]") {
    // VER=1, ULEN=4, USER="test", PLEN=6, PASS="secret"
    std::vector<uint8_t> data = {0x01, 0x04, 't', 'e', 's', 't',
                                  0x06, 's', 'e', 'c', 'r', 'e', 't'};
    auto result = parse_user_pass_auth(data);
    REQUIRE(result.has_value());
    REQUIRE(result->username == "test");
    REQUIRE(result->password == "secret");
}

TEST_CASE("SOCKS5 CONNECT request IPv4", "[socks5]") {
    // VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4, ADDR=127.0.0.1, PORT=9050
    std::vector<uint8_t> data = {0x05, 0x01, 0x00, 0x01,
                                  127, 0, 0, 1,
                                  0x23, 0x5A};  // 9050
    auto result = parse_connect_request(data);
    REQUIRE(result.has_value());
    REQUIRE(result->command == SOCKS5_CMD_CONNECT);
    REQUIRE(result->address.host == "127.0.0.1");
    REQUIRE(result->address.port == 9050);
}

TEST_CASE("SOCKS5 CONNECT request domain", "[socks5]") {
    // VER=5, CMD=CONNECT, RSV=0, ATYP=DOMAIN, LEN=11, "example.com", PORT=443
    std::vector<uint8_t> data = {0x05, 0x01, 0x00, 0x03,
                                  0x0B, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                                  '.', 'c', 'o', 'm',
                                  0x01, 0xBB};  // 443
    auto result = parse_connect_request(data);
    REQUIRE(result.has_value());
    REQUIRE(result->address.host == "example.com");
    REQUIRE(result->address.port == 443);
}

TEST_CASE("SOCKS5 connect reply", "[socks5]") {
    auto reply = make_connect_reply(SOCKS5_REPLY_SUCCEEDED);
    REQUIRE(reply.size() == 10);
    REQUIRE(reply[0] == 0x05);
    REQUIRE(reply[1] == 0x00);
    REQUIRE(reply[3] == SOCKS5_ATYP_IPV4);
}

TEST_CASE("PT args parsing", "[socks5]") {
    auto result = PtArgs::parse("cert=AAA;iat-mode=0");
    REQUIRE(result.has_value());
    REQUIRE(result->get("cert").value() == "AAA");
    REQUIRE(result->get("iat-mode").value() == "0");
    REQUIRE(!result->get("missing").has_value());
}

TEST_CASE("PT args with escaping", "[socks5]") {
    auto result = PtArgs::parse("key=val\\;ue;other=test");
    REQUIRE(result.has_value());
    REQUIRE(result->get("key").value() == "val;ue");
    REQUIRE(result->get("other").value() == "test");
}

TEST_CASE("SOCKS5 needs more data", "[socks5]") {
    std::vector<uint8_t> data = {0x05};  // Only version byte
    auto result = parse_method_negotiation(data);
    REQUIRE(!result.has_value());
    REQUIRE(result.error() == Socks5Error::NeedMore);
}
