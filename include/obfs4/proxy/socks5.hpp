#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace obfs4::proxy {

// SOCKS5 protocol (RFC 1928) + username/password auth (RFC 1929)
// Used by Tor's PT protocol to pass transport arguments.

// SOCKS5 constants
constexpr uint8_t SOCKS5_VERSION = 0x05;
constexpr uint8_t SOCKS5_AUTH_NONE = 0x00;
constexpr uint8_t SOCKS5_AUTH_USER_PASS = 0x02;
constexpr uint8_t SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF;
constexpr uint8_t SOCKS5_CMD_CONNECT = 0x01;
constexpr uint8_t SOCKS5_ATYP_IPV4 = 0x01;
constexpr uint8_t SOCKS5_ATYP_DOMAIN = 0x03;
constexpr uint8_t SOCKS5_ATYP_IPV6 = 0x04;

// SOCKS5 reply codes
constexpr uint8_t SOCKS5_REPLY_SUCCEEDED = 0x00;
constexpr uint8_t SOCKS5_REPLY_GENERAL_FAILURE = 0x01;
constexpr uint8_t SOCKS5_REPLY_NOT_ALLOWED = 0x02;
constexpr uint8_t SOCKS5_REPLY_NETWORK_UNREACHABLE = 0x03;
constexpr uint8_t SOCKS5_REPLY_HOST_UNREACHABLE = 0x04;
constexpr uint8_t SOCKS5_REPLY_CONN_REFUSED = 0x05;
constexpr uint8_t SOCKS5_REPLY_TTL_EXPIRED = 0x06;
constexpr uint8_t SOCKS5_REPLY_CMD_NOT_SUPPORTED = 0x07;
constexpr uint8_t SOCKS5_REPLY_ATYP_NOT_SUPPORTED = 0x08;

enum class Socks5Error {
    InvalidVersion,
    NoAcceptableAuth,
    AuthFailed,
    InvalidCommand,
    InvalidAddress,
    ProtocolError,
    NeedMore,
};

[[nodiscard]] std::string socks5_error_message(Socks5Error err);

// SOCKS5 address
struct Socks5Address {
    uint8_t type = 0;          // ATYP
    std::string host;          // IP string or domain name
    uint16_t port = 0;

    // IPv4 as 4 bytes, IPv6 as 16 bytes, domain as string
    std::string to_string() const;
};

// PT argument parser: "key=val;key=val" with backslash escaping
struct PtArgs {
    std::vector<std::pair<std::string, std::string>> args;

    static std::expected<PtArgs, Socks5Error> parse(const std::string& s);
    std::optional<std::string> get(const std::string& key) const;
};

// Parse SOCKS5 method negotiation: VER(1) + NMETHODS(1) + METHODS(n)
struct MethodNegotiation {
    uint8_t version = 0;
    std::vector<uint8_t> methods;
};

std::expected<MethodNegotiation, Socks5Error>
parse_method_negotiation(std::span<const uint8_t> data);

// Generate method selection reply
std::vector<uint8_t> make_method_reply(uint8_t method);

// Parse username/password auth: VER(1) + ULEN(1) + USER + PLEN(1) + PASS
struct UserPassAuth {
    std::string username;
    std::string password;
};

std::expected<UserPassAuth, Socks5Error>
parse_user_pass_auth(std::span<const uint8_t> data);

// Generate auth reply
std::vector<uint8_t> make_auth_reply(bool success);

// Parse SOCKS5 CONNECT request: VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR + DST.PORT(2)
struct ConnectRequest {
    uint8_t command = 0;
    Socks5Address address;
};

std::expected<ConnectRequest, Socks5Error>
parse_connect_request(std::span<const uint8_t> data);

// Generate CONNECT reply
std::vector<uint8_t> make_connect_reply(uint8_t reply_code,
                                         const Socks5Address& bind_addr = {});

}  // namespace obfs4::proxy
