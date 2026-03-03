#include "obfs4/proxy/socks5.hpp"
#include <sstream>

namespace obfs4::proxy {

std::string socks5_error_message(Socks5Error err) {
    switch (err) {
        case Socks5Error::InvalidVersion: return "invalid SOCKS version";
        case Socks5Error::NoAcceptableAuth: return "no acceptable auth method";
        case Socks5Error::AuthFailed: return "authentication failed";
        case Socks5Error::InvalidCommand: return "invalid SOCKS command";
        case Socks5Error::InvalidAddress: return "invalid address";
        case Socks5Error::ProtocolError: return "SOCKS protocol error";
        case Socks5Error::NeedMore: return "need more data";
    }
    return "unknown SOCKS5 error";
}

std::string Socks5Address::to_string() const {
    if (port > 0) {
        return host + ":" + std::to_string(port);
    }
    return host;
}

// PT arg parser: "key=val;key=val" with backslash escaping
std::expected<PtArgs, Socks5Error> PtArgs::parse(const std::string& s) {
    PtArgs result;
    if (s.empty()) return result;

    size_t i = 0;
    while (i < s.size()) {
        // Parse key
        std::string key;
        while (i < s.size() && s[i] != '=') {
            if (s[i] == '\\' && i + 1 < s.size()) {
                key += s[i + 1];
                i += 2;
            } else {
                key += s[i];
                ++i;
            }
        }
        if (i >= s.size()) break;
        ++i;  // skip '='

        // Parse value
        std::string val;
        while (i < s.size() && s[i] != ';') {
            if (s[i] == '\\' && i + 1 < s.size()) {
                val += s[i + 1];
                i += 2;
            } else {
                val += s[i];
                ++i;
            }
        }
        if (i < s.size()) ++i;  // skip ';'

        result.args.emplace_back(std::move(key), std::move(val));
    }

    return result;
}

std::optional<std::string> PtArgs::get(const std::string& key) const {
    for (const auto& [k, v] : args) {
        if (k == key) return v;
    }
    return std::nullopt;
}

std::expected<MethodNegotiation, Socks5Error>
parse_method_negotiation(std::span<const uint8_t> data) {
    if (data.size() < 2) {
        return std::unexpected(Socks5Error::NeedMore);
    }

    MethodNegotiation result;
    result.version = data[0];
    if (result.version != SOCKS5_VERSION) {
        return std::unexpected(Socks5Error::InvalidVersion);
    }

    uint8_t nmethods = data[1];
    if (data.size() < 2u + nmethods) {
        return std::unexpected(Socks5Error::NeedMore);
    }

    result.methods.assign(data.begin() + 2, data.begin() + 2 + nmethods);
    return result;
}

std::vector<uint8_t> make_method_reply(uint8_t method) {
    return {SOCKS5_VERSION, method};
}

std::expected<UserPassAuth, Socks5Error>
parse_user_pass_auth(std::span<const uint8_t> data) {
    if (data.size() < 2) {
        return std::unexpected(Socks5Error::NeedMore);
    }

    uint8_t ver = data[0];
    if (ver != 0x01) {  // RFC 1929 version
        return std::unexpected(Socks5Error::InvalidVersion);
    }

    uint8_t ulen = data[1];
    if (data.size() < 2u + ulen + 1) {
        return std::unexpected(Socks5Error::NeedMore);
    }

    UserPassAuth result;
    result.username = std::string(reinterpret_cast<const char*>(data.data() + 2), ulen);

    uint8_t plen = data[2 + ulen];
    if (data.size() < 2u + ulen + 1u + plen) {
        return std::unexpected(Socks5Error::NeedMore);
    }

    result.password = std::string(
        reinterpret_cast<const char*>(data.data() + 3 + ulen), plen);

    return result;
}

std::vector<uint8_t> make_auth_reply(bool success) {
    return {0x01, static_cast<uint8_t>(success ? 0x00 : 0x01)};
}

std::expected<ConnectRequest, Socks5Error>
parse_connect_request(std::span<const uint8_t> data) {
    if (data.size() < 4) {
        return std::unexpected(Socks5Error::NeedMore);
    }

    if (data[0] != SOCKS5_VERSION) {
        return std::unexpected(Socks5Error::InvalidVersion);
    }

    ConnectRequest result;
    result.command = data[1];

    if (result.command != SOCKS5_CMD_CONNECT) {
        return std::unexpected(Socks5Error::InvalidCommand);
    }

    // data[2] is reserved
    uint8_t atyp = data[3];
    result.address.type = atyp;

    size_t addr_start = 4;
    size_t addr_len = 0;

    switch (atyp) {
        case SOCKS5_ATYP_IPV4: {
            if (data.size() < addr_start + 4 + 2) {
                return std::unexpected(Socks5Error::NeedMore);
            }
            addr_len = 4;
            // Format as dotted quad
            result.address.host = std::to_string(data[addr_start]) + "." +
                                  std::to_string(data[addr_start + 1]) + "." +
                                  std::to_string(data[addr_start + 2]) + "." +
                                  std::to_string(data[addr_start + 3]);
            break;
        }
        case SOCKS5_ATYP_DOMAIN: {
            if (data.size() < addr_start + 1) {
                return std::unexpected(Socks5Error::NeedMore);
            }
            uint8_t domain_len = data[addr_start];
            addr_start += 1;
            if (data.size() < addr_start + domain_len + 2) {
                return std::unexpected(Socks5Error::NeedMore);
            }
            addr_len = domain_len;
            result.address.host = std::string(
                reinterpret_cast<const char*>(data.data() + addr_start), domain_len);
            break;
        }
        case SOCKS5_ATYP_IPV6: {
            if (data.size() < addr_start + 16 + 2) {
                return std::unexpected(Socks5Error::NeedMore);
            }
            addr_len = 16;
            // Format as hex groups
            std::ostringstream oss;
            for (int i = 0; i < 8; ++i) {
                if (i > 0) oss << ":";
                uint16_t word = (static_cast<uint16_t>(data[addr_start + i * 2]) << 8) |
                                data[addr_start + i * 2 + 1];
                oss << std::hex << word;
            }
            result.address.host = oss.str();
            break;
        }
        default:
            return std::unexpected(Socks5Error::InvalidAddress);
    }

    // Port (big-endian)
    size_t port_offset = addr_start + addr_len;
    result.address.port = (static_cast<uint16_t>(data[port_offset]) << 8) |
                          static_cast<uint16_t>(data[port_offset + 1]);

    return result;
}

std::vector<uint8_t> make_connect_reply(uint8_t reply_code,
                                         const Socks5Address& bind_addr) {
    std::vector<uint8_t> reply;
    reply.push_back(SOCKS5_VERSION);
    reply.push_back(reply_code);
    reply.push_back(0x00);  // Reserved

    if (bind_addr.type == SOCKS5_ATYP_IPV4 || bind_addr.type == 0) {
        reply.push_back(SOCKS5_ATYP_IPV4);
        reply.push_back(0); reply.push_back(0);
        reply.push_back(0); reply.push_back(0);
    } else if (bind_addr.type == SOCKS5_ATYP_IPV6) {
        reply.push_back(SOCKS5_ATYP_IPV6);
        for (int i = 0; i < 16; ++i) reply.push_back(0);
    } else {
        reply.push_back(SOCKS5_ATYP_IPV4);
        reply.push_back(0); reply.push_back(0);
        reply.push_back(0); reply.push_back(0);
    }

    // Port
    reply.push_back(static_cast<uint8_t>((bind_addr.port >> 8) & 0xFF));
    reply.push_back(static_cast<uint8_t>(bind_addr.port & 0xFF));

    return reply;
}

}  // namespace obfs4::proxy
