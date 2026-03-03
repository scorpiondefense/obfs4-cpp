#pragma once

#include <expected>
#include <memory>
#include <string>

namespace obfs4::proxy {

enum class DialError {
    ConnectionFailed,
    ProxyAuthFailed,
    ProxyError,
    InvalidAddress,
    UnsupportedProxy,
};

[[nodiscard]] std::string dial_error_message(DialError err);

// Abstract dialer interface for connecting to remote hosts,
// optionally through an upstream proxy.
class Dialer {
public:
    virtual ~Dialer() = default;

    // Connect to host:port, returns socket fd on success
    virtual std::expected<int, DialError> dial(const std::string& host,
                                                uint16_t port) = 0;
};

// Direct connection (no proxy)
class DirectDialer : public Dialer {
public:
    std::expected<int, DialError> dial(const std::string& host,
                                        uint16_t port) override;
};

// HTTP CONNECT proxy
class HttpProxyDialer : public Dialer {
public:
    HttpProxyDialer(const std::string& proxy_host, uint16_t proxy_port,
                    const std::string& username = "",
                    const std::string& password = "");

    std::expected<int, DialError> dial(const std::string& host,
                                        uint16_t port) override;

private:
    std::string proxy_host_;
    uint16_t proxy_port_;
    std::string username_;
    std::string password_;
};

// SOCKS5 upstream proxy
class Socks5ProxyDialer : public Dialer {
public:
    Socks5ProxyDialer(const std::string& proxy_host, uint16_t proxy_port,
                      const std::string& username = "",
                      const std::string& password = "");

    std::expected<int, DialError> dial(const std::string& host,
                                        uint16_t port) override;

private:
    std::string proxy_host_;
    uint16_t proxy_port_;
    std::string username_;
    std::string password_;
};

// Create a dialer from a PT proxy URL (e.g., "socks5://user:pass@host:port")
std::expected<std::unique_ptr<Dialer>, DialError>
create_dialer(const std::string& proxy_url = "");

}  // namespace obfs4::proxy
