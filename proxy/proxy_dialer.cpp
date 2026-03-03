#include "proxy_dialer.hpp"
#include "obfs4/common/log.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <sstream>

namespace obfs4::proxy {

std::string dial_error_message(DialError err) {
    switch (err) {
        case DialError::ConnectionFailed: return "connection failed";
        case DialError::ProxyAuthFailed: return "proxy authentication failed";
        case DialError::ProxyError: return "proxy error";
        case DialError::InvalidAddress: return "invalid address";
        case DialError::UnsupportedProxy: return "unsupported proxy type";
    }
    return "unknown dial error";
}

// Helper: TCP connect to host:port
static std::expected<int, DialError> tcp_connect(const std::string& host, uint16_t port) {
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    auto port_str = std::to_string(port);
    int ret = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (ret != 0 || !result) {
        return std::unexpected(DialError::InvalidAddress);
    }

    int fd = -1;
    for (auto* rp = result; rp != nullptr; rp = rp->ai_next) {
        fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;  // Success
        }

        ::close(fd);
        fd = -1;
    }

    freeaddrinfo(result);

    if (fd < 0) {
        return std::unexpected(DialError::ConnectionFailed);
    }

    return fd;
}

// DirectDialer
std::expected<int, DialError> DirectDialer::dial(const std::string& host,
                                                   uint16_t port) {
    return tcp_connect(host, port);
}

// HttpProxyDialer
HttpProxyDialer::HttpProxyDialer(const std::string& proxy_host, uint16_t proxy_port,
                                  const std::string& username,
                                  const std::string& password)
    : proxy_host_(proxy_host), proxy_port_(proxy_port),
      username_(username), password_(password) {}

std::expected<int, DialError> HttpProxyDialer::dial(const std::string& host,
                                                      uint16_t port) {
    auto fd = tcp_connect(proxy_host_, proxy_port_);
    if (!fd) return fd;

    // Send HTTP CONNECT
    std::ostringstream req;
    req << "CONNECT " << host << ":" << port << " HTTP/1.1\r\n";
    req << "Host: " << host << ":" << port << "\r\n";
    req << "\r\n";

    auto req_str = req.str();
    if (::send(*fd, req_str.data(), req_str.size(), 0) < 0) {
        ::close(*fd);
        return std::unexpected(DialError::ProxyError);
    }

    // Read response (check for 200)
    char buf[1024];
    ssize_t n = ::recv(*fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) {
        ::close(*fd);
        return std::unexpected(DialError::ProxyError);
    }
    buf[n] = '\0';

    if (std::string(buf).find("200") == std::string::npos) {
        ::close(*fd);
        return std::unexpected(DialError::ProxyError);
    }

    return fd;
}

// Socks5ProxyDialer
Socks5ProxyDialer::Socks5ProxyDialer(const std::string& proxy_host, uint16_t proxy_port,
                                      const std::string& username,
                                      const std::string& password)
    : proxy_host_(proxy_host), proxy_port_(proxy_port),
      username_(username), password_(password) {}

std::expected<int, DialError> Socks5ProxyDialer::dial(const std::string& host,
                                                        uint16_t port) {
    auto fd = tcp_connect(proxy_host_, proxy_port_);
    if (!fd) return fd;

    // SOCKS5 method negotiation
    uint8_t methods_msg[] = {0x05, 0x01, 0x00};  // No auth
    if (::send(*fd, methods_msg, sizeof(methods_msg), 0) < 0) {
        ::close(*fd);
        return std::unexpected(DialError::ProxyError);
    }

    uint8_t method_reply[2];
    if (::recv(*fd, method_reply, 2, 0) != 2) {
        ::close(*fd);
        return std::unexpected(DialError::ProxyError);
    }

    // CONNECT request
    std::vector<uint8_t> connect_req;
    connect_req.push_back(0x05);  // VER
    connect_req.push_back(0x01);  // CMD: CONNECT
    connect_req.push_back(0x00);  // RSV
    connect_req.push_back(0x03);  // ATYP: DOMAIN
    connect_req.push_back(static_cast<uint8_t>(host.size()));
    connect_req.insert(connect_req.end(), host.begin(), host.end());
    connect_req.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    connect_req.push_back(static_cast<uint8_t>(port & 0xFF));

    if (::send(*fd, connect_req.data(), connect_req.size(), 0) < 0) {
        ::close(*fd);
        return std::unexpected(DialError::ProxyError);
    }

    uint8_t connect_reply[256];
    ssize_t n = ::recv(*fd, connect_reply, sizeof(connect_reply), 0);
    if (n < 4 || connect_reply[1] != 0x00) {
        ::close(*fd);
        return std::unexpected(DialError::ProxyError);
    }

    return fd;
}

// Factory
std::expected<std::unique_ptr<Dialer>, DialError>
create_dialer(const std::string& proxy_url) {
    if (proxy_url.empty()) {
        return std::make_unique<DirectDialer>();
    }

    // Parse proxy URL: scheme://[user:pass@]host:port
    auto scheme_end = proxy_url.find("://");
    if (scheme_end == std::string::npos) {
        return std::unexpected(DialError::UnsupportedProxy);
    }

    std::string scheme = proxy_url.substr(0, scheme_end);
    std::string rest = proxy_url.substr(scheme_end + 3);

    std::string user, pass, host;
    uint16_t port = 0;

    auto at_pos = rest.find('@');
    std::string host_port;
    if (at_pos != std::string::npos) {
        auto cred = rest.substr(0, at_pos);
        host_port = rest.substr(at_pos + 1);
        auto colon = cred.find(':');
        if (colon != std::string::npos) {
            user = cred.substr(0, colon);
            pass = cred.substr(colon + 1);
        }
    } else {
        host_port = rest;
    }

    auto colon = host_port.rfind(':');
    if (colon == std::string::npos) {
        return std::unexpected(DialError::InvalidAddress);
    }
    host = host_port.substr(0, colon);
    port = static_cast<uint16_t>(std::stoi(host_port.substr(colon + 1)));

    if (scheme == "http") {
        return std::make_unique<HttpProxyDialer>(host, port, user, pass);
    } else if (scheme == "socks5") {
        return std::make_unique<Socks5ProxyDialer>(host, port, user, pass);
    }

    return std::unexpected(DialError::UnsupportedProxy);
}

}  // namespace obfs4::proxy
