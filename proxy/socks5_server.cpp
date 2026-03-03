#include "socks5_server.hpp"
#include "obfs4/proxy/socks5.hpp"
#include "obfs4/common/log.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>

namespace obfs4::proxy {

Socks5Server::~Socks5Server() {
    stop();
}

std::string Socks5Server::start(Socks5AcceptCallback callback) {
    callback_ = std::move(callback);

    // Create TCP socket
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        return "";
    }

    int optval = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // Bind to localhost:0 (OS-assigned port)
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (::bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        return "";
    }

    // Get assigned port
    socklen_t addr_len = sizeof(addr);
    getsockname(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), &addr_len);
    port_ = ntohs(addr.sin_port);

    if (::listen(listen_fd_, 128) < 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        return "";
    }

    running_ = true;
    accept_thread_ = std::jthread([this](std::stop_token stoken) {
        accept_loop(stoken);
    });

    return "127.0.0.1:" + std::to_string(port_);
}

void Socks5Server::stop() {
    running_ = false;
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    if (accept_thread_.joinable()) {
        accept_thread_.request_stop();
        accept_thread_.join();
    }
}

void Socks5Server::accept_loop(std::stop_token stoken) {
    while (!stoken.stop_requested() && running_) {
        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = ::accept(listen_fd_,
                                  reinterpret_cast<struct sockaddr*>(&client_addr),
                                  &client_len);
        if (client_fd < 0) {
            if (!running_) break;
            continue;
        }

        // Handle client in a detached thread
        std::thread([this, client_fd]() {
            handle_client(client_fd);
        }).detach();
    }
}

void Socks5Server::handle_client(int client_fd) {
    // Read method negotiation
    uint8_t buf[512];
    ssize_t n = ::recv(client_fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        ::close(client_fd);
        return;
    }

    auto methods = parse_method_negotiation(std::span<const uint8_t>(buf, n));
    if (!methods) {
        ::close(client_fd);
        return;
    }

    // Check for username/password auth (used by PT for args)
    bool has_user_pass = false;
    for (auto m : methods->methods) {
        if (m == SOCKS5_AUTH_USER_PASS) { has_user_pass = true; break; }
    }

    std::string pt_args_str;
    if (has_user_pass) {
        auto reply = make_method_reply(SOCKS5_AUTH_USER_PASS);
        ::send(client_fd, reply.data(), reply.size(), 0);

        // Read auth
        n = ::recv(client_fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            ::close(client_fd);
            return;
        }

        auto auth = parse_user_pass_auth(std::span<const uint8_t>(buf, n));
        if (!auth) {
            auto fail = make_auth_reply(false);
            ::send(client_fd, fail.data(), fail.size(), 0);
            ::close(client_fd);
            return;
        }

        // PT args are in the password field
        pt_args_str = auth->password;

        auto ok = make_auth_reply(true);
        ::send(client_fd, ok.data(), ok.size(), 0);
    } else {
        auto reply = make_method_reply(SOCKS5_AUTH_NONE);
        ::send(client_fd, reply.data(), reply.size(), 0);
    }

    // Read CONNECT request
    n = ::recv(client_fd, buf, sizeof(buf), 0);
    if (n <= 0) {
        ::close(client_fd);
        return;
    }

    auto connect = parse_connect_request(std::span<const uint8_t>(buf, n));
    if (!connect) {
        auto reply = make_connect_reply(SOCKS5_REPLY_GENERAL_FAILURE);
        ::send(client_fd, reply.data(), reply.size(), 0);
        ::close(client_fd);
        return;
    }

    // Dispatch to callback
    if (callback_) {
        callback_(client_fd, connect->address.host,
                  connect->address.port, pt_args_str);
    } else {
        auto reply = make_connect_reply(SOCKS5_REPLY_GENERAL_FAILURE);
        ::send(client_fd, reply.data(), reply.size(), 0);
        ::close(client_fd);
    }
}

}  // namespace obfs4::proxy
