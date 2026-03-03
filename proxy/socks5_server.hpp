#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <vector>

namespace obfs4::proxy {

// Callback for accepted SOCKS5 connections.
// Parameters: client socket fd, target address, target port, PT args string
using Socks5AcceptCallback = std::function<void(int client_fd,
                                                 const std::string& target,
                                                 uint16_t port,
                                                 const std::string& pt_args)>;

// SOCKS5 listener for client mode.
// Listens on 127.0.0.1:0 (OS-assigned port) and handles SOCKS5
// method negotiation + CONNECT requests.
class Socks5Server {
public:
    Socks5Server() = default;
    ~Socks5Server();

    Socks5Server(const Socks5Server&) = delete;
    Socks5Server& operator=(const Socks5Server&) = delete;

    // Start listening. Returns the bound address as "host:port".
    std::string start(Socks5AcceptCallback callback);

    // Stop the server
    void stop();

    // Get bound port
    uint16_t port() const { return port_; }

    bool running() const { return running_.load(); }

private:
    int listen_fd_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> running_{false};
    std::jthread accept_thread_;
    Socks5AcceptCallback callback_;

    void accept_loop(std::stop_token stoken);
    void handle_client(int client_fd);
};

}  // namespace obfs4::proxy
