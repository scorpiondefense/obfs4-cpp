#include "server_handler.hpp"
#include "copy_loop.hpp"
#include "obfs4/common/log.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <thread>

namespace obfs4::proxy {

ServerHandler::ServerHandler(transports::TransportRegistry& registry,
                              const std::string& orport)
    : registry_(registry), orport_(orport) {}

std::string ServerHandler::start(const std::string& transport_name,
                                  const std::string& bind_addr,
                                  const transports::Args& /*args*/) {
    transport_name_ = transport_name;

    // Parse bind address
    auto colon = bind_addr.rfind(':');
    std::string host = "0.0.0.0";
    uint16_t port = 0;
    if (colon != std::string::npos) {
        host = bind_addr.substr(0, colon);
        port = static_cast<uint16_t>(std::stoi(bind_addr.substr(colon + 1)));
    }

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) return "";

    int optval = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    inet_aton(host.c_str(), &addr.sin_addr);
    addr.sin_port = htons(port);

    if (::bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        return "";
    }

    socklen_t addr_len = sizeof(addr);
    getsockname(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), &addr_len);
    uint16_t actual_port = ntohs(addr.sin_port);

    if (::listen(listen_fd_, 128) < 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
        return "";
    }

    running_ = true;
    accept_thread_ = std::jthread([this](std::stop_token st) {
        accept_loop(st);
    });

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip_str, sizeof(ip_str));
    return std::string(ip_str) + ":" + std::to_string(actual_port);
}

void ServerHandler::stop() {
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

void ServerHandler::accept_loop(std::stop_token stoken) {
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

        common::log_info("accepted connection from " +
                          common::elide_address(inet_ntoa(client_addr.sin_addr)));

        std::thread([this, client_fd]() {
            handle_client(client_fd);
        }).detach();
    }
}

void ServerHandler::handle_client(int client_fd) {
    // Parse ORPort address
    auto colon = orport_.rfind(':');
    if (colon == std::string::npos) {
        common::log_error("invalid ORPort address: " + orport_);
        ::close(client_fd);
        return;
    }

    auto or_host = orport_.substr(0, colon);
    auto or_port = static_cast<uint16_t>(std::stoi(orport_.substr(colon + 1)));

    // Connect to ORPort
    DirectDialer dialer;
    auto or_fd = dialer.dial(or_host, or_port);
    if (!or_fd) {
        common::log_error("failed to connect to ORPort: " + orport_);
        ::close(client_fd);
        return;
    }

    // In a full implementation, transport unwrapping would happen here.
    // Start bidirectional relay
    auto loop = std::make_shared<CopyLoop>();
    loop->start(client_fd, *or_fd);

    std::thread([loop]() {
        loop->wait();
    }).detach();
}

}  // namespace obfs4::proxy
