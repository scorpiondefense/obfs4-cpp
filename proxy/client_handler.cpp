#include "client_handler.hpp"
#include "copy_loop.hpp"
#include "obfs4/proxy/socks5.hpp"
#include "obfs4/common/log.hpp"

#include <sys/socket.h>
#include <unistd.h>
#include <thread>

namespace obfs4::proxy {

ClientHandler::ClientHandler(transports::TransportRegistry& registry,
                              std::shared_ptr<Dialer> dialer)
    : registry_(registry), dialer_(std::move(dialer)) {}

void ClientHandler::handle(int client_fd, const std::string& target_host,
                            uint16_t target_port, const std::string& transport_name,
                            const std::string& pt_args_str) {
    // Parse PT args
    transports::Args args;
    if (!pt_args_str.empty()) {
        auto parsed = PtArgs::parse(pt_args_str);
        if (parsed) {
            for (const auto& [k, v] : parsed->args) {
                args[k] = v;
            }
        }
    }

    // Get transport factory
    auto factory_opt = registry_.client_factory(transport_name);
    if (!factory_opt) {
        common::log_error("unknown transport: " + transport_name);
        auto reply = make_connect_reply(SOCKS5_REPLY_GENERAL_FAILURE);
        ::send(client_fd, reply.data(), reply.size(), 0);
        ::close(client_fd);
        return;
    }

    // Connect to remote
    auto remote_fd = dialer_->dial(target_host, target_port);
    if (!remote_fd) {
        common::log_error("failed to connect to " +
                          common::elide_address(target_host + ":" + std::to_string(target_port)));
        auto reply = make_connect_reply(SOCKS5_REPLY_HOST_UNREACHABLE);
        ::send(client_fd, reply.data(), reply.size(), 0);
        ::close(client_fd);
        return;
    }

    // Send SOCKS5 success reply
    auto reply = make_connect_reply(SOCKS5_REPLY_SUCCEEDED);
    ::send(client_fd, reply.data(), reply.size(), 0);

    common::log_info("connected to " +
                     common::elide_address(target_host + ":" + std::to_string(target_port)) +
                     " via " + transport_name);

    // Start bidirectional relay
    // In a full implementation, the transport handshake would happen here
    // between client_fd and remote_fd, wrapping data through the transport.
    // For now, we do a direct relay (the transport wrapping happens at a higher level).
    auto loop = std::make_shared<CopyLoop>();
    loop->start(client_fd, *remote_fd);

    // Detach - the CopyLoop manages its own lifecycle
    std::thread([loop]() {
        loop->wait();
    }).detach();
}

}  // namespace obfs4::proxy
