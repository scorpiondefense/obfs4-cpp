#pragma once

#include <memory>
#include <string>
#include "proxy_dialer.hpp"
#include "obfs4/transports/registry.hpp"

namespace obfs4::proxy {

// Client mode handler: receives SOCKS5 connections,
// establishes transport connection to remote, then relays.
class ClientHandler {
public:
    ClientHandler(transports::TransportRegistry& registry,
                  std::shared_ptr<Dialer> dialer);

    // Handle an accepted SOCKS5 connection.
    // Called from SOCKS5 server accept callback.
    // Takes ownership of client_fd.
    void handle(int client_fd, const std::string& target_host,
                uint16_t target_port, const std::string& transport_name,
                const std::string& pt_args_str);

private:
    transports::TransportRegistry& registry_;
    std::shared_ptr<Dialer> dialer_;
};

}  // namespace obfs4::proxy
