#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include "proxy_dialer.hpp"
#include "obfs4/transports/registry.hpp"

namespace obfs4::proxy {

// Server mode handler: accepts raw TCP connections,
// unwraps transport, connects to ORPort, relays.
class ServerHandler {
public:
    ServerHandler(transports::TransportRegistry& registry,
                  const std::string& orport);

    // Start listening on the given address
    std::string start(const std::string& transport_name,
                      const std::string& bind_addr,
                      const transports::Args& args);

    void stop();
    bool running() const { return running_.load(); }

private:
    [[maybe_unused]] transports::TransportRegistry& registry_;
    std::string orport_;
    int listen_fd_ = -1;
    std::atomic<bool> running_{false};
    std::jthread accept_thread_;
    std::string transport_name_;

    void accept_loop(std::stop_token stoken);
    void handle_client(int client_fd);
};

}  // namespace obfs4::proxy
