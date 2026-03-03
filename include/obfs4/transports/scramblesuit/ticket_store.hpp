#pragma once

#include <chrono>
#include <expected>
#include <optional>
#include <string>
#include <unordered_map>
#include "obfs4/transports/scramblesuit/scramblesuit.hpp"
#include "obfs4/transports/base.hpp"

namespace obfs4::transports::scramblesuit {

// Persistent session ticket storage (JSON file).
// Tickets enable fast reconnect by skipping the DH handshake.
class TicketStore {
public:
    TicketStore() = default;

    // Load tickets from file
    std::expected<void, TransportError> load(const std::string& path);

    // Save tickets to file
    std::expected<void, TransportError> save(const std::string& path) const;

    // Get a valid ticket for a server
    std::optional<SessionTicket> get(const std::string& server_id) const;

    // Store a new ticket for a server
    void put(const std::string& server_id, const SessionTicket& ticket);

    // Remove expired tickets
    void prune();

private:
    std::unordered_map<std::string, SessionTicket> tickets_;
};

}  // namespace obfs4::transports::scramblesuit
