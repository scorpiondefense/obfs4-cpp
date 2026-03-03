#include "obfs4/transports/scramblesuit/ticket_store.hpp"
#include <fstream>
#include <sstream>

namespace obfs4::transports::scramblesuit {

std::expected<void, TransportError> TicketStore::load(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return {};  // No file is not an error, just no tickets
    }

    // Simple line-based format: server_id<tab>hex_ticket<tab>timestamp
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        auto tab1 = line.find('\t');
        auto tab2 = line.find('\t', tab1 + 1);
        if (tab1 == std::string::npos || tab2 == std::string::npos) continue;

        std::string server_id = line.substr(0, tab1);
        std::string hex_ticket = line.substr(tab1 + 1, tab2 - tab1 - 1);
        std::string timestamp_str = line.substr(tab2 + 1);

        SessionTicket ticket;
        // Parse hex ticket
        if (hex_ticket.size() != TICKET_LEN * 2) continue;
        for (size_t i = 0; i < TICKET_LEN; ++i) {
            auto byte_str = hex_ticket.substr(i * 2, 2);
            ticket.data[i] = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        }

        // Parse timestamp
        auto ts = std::chrono::seconds(std::stoll(timestamp_str));
        ticket.issued = std::chrono::system_clock::time_point(ts);

        if (ticket.is_valid()) {
            tickets_[server_id] = ticket;
        }
    }

    return {};
}

std::expected<void, TransportError> TicketStore::save(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) {
        return std::unexpected(TransportError::InternalError);
    }

    for (const auto& [server_id, ticket] : tickets_) {
        if (!ticket.is_valid()) continue;

        file << server_id << "\t";

        // Hex encode ticket
        static constexpr char hex_chars[] = "0123456789abcdef";
        for (auto b : ticket.data) {
            file << hex_chars[b >> 4] << hex_chars[b & 0x0F];
        }

        auto ts = std::chrono::duration_cast<std::chrono::seconds>(
            ticket.issued.time_since_epoch()).count();
        file << "\t" << ts << "\n";
    }

    return {};
}

std::optional<SessionTicket> TicketStore::get(const std::string& server_id) const {
    auto it = tickets_.find(server_id);
    if (it == tickets_.end()) return std::nullopt;
    if (!it->second.is_valid()) return std::nullopt;
    return it->second;
}

void TicketStore::put(const std::string& server_id, const SessionTicket& ticket) {
    tickets_[server_id] = ticket;
}

void TicketStore::prune() {
    for (auto it = tickets_.begin(); it != tickets_.end();) {
        if (!it->second.is_valid()) {
            it = tickets_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace obfs4::transports::scramblesuit
