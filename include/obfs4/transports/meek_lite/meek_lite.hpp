#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <expected>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include "obfs4/transports/base.hpp"

#ifdef OBFS4_ENABLE_MEEK

namespace obfs4::transports::meek_lite {

// meek_lite protocol constants
constexpr size_t MAX_PAYLOAD = 65536;
constexpr size_t SESSION_ID_LEN = 32;

// Polling parameters
constexpr auto INITIAL_POLL_DELAY = std::chrono::milliseconds(100);
constexpr double POLL_DELAY_MULTIPLIER = 1.5;
constexpr auto MAX_POLL_DELAY = std::chrono::seconds(5);

// meek_lite connection (client-only)
// Tunnels data over HTTP POST requests, optionally with domain fronting.
class MeekLiteConn {
public:
    MeekLiteConn() = default;

    static constexpr std::string_view transport_name() { return "meek_lite"; }

    // Initialize with URL and optional front domain for domain fronting
    void init(const std::string& url, const std::string& front = "");

    // Post data to the meek reflector. Returns response body.
    std::expected<std::vector<uint8_t>, TransportError>
    round_trip(std::span<const uint8_t> data);

    // Write data (queues for next poll)
    std::vector<uint8_t> write(std::span<const uint8_t> data);

    // Read data (returns buffered response data)
    std::expected<ReadResult, TransportError> read(std::span<const uint8_t> data);

    const std::string& session_id() const { return session_id_; }

private:
    std::string url_;
    std::string front_;  // Domain fronting: Host header value
    std::string session_id_;

    // Pending data to send
    std::vector<uint8_t> send_buf_;

    // Received data buffer
    std::vector<uint8_t> recv_buf_;

    std::mutex mutex_;

    // Generate session ID (hex-encoded half of SHA-256 of random bytes)
    void generate_session_id();
};

// Client factory
class MeekLiteClientFactory {
public:
    static constexpr std::string_view transport_name() { return "meek_lite"; }

    // Args: "url" (required), "front" (optional domain fronting)
    std::expected<void, TransportError> parse_args(const Args& args);

    MeekLiteConn create() const;

private:
    std::string url_;
    std::string front_;
};

}  // namespace obfs4::transports::meek_lite

#endif  // OBFS4_ENABLE_MEEK
