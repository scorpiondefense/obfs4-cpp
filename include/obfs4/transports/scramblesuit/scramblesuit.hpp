#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include "obfs4/crypto/aes_ctr.hpp"
#include "obfs4/crypto/hash.hpp"
#include "obfs4/common/uniform_dh.hpp"
#include "obfs4/common/prob_dist.hpp"
#include "obfs4/transports/base.hpp"

namespace obfs4::transports::scramblesuit {

// ScrambleSuit protocol constants
constexpr size_t TICKET_LEN = 112;       // Session ticket length
constexpr size_t TICKET_KEY_LEN = 32;    // Master key for ticket encryption
constexpr size_t TICKET_LIFETIME_DAYS = 7;
constexpr size_t MARK_LEN = 32;          // HMAC-SHA256 mark
constexpr size_t MAX_PADDING = 1388;
constexpr size_t HEADER_LEN = 16 + 2 + 2 + 1;  // MAC(16) + total_len(2) + payload_len(2) + flags(1)

// HKDF info strings
constexpr std::string_view HKDF_INFO = "ScrambleSuit";

// KDF output length: tx_key(32) + tx_iv(16) + rx_key(32) + rx_iv(16) + tx_mac(32) + rx_mac(32)
constexpr size_t KDF_OUTPUT_LEN = 160;

// Flags
constexpr uint8_t FLAG_PAYLOAD = 1;
constexpr uint8_t FLAG_NEW_TICKET = 1 << 1;
constexpr uint8_t FLAG_PRNG_SEED = 1 << 2;

enum class ScrambleSuitState {
    Initial,
    AwaitingHandshakeResponse,
    Established,
    Failed,
};

// Session ticket for fast reconnect
struct SessionTicket {
    std::array<uint8_t, TICKET_LEN> data{};
    std::chrono::system_clock::time_point issued;

    bool is_valid() const;
};

// ScrambleSuit connection (client-only)
class ScrambleSuitConn {
public:
    ScrambleSuitConn() = default;

    static constexpr std::string_view transport_name() { return "scramblesuit"; }

    // Initialize as client
    void init(const std::array<uint8_t, 20>& server_id,
              const std::optional<SessionTicket>& ticket = std::nullopt);

    // Generate handshake message
    std::vector<uint8_t> generate_handshake();

    // Consume handshake response
    std::expected<size_t, TransportError> consume_handshake(std::span<const uint8_t> data);

    // Post-handshake data transfer
    std::vector<uint8_t> write(std::span<const uint8_t> data);
    std::expected<ReadResult, TransportError> read(std::span<const uint8_t> data);

    bool handshake_complete() const { return state_ == ScrambleSuitState::Established; }

private:
    ScrambleSuitState state_ = ScrambleSuitState::Initial;
    std::array<uint8_t, 20> server_id_{};

    // DH keypair for UniformDH handshake
    common::UniformDHKeypair keypair_{};

    // Session keys
    crypto::AesCtrStream send_cipher_;
    crypto::AesCtrStream recv_cipher_;
    std::array<uint8_t, 32> send_mac_key_{};
    std::array<uint8_t, 32> recv_mac_key_{};

    // Length distribution
    common::WeightedDist len_dist_;

    // Handshake buffer
    std::vector<uint8_t> handshake_buf_;

    // Optional session ticket
    std::optional<SessionTicket> ticket_;

    // Derive session keys from shared secret via HKDF
    void derive_keys(std::span<const uint8_t> shared_secret);

    // Compute per-packet MAC
    std::array<uint8_t, 16> compute_mac(std::span<const uint8_t> data,
                                         std::span<const uint8_t, 32> key) const;

    // Build a framed packet
    std::vector<uint8_t> frame_packet(std::span<const uint8_t> payload,
                                       uint8_t flags, size_t pad_len);
};

// Client factory (no server - client only)
class ScrambleSuitClientFactory {
public:
    static constexpr std::string_view transport_name() { return "scramblesuit"; }

    // Args: "password" (base32 shared secret)
    std::expected<void, TransportError> parse_args(const Args& args);

    ScrambleSuitConn create() const;

private:
    std::array<uint8_t, 20> server_id_{};
    std::optional<SessionTicket> ticket_;
};

}  // namespace obfs4::transports::scramblesuit
