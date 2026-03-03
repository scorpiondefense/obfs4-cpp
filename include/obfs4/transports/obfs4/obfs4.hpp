#pragma once

#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include "obfs4/transport/conn.hpp"
#include "obfs4/transport/handshake.hpp"
#include "obfs4/transport/state.hpp"
#include "obfs4/transports/base.hpp"

namespace obfs4::transports::obfs4_transport {

// Thin wrapper around existing transport::Obfs4Conn to conform to
// the TransportConn concept defined in transports/base.hpp.
class Obfs4TransportConn {
public:
    Obfs4TransportConn() = default;

    static constexpr std::string_view transport_name() { return "obfs4"; }

    // Initialize from handshake keys
    void init(const transport::HandshakeKeys& keys,
              transport::IATMode iat_mode = transport::IATMode::None,
              bool is_server = false);

    std::vector<uint8_t> write(std::span<const uint8_t> data);
    std::expected<ReadResult, TransportError> read(std::span<const uint8_t> data);

private:
    transport::Obfs4Conn conn_;
    bool is_server_ = false;
};

// Client factory for obfs4
class Obfs4ClientFactory {
public:
    static constexpr std::string_view transport_name() { return "obfs4"; }

    // Required args: "cert" (base64 node_id+pubkey), optional "iat-mode"
    std::expected<void, TransportError> parse_args(const Args& args);

    // Get parsed values
    const common::NodeID& node_id() const { return node_id_; }
    const crypto::PublicKey& public_key() const { return public_key_; }
    transport::IATMode iat_mode() const { return iat_mode_; }

private:
    common::NodeID node_id_{};
    crypto::PublicKey public_key_{};
    transport::IATMode iat_mode_ = transport::IATMode::None;
};

// Server factory for obfs4
class Obfs4ServerFactory {
public:
    static constexpr std::string_view transport_name() { return "obfs4"; }

    // Required: state directory path with node_id, identity keys, drbg_seed
    std::expected<void, TransportError> parse_args(const Args& args);

    const transport::ServerState& state() const { return state_; }

private:
    transport::ServerState state_{};
};

}  // namespace obfs4::transports::obfs4_transport
