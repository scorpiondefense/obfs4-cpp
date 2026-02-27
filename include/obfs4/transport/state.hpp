#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include "obfs4/common/ntor.hpp"
#include "obfs4/common/drbg.hpp"
#include "obfs4/transport/conn.hpp"

namespace obfs4::transport {

enum class StateError {
    InvalidCert,
    InvalidStateFile,
    IOError,
};

[[nodiscard]] std::string state_error_message(StateError err);

// Server state: identity keys + DRBG seed + IAT mode
struct ServerState {
    common::NodeID node_id;
    crypto::Keypair identity;
    common::DrbgSeed drbg_seed;
    IATMode iat_mode = IATMode::None;
};

// Cert = base64url_nopad(node_id[20] || public_key[32])
std::string encode_cert(const common::NodeID& node_id, const crypto::PublicKey& pub);
std::expected<std::pair<common::NodeID, crypto::PublicKey>, StateError>
decode_cert(const std::string& cert);

// State file serialization (JSON)
std::expected<ServerState, StateError> load_state(const std::string& path);
std::expected<void, StateError> save_state(const std::string& path, const ServerState& state);

}  // namespace obfs4::transport
