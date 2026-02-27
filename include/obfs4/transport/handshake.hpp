#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>
#include "obfs4/crypto/elligator2.hpp"
#include "obfs4/crypto/hash.hpp"
#include "obfs4/common/ntor.hpp"
#include "obfs4/common/drbg.hpp"
#include "obfs4/common/replay_filter.hpp"

namespace obfs4::transport {

constexpr size_t MAX_HANDSHAKE_LENGTH = 8192;
constexpr size_t MARK_LENGTH = 16;
constexpr size_t MAC_LENGTH = 16;
constexpr size_t REPRESENTATIVE_LENGTH = 32;
constexpr size_t AUTH_LENGTH = 32;
constexpr size_t INLINE_SEED_FRAME_LENGTH = 18 + 3 + 24;  // 45

enum class HandshakeError {
    BufferOverflow,
    MarkNotFound,
    MacVerificationFailed,
    ReplayDetected,
    NtorFailed,
    KeyGenerationFailed,
    NeedMore,
    InternalError,
};

[[nodiscard]] std::string handshake_error_message(HandshakeError err);

// Epoch hour calculation
int64_t epoch_hour();
int64_t epoch_hour(std::chrono::system_clock::time_point tp);

struct HandshakeKeys {
    // 72 bytes each: key[32] + nonce_prefix[16] + drbg_seed[24]
    std::array<uint8_t, 72> encoder_key_material;
    std::array<uint8_t, 72> decoder_key_material;
};

// Client-side handshake
class ClientHandshake {
public:
    ClientHandshake(const crypto::PublicKey& id_pub, const common::NodeID& node_id);

    // Generate client hello message
    std::vector<uint8_t> generate();

    // Parse server response. Returns (consumed_bytes, drbg_seed) on success.
    std::expected<std::pair<size_t, common::DrbgSeed>, HandshakeError>
    parse_server_response(std::span<const uint8_t> data);

    const HandshakeKeys& keys() const { return keys_; }

private:
    crypto::PublicKey id_pub_;
    common::NodeID node_id_;
    crypto::Keypair ephemeral_;
    std::vector<uint8_t> pad_len_seed_;
    HandshakeKeys keys_{};

    std::vector<uint8_t> mac_key() const;
};

// Server-side handshake
class ServerHandshake {
public:
    ServerHandshake(const crypto::Keypair& id_keypair,
                    const common::NodeID& node_id,
                    common::ReplayFilter& replay_filter);

    // Feed data into the handshake. Returns consumed bytes on completion.
    std::expected<size_t, HandshakeError> consume(std::span<const uint8_t> data);

    // Generate server hello message (call after consume succeeds)
    std::expected<std::vector<uint8_t>, HandshakeError> generate();

    bool completed() const { return completed_; }
    const HandshakeKeys& keys() const { return keys_; }

private:
    crypto::Keypair id_keypair_;
    common::NodeID node_id_;
    common::ReplayFilter& replay_filter_;

    std::vector<uint8_t> buffer_;
    bool completed_ = false;

    crypto::PublicKey client_pub_{};
    crypto::Representative client_repr_{};
    crypto::Keypair server_ephemeral_{};
    common::KeySeed key_seed_{};
    common::Auth auth_{};
    HandshakeKeys keys_{};

    std::vector<uint8_t> mac_key() const;
    std::optional<size_t> find_mark() const;
    bool verify_epoch_mac(size_t mark_pos) const;
    void derive_keys();
};

}  // namespace obfs4::transport
