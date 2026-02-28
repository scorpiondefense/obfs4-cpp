#include "obfs4/transport/handshake.hpp"
#include "obfs4/transport/framing.hpp"
#include "obfs4/common/csrand.hpp"
#include <algorithm>
#include <cstring>
#include <string>

namespace obfs4::transport {

// --- Utility ---

int64_t epoch_hour() {
    return epoch_hour(std::chrono::system_clock::now());
}

int64_t epoch_hour(std::chrono::system_clock::time_point tp) {
    auto secs = std::chrono::duration_cast<std::chrono::seconds>(
        tp.time_since_epoch()).count();
    return secs / 3600;
}

std::string handshake_error_message(HandshakeError err) {
    switch (err) {
        case HandshakeError::BufferOverflow: return "Handshake buffer overflow";
        case HandshakeError::MarkNotFound: return "HMAC mark not found";
        case HandshakeError::MacVerificationFailed: return "Epoch-hour MAC verification failed";
        case HandshakeError::ReplayDetected: return "Replay detected";
        case HandshakeError::NtorFailed: return "ntor handshake failed";
        case HandshakeError::KeyGenerationFailed: return "Key generation failed";
        case HandshakeError::NeedMore: return "Need more data";
        case HandshakeError::InternalError: return "Internal error";
        default: return "Unknown handshake error";
    }
}

// --- ClientHandshake ---

ClientHandshake::ClientHandshake(const crypto::PublicKey& id_pub,
                                  const common::NodeID& node_id)
    : id_pub_(id_pub), node_id_(node_id) {
    ephemeral_ = crypto::elligator2::generate_representable_keypair();
}

std::vector<uint8_t> ClientHandshake::mac_key() const {
    std::vector<uint8_t> key;
    key.reserve(32 + 20);
    key.insert(key.end(), id_pub_.begin(), id_pub_.end());
    key.insert(key.end(), node_id_.begin(), node_id_.end());
    return key;
}

std::vector<uint8_t> ClientHandshake::generate() {
    auto key = mac_key();
    auto& repr = *ephemeral_.representative;

    // Random padding: 0 to MAX_HANDSHAKE_LENGTH - (32 + 16 + 16)
    size_t max_pad = MAX_HANDSHAKE_LENGTH - REPRESENTATIVE_LENGTH - MARK_LENGTH - MAC_LENGTH;
    auto pad_rng = common::random_bytes(2);
    size_t pad_len = (static_cast<uint16_t>(pad_rng[0]) |
                     (static_cast<uint16_t>(pad_rng[1]) << 8)) % (max_pad + 1);
    auto padding = common::random_bytes(pad_len);

    std::vector<uint8_t> hello;
    hello.reserve(REPRESENTATIVE_LENGTH + pad_len + MARK_LENGTH + MAC_LENGTH);

    // repr[32]
    hello.insert(hello.end(), repr.begin(), repr.end());

    // padding
    hello.insert(hello.end(), padding.begin(), padding.end());

    // mark = HMAC-SHA256-128(key, repr)
    auto mark_hmac = crypto::hmac_sha256(key, repr);
    if (mark_hmac) {
        hello.insert(hello.end(), mark_hmac->begin(), mark_hmac->begin() + MARK_LENGTH);
    }

    // mac = HMAC-SHA256-128(key, repr || padding || mark || epoch_hour_string)
    auto hour_str = std::to_string(epoch_hour());
    std::vector<uint8_t> mac_input(hello.begin(), hello.end());
    mac_input.insert(mac_input.end(),
                     reinterpret_cast<const uint8_t*>(hour_str.data()),
                     reinterpret_cast<const uint8_t*>(hour_str.data() + hour_str.size()));

    auto epoch_mac = crypto::hmac_sha256(key, mac_input);
    if (epoch_mac) {
        hello.insert(hello.end(), epoch_mac->begin(), epoch_mac->begin() + MAC_LENGTH);
    }

    return hello;
}

std::expected<std::pair<size_t, common::DrbgSeed>, HandshakeError>
ClientHandshake::parse_server_response(std::span<const uint8_t> data) {
    // Server response: repr[32] || auth[32] || padding || mark[16] || mac[16]
    // Minimum: 32 + 32 + 0 + 16 + 16 = 96

    if (data.size() < REPRESENTATIVE_LENGTH + AUTH_LENGTH + MARK_LENGTH + MAC_LENGTH) {
        return std::unexpected(HandshakeError::NeedMore);
    }

    // Extract server representative and auth
    crypto::Representative server_repr;
    std::memcpy(server_repr.data(), data.data(), REPRESENTATIVE_LENGTH);

    common::Auth server_auth;
    std::memcpy(server_auth.data(), data.data() + REPRESENTATIVE_LENGTH, AUTH_LENGTH);

    // Recover server public key from representative
    auto server_pub = crypto::elligator2::representative_to_public_key(server_repr);

    // Find mark
    auto key = mac_key();
    auto mark_hmac = crypto::hmac_sha256(key, server_repr);
    if (!mark_hmac) {
        return std::unexpected(HandshakeError::InternalError);
    }

    // Search for mark after repr+auth
    size_t search_start = REPRESENTATIVE_LENGTH + AUTH_LENGTH;
    std::optional<size_t> mark_pos;
    for (size_t pos = search_start; pos + MARK_LENGTH <= data.size(); ++pos) {
        bool match = true;
        for (size_t j = 0; j < MARK_LENGTH; ++j) {
            if (data[pos + j] != (*mark_hmac)[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            mark_pos = pos;
            break;
        }
    }

    if (!mark_pos) {
        if (data.size() >= MAX_HANDSHAKE_LENGTH) {
            return std::unexpected(HandshakeError::MarkNotFound);
        }
        return std::unexpected(HandshakeError::NeedMore);
    }

    size_t mac_start = *mark_pos + MARK_LENGTH;
    if (mac_start + MAC_LENGTH > data.size()) {
        return std::unexpected(HandshakeError::NeedMore);
    }

    // Verify epoch-hour MAC
    bool mac_valid = false;
    auto current_hour = epoch_hour();
    for (int64_t offset = -1; offset <= 1; ++offset) {
        auto hour = current_hour + offset;
        auto hour_str = std::to_string(hour);

        std::vector<uint8_t> mac_input(data.begin(), data.begin() + mac_start);
        mac_input.insert(mac_input.end(),
                         reinterpret_cast<const uint8_t*>(hour_str.data()),
                         reinterpret_cast<const uint8_t*>(hour_str.data() + hour_str.size()));

        auto expected_mac = crypto::hmac_sha256(key, mac_input);
        if (!expected_mac) continue;

        if (crypto::constant_time_compare(
                std::span<const uint8_t>(data.data() + mac_start, MAC_LENGTH),
                std::span<const uint8_t>(expected_mac->data(), MAC_LENGTH))) {
            mac_valid = true;
            break;
        }
    }

    if (!mac_valid) {
        return std::unexpected(HandshakeError::MacVerificationFailed);
    }

    // Complete ntor handshake
    auto ntor_result = common::client_handshake(ephemeral_, server_pub, id_pub_, node_id_);
    if (!ntor_result) {
        return std::unexpected(HandshakeError::NtorFailed);
    }

    auto& [key_seed, auth] = *ntor_result;

    // Verify server auth matches
    if (!crypto::constant_time_compare(auth, server_auth)) {
        return std::unexpected(HandshakeError::NtorFailed);
    }

    // Derive session keys
    auto okm = common::kdf(key_seed, KEY_MATERIAL_LENGTH * 2);  // 144 bytes
    if (okm.size() < KEY_MATERIAL_LENGTH * 2) {
        return std::unexpected(HandshakeError::InternalError);
    }

    // Client: encoder=okm[0:72], decoder=okm[72:144]
    std::memcpy(keys_.encoder_key_material.data(), okm.data(), 72);
    std::memcpy(keys_.decoder_key_material.data(), okm.data() + 72, 72);

    size_t consumed = mac_start + MAC_LENGTH;

    // Extract DRBG seed from inline seed frame if present
    common::DrbgSeed seed{};

    return std::make_pair(consumed, seed);
}

// --- ServerHandshake ---

ServerHandshake::ServerHandshake(const crypto::Keypair& id_keypair,
                                  const common::NodeID& node_id,
                                  common::ReplayFilter& replay_filter)
    : id_keypair_(id_keypair), node_id_(node_id), replay_filter_(replay_filter) {}

std::vector<uint8_t> ServerHandshake::mac_key() const {
    std::vector<uint8_t> key;
    key.reserve(32 + 20);
    key.insert(key.end(), id_keypair_.public_key.begin(), id_keypair_.public_key.end());
    key.insert(key.end(), node_id_.begin(), node_id_.end());
    return key;
}

std::optional<size_t> ServerHandshake::find_mark() const {
    if (buffer_.size() < REPRESENTATIVE_LENGTH + MARK_LENGTH) {
        return std::nullopt;
    }

    auto key = mac_key();
    auto hmac_result = crypto::hmac_sha256(
        key,
        std::span<const uint8_t>(buffer_.data(), REPRESENTATIVE_LENGTH));

    if (!hmac_result) return std::nullopt;

    for (size_t pos = REPRESENTATIVE_LENGTH; pos + MARK_LENGTH <= buffer_.size(); ++pos) {
        bool match = true;
        for (size_t j = 0; j < MARK_LENGTH; ++j) {
            if (buffer_[pos + j] != (*hmac_result)[j]) {
                match = false;
                break;
            }
        }
        if (match) return pos;
    }

    return std::nullopt;
}

bool ServerHandshake::verify_epoch_mac(size_t mark_pos) const {
    size_t mac_start = mark_pos + MARK_LENGTH;
    if (buffer_.size() < mac_start + MAC_LENGTH) return false;

    auto key = mac_key();
    auto current_hour = epoch_hour();

    for (int64_t offset = -1; offset <= 1; ++offset) {
        auto hour = current_hour + offset;
        auto hour_str = std::to_string(hour);

        std::vector<uint8_t> mac_input(buffer_.begin(),
                                        buffer_.begin() + mark_pos + MARK_LENGTH);
        mac_input.insert(mac_input.end(),
                         reinterpret_cast<const uint8_t*>(hour_str.data()),
                         reinterpret_cast<const uint8_t*>(hour_str.data() + hour_str.size()));

        auto expected_mac = crypto::hmac_sha256(key, mac_input);
        if (!expected_mac) continue;

        if (crypto::constant_time_compare(
                std::span<const uint8_t>(buffer_.data() + mac_start, MAC_LENGTH),
                std::span<const uint8_t>(expected_mac->data(), MAC_LENGTH))) {
            return true;
        }
    }

    return false;
}

void ServerHandshake::derive_keys() {
    auto ntor_result = common::server_handshake(
        client_pub_, server_ephemeral_, id_keypair_, node_id_);

    if (!ntor_result) return;

    auto& [ks, auth] = *ntor_result;
    key_seed_ = ks;
    auth_ = auth;

    auto okm = common::kdf(key_seed_, KEY_MATERIAL_LENGTH * 2);
    if (okm.size() < KEY_MATERIAL_LENGTH * 2) return;

    // Server: encoder=okm[72:144], decoder=okm[0:72] (SWAPPED vs client)
    std::memcpy(keys_.decoder_key_material.data(), okm.data(), 72);
    std::memcpy(keys_.encoder_key_material.data(), okm.data() + 72, 72);
}

std::expected<size_t, HandshakeError>
ServerHandshake::consume(std::span<const uint8_t> data) {
    if (completed_) return 0;

    size_t space = MAX_HANDSHAKE_LENGTH - buffer_.size();
    size_t to_copy = std::min(data.size(), space);
    buffer_.insert(buffer_.end(), data.begin(), data.begin() + to_copy);

    if (buffer_.size() >= MAX_HANDSHAKE_LENGTH) {
        auto mark_pos = find_mark();
        if (!mark_pos) {
            return std::unexpected(HandshakeError::BufferOverflow);
        }
    }

    if (buffer_.size() < REPRESENTATIVE_LENGTH + MARK_LENGTH) {
        return std::unexpected(HandshakeError::NeedMore);
    }

    auto mark_pos = find_mark();
    if (!mark_pos) {
        return std::unexpected(HandshakeError::NeedMore);
    }

    size_t mac_end = *mark_pos + MARK_LENGTH + MAC_LENGTH;
    if (buffer_.size() < mac_end) {
        return std::unexpected(HandshakeError::NeedMore);
    }

    if (!verify_epoch_mac(*mark_pos)) {
        return std::unexpected(HandshakeError::MacVerificationFailed);
    }

    // Extract representative
    std::memcpy(client_repr_.data(), buffer_.data(), REPRESENTATIVE_LENGTH);

    // Check replay
    if (replay_filter_.test_and_set(client_repr_)) {
        return std::unexpected(HandshakeError::ReplayDetected);
    }

    // Recover client public key
    client_pub_ = crypto::elligator2::representative_to_public_key(client_repr_);

    // Generate server ephemeral keypair
    server_ephemeral_ = crypto::elligator2::generate_representable_keypair();

    // Derive keys
    derive_keys();

    completed_ = true;
    return mac_end;
}

std::expected<std::vector<uint8_t>, HandshakeError>
ServerHandshake::generate() {
    if (!completed_) {
        return std::unexpected(HandshakeError::InternalError);
    }

    auto key = mac_key();
    auto& repr = *server_ephemeral_.representative;

    std::vector<uint8_t> hello;

    // repr[32]
    hello.insert(hello.end(), repr.begin(), repr.end());

    // auth[32]
    hello.insert(hello.end(), auth_.begin(), auth_.end());

    // Random padding
    auto pad_rng = common::random_bytes(2);
    size_t pad_len = (static_cast<uint16_t>(pad_rng[0]) |
                     (static_cast<uint16_t>(pad_rng[1]) << 8)) % 512;
    auto padding = common::random_bytes(pad_len);
    hello.insert(hello.end(), padding.begin(), padding.end());

    // mark = HMAC-SHA256-128(key, repr)
    auto mark_hmac = crypto::hmac_sha256(key, repr);
    if (!mark_hmac) {
        return std::unexpected(HandshakeError::InternalError);
    }
    hello.insert(hello.end(), mark_hmac->begin(), mark_hmac->begin() + MARK_LENGTH);

    // mac = HMAC-SHA256-128(key, hello || epoch_hour_string)
    auto hour_str = std::to_string(epoch_hour());
    std::vector<uint8_t> mac_input(hello.begin(), hello.end());
    mac_input.insert(mac_input.end(),
                     reinterpret_cast<const uint8_t*>(hour_str.data()),
                     reinterpret_cast<const uint8_t*>(hour_str.data() + hour_str.size()));

    auto epoch_mac = crypto::hmac_sha256(key, mac_input);
    if (!epoch_mac) {
        return std::unexpected(HandshakeError::InternalError);
    }
    hello.insert(hello.end(), epoch_mac->begin(), epoch_mac->begin() + MAC_LENGTH);

    return hello;
}

}  // namespace obfs4::transport
