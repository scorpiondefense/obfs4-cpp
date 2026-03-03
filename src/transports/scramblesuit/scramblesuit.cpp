#include "obfs4/transports/scramblesuit/scramblesuit.hpp"
#include "obfs4/common/csrand.hpp"
#include <cstring>

namespace obfs4::transports::scramblesuit {

bool SessionTicket::is_valid() const {
    auto now = std::chrono::system_clock::now();
    auto age = std::chrono::duration_cast<std::chrono::hours>(now - issued);
    return age < std::chrono::hours(TICKET_LIFETIME_DAYS * 24);
}

void ScrambleSuitConn::init(const std::array<uint8_t, 20>& server_id,
                             const std::optional<SessionTicket>& ticket) {
    server_id_ = server_id;
    ticket_ = ticket;

    // Generate DH keypair for handshake
    auto kp = common::uniform_dh_keygen();
    keypair_ = kp.value();

    state_ = ScrambleSuitState::AwaitingHandshakeResponse;
}

void ScrambleSuitConn::derive_keys(std::span<const uint8_t> shared_secret) {
    // HKDF-SHA256: salt = empty, ikm = shared_secret, info = "ScrambleSuit"
    std::vector<uint8_t> salt;  // empty
    std::vector<uint8_t> info(HKDF_INFO.begin(), HKDF_INFO.end());

    auto okm = crypto::hkdf_sha256(salt, shared_secret, info, KDF_OUTPUT_LEN).value();

    // Split KDF output:
    // tx_key(32) + tx_iv(16) + rx_key(32) + rx_iv(16) + tx_mac(32) + rx_mac(32) = 160
    size_t offset = 0;

    std::array<uint8_t, 32> tx_key;
    std::memcpy(tx_key.data(), okm.data() + offset, 32);
    offset += 32;

    std::array<uint8_t, 16> tx_iv;
    std::memcpy(tx_iv.data(), okm.data() + offset, 16);
    offset += 16;

    std::array<uint8_t, 32> rx_key;
    std::memcpy(rx_key.data(), okm.data() + offset, 32);
    offset += 32;

    std::array<uint8_t, 16> rx_iv;
    std::memcpy(rx_iv.data(), okm.data() + offset, 16);
    offset += 16;

    std::memcpy(send_mac_key_.data(), okm.data() + offset, 32);
    offset += 32;

    std::memcpy(recv_mac_key_.data(), okm.data() + offset, 32);

    // Initialize AES-256-CTR ciphers
    (void)send_cipher_.init(tx_key, tx_iv);
    (void)recv_cipher_.init(rx_key, rx_iv);
}

std::array<uint8_t, 16> ScrambleSuitConn::compute_mac(
    std::span<const uint8_t> data,
    std::span<const uint8_t, 32> key) const {
    auto full_mac = crypto::hmac_sha256(key, data).value();
    std::array<uint8_t, 16> truncated;
    std::memcpy(truncated.data(), full_mac.data(), 16);
    return truncated;
}

std::vector<uint8_t> ScrambleSuitConn::frame_packet(
    std::span<const uint8_t> payload,
    uint8_t flags, size_t pad_len) {
    // Frame: MAC(16) || E(total_len(2) + payload_len(2) + flags(1) + payload + padding)
    uint16_t payload_len = static_cast<uint16_t>(payload.size());
    uint16_t total_len = static_cast<uint16_t>(5 + payload.size() + pad_len);  // header + payload + padding

    // Build cleartext body
    std::vector<uint8_t> body;
    body.reserve(total_len);

    // total_len (big-endian)
    body.push_back(static_cast<uint8_t>((total_len >> 8) & 0xFF));
    body.push_back(static_cast<uint8_t>(total_len & 0xFF));

    // payload_len (big-endian)
    body.push_back(static_cast<uint8_t>((payload_len >> 8) & 0xFF));
    body.push_back(static_cast<uint8_t>(payload_len & 0xFF));

    // flags
    body.push_back(flags);

    // payload
    body.insert(body.end(), payload.begin(), payload.end());

    // padding
    if (pad_len > 0) {
        auto padding = common::random_bytes(pad_len);
        body.insert(body.end(), padding.begin(), padding.end());
    }

    // Encrypt body
    (void)send_cipher_.process(std::span<uint8_t>(body));

    // Compute MAC over encrypted body
    auto mac = compute_mac(body, send_mac_key_);

    // Final frame: MAC || encrypted_body
    std::vector<uint8_t> frame;
    frame.reserve(16 + body.size());
    frame.insert(frame.end(), mac.begin(), mac.end());
    frame.insert(frame.end(), body.begin(), body.end());

    return frame;
}

std::vector<uint8_t> ScrambleSuitConn::generate_handshake() {
    // UniformDH handshake: PUBKEY(192) || MARK(32) || PADDING(random)
    // Mark = HMAC-SHA256(server_id, pubkey)

    auto mark = crypto::hmac_sha256(
        std::span<const uint8_t>(server_id_.data(), server_id_.size()),
        std::span<const uint8_t>(keypair_.public_key.data(), keypair_.public_key.size()))
        .value();

    uint32_t pad_len = static_cast<uint32_t>(common::random_intn(MAX_PADDING + 1));

    std::vector<uint8_t> msg;
    msg.reserve(common::UNIFORM_DH_KEY_LEN + MARK_LEN + pad_len);

    // Public key
    msg.insert(msg.end(), keypair_.public_key.begin(), keypair_.public_key.end());

    // Mark
    msg.insert(msg.end(), mark.begin(), mark.end());

    // Random padding
    if (pad_len > 0) {
        auto padding = common::random_bytes(pad_len);
        msg.insert(msg.end(), padding.begin(), padding.end());
    }

    return msg;
}

std::expected<size_t, TransportError>
ScrambleSuitConn::consume_handshake(std::span<const uint8_t> data) {
    handshake_buf_.insert(handshake_buf_.end(), data.begin(), data.end());

    // Expect server's response: PUBKEY(192) || MARK(32) || padding
    if (handshake_buf_.size() < common::UNIFORM_DH_KEY_LEN + MARK_LEN) {
        return 0;  // Need more data
    }

    // Extract server's public key
    std::array<uint8_t, common::UNIFORM_DH_KEY_LEN> server_pubkey;
    std::memcpy(server_pubkey.data(), handshake_buf_.data(), common::UNIFORM_DH_KEY_LEN);

    // Verify mark
    auto expected_mark = crypto::hmac_sha256(
        std::span<const uint8_t>(server_id_.data(), server_id_.size()),
        std::span<const uint8_t>(server_pubkey.data(), server_pubkey.size()))
        .value();

    if (!crypto::constant_time_compare(
            std::span<const uint8_t>(handshake_buf_.data() + common::UNIFORM_DH_KEY_LEN, MARK_LEN),
            std::span<const uint8_t>(expected_mark.data(), MARK_LEN))) {
        state_ = ScrambleSuitState::Failed;
        return std::unexpected(TransportError::HandshakeFailed);
    }

    // Compute shared secret
    auto secret = common::uniform_dh_shared_secret(keypair_.private_key, server_pubkey);
    if (!secret) {
        state_ = ScrambleSuitState::Failed;
        return std::unexpected(TransportError::HandshakeFailed);
    }

    // Derive session keys
    derive_keys(*secret);

    size_t consumed = common::UNIFORM_DH_KEY_LEN + MARK_LEN;
    state_ = ScrambleSuitState::Established;

    // Keep excess data
    if (handshake_buf_.size() > consumed) {
        std::vector<uint8_t> remaining(handshake_buf_.begin() + consumed,
                                        handshake_buf_.end());
        handshake_buf_ = std::move(remaining);
    } else {
        handshake_buf_.clear();
    }

    return consumed;
}

std::vector<uint8_t> ScrambleSuitConn::write(std::span<const uint8_t> data) {
    // Determine padding from length distribution
    size_t pad_len = 0;
    if (len_dist_.initialized()) {
        int target = len_dist_.sample();
        if (target > static_cast<int>(data.size() + HEADER_LEN)) {
            pad_len = target - data.size() - HEADER_LEN;
        }
    }

    return frame_packet(data, FLAG_PAYLOAD, pad_len);
}

std::expected<ReadResult, TransportError>
ScrambleSuitConn::read(std::span<const uint8_t> data) {
    ReadResult result;

    std::vector<uint8_t> combined;
    if (!handshake_buf_.empty()) {
        combined.insert(combined.end(), handshake_buf_.begin(), handshake_buf_.end());
        combined.insert(combined.end(), data.begin(), data.end());
        handshake_buf_.clear();
        data = combined;
    }

    if (data.size() < 16 + 4) {
        result.consumed = 0;
        return result;
    }

    size_t offset = 0;
    while (offset + 16 + 4 <= data.size()) {
        // Read MAC (16 bytes)
        // We need at least 5 bytes of body (total_len + payload_len + flags)
        if (offset + 16 + 5 > data.size()) break;

        // Copy and decrypt enough to get total_len
        std::vector<uint8_t> body_copy(data.begin() + offset + 16,
                                        data.end());
        (void)recv_cipher_.process(std::span<uint8_t>(body_copy));

        uint16_t total_len = (static_cast<uint16_t>(body_copy[0]) << 8) |
                             static_cast<uint16_t>(body_copy[1]);

        if (offset + 16 + total_len > data.size()) {
            // Not enough data for full frame, need to buffer
            // Note: we've already advanced the cipher, so in a production
            // implementation we'd need to handle this differently
            break;
        }

        uint16_t payload_len = (static_cast<uint16_t>(body_copy[2]) << 8) |
                               static_cast<uint16_t>(body_copy[3]);
        uint8_t flags = body_copy[4];

        if (payload_len > total_len - 5) {
            return std::unexpected(TransportError::DecodeFailed);
        }

        // Extract payload
        if (flags & FLAG_PAYLOAD) {
            result.plaintext.insert(result.plaintext.end(),
                                    body_copy.begin() + 5,
                                    body_copy.begin() + 5 + payload_len);
        }

        offset += 16 + total_len;
    }

    result.consumed = offset;
    return result;
}

// Factory
std::expected<void, TransportError>
ScrambleSuitClientFactory::parse_args(const Args& args) {
    auto pw_it = args.find("password");
    if (pw_it == args.end()) {
        return std::unexpected(TransportError::InvalidArgs);
    }

    // Derive server_id from password (SHA-256 truncated to 20 bytes)
    std::vector<uint8_t> pw_bytes(pw_it->second.begin(), pw_it->second.end());
    auto hash = crypto::sha256(pw_bytes).value();
    std::memcpy(server_id_.data(), hash.data(), 20);

    return {};
}

ScrambleSuitConn ScrambleSuitClientFactory::create() const {
    ScrambleSuitConn conn;
    conn.init(server_id_, ticket_);
    return conn;
}

}  // namespace obfs4::transports::scramblesuit
