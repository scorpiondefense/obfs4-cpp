#include "obfs4/transports/obfs3/obfs3.hpp"
#include "obfs4/common/csrand.hpp"
#include "obfs4/crypto/hash.hpp"
#include <cstring>

namespace obfs4::transports::obfs3 {

void Obfs3Conn::derive_keys() {
    // Stream keys: HMAC-SHA256(shared_secret, kdf_string)
    // Initiator send key = HMAC-SHA256(shared_secret, "Initiator obfuscated data")
    // Responder send key = HMAC-SHA256(shared_secret, "Responder obfuscated data")

    std::span<const uint8_t> secret(shared_secret_.data(), shared_secret_.size());

    // Initiator stream key
    std::vector<uint8_t> init_kdf(INITIATOR_KDF_STRING.begin(), INITIATOR_KDF_STRING.end());
    auto init_key = crypto::hmac_sha256(secret, init_kdf).value();

    // Responder stream key
    std::vector<uint8_t> resp_kdf(RESPONDER_KDF_STRING.begin(), RESPONDER_KDF_STRING.end());
    auto resp_key = crypto::hmac_sha256(secret, resp_kdf).value();

    // Magic values for handshake verification
    std::vector<uint8_t> init_magic_data(INITIATOR_MAGIC_STRING.begin(), INITIATOR_MAGIC_STRING.end());
    initiator_magic_ = crypto::hmac_sha256(secret, init_magic_data).value();

    std::vector<uint8_t> resp_magic_data(RESPONDER_MAGIC_STRING.begin(), RESPONDER_MAGIC_STRING.end());
    responder_magic_ = crypto::hmac_sha256(secret, resp_magic_data).value();

    // Setup ciphers
    std::array<uint8_t, 16> iv{};  // zero IV

    if (is_initiator_) {
        std::array<uint8_t, 16> send_key, recv_key;
        std::memcpy(send_key.data(), init_key.data(), 16);
        std::memcpy(recv_key.data(), resp_key.data(), 16);
        (void)send_cipher_.init(send_key, iv);
        (void)recv_cipher_.init(recv_key, iv);
    } else {
        std::array<uint8_t, 16> send_key, recv_key;
        std::memcpy(send_key.data(), resp_key.data(), 16);
        std::memcpy(recv_key.data(), init_key.data(), 16);
        (void)send_cipher_.init(send_key, iv);
        (void)recv_cipher_.init(recv_key, iv);
    }
}

std::optional<size_t> Obfs3Conn::find_magic() const {
    // Scan for the peer's magic value in the handshake buffer
    // (after the public key)
    auto& target_magic = is_initiator_ ? responder_magic_ : initiator_magic_;

    if (handshake_buf_.size() < PUBKEY_LEN + MAGIC_LEN) {
        return std::nullopt;
    }

    // Scan from after the public key to end of buffer
    for (size_t i = PUBKEY_LEN; i + MAGIC_LEN <= handshake_buf_.size(); ++i) {
        if (std::memcmp(handshake_buf_.data() + i, target_magic.data(), MAGIC_LEN) == 0) {
            return i;
        }
    }

    return std::nullopt;
}

void Obfs3Conn::init_client() {
    is_initiator_ = true;
    auto kp = common::uniform_dh_keygen();
    keypair_ = kp.value();
    state_ = Obfs3State::AwaitingPeerKey;
}

void Obfs3Conn::init_server() {
    is_initiator_ = false;
    auto kp = common::uniform_dh_keygen();
    keypair_ = kp.value();
    state_ = Obfs3State::AwaitingPeerKey;
}

std::vector<uint8_t> Obfs3Conn::generate_handshake() {
    uint32_t pad_len = static_cast<uint32_t>(common::random_intn(MAX_PADDING + 1));

    std::vector<uint8_t> msg;
    msg.reserve(PUBKEY_LEN + pad_len);

    // Public key (192 bytes, already zero-padded)
    msg.insert(msg.end(), keypair_.public_key.begin(), keypair_.public_key.end());

    // Random padding
    if (pad_len > 0) {
        auto padding = common::random_bytes(pad_len);
        msg.insert(msg.end(), padding.begin(), padding.end());
    }

    return msg;
}

std::expected<size_t, TransportError>
Obfs3Conn::consume_handshake(std::span<const uint8_t> data) {
    handshake_buf_.insert(handshake_buf_.end(), data.begin(), data.end());

    if (state_ == Obfs3State::AwaitingPeerKey) {
        if (handshake_buf_.size() < PUBKEY_LEN) {
            return 0;  // Need more data
        }

        // Extract peer public key
        std::memcpy(peer_pubkey_.data(), handshake_buf_.data(), PUBKEY_LEN);

        // Compute shared secret
        auto secret = common::uniform_dh_shared_secret(keypair_.private_key, peer_pubkey_);
        if (!secret) {
            state_ = Obfs3State::Failed;
            return std::unexpected(TransportError::HandshakeFailed);
        }
        shared_secret_ = *secret;

        // Derive all keys and magic values
        derive_keys();
        state_ = Obfs3State::AwaitingMagic;
    }

    if (state_ == Obfs3State::AwaitingMagic) {
        // Scan for magic value
        auto magic_pos = find_magic();
        if (!magic_pos) {
            // Check if we've exceeded maximum possible handshake size
            if (handshake_buf_.size() > PUBKEY_LEN + MAX_PADDING + MAGIC_LEN) {
                state_ = Obfs3State::Failed;
                return std::unexpected(TransportError::HandshakeFailed);
            }
            return 0;  // Need more data
        }

        // Everything up to and including the magic is the handshake
        size_t consumed = *magic_pos + MAGIC_LEN;
        state_ = Obfs3State::Established;

        // Keep any excess data
        if (handshake_buf_.size() > consumed) {
            std::vector<uint8_t> remaining(handshake_buf_.begin() + consumed,
                                            handshake_buf_.end());
            handshake_buf_ = std::move(remaining);
        } else {
            handshake_buf_.clear();
        }

        return consumed;
    }

    return std::unexpected(TransportError::HandshakeFailed);
}

std::vector<uint8_t> Obfs3Conn::write(std::span<const uint8_t> data) {
    return send_cipher_.process(data).value();
}

std::expected<ReadResult, TransportError>
Obfs3Conn::read(std::span<const uint8_t> data) {
    ReadResult result;

    std::vector<uint8_t> combined;
    if (!handshake_buf_.empty()) {
        combined.insert(combined.end(), handshake_buf_.begin(), handshake_buf_.end());
        combined.insert(combined.end(), data.begin(), data.end());
        handshake_buf_.clear();
        data = combined;
    }

    if (data.empty()) {
        result.consumed = 0;
        return result;
    }

    std::vector<uint8_t> buf(data.begin(), data.end());
    auto dec_result = recv_cipher_.process(std::span<uint8_t>(buf));
    if (!dec_result) {
        return std::unexpected(TransportError::DecodeFailed);
    }

    result.plaintext = std::move(buf);
    result.consumed = data.size();
    return result;
}

// Factories
std::expected<void, TransportError>
Obfs3ClientFactory::parse_args(const Args& /*args*/) {
    return {};
}

Obfs3Conn Obfs3ClientFactory::create() const {
    Obfs3Conn conn;
    conn.init_client();
    return conn;
}

std::expected<void, TransportError>
Obfs3ServerFactory::parse_args(const Args& /*args*/) {
    return {};
}

Obfs3Conn Obfs3ServerFactory::create() const {
    Obfs3Conn conn;
    conn.init_server();
    return conn;
}

}  // namespace obfs4::transports::obfs3
