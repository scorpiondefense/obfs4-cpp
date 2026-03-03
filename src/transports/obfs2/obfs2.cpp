#include "obfs4/transports/obfs2/obfs2.hpp"
#include "obfs4/common/csrand.hpp"
#include "obfs4/crypto/hash.hpp"
#include <cstring>

namespace obfs4::transports::obfs2 {

// KDF: SHA256(pad_string || seed) to produce pad encryption key
std::array<uint8_t, 32> Obfs2Conn::derive_pad_key(
    std::span<const uint8_t, SEED_LEN> seed, bool initiator) const {
    auto pad_string = initiator ? INITIATOR_PAD_STRING : RESPONDER_PAD_STRING;

    std::vector<uint8_t> input;
    input.insert(input.end(), pad_string.begin(), pad_string.end());
    input.insert(input.end(), seed.begin(), seed.end());

    auto hash = crypto::sha256(input);
    return hash.value();
}

void Obfs2Conn::derive_stream_keys() {
    // Initiator stream key: SHA256("Initiator obfuscated data" || initiator_seed || responder_seed)
    // Responder stream key: SHA256("Responder obfuscated data" || responder_seed || initiator_seed)

    auto& init_seed = is_initiator_ ? local_seed_ : peer_seed_;
    auto& resp_seed = is_initiator_ ? peer_seed_ : local_seed_;

    // Send key
    {
        auto kdf_string = is_initiator_ ? INITIATOR_KDF_STRING : RESPONDER_KDF_STRING;
        std::vector<uint8_t> input;
        input.insert(input.end(), kdf_string.begin(), kdf_string.end());
        if (is_initiator_) {
            input.insert(input.end(), init_seed.begin(), init_seed.end());
            input.insert(input.end(), resp_seed.begin(), resp_seed.end());
        } else {
            input.insert(input.end(), resp_seed.begin(), resp_seed.end());
            input.insert(input.end(), init_seed.begin(), init_seed.end());
        }
        auto key = crypto::sha256(input).value();
        std::array<uint8_t, 16> aes_key;
        std::memcpy(aes_key.data(), key.data(), 16);
        std::array<uint8_t, 16> iv{};  // zero IV for obfs2
        (void)send_cipher_.init(aes_key, iv);
    }

    // Receive key
    {
        auto kdf_string = is_initiator_ ? RESPONDER_KDF_STRING : INITIATOR_KDF_STRING;
        std::vector<uint8_t> input;
        input.insert(input.end(), kdf_string.begin(), kdf_string.end());
        if (is_initiator_) {
            // Responder's send key uses: responder_seed || initiator_seed
            input.insert(input.end(), resp_seed.begin(), resp_seed.end());
            input.insert(input.end(), init_seed.begin(), init_seed.end());
        } else {
            // Initiator's send key uses: initiator_seed || responder_seed
            input.insert(input.end(), init_seed.begin(), init_seed.end());
            input.insert(input.end(), resp_seed.begin(), resp_seed.end());
        }
        auto key = crypto::sha256(input).value();
        std::array<uint8_t, 16> aes_key;
        std::memcpy(aes_key.data(), key.data(), 16);
        std::array<uint8_t, 16> iv{};
        (void)recv_cipher_.init(aes_key, iv);
    }
}

void Obfs2Conn::init_client() {
    is_initiator_ = true;
    common::random_bytes(local_seed_);
    state_ = Obfs2State::AwaitingPeerSeed;
}

void Obfs2Conn::init_server() {
    is_initiator_ = false;
    common::random_bytes(local_seed_);
    state_ = Obfs2State::AwaitingPeerSeed;
}

std::vector<uint8_t> Obfs2Conn::generate_handshake() {
    // Generate random padding length
    uint32_t pad_len = static_cast<uint32_t>(common::random_intn(MAX_PADDING + 1));

    // Derive pad encryption key from our seed
    auto pad_key = derive_pad_key(local_seed_, is_initiator_);

    // Build the encrypted header: E(pad_key, MAGIC || PADLEN)
    std::array<uint8_t, 8> header{};
    // Big-endian magic value
    header[0] = static_cast<uint8_t>((MAGIC_VALUE >> 24) & 0xFF);
    header[1] = static_cast<uint8_t>((MAGIC_VALUE >> 16) & 0xFF);
    header[2] = static_cast<uint8_t>((MAGIC_VALUE >> 8) & 0xFF);
    header[3] = static_cast<uint8_t>(MAGIC_VALUE & 0xFF);
    // Big-endian pad length
    header[4] = static_cast<uint8_t>((pad_len >> 24) & 0xFF);
    header[5] = static_cast<uint8_t>((pad_len >> 16) & 0xFF);
    header[6] = static_cast<uint8_t>((pad_len >> 8) & 0xFF);
    header[7] = static_cast<uint8_t>(pad_len & 0xFF);

    // Encrypt header with AES-128-CTR using pad key
    crypto::AesCtrStream pad_cipher;
    std::array<uint8_t, 16> aes_key;
    std::memcpy(aes_key.data(), pad_key.data(), 16);
    std::array<uint8_t, 16> iv{};
    (void)pad_cipher.init(aes_key, iv);
    (void)pad_cipher.process(std::span<uint8_t>(header));

    // Build message: SEED || E(header) || PADDING
    std::vector<uint8_t> msg;
    msg.reserve(SEED_LEN + 8 + pad_len);
    msg.insert(msg.end(), local_seed_.begin(), local_seed_.end());
    msg.insert(msg.end(), header.begin(), header.end());

    // Random padding
    if (pad_len > 0) {
        auto padding = common::random_bytes(pad_len);
        msg.insert(msg.end(), padding.begin(), padding.end());
    }

    return msg;
}

std::expected<size_t, TransportError>
Obfs2Conn::consume_handshake(std::span<const uint8_t> data) {
    handshake_buf_.insert(handshake_buf_.end(), data.begin(), data.end());

    if (state_ == Obfs2State::AwaitingPeerSeed) {
        if (handshake_buf_.size() < HANDSHAKE_HEADER_LEN) {
            return 0;  // Need more data
        }

        // Extract peer seed
        std::memcpy(peer_seed_.data(), handshake_buf_.data(), SEED_LEN);

        // Derive pad key from peer seed (peer is the opposite role)
        auto pad_key = derive_pad_key(peer_seed_, !is_initiator_);

        // Decrypt header
        std::array<uint8_t, 8> header;
        std::memcpy(header.data(), handshake_buf_.data() + SEED_LEN, 8);

        crypto::AesCtrStream pad_cipher;
        std::array<uint8_t, 16> aes_key;
        std::memcpy(aes_key.data(), pad_key.data(), 16);
        std::array<uint8_t, 16> iv{};
        (void)pad_cipher.init(aes_key, iv);
        (void)pad_cipher.process(std::span<uint8_t>(header));

        // Verify magic
        uint32_t magic = (static_cast<uint32_t>(header[0]) << 24) |
                         (static_cast<uint32_t>(header[1]) << 16) |
                         (static_cast<uint32_t>(header[2]) << 8) |
                         static_cast<uint32_t>(header[3]);

        if (magic != MAGIC_VALUE) {
            state_ = Obfs2State::Failed;
            return std::unexpected(TransportError::HandshakeFailed);
        }

        // Extract padding length
        peer_pad_len_ = (static_cast<uint32_t>(header[4]) << 24) |
                        (static_cast<uint32_t>(header[5]) << 16) |
                        (static_cast<uint32_t>(header[6]) << 8) |
                        static_cast<uint32_t>(header[7]);

        if (peer_pad_len_ > MAX_PADDING) {
            state_ = Obfs2State::Failed;
            return std::unexpected(TransportError::HandshakeFailed);
        }

        state_ = Obfs2State::AwaitingPeerPadding;
    }

    if (state_ == Obfs2State::AwaitingPeerPadding) {
        size_t total_needed = HANDSHAKE_HEADER_LEN + peer_pad_len_;
        if (handshake_buf_.size() < total_needed) {
            return 0;  // Need more padding data
        }

        // Handshake complete - derive stream keys
        derive_stream_keys();
        state_ = Obfs2State::Established;

        size_t consumed = total_needed;
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

std::vector<uint8_t> Obfs2Conn::write(std::span<const uint8_t> data) {
    auto result = send_cipher_.process(data);
    return result.value();
}

std::expected<ReadResult, TransportError>
Obfs2Conn::read(std::span<const uint8_t> data) {
    ReadResult result;

    // If there's leftover handshake data, prepend it
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

    // Decrypt data in place
    std::vector<uint8_t> buf(data.begin(), data.end());
    auto dec_result = recv_cipher_.process(std::span<uint8_t>(buf));
    if (!dec_result) {
        return std::unexpected(TransportError::DecodeFailed);
    }

    result.plaintext = std::move(buf);
    result.consumed = data.size();
    return result;
}

// Factory implementations
std::expected<void, TransportError>
Obfs2ClientFactory::parse_args(const Args& /*args*/) {
    // obfs2 has no arguments
    return {};
}

Obfs2Conn Obfs2ClientFactory::create() const {
    Obfs2Conn conn;
    conn.init_client();
    return conn;
}

std::expected<void, TransportError>
Obfs2ServerFactory::parse_args(const Args& /*args*/) {
    return {};
}

Obfs2Conn Obfs2ServerFactory::create() const {
    Obfs2Conn conn;
    conn.init_server();
    return conn;
}

}  // namespace obfs4::transports::obfs2
