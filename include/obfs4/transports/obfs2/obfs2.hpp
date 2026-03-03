#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include "obfs4/crypto/aes_ctr.hpp"
#include "obfs4/transports/base.hpp"

namespace obfs4::transports::obfs2 {

// obfs2 protocol constants
constexpr uint32_t MAGIC_VALUE = 0x2BF5CA7E;
constexpr size_t SEED_LEN = 16;
constexpr size_t MAX_PADDING = 8192;
constexpr size_t HANDSHAKE_HEADER_LEN = SEED_LEN + 8;  // seed + E(magic + padlen)

// KDF padstring constants
constexpr std::string_view INITIATOR_PAD_STRING = "Initiator obfuscation padding";
constexpr std::string_view RESPONDER_PAD_STRING = "Responder obfuscation padding";
constexpr std::string_view INITIATOR_KDF_STRING = "Initiator obfuscated data";
constexpr std::string_view RESPONDER_KDF_STRING = "Responder obfuscated data";

// Handshake state
enum class Obfs2State {
    Initial,
    AwaitingPeerSeed,
    AwaitingPeerPadding,
    Established,
    Failed,
};

// obfs2 connection (handles both client and server)
class Obfs2Conn {
public:
    Obfs2Conn() = default;

    static constexpr std::string_view transport_name() { return "obfs2"; }

    // Initialize as client (initiator) or server (responder)
    void init_client();
    void init_server();

    // Generate handshake message to send to peer
    std::vector<uint8_t> generate_handshake();

    // Feed received handshake data. Returns consumed bytes on completion.
    std::expected<size_t, TransportError> consume_handshake(std::span<const uint8_t> data);

    // Encode plaintext to wire format (post-handshake)
    std::vector<uint8_t> write(std::span<const uint8_t> data);

    // Decode wire format to plaintext (post-handshake)
    std::expected<ReadResult, TransportError> read(std::span<const uint8_t> data);

    bool handshake_complete() const { return state_ == Obfs2State::Established; }

private:
    bool is_initiator_ = true;
    Obfs2State state_ = Obfs2State::Initial;

    // Local seed
    std::array<uint8_t, SEED_LEN> local_seed_{};
    // Peer seed
    std::array<uint8_t, SEED_LEN> peer_seed_{};

    // Padding length we expect from peer
    uint32_t peer_pad_len_ = 0;

    // Stream ciphers for data phase
    crypto::AesCtrStream send_cipher_;
    crypto::AesCtrStream recv_cipher_;

    // Handshake buffer
    std::vector<uint8_t> handshake_buf_;

    // Derive pad key from seed
    std::array<uint8_t, 32> derive_pad_key(std::span<const uint8_t, SEED_LEN> seed,
                                            bool initiator) const;

    // Derive stream keys from both seeds
    void derive_stream_keys();
};

// Client factory
class Obfs2ClientFactory {
public:
    static constexpr std::string_view transport_name() { return "obfs2"; }

    std::expected<void, TransportError> parse_args(const Args& args);

    Obfs2Conn create() const;
};

// Server factory
class Obfs2ServerFactory {
public:
    static constexpr std::string_view transport_name() { return "obfs2"; }

    std::expected<void, TransportError> parse_args(const Args& args);

    Obfs2Conn create() const;
};

}  // namespace obfs4::transports::obfs2
