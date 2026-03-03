#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include "obfs4/crypto/aes_ctr.hpp"
#include "obfs4/common/uniform_dh.hpp"
#include "obfs4/transports/base.hpp"

namespace obfs4::transports::obfs3 {

// obfs3 protocol constants
constexpr size_t MAX_PADDING = 8194;
constexpr size_t PUBKEY_LEN = common::UNIFORM_DH_KEY_LEN;  // 192 bytes

// KDF strings for HMAC-SHA256 key derivation
constexpr std::string_view INITIATOR_KDF_STRING = "Initiator obfuscated data";
constexpr std::string_view RESPONDER_KDF_STRING = "Responder obfuscated data";
constexpr std::string_view INITIATOR_MAGIC_STRING = "Initiator magic";
constexpr std::string_view RESPONDER_MAGIC_STRING = "Responder magic";

// Magic value length (HMAC-SHA256 truncated)
constexpr size_t MAGIC_LEN = 32;

enum class Obfs3State {
    Initial,
    AwaitingPeerKey,
    AwaitingMagic,
    Established,
    Failed,
};

// obfs3 connection
class Obfs3Conn {
public:
    Obfs3Conn() = default;

    static constexpr std::string_view transport_name() { return "obfs3"; }

    void init_client();
    void init_server();

    // Generate handshake message: PUBKEY(192) || PADDING(random 0..8194)
    std::vector<uint8_t> generate_handshake();

    // Feed received handshake data
    std::expected<size_t, TransportError> consume_handshake(std::span<const uint8_t> data);

    // Post-handshake data transfer
    std::vector<uint8_t> write(std::span<const uint8_t> data);
    std::expected<ReadResult, TransportError> read(std::span<const uint8_t> data);

    bool handshake_complete() const { return state_ == Obfs3State::Established; }

private:
    bool is_initiator_ = true;
    Obfs3State state_ = Obfs3State::Initial;

    // DH keypair
    common::UniformDHKeypair keypair_{};

    // Peer's public key
    std::array<uint8_t, PUBKEY_LEN> peer_pubkey_{};

    // Shared secret
    std::array<uint8_t, PUBKEY_LEN> shared_secret_{};

    // Stream ciphers
    crypto::AesCtrStream send_cipher_;
    crypto::AesCtrStream recv_cipher_;

    // Magic values for handshake verification
    std::array<uint8_t, MAGIC_LEN> initiator_magic_{};
    std::array<uint8_t, MAGIC_LEN> responder_magic_{};

    // Handshake buffer
    std::vector<uint8_t> handshake_buf_;

    // Derive all keys from shared secret
    void derive_keys();

    // Scan buffer for magic value
    std::optional<size_t> find_magic() const;
};

// Client factory
class Obfs3ClientFactory {
public:
    static constexpr std::string_view transport_name() { return "obfs3"; }

    std::expected<void, TransportError> parse_args(const Args& args);
    Obfs3Conn create() const;
};

// Server factory
class Obfs3ServerFactory {
public:
    static constexpr std::string_view transport_name() { return "obfs3"; }

    std::expected<void, TransportError> parse_args(const Args& args);
    Obfs3Conn create() const;
};

}  // namespace obfs4::transports::obfs3
