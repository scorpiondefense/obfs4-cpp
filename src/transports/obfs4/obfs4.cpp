#include "obfs4/transports/obfs4/obfs4.hpp"

namespace obfs4::transports::obfs4_transport {

void Obfs4TransportConn::init(const transport::HandshakeKeys& keys,
                               transport::IATMode iat_mode,
                               bool is_server) {
    is_server_ = is_server;

    if (is_server) {
        // Server: encoder uses decoder key material, decoder uses encoder key material
        conn_.init(
            std::span<const uint8_t, 72>(keys.decoder_key_material.data(), 72),
            std::span<const uint8_t, 72>(keys.encoder_key_material.data(), 72),
            iat_mode);
    } else {
        conn_.init(
            std::span<const uint8_t, 72>(keys.encoder_key_material.data(), 72),
            std::span<const uint8_t, 72>(keys.decoder_key_material.data(), 72),
            iat_mode);
    }
}

std::vector<uint8_t> Obfs4TransportConn::write(std::span<const uint8_t> data) {
    return conn_.write(data);
}

std::expected<ReadResult, TransportError>
Obfs4TransportConn::read(std::span<const uint8_t> data) {
    auto result = conn_.read(data);
    if (!result) {
        return std::unexpected(TransportError::DecodeFailed);
    }

    ReadResult tr;
    tr.plaintext = std::move(result->plaintext);
    tr.consumed = result->consumed;
    return tr;
}

std::expected<void, TransportError>
Obfs4ClientFactory::parse_args(const Args& args) {
    auto cert_it = args.find("cert");
    if (cert_it == args.end()) {
        return std::unexpected(TransportError::InvalidArgs);
    }

    auto decoded = transport::decode_cert(cert_it->second);
    if (!decoded) {
        return std::unexpected(TransportError::InvalidArgs);
    }

    node_id_ = decoded->first;
    public_key_ = decoded->second;

    // Optional iat-mode
    auto iat_it = args.find("iat-mode");
    if (iat_it != args.end()) {
        int mode = std::stoi(iat_it->second);
        iat_mode_ = static_cast<transport::IATMode>(mode);
    }

    return {};
}

std::expected<void, TransportError>
Obfs4ServerFactory::parse_args(const Args& args) {
    auto state_dir_it = args.find("state");
    if (state_dir_it == args.end()) {
        return std::unexpected(TransportError::InvalidArgs);
    }

    auto state = transport::load_state(state_dir_it->second);
    if (!state) {
        return std::unexpected(TransportError::InvalidArgs);
    }

    state_ = *state;
    return {};
}

}  // namespace obfs4::transports::obfs4_transport
