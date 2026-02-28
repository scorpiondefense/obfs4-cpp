#include "obfs4/transport/conn.hpp"
#include <algorithm>
#include <cstring>

namespace obfs4::transport {

void Obfs4Conn::init(std::span<const uint8_t, 72> encoder_km,
                     std::span<const uint8_t, 72> decoder_km,
                     IATMode iat_mode) {
    // Each 72-byte key material block: key[32] || nonce_prefix[16] || drbg_seed[24]
    encoder_.init(
        std::span<const uint8_t, 32>(encoder_km.data(), 32),
        std::span<const uint8_t, 16>(encoder_km.data() + 32, 16),
        std::span<const uint8_t, 24>(encoder_km.data() + 48, 24));

    decoder_.init(
        std::span<const uint8_t, 32>(decoder_km.data(), 32),
        std::span<const uint8_t, 16>(decoder_km.data() + 32, 16),
        std::span<const uint8_t, 24>(decoder_km.data() + 48, 24));

    iat_mode_ = iat_mode;
    initialized_ = true;
}

std::vector<uint8_t> Obfs4Conn::write(std::span<const uint8_t> data) {
    std::vector<uint8_t> result;

    // Split data into max-payload-sized chunks
    size_t offset = 0;
    while (offset < data.size()) {
        size_t chunk_size = std::min(data.size() - offset, MAX_FRAME_PAYLOAD - PACKET_OVERHEAD);
        auto chunk = data.subspan(offset, chunk_size);

        // Build payload packet
        auto pkt = make_packet(PacketType::Payload, chunk);

        // Determine padding
        size_t pad_len = 0;
        if (len_dist_.initialized()) {
            int target = len_dist_.sample();
            if (target > static_cast<int>(pkt.size())) {
                pad_len = target - pkt.size();
            }
        }

        // Add padding to packet
        if (pad_len > 0) {
            pkt.resize(pkt.size() + pad_len, 0);
        }

        // Frame and encrypt
        auto frame = encoder_.encode(pkt);
        result.insert(result.end(), frame.begin(), frame.end());

        offset += chunk_size;
    }

    return result;
}

std::expected<Obfs4Conn::ReadResult, ConnError>
Obfs4Conn::read(std::span<const uint8_t> data) {
    ReadResult result;

    auto decode_result = decoder_.decode(data);
    if (!decode_result) {
        return std::unexpected(ConnError::DecodeFailed);
    }

    result.consumed = decode_result->consumed;

    for (auto& frame : decode_result->frames) {
        auto packets = parse_packets(frame.payload);
        for (auto& pkt : packets) {
            switch (pkt.type) {
                case PacketType::Payload:
                    result.plaintext.insert(result.plaintext.end(),
                                            pkt.payload.begin(), pkt.payload.end());
                    break;
                case PacketType::PrngSeed:
                    if (pkt.payload.size() == 24) {
                        common::DrbgSeed seed;
                        std::memcpy(seed.data(), pkt.payload.data(), 24);
                        update_prng_seed(seed);
                    }
                    break;
            }
        }
    }

    return result;
}

void Obfs4Conn::update_prng_seed(const common::DrbgSeed& seed) {
    len_dist_.reset(seed, 0, MAX_FRAME_PAYLOAD, true);
    if (iat_mode_ != IATMode::None) {
        iat_dist_.reset(seed, 0, 100000, true);  // IAT in microseconds
    }
}

}  // namespace obfs4::transport
