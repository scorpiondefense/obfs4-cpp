#include "obfs4/transport/packet.hpp"
#include <cstring>

namespace obfs4::transport {

std::vector<uint8_t> make_packet(PacketType type, std::span<const uint8_t> data,
                                  size_t pad_len) {
    size_t total = PACKET_OVERHEAD + data.size() + pad_len;
    std::vector<uint8_t> pkt(total, 0);

    pkt[0] = static_cast<uint8_t>(type);
    uint16_t len = static_cast<uint16_t>(data.size());
    pkt[1] = static_cast<uint8_t>(len >> 8);
    pkt[2] = static_cast<uint8_t>(len & 0xff);

    if (!data.empty()) {
        std::memcpy(pkt.data() + PACKET_OVERHEAD, data.data(), data.size());
    }
    // Padding is already zero-filled

    return pkt;
}

std::vector<Packet> parse_packets(std::span<const uint8_t> buf) {
    std::vector<Packet> packets;

    size_t offset = 0;
    while (offset + PACKET_OVERHEAD <= buf.size()) {
        PacketType type = static_cast<PacketType>(buf[offset]);
        uint16_t len = (static_cast<uint16_t>(buf[offset + 1]) << 8) |
                        static_cast<uint16_t>(buf[offset + 2]);
        offset += PACKET_OVERHEAD;

        if (offset + len > buf.size()) break;

        Packet pkt;
        pkt.type = type;
        pkt.payload.assign(buf.data() + offset, buf.data() + offset + len);
        packets.push_back(std::move(pkt));

        offset += len;

        // Skip any remaining padding (zeros after the payload)
        // Padding extends to end of frame, so break here
        break;
    }

    return packets;
}

}  // namespace obfs4::transport
