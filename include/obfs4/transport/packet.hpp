#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace obfs4::transport {

enum class PacketType : uint8_t {
    Payload = 0,
    PrngSeed = 1,
};

constexpr size_t PACKET_OVERHEAD = 3;  // type(1) + length(2)
constexpr size_t MAX_PACKET_PAYLOAD = 1430 - PACKET_OVERHEAD;  // 1427
constexpr size_t SEED_PACKET_PAYLOAD = 24;

struct Packet {
    PacketType type;
    std::vector<uint8_t> payload;
};

// Create a packet: type[1] || length_be16[2] || data || zeros[pad_len]
std::vector<uint8_t> make_packet(PacketType type, std::span<const uint8_t> data,
                                  size_t pad_len = 0);

// Parse packets from decrypted frame payload
std::vector<Packet> parse_packets(std::span<const uint8_t> buf);

}  // namespace obfs4::transport
