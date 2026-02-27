#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace obfs4::common {

// CSPRNG wrappers around OpenSSL RAND_bytes
std::vector<uint8_t> random_bytes(size_t count);
void random_bytes(std::span<uint8_t> out);

template<size_t N>
std::array<uint8_t, N> random_array() {
    std::array<uint8_t, N> out;
    random_bytes(out);
    return out;
}

}  // namespace obfs4::common
