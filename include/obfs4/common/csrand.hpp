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

// Return random integer in [0, n) with uniform distribution
uint64_t random_intn(uint64_t n);

// Return random integer in [min, max] with uniform distribution
int64_t random_int_range(int64_t min, int64_t max);

// Return random double in [0.0, 1.0)
double random_float64();

}  // namespace obfs4::common
