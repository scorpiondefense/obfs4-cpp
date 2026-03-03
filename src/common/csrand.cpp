#include "obfs4/common/csrand.hpp"
#include <openssl/rand.h>
#include <cstring>
#include <stdexcept>

namespace obfs4::common {

std::vector<uint8_t> random_bytes(size_t count) {
    std::vector<uint8_t> out(count);
    if (RAND_bytes(out.data(), static_cast<int>(count)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return out;
}

void random_bytes(std::span<uint8_t> out) {
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
}

uint64_t random_intn(uint64_t n) {
    if (n == 0) return 0;
    if (n == 1) return 0;

    // Rejection sampling for uniform distribution
    // Reject values >= max_valid to avoid modulo bias
    uint64_t max_valid = UINT64_MAX - (UINT64_MAX % n);

    uint64_t val;
    do {
        auto bytes = random_array<8>();
        std::memcpy(&val, bytes.data(), 8);
    } while (val >= max_valid);

    return val % n;
}

int64_t random_int_range(int64_t min, int64_t max) {
    if (min >= max) return min;
    uint64_t range = static_cast<uint64_t>(max - min) + 1;
    return min + static_cast<int64_t>(random_intn(range));
}

double random_float64() {
    // Generate a random 53-bit mantissa for IEEE 754 double
    auto bytes = random_array<8>();
    uint64_t val;
    std::memcpy(&val, bytes.data(), 8);
    // Mask to 53 bits and divide by 2^53
    val &= (1ULL << 53) - 1;
    return static_cast<double>(val) / static_cast<double>(1ULL << 53);
}

}  // namespace obfs4::common
