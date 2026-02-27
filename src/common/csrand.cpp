#include "obfs4/common/csrand.hpp"
#include <openssl/rand.h>
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

}  // namespace obfs4::common
