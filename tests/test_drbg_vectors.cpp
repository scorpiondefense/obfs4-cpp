#include <cstdio>
#include <cstdint>
#include <array>
#include "obfs4/common/drbg.hpp"

int main() {
    // Known seed: bytes 0,1,2,...,23
    obfs4::common::DrbgSeed seed{};
    for (int i = 0; i < 24; ++i) seed[i] = static_cast<uint8_t>(i);

    obfs4::common::HashDrbg drbg;
    drbg.init(seed);

    printf("Seed: ");
    for (int i = 0; i < 24; ++i) printf("%02x", seed[i]);
    printf("\n\n");

    for (int i = 0; i < 5; ++i) {
        auto block = drbg.next_block();
        printf("Block %d: ", i);
        for (int j = 0; j < 8; ++j) printf("%02x", block[j]);
        uint16_t mask = (static_cast<uint16_t>(block[0]) << 8) |
                        static_cast<uint16_t>(block[1]);
        printf("  (length_mask=0x%04x = %u)\n", mask, mask);
    }

    return 0;
}
