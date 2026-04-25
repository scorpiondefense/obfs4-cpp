#include <cstdio>
#include <cstdint>
#include <cstring>
#include <array>
#include <vector>
#include <span>

// Forward declare poly1305 from secretbox.cpp
namespace obfs4::crypto {
void poly1305(std::span<uint8_t, 16> out,
              std::span<const uint8_t> message,
              std::span<const uint8_t, 32> key);
}

std::string to_hex(const uint8_t* data, size_t len) {
    std::string out;
    for (size_t i = 0; i < len; ++i) {
        char buf[3]; snprintf(buf, sizeof(buf), "%02x", data[i]);
        out += buf;
    }
    return out;
}

std::vector<uint8_t> from_hex(const char* hex) {
    std::vector<uint8_t> out;
    while (*hex) {
        uint8_t hi = (*hex >= 'a') ? (*hex - 'a' + 10) : (*hex - '0');
        hex++;
        uint8_t lo = (*hex >= 'a') ? (*hex - 'a' + 10) : (*hex - '0');
        hex++;
        out.push_back((hi << 4) | lo);
    }
    return out;
}

int main() {
    int pass = 0, fail = 0;

    // RFC 8439 Section 2.5.2 test vector
    {
        auto key_bytes = from_hex(
            "85d6be7857556d337f4452fe42d506a8"  // r
            "0103808afb0db2fd4abff6af4149f51b"  // s
        );
        std::array<uint8_t, 32> key;
        memcpy(key.data(), key_bytes.data(), 32);

        const char* msg_str = "Cryptographic Forum Research Group";
        auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(msg_str), strlen(msg_str));

        auto expected_tag = from_hex("a8061dc1305136c6c22b8baf0c0127a9");

        std::array<uint8_t, 16> tag;
        obfs4::crypto::poly1305(tag, msg, key);

        printf("RFC 8439 Section 2.5.2:\n");
        printf("  Expected: %s\n", to_hex(expected_tag.data(), 16).c_str());
        printf("  Got:      %s\n", to_hex(tag.data(), 16).c_str());

        if (memcmp(tag.data(), expected_tag.data(), 16) == 0) {
            printf("  PASS\n");
            pass++;
        } else {
            printf("  FAIL\n");
            fail++;
        }
    }

    // Test 2: Empty message (tag should be just s)
    {
        auto key_bytes = from_hex(
            "85d6be7857556d337f4452fe42d506a8"
            "0103808afb0db2fd4abff6af4149f51b"
        );
        std::array<uint8_t, 32> key;
        memcpy(key.data(), key_bytes.data(), 32);

        std::array<uint8_t, 16> tag;
        obfs4::crypto::poly1305(tag, std::span<const uint8_t>{}, key);

        // For empty message, h=0, so tag = 0 + s = s
        auto expected = from_hex("0103808afb0db2fd4abff6af4149f51b");
        printf("\nEmpty message (should be s value):\n");
        printf("  Expected: %s\n", to_hex(expected.data(), 16).c_str());
        printf("  Got:      %s\n", to_hex(tag.data(), 16).c_str());

        if (memcmp(tag.data(), expected.data(), 16) == 0) {
            printf("  PASS\n");
            pass++;
        } else {
            printf("  FAIL\n");
            fail++;
        }
    }

    // Test 3: Single byte message
    {
        // Use a simple key: r=all zeros (after clamping), s=all zeros
        std::array<uint8_t, 32> key{};
        key[0] = 1;  // r has value 1 (after clamping: r=1)
        // s = 0

        uint8_t msg[] = {1};  // message = [0x01]

        std::array<uint8_t, 16> tag;
        obfs4::crypto::poly1305(tag, std::span<const uint8_t>(msg, 1), key);

        // h = (0x0101) * 1 mod p = 0x0101 = 257
        // (message byte 0x01 + hibit at position 1 = 0x01 + 0x100 = 0x101 = 257)
        // tag = h + s = 257 + 0 = 257 = 0x0101000000000000...
        auto expected = from_hex("01010000000000000000000000000000");
        printf("\nSingle byte [0x01], r=1, s=0:\n");
        printf("  Expected: %s\n", to_hex(expected.data(), 16).c_str());
        printf("  Got:      %s\n", to_hex(tag.data(), 16).c_str());

        if (memcmp(tag.data(), expected.data(), 16) == 0) {
            printf("  PASS\n");
            pass++;
        } else {
            printf("  FAIL\n");
            fail++;
        }
    }

    // Test 4: RFC 8439 Appendix A.3 Test Vector 1
    {
        std::array<uint8_t, 32> key{};  // all zeros
        std::vector<uint8_t> msg(64, 0);  // 64 zero bytes

        std::array<uint8_t, 16> tag;
        obfs4::crypto::poly1305(tag, msg, key);

        auto expected = from_hex("00000000000000000000000000000000");
        printf("\nAll zeros key, 64 zero bytes:\n");
        printf("  Expected: %s\n", to_hex(expected.data(), 16).c_str());
        printf("  Got:      %s\n", to_hex(tag.data(), 16).c_str());

        if (memcmp(tag.data(), expected.data(), 16) == 0) {
            printf("  PASS\n");
            pass++;
        } else {
            printf("  FAIL\n");
            fail++;
        }
    }

    printf("\n=== Results: %d passed, %d failed ===\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
