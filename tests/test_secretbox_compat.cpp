#include <cstdio>
#include <cstdint>
#include <cstring>
#include <array>
#include <vector>
#include "obfs4/crypto/secretbox.hpp"

// Parse hex string to bytes
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

std::string to_hex(const uint8_t* data, size_t len) {
    std::string out;
    for (size_t i = 0; i < len; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        out += buf;
    }
    return out;
}

int main() {
    // Test vector from Go: key = 0x00..0x1f, nonce = 0x40..0x57
    std::array<uint8_t, 32> key;
    for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);

    std::array<uint8_t, 24> nonce;
    for (int i = 0; i < 24; ++i) nonce[i] = static_cast<uint8_t>(0x40 + i);

    int pass = 0, fail = 0;

    // Test 1: "Hello, obfs4 world!"
    {
        auto plaintext = from_hex("48656c6c6f2c206f6266733420776f726c6421");
        auto go_sealed = from_hex("9b479a670e0164703089db2ea60f82d802723915557d9b45a43f025548fe3583a25367");

        // Our seal
        auto our_sealed = obfs4::crypto::Secretbox::seal(key, nonce, plaintext);
        printf("Test 1: 'Hello, obfs4 world!'\n");
        printf("  Go sealed:  %s\n", to_hex(go_sealed.data(), go_sealed.size()).c_str());
        printf("  C++ sealed: %s\n", to_hex(our_sealed.data(), our_sealed.size()).c_str());

        if (our_sealed == go_sealed) {
            printf("  SEAL: PASS (exact match)\n");
            pass++;
        } else {
            printf("  SEAL: FAIL (mismatch!)\n");
            fail++;
        }

        // Our open of Go's sealed data
        auto opened = obfs4::crypto::Secretbox::open(key, nonce, go_sealed);
        if (opened && *opened == plaintext) {
            printf("  OPEN: PASS (decrypted Go ciphertext)\n");
            pass++;
        } else {
            printf("  OPEN: FAIL (%s)\n", opened ? "wrong plaintext" : "decryption failed!");
            fail++;
        }
    }

    // Test 2: Empty message
    {
        auto go_sealed = from_hex("25ad7f4489ddd636717f1a6bbc7daf99");
        std::vector<uint8_t> empty;

        auto our_sealed = obfs4::crypto::Secretbox::seal(key, nonce, empty);
        printf("\nTest 2: Empty message\n");
        printf("  Go sealed:  %s\n", to_hex(go_sealed.data(), go_sealed.size()).c_str());
        printf("  C++ sealed: %s\n", to_hex(our_sealed.data(), our_sealed.size()).c_str());

        if (our_sealed == go_sealed) {
            printf("  SEAL: PASS\n");
            pass++;
        } else {
            printf("  SEAL: FAIL\n");
            fail++;
        }

        auto opened = obfs4::crypto::Secretbox::open(key, nonce, go_sealed);
        if (opened && opened->empty()) {
            printf("  OPEN: PASS\n");
            pass++;
        } else {
            printf("  OPEN: FAIL\n");
            fail++;
        }
    }

    // Test 3: 64-byte payload
    {
        auto plaintext = from_hex("000306090c0f1215181b1e2124272a2d303336393c3f4245484b4e5154575a5d606366696c6f7275787b7e8184878a8d909396999c9fa2a5a8abaeb1b4b7babd");
        auto go_sealed = from_hex("dbad2da004ab2e81fca8618d22863ea44a145370365ea93fde426f404cae70dcfe04706d517c1d8dac9e6c9bad8ed909b4570f7882d8b471213762f8b575d0a21027b5f43b1112e320791503b3c02408");

        auto our_sealed = obfs4::crypto::Secretbox::seal(key, nonce, plaintext);
        printf("\nTest 3: 64-byte payload\n");
        printf("  Go sealed:  %s\n", to_hex(go_sealed.data(), go_sealed.size()).c_str());
        printf("  C++ sealed: %s\n", to_hex(our_sealed.data(), our_sealed.size()).c_str());

        if (our_sealed == go_sealed) {
            printf("  SEAL: PASS\n");
            pass++;
        } else {
            printf("  SEAL: FAIL\n");
            fail++;
        }

        auto opened = obfs4::crypto::Secretbox::open(key, nonce, go_sealed);
        if (opened && *opened == plaintext) {
            printf("  OPEN: PASS\n");
            pass++;
        } else {
            printf("  OPEN: FAIL\n");
            fail++;
        }
    }

    printf("\n=== Results: %d passed, %d failed ===\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
