#include "obfs4/common/replay_filter.hpp"
#include "obfs4/common/csrand.hpp"
#include "obfs4/common/drbg.hpp"
#include <cstring>

namespace obfs4::common {

ReplayFilter::ReplayFilter(size_t max_entries, std::chrono::seconds ttl)
    : max_entries_(max_entries), ttl_(ttl) {
    key_ = random_array<16>();
}

bool ReplayFilter::test_and_set(std::span<const uint8_t> data) {
    evict_expired();

    // Compute SipHash-2-4 digest of the data
    // For data longer than 8 bytes, we hash in chunks
    // Simple approach: hash the first 8 bytes (padded if shorter)
    uint8_t msg[8] = {};
    size_t to_copy = (data.size() < 8) ? data.size() : 8;
    std::memcpy(msg, data.data(), to_copy);

    // For longer data, XOR additional 8-byte chunks
    for (size_t i = 8; i < data.size(); i += 8) {
        uint8_t chunk[8] = {};
        size_t chunk_len = (data.size() - i < 8) ? (data.size() - i) : 8;
        std::memcpy(chunk, data.data() + i, chunk_len);
        auto h = siphash_2_4(key_.data(), chunk);
        for (int j = 0; j < 8; ++j) {
            msg[j] ^= static_cast<uint8_t>(h >> (j * 8));
        }
    }

    uint64_t digest = siphash_2_4(key_.data(), msg);

    // Check if seen
    if (seen_.count(digest)) {
        return true;  // Replay detected
    }

    // Add to filter
    seen_.insert(digest);
    entries_.push_back({digest, std::chrono::steady_clock::now() + ttl_});

    // Evict if over capacity
    while (entries_.size() > max_entries_) {
        seen_.erase(entries_.front().digest);
        entries_.pop_front();
    }

    return false;
}

void ReplayFilter::reset() {
    seen_.clear();
    entries_.clear();
    key_ = random_array<16>();
}

void ReplayFilter::evict_expired() {
    auto now = std::chrono::steady_clock::now();
    while (!entries_.empty() && entries_.front().expire <= now) {
        seen_.erase(entries_.front().digest);
        entries_.pop_front();
    }
}

}  // namespace obfs4::common
