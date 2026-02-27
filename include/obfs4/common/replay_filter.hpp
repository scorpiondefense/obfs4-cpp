#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <span>
#include <unordered_set>

namespace obfs4::common {

// SipHash-based replay detection filter.
// Port of Go's common/replayfilter.
class ReplayFilter {
public:
    // max_entries: maximum number of digests to remember
    // ttl: time-to-live for entries
    ReplayFilter(size_t max_entries = 65536,
                 std::chrono::seconds ttl = std::chrono::hours(1));

    // Returns true if this data has been seen before
    // If not seen, adds it to the filter
    bool test_and_set(std::span<const uint8_t> data);

    void reset();

private:
    struct Entry {
        uint64_t digest;
        std::chrono::steady_clock::time_point expire;
    };

    void evict_expired();

    size_t max_entries_;
    std::chrono::seconds ttl_;
    std::array<uint8_t, 16> key_;
    std::unordered_set<uint64_t> seen_;
    std::deque<Entry> entries_;
};

}  // namespace obfs4::common
