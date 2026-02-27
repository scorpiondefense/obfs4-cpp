#include "obfs4/common/prob_dist.hpp"
#include <algorithm>
#include <cstring>
#include <numeric>
#include <stack>

namespace obfs4::common {

WeightedDist::WeightedDist(const DrbgSeed& seed, int min_val, int max_val, bool biased) {
    reset(seed, min_val, max_val, biased);
}

void WeightedDist::reset(const DrbgSeed& seed, int min_val, int max_val, bool biased) {
    min_val_ = min_val;
    max_val_ = max_val;
    n_ = max_val - min_val + 1;

    if (n_ <= 0) {
        initialized_ = false;
        return;
    }

    drbg_.init(seed);

    std::vector<double> weights(n_);

    if (biased) {
        // Generate weights from DRBG
        for (int i = 0; i < n_; ++i) {
            auto block = drbg_.next_block();
            uint64_t val = 0;
            std::memcpy(&val, block.data(), 8);
            weights[i] = static_cast<double>(val) + 1.0;  // Avoid zero weight
        }
    } else {
        // Uniform weights
        std::fill(weights.begin(), weights.end(), 1.0);
    }

    build_tables(weights);
    initialized_ = true;
}

// Vose's Alias Method: O(n) setup, O(1) sampling
void WeightedDist::build_tables(const std::vector<double>& weights) {
    prob_.resize(n_);
    alias_.resize(n_);

    double total = std::accumulate(weights.begin(), weights.end(), 0.0);

    // Normalize to n * probability
    std::vector<double> scaled(n_);
    for (int i = 0; i < n_; ++i) {
        scaled[i] = (weights[i] / total) * n_;
    }

    // Partition into small (< 1) and large (>= 1) groups
    std::stack<int> small, large;
    for (int i = 0; i < n_; ++i) {
        if (scaled[i] < 1.0) {
            small.push(i);
        } else {
            large.push(i);
        }
    }

    while (!small.empty() && !large.empty()) {
        int s = small.top(); small.pop();
        int l = large.top(); large.pop();

        prob_[s] = scaled[s];
        alias_[s] = l;

        scaled[l] = (scaled[l] + scaled[s]) - 1.0;
        if (scaled[l] < 1.0) {
            small.push(l);
        } else {
            large.push(l);
        }
    }

    // Remaining entries
    while (!large.empty()) {
        prob_[large.top()] = 1.0;
        large.pop();
    }
    while (!small.empty()) {
        prob_[small.top()] = 1.0;
        small.pop();
    }
}

int WeightedDist::sample() {
    if (!initialized_ || n_ <= 0) return min_val_;

    // Generate random column and coin flip
    auto block1 = drbg_.next_block();
    auto block2 = drbg_.next_block();

    uint64_t r1 = 0, r2 = 0;
    std::memcpy(&r1, block1.data(), 8);
    std::memcpy(&r2, block2.data(), 8);

    int col = static_cast<int>(r1 % static_cast<uint64_t>(n_));
    double coin = static_cast<double>(r2) / static_cast<double>(UINT64_MAX);

    int result;
    if (coin < prob_[col]) {
        result = col;
    } else {
        result = alias_[col];
    }

    return min_val_ + result;
}

}  // namespace obfs4::common
