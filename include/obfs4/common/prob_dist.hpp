#pragma once

#include <cstdint>
#include <vector>
#include "obfs4/common/drbg.hpp"

namespace obfs4::common {

// Vose's Alias Method weighted distribution.
// Port of Go's common/probdist.
class WeightedDist {
public:
    WeightedDist() = default;

    // Construct from DRBG seed with min/max range.
    // If biased is true, weights are generated from the DRBG;
    // otherwise uniform distribution.
    WeightedDist(const DrbgSeed& seed, int min_val, int max_val, bool biased);

    // O(1) weighted sampling
    int sample();

    // Reset with new seed
    void reset(const DrbgSeed& seed, int min_val, int max_val, bool biased);

    bool initialized() const { return initialized_; }

private:
    void build_tables(const std::vector<double>& weights);

    HashDrbg drbg_;
    int min_val_ = 0;
    int max_val_ = 0;
    int n_ = 0;
    std::vector<double> prob_;
    std::vector<int> alias_;
    bool initialized_ = false;
};

}  // namespace obfs4::common
