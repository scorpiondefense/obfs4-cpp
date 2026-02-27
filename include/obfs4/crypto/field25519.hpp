#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <utility>

namespace obfs4::crypto {

// GF(2^255-19) field element using 5x51-bit radix-2^51 limb representation.
// All operations are constant-time to prevent timing side-channels.
class FieldElement {
public:
    static constexpr int LIMBS = 5;
    static constexpr uint64_t MASK51 = (1ULL << 51) - 1;

    FieldElement() : limbs_{} {}

    explicit FieldElement(uint64_t l0, uint64_t l1, uint64_t l2,
                          uint64_t l3, uint64_t l4)
        : limbs_{l0, l1, l2, l3, l4} {}

    static FieldElement from_bytes(std::span<const uint8_t, 32> bytes);
    void to_bytes(std::span<uint8_t, 32> out) const;
    [[nodiscard]] std::array<uint8_t, 32> to_bytes() const;

    [[nodiscard]] FieldElement operator+(const FieldElement& rhs) const;
    [[nodiscard]] FieldElement operator-(const FieldElement& rhs) const;
    [[nodiscard]] FieldElement operator*(const FieldElement& rhs) const;
    [[nodiscard]] FieldElement operator-() const;

    FieldElement& operator+=(const FieldElement& rhs);
    FieldElement& operator-=(const FieldElement& rhs);
    FieldElement& operator*=(const FieldElement& rhs);

    [[nodiscard]] bool operator==(const FieldElement& rhs) const;
    [[nodiscard]] bool operator!=(const FieldElement& rhs) const { return !(*this == rhs); }

    [[nodiscard]] FieldElement square() const;
    [[nodiscard]] FieldElement square_n(int n) const;
    [[nodiscard]] FieldElement invert() const;
    [[nodiscard]] std::pair<FieldElement, bool> sqrt() const;
    [[nodiscard]] FieldElement pow_p58() const;

    [[nodiscard]] bool is_negative() const;
    [[nodiscard]] bool is_zero() const;

    [[nodiscard]] FieldElement conditional_negate(bool negate) const;
    static FieldElement conditional_select(const FieldElement& a,
                                            const FieldElement& b,
                                            bool flag);
    static void conditional_swap(FieldElement& a, FieldElement& b, bool flag);

    // Multiply by small integer
    [[nodiscard]] FieldElement mul_small(uint64_t small) const;

    static FieldElement zero();
    static FieldElement one();
    static FieldElement A();       // 486662
    static FieldElement sqrt_m1(); // sqrt(-1) mod p
    static FieldElement neg_A();   // -486662 mod p

    [[nodiscard]] const uint64_t* data() const { return limbs_; }
    [[nodiscard]] uint64_t limb(int i) const { return limbs_[i]; }

private:
    uint64_t limbs_[LIMBS];
    void carry();
    void reduce();
};

}  // namespace obfs4::crypto
