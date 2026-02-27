#include "obfs4/crypto/field25519.hpp"
#include <cstring>

namespace obfs4::crypto {

using u64 = uint64_t;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
using u128 = unsigned __int128;
#pragma GCC diagnostic pop

[[maybe_unused]] constexpr u64 MASK51 = FieldElement::MASK51;

// --- Serialization ---

FieldElement FieldElement::from_bytes(std::span<const uint8_t, 32> bytes) {
    auto load64le = [](const uint8_t* p) -> u64 {
        u64 r = 0;
        for (int i = 7; i >= 0; --i)
            r = (r << 8) | p[i];
        return r;
    };

    u64 l0 = (load64le(&bytes[0])) & MASK51;
    u64 l1 = (load64le(&bytes[6]) >> 3) & MASK51;
    u64 l2 = (load64le(&bytes[12]) >> 6) & MASK51;
    u64 l3 = (load64le(&bytes[19]) >> 1) & MASK51;
    u64 l4 = (load64le(&bytes[24]) >> 12) & MASK51;

    return FieldElement(l0, l1, l2, l3, l4);
}

void FieldElement::to_bytes(std::span<uint8_t, 32> out) const {
    FieldElement t = *this;
    t.reduce();

    auto store = [&out](u64 val, int byte_offset, int bit_offset, int bits) {
        while (bits > 0) {
            int space = 8 - bit_offset;
            int chunk = (bits < space) ? bits : space;
            uint8_t mask = static_cast<uint8_t>(((1 << chunk) - 1) << bit_offset);
            out[byte_offset] = static_cast<uint8_t>(
                (out[byte_offset] & ~mask) |
                ((static_cast<uint8_t>(val) << bit_offset) & mask));
            val >>= chunk;
            bits -= chunk;
            bit_offset = 0;
            byte_offset++;
        }
    };

    std::memset(out.data(), 0, 32);
    store(t.limbs_[0], 0, 0, 51);
    store(t.limbs_[1], 6, 3, 51);
    store(t.limbs_[2], 12, 6, 51);
    store(t.limbs_[3], 19, 1, 51);
    store(t.limbs_[4], 25, 4, 51);
}

std::array<uint8_t, 32> FieldElement::to_bytes() const {
    std::array<uint8_t, 32> out{};
    to_bytes(out);
    return out;
}

// --- Carry propagation ---

void FieldElement::carry() {
    limbs_[1] += limbs_[0] >> 51; limbs_[0] &= MASK51;
    limbs_[2] += limbs_[1] >> 51; limbs_[1] &= MASK51;
    limbs_[3] += limbs_[2] >> 51; limbs_[2] &= MASK51;
    limbs_[4] += limbs_[3] >> 51; limbs_[3] &= MASK51;
    limbs_[0] += (limbs_[4] >> 51) * 19; limbs_[4] &= MASK51;
}

// --- Full reduction to [0, p) ---

void FieldElement::reduce() {
    carry();
    carry();

    u64 q = (limbs_[0] + 19) >> 51;
    q = (limbs_[1] + q) >> 51;
    q = (limbs_[2] + q) >> 51;
    q = (limbs_[3] + q) >> 51;
    q = (limbs_[4] + q) >> 51;

    limbs_[0] += 19 * q;

    limbs_[1] += limbs_[0] >> 51; limbs_[0] &= MASK51;
    limbs_[2] += limbs_[1] >> 51; limbs_[1] &= MASK51;
    limbs_[3] += limbs_[2] >> 51; limbs_[2] &= MASK51;
    limbs_[4] += limbs_[3] >> 51; limbs_[3] &= MASK51;
    limbs_[4] &= MASK51;
}

// --- Addition ---

FieldElement FieldElement::operator+(const FieldElement& rhs) const {
    FieldElement r(
        limbs_[0] + rhs.limbs_[0],
        limbs_[1] + rhs.limbs_[1],
        limbs_[2] + rhs.limbs_[2],
        limbs_[3] + rhs.limbs_[3],
        limbs_[4] + rhs.limbs_[4]
    );
    r.carry();
    return r;
}

FieldElement& FieldElement::operator+=(const FieldElement& rhs) {
    *this = *this + rhs;
    return *this;
}

// --- Subtraction ---

FieldElement FieldElement::operator-(const FieldElement& rhs) const {
    FieldElement r(
        (limbs_[0] + 0xfffffffffffda) - rhs.limbs_[0],
        (limbs_[1] + 0xffffffffffffe) - rhs.limbs_[1],
        (limbs_[2] + 0xffffffffffffe) - rhs.limbs_[2],
        (limbs_[3] + 0xffffffffffffe) - rhs.limbs_[3],
        (limbs_[4] + 0xffffffffffffe) - rhs.limbs_[4]
    );
    r.carry();
    return r;
}

FieldElement& FieldElement::operator-=(const FieldElement& rhs) {
    *this = *this - rhs;
    return *this;
}

FieldElement FieldElement::operator-() const {
    return FieldElement::zero() - *this;
}

// --- Multiplication ---

FieldElement FieldElement::operator*(const FieldElement& rhs) const {
    const u64* a = limbs_;
    const u64* b = rhs.limbs_;

    u64 b1_19 = b[1] * 19;
    u64 b2_19 = b[2] * 19;
    u64 b3_19 = b[3] * 19;
    u64 b4_19 = b[4] * 19;

    u128 t0 = (u128)a[0] * b[0] + (u128)a[4] * b1_19 + (u128)a[3] * b2_19
            + (u128)a[2] * b3_19 + (u128)a[1] * b4_19;
    u128 t1 = (u128)a[1] * b[0] + (u128)a[0] * b[1] + (u128)a[4] * b2_19
            + (u128)a[3] * b3_19 + (u128)a[2] * b4_19;
    u128 t2 = (u128)a[2] * b[0] + (u128)a[1] * b[1] + (u128)a[0] * b[2]
            + (u128)a[4] * b3_19 + (u128)a[3] * b4_19;
    u128 t3 = (u128)a[3] * b[0] + (u128)a[2] * b[1] + (u128)a[1] * b[2]
            + (u128)a[0] * b[3] + (u128)a[4] * b4_19;
    u128 t4 = (u128)a[4] * b[0] + (u128)a[3] * b[1] + (u128)a[2] * b[2]
            + (u128)a[1] * b[3] + (u128)a[0] * b[4];

    u64 r0 = static_cast<u64>(t0) & MASK51; t1 += static_cast<u64>(t0 >> 51);
    u64 r1 = static_cast<u64>(t1) & MASK51; t2 += static_cast<u64>(t1 >> 51);
    u64 r2 = static_cast<u64>(t2) & MASK51; t3 += static_cast<u64>(t2 >> 51);
    u64 r3 = static_cast<u64>(t3) & MASK51; t4 += static_cast<u64>(t3 >> 51);
    u64 r4 = static_cast<u64>(t4) & MASK51;
    r0 += static_cast<u64>(t4 >> 51) * 19;
    r1 += r0 >> 51; r0 &= MASK51;

    return FieldElement(r0, r1, r2, r3, r4);
}

FieldElement& FieldElement::operator*=(const FieldElement& rhs) {
    *this = *this * rhs;
    return *this;
}

// --- Squaring ---

FieldElement FieldElement::square() const {
    const u64* a = limbs_;

    u64 a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    u64 a4_19 = a4 * 19;

    u128 s0 = (u128)a0 * a0 + 2 * ((u128)a1 * a4_19 + (u128)a2 * (a3 * 19));
    u128 s1 = 2 * ((u128)a0 * a1) + 2 * (u128)a2 * a4_19 + (u128)a3 * (a3 * 19);
    u128 s2 = 2 * ((u128)a0 * a2) + (u128)a1 * a1 + 2 * (u128)a3 * a4_19;
    u128 s3 = 2 * ((u128)a0 * a3 + (u128)a1 * a2) + (u128)a4 * a4_19;
    u128 s4 = 2 * ((u128)a0 * a4 + (u128)a1 * a3) + (u128)a2 * a2;

    u64 r0 = static_cast<u64>(s0) & MASK51; s1 += static_cast<u64>(s0 >> 51);
    u64 r1 = static_cast<u64>(s1) & MASK51; s2 += static_cast<u64>(s1 >> 51);
    u64 r2 = static_cast<u64>(s2) & MASK51; s3 += static_cast<u64>(s2 >> 51);
    u64 r3 = static_cast<u64>(s3) & MASK51; s4 += static_cast<u64>(s3 >> 51);
    u64 r4 = static_cast<u64>(s4) & MASK51;
    r0 += static_cast<u64>(s4 >> 51) * 19;
    r1 += r0 >> 51; r0 &= MASK51;

    return FieldElement(r0, r1, r2, r3, r4);
}

FieldElement FieldElement::square_n(int n) const {
    FieldElement r = *this;
    for (int i = 0; i < n; ++i)
        r = r.square();
    return r;
}

// --- Equality (constant-time) ---

bool FieldElement::operator==(const FieldElement& rhs) const {
    auto a = to_bytes();
    auto b = rhs.to_bytes();
    uint8_t diff = 0;
    for (int i = 0; i < 32; ++i)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

// --- Inversion via Fermat: a^(p-2) ---

FieldElement FieldElement::invert() const {
    FieldElement a = *this;

    FieldElement a2 = a.square();
    FieldElement a_9 = a2.square_n(2);
    a_9 = a_9 * a;
    FieldElement a_11 = a_9 * a2;
    FieldElement a_22 = a_11.square();
    a_22 = a_22 * a_9;

    FieldElement t = a_22;
    FieldElement a_2_5_0 = t;

    t = a_2_5_0.square_n(5);
    FieldElement a_2_10_0 = t * a_2_5_0;

    t = a_2_10_0.square_n(10);
    FieldElement a_2_20_0 = t * a_2_10_0;

    t = a_2_20_0.square_n(20);
    t = t * a_2_20_0;

    t = t.square_n(10);
    FieldElement a_2_50_0 = t * a_2_10_0;

    t = a_2_50_0.square_n(50);
    FieldElement a_2_100_0 = t * a_2_50_0;

    t = a_2_100_0.square_n(100);
    t = t * a_2_100_0;

    t = t.square_n(50);
    t = t * a_2_50_0;

    t = t.square_n(5);
    t = t * a_11;

    return t;
}

// --- Power (p-5)/8 = 2^252 - 3 ---

FieldElement FieldElement::pow_p58() const {
    FieldElement a = *this;

    FieldElement a2 = a.square();
    FieldElement a_9 = a2.square_n(2) * a;
    FieldElement a_11 = a_9 * a2;

    FieldElement a_2_5_0 = a_11.square() * a_9;

    FieldElement t = a_2_5_0.square_n(5);
    FieldElement a_2_10_0 = t * a_2_5_0;

    t = a_2_10_0.square_n(10);
    FieldElement a_2_20_0 = t * a_2_10_0;

    t = a_2_20_0.square_n(20);
    t = t * a_2_20_0;

    t = t.square_n(10);
    FieldElement a_2_50_0 = t * a_2_10_0;

    t = a_2_50_0.square_n(50);
    FieldElement a_2_100_0 = t * a_2_50_0;

    t = a_2_100_0.square_n(100);
    t = t * a_2_100_0;

    t = t.square_n(50);
    t = t * a_2_50_0;

    t = t.square_n(2);
    t = t * a;

    return t;
}

// --- Square root ---

std::pair<FieldElement, bool> FieldElement::sqrt() const {
    FieldElement beta = this->pow_p58() * *this;
    FieldElement check = beta.square();

    if (check == *this) {
        return {beta, true};
    }

    FieldElement neg = FieldElement::zero() - *this;
    if (check == neg) {
        return {beta * sqrt_m1(), true};
    }

    return {FieldElement::zero(), false};
}

// --- Predicates ---

bool FieldElement::is_negative() const {
    auto bytes = to_bytes();
    return (bytes[0] & 1) != 0;
}

bool FieldElement::is_zero() const {
    return *this == FieldElement::zero();
}

// --- Conditional operations (constant-time) ---

FieldElement FieldElement::conditional_negate(bool negate) const {
    FieldElement neg = -*this;
    return conditional_select(*this, neg, negate);
}

FieldElement FieldElement::conditional_select(const FieldElement& a,
                                               const FieldElement& b,
                                               bool flag) {
    u64 mask = static_cast<u64>(-static_cast<int64_t>(flag));
    return FieldElement(
        a.limbs_[0] ^ (mask & (a.limbs_[0] ^ b.limbs_[0])),
        a.limbs_[1] ^ (mask & (a.limbs_[1] ^ b.limbs_[1])),
        a.limbs_[2] ^ (mask & (a.limbs_[2] ^ b.limbs_[2])),
        a.limbs_[3] ^ (mask & (a.limbs_[3] ^ b.limbs_[3])),
        a.limbs_[4] ^ (mask & (a.limbs_[4] ^ b.limbs_[4]))
    );
}

void FieldElement::conditional_swap(FieldElement& a, FieldElement& b, bool flag) {
    u64 mask = static_cast<u64>(-static_cast<int64_t>(flag));
    for (int i = 0; i < LIMBS; ++i) {
        u64 t = mask & (a.limbs_[i] ^ b.limbs_[i]);
        a.limbs_[i] ^= t;
        b.limbs_[i] ^= t;
    }
}

// --- Multiply by small integer ---

FieldElement FieldElement::mul_small(uint64_t small) const {
    u128 t0 = (u128)limbs_[0] * small;
    u128 t1 = (u128)limbs_[1] * small;
    u128 t2 = (u128)limbs_[2] * small;
    u128 t3 = (u128)limbs_[3] * small;
    u128 t4 = (u128)limbs_[4] * small;

    u64 r0 = static_cast<u64>(t0) & MASK51; t1 += static_cast<u64>(t0 >> 51);
    u64 r1 = static_cast<u64>(t1) & MASK51; t2 += static_cast<u64>(t1 >> 51);
    u64 r2 = static_cast<u64>(t2) & MASK51; t3 += static_cast<u64>(t2 >> 51);
    u64 r3 = static_cast<u64>(t3) & MASK51; t4 += static_cast<u64>(t3 >> 51);
    u64 r4 = static_cast<u64>(t4) & MASK51;
    r0 += static_cast<u64>(t4 >> 51) * 19;
    r1 += r0 >> 51; r0 &= MASK51;

    return FieldElement(r0, r1, r2, r3, r4);
}

// --- Constants ---

FieldElement FieldElement::zero() {
    return FieldElement(0, 0, 0, 0, 0);
}

FieldElement FieldElement::one() {
    return FieldElement(1, 0, 0, 0, 0);
}

FieldElement FieldElement::A() {
    return FieldElement(486662, 0, 0, 0, 0);
}

FieldElement FieldElement::neg_A() {
    return -A();
}

FieldElement FieldElement::sqrt_m1() {
    // sqrt(-1) mod p
    static const uint8_t bytes[32] = {
        0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
        0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
        0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
        0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
    };
    std::span<const uint8_t, 32> sp(bytes, 32);
    return from_bytes(sp);
}

}  // namespace obfs4::crypto
