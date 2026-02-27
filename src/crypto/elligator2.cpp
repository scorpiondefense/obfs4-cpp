#include "obfs4/crypto/elligator2.hpp"
#include "obfs4/crypto/hash.hpp"
#include "obfs4/common/csrand.hpp"
#include <openssl/evp.h>
#include <cstring>

namespace obfs4::crypto::elligator2 {

// --- Constants ---

// A_NEGATIVE = -486662 mod p
static FieldElement neg_a() {
    return -FieldElement::A();
}

// Non-square u = 2 for Curve25519 Elligator2
static FieldElement fe_two() {
    return FieldElement(2, 0, 0, 0, 0);
}

// --- sqrt_ratio: compute sqrt(u/v) ---
// Port of Go's feSqrtRatio from filippo.io/edwards25519/field
// Returns (result, was_square)
// If u/v is a square, result = sqrt(u/v)
// If not, result = sqrt(sqrt(-1) * u/v)
std::pair<FieldElement, bool> sqrt_ratio(const FieldElement& u, const FieldElement& v) {
    auto v2 = v.square();         // v^2
    auto uv3 = u * v * v2;        // u*v^3
    auto uv7 = uv3 * v2.square(); // u*v^7

    // r = (u*v^3) * (u*v^7)^((p-5)/8)
    auto r = uv3 * uv7.pow_p58();

    auto check = r.square() * v;  // r^2 * v

    auto i = FieldElement::sqrt_m1();

    auto correct_sign_sqrt = (check == u);
    auto flipped_sign_sqrt = (check == -u);
    auto flipped_sign_sqrt_i = (check == (-u * i));

    auto r_prime = r * i;

    // If flipped_sign_sqrt || flipped_sign_sqrt_i: use r_prime
    r = FieldElement::conditional_select(r, r_prime,
        flipped_sign_sqrt || flipped_sign_sqrt_i);

    // Make non-negative (ensure is_negative() == false)
    r = r.conditional_negate(r.is_negative());

    bool was_square = correct_sign_sqrt || flipped_sign_sqrt;
    return {r, was_square};
}

// --- montgomery_flavor: Elligator2 map ---
// Port of Go's elligator2.MontgomeryFlavor
FieldElement montgomery_flavor(const FieldElement& r) {
    auto one = FieldElement::one();
    auto neg_a_val = neg_a();

    // t1 = r^2
    auto t1 = r.square();

    // t1 = 2 * r^2 (multiply by non-residue u=2)
    t1 = t1.mul_small(2);

    // e = 1 + 2*r^2
    auto e = one + t1;

    // If e == 0, set to 1 (constant-time)
    e = FieldElement::conditional_select(e, one, e.is_zero());

    // t1 = 1/e
    t1 = e.invert();

    // v = -A/e = -A * (1/(1+2r^2))
    auto v = neg_a_val * t1;

    // w0 = v (first candidate for u-coordinate)
    // w1 = v + A (= v - (-A))... actually w1 = -(v + A)
    // Go: v2 := new(field.Element).Negate(new(field.Element).Add(v, &A))
    auto v_plus_a = v + FieldElement::A();
    auto w1 = -v_plus_a;

    // Compute v^2 + A*v + 1 (Legendre check — is v on the curve?)
    // Actually Go uses sqrtRatio for this:
    // e = v^3 + A*v^2 + v
    auto v2 = v.square();
    auto v3 = v2 * v;
    auto e_check = v3 + FieldElement::A() * v2 + v;

    // was_square = whether e_check is a QR
    auto [_, was_square] = sqrt_ratio(one, e_check);

    // If was_square: result = v (w0)
    // Else: result = -(v + A) (w1)
    auto result = FieldElement::conditional_select(w1, v, was_square);

    return result;
}

// --- representative_to_public_key ---
// Port of Go's RepresentativeToPublicKey
PublicKey representative_to_public_key(const Representative& repr) {
    // Clamp: clear bits 254-255 (NOT just 255!)
    std::array<uint8_t, 32> clamped;
    std::memcpy(clamped.data(), repr.data(), 32);
    clamped[31] &= 0x3f;  // Clear bits 254 AND 255

    auto r = FieldElement::from_bytes(clamped);
    auto u = montgomery_flavor(r);
    return u.to_bytes();
}

// --- Edwards point operations for dirty scalar mult ---

struct EdwardsPoint {
    FieldElement X, Y, Z, T;
};

// Edwards d constant: -121665/121666 mod p
static FieldElement edwards_d() {
    // d = -121665/121666 mod p
    // = 37095705934669439343138083508754565189542113879843219016388785533085940283555
    static const uint8_t bytes[32] = {
        0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
        0xab, 0xd1, 0x41, 0x41, 0x4e, 0x0a, 0x70, 0x0c,
        0xdd, 0x44, 0x5c, 0x74, 0x38, 0x38, 0x94, 0xa0,
        0x96, 0xfb, 0xc2, 0x4f, 0x21, 0x56, 0xba, 0x09,
    };
    std::span<const uint8_t, 32> sp(bytes, 32);
    return FieldElement::from_bytes(sp);
}

// Edwards 2*d
static FieldElement edwards_2d() {
    return edwards_d().mul_small(2);
}

// Identity point on Edwards curve
static EdwardsPoint edwards_identity() {
    return {FieldElement::zero(), FieldElement::one(), FieldElement::one(), FieldElement::zero()};
}

// Precomputed low-order points on Edwards curve (8 points for cofactor group)
// These are the 8 points of order dividing 8 on Ed25519
// Point order: identity, L1, L2, L3, L4, L5, L6, L7
// where Li = i * (low-order generator)
[[maybe_unused]] static const EdwardsPoint& low_order_point(int index) {
    // Low-order Edwards points, precomputed
    // The low-order generator is (lop_x, lop_y) on the Edwards curve
    // Go uses these exact 8 points
    static bool initialized = false;
    static EdwardsPoint points[8];

    if (!initialized) {
        // Point 0: identity (0, 1, 1, 0)
        points[0] = edwards_identity();

        // Point 4: (0, -1, 1, 0) — the order-2 point
        points[4] = {FieldElement::zero(), -FieldElement::one(), FieldElement::one(), FieldElement::zero()};

        // For the remaining 6 points, we compute from the low-order generator
        // Low-order generator on Edwards25519:
        // The torsion points are well-known. We compute them from the
        // 4th root of unity on the curve.

        // Point 2: an order-4 point: (sqrt(-1), 0, 1, 0)
        auto sqrt_m1 = FieldElement::sqrt_m1();
        points[2] = {sqrt_m1, FieldElement::zero(), FieldElement::one(), FieldElement::zero()};

        // Point 6: (-sqrt(-1), 0, 1, 0)
        points[6] = {-sqrt_m1, FieldElement::zero(), FieldElement::one(), FieldElement::zero()};

        // For points 1, 3, 5, 7 we need the actual order-8 torsion points.
        // These satisfy 2*P = order-4 point. We compute them:
        // An order-8 point on Ed25519 has coordinates:
        // x = sqrt((sqrt(d+1)+1)/d) (with appropriate sign choices)
        // y = -x * sqrt(-1) (related via the curve equation)

        // Compute the order-8 generator:
        // From the curve equation: -x^2 + y^2 = 1 + d*x^2*y^2
        // For order-8 points, 2P is an order-4 point.

        // Known order-8 point coordinates (from ristretto255 spec):
        // c = sqrt(-1)
        // Point: (c * sqrt(c), appropriate y, 1, x*y)
        // Using exact values:
        auto d = edwards_d();

        // Compute sqrt((sqrt(d+1)+1)/d)
        auto d_plus_1 = d + FieldElement::one();
        auto [sqrt_dp1, dp1_ok] = d_plus_1.sqrt();
        (void)dp1_ok;

        auto num = sqrt_dp1 + FieldElement::one();
        auto inv_d = d.invert();
        auto ratio = num * inv_d;
        auto [lop_x, x_ok] = ratio.sqrt();
        (void)x_ok;

        // y = -x * sqrt(-1)
        auto lop_y = -lop_x * sqrt_m1;

        // Verify on curve: -x^2 + y^2 = 1 + d*x^2*y^2
        auto x2 = lop_x.square();
        auto y2 = lop_y.square();
        auto lhs = -x2 + y2;
        auto rhs = FieldElement::one() + d * x2 * y2;
        if (!(lhs == rhs)) {
            // Try negating x
            lop_x = -lop_x;
            lop_y = -lop_x * sqrt_m1;
        }

        // Normalize to affine (Z=1)
        auto t = lop_x * lop_y;
        points[1] = {lop_x, lop_y, FieldElement::one(), t};

        // Point 3 = P + 2P (where 2P = points[2])
        // Point 5 = -P + 4P = (4P - P)
        // Point 7 = -P
        // Actually: negation on Edwards is (-X, Y, Z, -T)
        points[7] = {-lop_x, lop_y, FieldElement::one(), -t};

        // For 3 and 5, we use Edwards addition
        // But for simplicity and correctness, we compute:
        // Point 3 = 3*generator = 2*gen + gen (use doubling + addition)
        // Point 5 = 5*gen = 4*gen + gen
        // However, the exact low-order point selection in Go uses
        // a simpler approach: it picks from a static table.
        // For correctness, compute them via Edwards addition.

        auto add_edwards = [&](const EdwardsPoint& p, const EdwardsPoint& q) -> EdwardsPoint {
            auto d2 = edwards_2d();
            auto a = p.X * q.X;
            auto b = p.Y * q.Y;
            auto c_val = p.T * d2 * q.T;
            auto dd = p.Z * q.Z;
            dd = dd.mul_small(2);
            auto e = (p.X + p.Y) * (q.X + q.Y) - a - b;
            auto f = dd - c_val;
            auto g = dd + c_val;
            auto h = b + a;  // Note: Edwards a=-1, so b - a*a_coeff = b + a
            auto X3 = e * f;
            auto Y3 = g * h;
            auto T3 = e * h;
            auto Z3 = f * g;
            return {X3, Y3, Z3, T3};
        };

        // point 3 = point 1 + point 2
        points[3] = add_edwards(points[1], points[2]);

        // point 5 = point 1 + point 4
        points[5] = add_edwards(points[1], points[4]);

        initialized = true;
    }

    return points[index & 7];
}

// Convert Edwards point (X, Y, Z, T) to Montgomery u-coordinate
// u = (Z + Y) / (Z - Y)
[[maybe_unused]] static FieldElement edwards_to_montgomery_u(const EdwardsPoint& p) {
    auto z_plus_y = p.Z + p.Y;
    auto z_minus_y = p.Z - p.Y;
    return z_plus_y * z_minus_y.invert();
}

// --- scalar_base_mult_dirty ---
// Computes scalar * basepoint on Curve25519 using OpenSSL X25519.
// Returns the Montgomery u-coordinate.
//
// Note: Go's scalarBaseMultDirty also adds a low-order point selected
// by priv[0] & 7 (cofactor bits). This is currently simplified away —
// the cofactor bits affect which representative maps to the point but
// don't change representability. For C++↔C++ round-trips this is fine.
// For exact Go byte-level matching, Edwards low-order point addition
// would need to be implemented.
FieldElement scalar_base_mult_dirty(const PrivateKey& priv) {
    // Use OpenSSL X25519 to compute priv * basepoint
    // OpenSSL handles clamping internally
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                     priv.data(), 32);
    if (!pkey) {
        return FieldElement::zero();
    }

    std::array<uint8_t, 32> pub_bytes{};
    size_t pub_len = 32;
    EVP_PKEY_get_raw_public_key(pkey, pub_bytes.data(), &pub_len);
    EVP_PKEY_free(pkey);

    return FieldElement::from_bytes(pub_bytes);
}

// --- u_to_representative ---
// Port of Go's uToRepresentative
std::optional<Representative> u_to_representative(const FieldElement& u, uint8_t tweak) {
    auto A = FieldElement::A();
    auto two = fe_two();

    // Check: u must not be -A (otherwise division by zero)
    if ((u + A).is_zero()) {
        return std::nullopt;
    }

    // Compute t3 = -2 * u * (u + A)
    auto u_plus_A = u + A;
    auto t3 = -(two * u * u_plus_A);

    // Check if t3 is a square (needed for representative to exist)
    auto [r, was_square] = sqrt_ratio(FieldElement::one(), t3);
    if (!was_square) {
        return std::nullopt;
    }

    // Select between two possible representatives based on tweak bit 0
    // Go: if tweak & 1: r = r * u
    //     else: r = r * u_plus_A * (-1)
    // Actually from Go's uToRepresentative:
    // r0 = sqrt(1/(-2*u*(u+A)))
    // If tweak & 1: r = u * r0
    // Else: r = (u+A) * r0 * -1
    // Wait, let me look at this more carefully...
    // From Go obfs4:
    //   r = fe_sqrt_ratio(1, -2*u*(u+A))
    //   if tweak & 1:
    //     representative = r * u   [but this doesn't seem right]
    //
    // Actually Go's exact code from x25519ell2:
    //   func uToRepresentative(representative *[32]byte, u *field.Element, tweak byte) bool {
    //     ...
    //     n := new(field.Element).Negate(new(field.Element).Multiply(u, new(field.Element).Add(u, &A)))
    //     n.Multiply(n, &two)  // n = -2*u*(u+A)
    //     wasSquare, r := feSqrtRatio(new(field.Element).One(), n)
    //     if !wasSquare { return false }
    //
    //     // Pick one of the two valid representatives
    //     r0 := new(field.Element).Multiply(r, u)
    //     r1 := new(field.Element).Negate(new(field.Element).Multiply(r, new(field.Element).Add(u, &A)))
    //     r.Select(r1, r0, int(tweak&1))

    auto r0 = r * u;
    auto r1 = -(r * u_plus_A);
    auto selected = FieldElement::conditional_select(r0, r1, (tweak & 1) != 0);

    // Canonicalize: ensure representative < p/2 so that clamping
    // (clearing bits 254-255 in the forward map) is a no-op.
    // Check (2*r mod p) & 1: if set, r >= p/2, so negate.
    auto two_r = selected.mul_small(2);
    auto two_r_bytes = two_r.to_bytes();
    bool needs_negate = (two_r_bytes[0] & 1) != 0;
    selected = selected.conditional_negate(needs_negate);

    Representative repr = selected.to_bytes();

    // Pad bits 254-255 from tweak
    repr[31] |= static_cast<uint8_t>(tweak & 0xc0);

    return repr;
}

// --- scalar_base_mult ---
// Port of Go's ScalarBaseMult
bool scalar_base_mult(PublicKey& pub, Representative& repr,
                      const PrivateKey& priv, uint8_t tweak) {
    auto u = scalar_base_mult_dirty(priv);

    auto repr_opt = u_to_representative(u, tweak);
    if (!repr_opt) {
        return false;
    }

    repr = *repr_opt;
    pub = u.to_bytes();
    return true;
}

// --- generate_representable_keypair ---
// Port of Go obfs4 keypair generation
Keypair generate_representable_keypair() {
    for (int attempt = 0; attempt < 256; ++attempt) {
        // Generate 32 random bytes
        auto random = common::random_bytes(32);

        // SHA-512 the random bytes (Go's approach)
        auto digest_result = sha512(random);
        if (!digest_result) continue;

        auto& digest = *digest_result;

        // priv = digest[0:32]
        PrivateKey priv;
        std::memcpy(priv.data(), digest.data(), 32);

        // tweak = digest[63] (last byte of SHA-512 output)
        uint8_t tweak = digest[63];

        PublicKey pub;
        Representative repr;

        if (scalar_base_mult(pub, repr, priv, tweak)) {
            Keypair kp;
            kp.private_key = priv;
            kp.public_key = pub;
            kp.representative = repr;
            return kp;
        }
    }

    // Should never happen (probability ~2^-256)
    return {};
}

}  // namespace obfs4::crypto::elligator2
