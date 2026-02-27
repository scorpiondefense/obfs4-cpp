#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include "obfs4/crypto/field25519.hpp"

namespace obfs4::crypto {

using PublicKey = std::array<uint8_t, 32>;
using PrivateKey = std::array<uint8_t, 32>;
using Representative = std::array<uint8_t, 32>;

struct Keypair {
    PrivateKey private_key;
    PublicKey public_key;
    std::optional<Representative> representative;
};

// Faithful port of Go's x25519ell2 Elligator2 implementation.
// Fixes all known bugs from our previous implementation:
// - Representative clamping: &= 0x3f (not 0x7f)
// - Canonicalization: r < p/2 (not just is_negative)
// - Padding bits: both 254-255 (not just 255)
// - Low-order point addition in scalarBaseMultDirty
namespace elligator2 {

// Forward map: representative -> Montgomery u-coordinate
// Port of Go's RepresentativeToPublicKey
PublicKey representative_to_public_key(const Representative& repr);

// Montgomery flavor of Elligator2 map
// Port of Go's MontgomeryFlavor
FieldElement montgomery_flavor(const FieldElement& r);

// SqrtRatio: compute sqrt(u/v) if it exists
// Returns (result, was_square)
// Port of Go's feSqrtRatio
std::pair<FieldElement, bool> sqrt_ratio(const FieldElement& u, const FieldElement& v);

// Dirty scalar base multiplication: base mult + low-order point addition
// Port of Go's scalarBaseMultDirty
FieldElement scalar_base_mult_dirty(const PrivateKey& priv);

// Compute representative from Montgomery u-coordinate
// Returns nullopt if u is not representable (~50%)
// Port of Go's uToRepresentative
std::optional<Representative> u_to_representative(const FieldElement& u, uint8_t tweak);

// Full scalar base mult producing both public key and representative
// Port of Go's ScalarBaseMult
bool scalar_base_mult(PublicKey& pub, Representative& repr,
                      const PrivateKey& priv, uint8_t tweak);

// Generate a representable keypair
// Port of Go's generateKeypair (from obfs4 handshake)
Keypair generate_representable_keypair();

}  // namespace elligator2
}  // namespace obfs4::crypto
