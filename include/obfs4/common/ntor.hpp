#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>
#include "obfs4/crypto/elligator2.hpp"

namespace obfs4::common {

using NodeID = std::array<uint8_t, 20>;
using KeySeed = std::array<uint8_t, 32>;
using Auth = std::array<uint8_t, 32>;

using crypto::PublicKey;
using crypto::PrivateKey;
using crypto::Representative;
using crypto::Keypair;

// ntor protocol constants (byte arrays, no null terminators)
constexpr std::string_view PROTO_ID = "ntor-curve25519-sha256-1";
constexpr std::string_view T_MAC = "ntor-curve25519-sha256-1:mac";
constexpr std::string_view T_KEY = "ntor-curve25519-sha256-1:key_extract";
constexpr std::string_view T_VERIFY = "ntor-curve25519-sha256-1:key_verify";
constexpr std::string_view M_EXPAND = "ntor-curve25519-sha256-1:key_expand";

// X25519 Diffie-Hellman using OpenSSL
std::optional<std::array<uint8_t, 32>>
x25519_dh(const PrivateKey& priv, const PublicKey& pub);

// ntor server-side handshake
// Returns (key_seed, auth) or nullopt on failure
std::optional<std::tuple<KeySeed, Auth>>
server_handshake(const PublicKey& client_pub,
                 const Keypair& server_keypair,
                 const Keypair& id_keypair,
                 const NodeID& node_id);

// ntor client-side handshake
std::optional<std::tuple<KeySeed, Auth>>
client_handshake(const Keypair& client_keypair,
                 const PublicKey& server_pub,
                 const PublicKey& id_pub,
                 const NodeID& node_id);

// KDF: HKDF with salt=T_KEY, info=M_EXPAND
std::vector<uint8_t> kdf(const KeySeed& key_seed, size_t okm_len);

}  // namespace obfs4::common
