#include "obfs4/common/ntor.hpp"
#include "obfs4/crypto/hash.hpp"
#include <openssl/evp.h>
#include <cstring>

namespace obfs4::common {

// X25519 DH via OpenSSL
std::optional<std::array<uint8_t, 32>>
x25519_dh(const PrivateKey& priv, const PublicKey& pub) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                    priv.data(), 32);
    if (!pkey) return std::nullopt;

    EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                   pub.data(), 32);
    if (!peer) {
        EVP_PKEY_free(pkey);
        return std::nullopt;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peer);
        return std::nullopt;
    }

    std::array<uint8_t, 32> shared;
    size_t shared_len = 32;

    bool ok = EVP_PKEY_derive_init(ctx) == 1 &&
              EVP_PKEY_derive_set_peer(ctx, peer) == 1 &&
              EVP_PKEY_derive(ctx, shared.data(), &shared_len) == 1;

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peer);

    if (!ok || shared_len != 32) return std::nullopt;
    return shared;
}

// ntor common computation
static std::optional<std::tuple<KeySeed, Auth>>
ntor_common(const std::array<uint8_t, 32>& exp_xy,
            const std::array<uint8_t, 32>& exp_xb,
            const NodeID& node_id,
            const PublicKey& b_pub,
            const PublicKey& x_pub,
            const PublicKey& y_pub) {
    // secret_input = EXP(X,y) | EXP(X,b) | B | B | X | Y | PROTOID | node_id
    std::vector<uint8_t> secret_input;
    secret_input.reserve(32 + 32 + 32 + 32 + 32 + 32 + PROTO_ID.size() + 20);

    secret_input.insert(secret_input.end(), exp_xy.begin(), exp_xy.end());
    secret_input.insert(secret_input.end(), exp_xb.begin(), exp_xb.end());
    secret_input.insert(secret_input.end(), b_pub.begin(), b_pub.end());
    secret_input.insert(secret_input.end(), b_pub.begin(), b_pub.end());
    secret_input.insert(secret_input.end(), x_pub.begin(), x_pub.end());
    secret_input.insert(secret_input.end(), y_pub.begin(), y_pub.end());
    auto proto = reinterpret_cast<const uint8_t*>(PROTO_ID.data());
    secret_input.insert(secret_input.end(), proto, proto + PROTO_ID.size());
    secret_input.insert(secret_input.end(), node_id.begin(), node_id.end());

    // KEY_SEED = HMAC-SHA256(key=T_KEY, message=secret_input)
    auto t_key_bytes = reinterpret_cast<const uint8_t*>(T_KEY.data());
    auto key_seed_result = crypto::hmac_sha256(
        std::span<const uint8_t>(t_key_bytes, T_KEY.size()),
        secret_input);
    if (!key_seed_result) return std::nullopt;

    // verify = HMAC-SHA256(key=T_VERIFY, message=secret_input)
    auto t_verify_bytes = reinterpret_cast<const uint8_t*>(T_VERIFY.data());
    auto verify = crypto::hmac_sha256(
        std::span<const uint8_t>(t_verify_bytes, T_VERIFY.size()),
        secret_input);
    if (!verify) return std::nullopt;

    // auth_input = verify | B | B | X | Y | PROTOID | node_id | "Server"
    std::vector<uint8_t> auth_input;
    auth_input.insert(auth_input.end(), verify->begin(), verify->end());
    // Suffix: same as secret_input[64:] but we rebuild
    auth_input.insert(auth_input.end(), b_pub.begin(), b_pub.end());
    auth_input.insert(auth_input.end(), b_pub.begin(), b_pub.end());
    auth_input.insert(auth_input.end(), x_pub.begin(), x_pub.end());
    auth_input.insert(auth_input.end(), y_pub.begin(), y_pub.end());
    auth_input.insert(auth_input.end(), proto, proto + PROTO_ID.size());
    auth_input.insert(auth_input.end(), node_id.begin(), node_id.end());
    static constexpr std::string_view SERVER = "Server";
    auto server_bytes = reinterpret_cast<const uint8_t*>(SERVER.data());
    auth_input.insert(auth_input.end(), server_bytes, server_bytes + SERVER.size());

    // auth = HMAC-SHA256(key=T_MAC, message=auth_input)
    auto t_mac_bytes = reinterpret_cast<const uint8_t*>(T_MAC.data());
    auto auth = crypto::hmac_sha256(
        std::span<const uint8_t>(t_mac_bytes, T_MAC.size()),
        auth_input);
    if (!auth) return std::nullopt;

    return std::make_tuple(*key_seed_result, *auth);
}

std::optional<std::tuple<KeySeed, Auth>>
server_handshake(const PublicKey& client_pub,
                 const Keypair& server_keypair,
                 const Keypair& id_keypair,
                 const NodeID& node_id) {
    // EXP(X, y) = DH(server_ephemeral, client)
    auto exp_xy = x25519_dh(server_keypair.private_key, client_pub);
    if (!exp_xy) return std::nullopt;

    // EXP(X, b) = DH(identity, client)
    auto exp_xb = x25519_dh(id_keypair.private_key, client_pub);
    if (!exp_xb) return std::nullopt;

    return ntor_common(*exp_xy, *exp_xb, node_id,
                       id_keypair.public_key, client_pub,
                       server_keypair.public_key);
}

std::optional<std::tuple<KeySeed, Auth>>
client_handshake(const Keypair& client_keypair,
                 const PublicKey& server_pub,
                 const PublicKey& id_pub,
                 const NodeID& node_id) {
    // EXP(Y, x) = DH(client, server_ephemeral)
    auto exp_xy = x25519_dh(client_keypair.private_key, server_pub);
    if (!exp_xy) return std::nullopt;

    // EXP(B, x) = DH(client, identity)
    auto exp_xb = x25519_dh(client_keypair.private_key, id_pub);
    if (!exp_xb) return std::nullopt;

    return ntor_common(*exp_xy, *exp_xb, node_id,
                       id_pub, client_keypair.public_key, server_pub);
}

// KDF
std::vector<uint8_t> kdf(const KeySeed& key_seed, size_t okm_len) {
    auto t_key_bytes = reinterpret_cast<const uint8_t*>(T_KEY.data());
    auto m_expand_bytes = reinterpret_cast<const uint8_t*>(M_EXPAND.data());

    auto result = crypto::hkdf_sha256(
        std::span<const uint8_t>(t_key_bytes, T_KEY.size()),
        key_seed,
        std::span<const uint8_t>(m_expand_bytes, M_EXPAND.size()),
        okm_len);

    if (!result) return {};
    return *result;
}

}  // namespace obfs4::common
