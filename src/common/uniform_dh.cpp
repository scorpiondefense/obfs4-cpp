#include "obfs4/common/uniform_dh.hpp"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <cstring>

namespace obfs4::common {

std::string uniform_dh_error_message(UniformDHError err) {
    switch (err) {
        case UniformDHError::KeygenFailed: return "DH key generation failed";
        case UniformDHError::SharedSecretFailed: return "DH shared secret computation failed";
        case UniformDHError::InvalidPublicKey: return "invalid DH public key";
        case UniformDHError::OpenSSLError: return "OpenSSL error in DH operation";
    }
    return "unknown UniformDH error";
}

// RFC 3526 Group 5: 1536-bit MODP prime
// p = 2^1536 - 2^1472 - 1 + 2^64 * { [2^1406 pi] + 741804 }
static const char* GROUP5_PRIME_HEX =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";

static constexpr int GROUP5_GENERATOR = 2;

// RAII wrapper for OpenSSL BIGNUMs
struct BnCtx {
    BN_CTX* ctx;
    BnCtx() : ctx(BN_CTX_new()) {}
    ~BnCtx() { if (ctx) BN_CTX_free(ctx); }
    operator BN_CTX*() { return ctx; }
};

struct Bn {
    BIGNUM* bn;
    Bn() : bn(BN_new()) {}
    explicit Bn(BIGNUM* b) : bn(b) {}
    ~Bn() { if (bn) BN_free(bn); }
    operator BIGNUM*() { return bn; }
    operator const BIGNUM*() const { return bn; }
};

// Convert BIGNUM to zero-padded 192-byte big-endian array
static void bn_to_padded(std::array<uint8_t, UNIFORM_DH_KEY_LEN>& out, const BIGNUM* bn) {
    std::memset(out.data(), 0, UNIFORM_DH_KEY_LEN);
    int bn_len = BN_num_bytes(bn);
    if (bn_len > 0 && bn_len <= static_cast<int>(UNIFORM_DH_KEY_LEN)) {
        BN_bn2bin(bn, out.data() + (UNIFORM_DH_KEY_LEN - bn_len));
    }
}

std::expected<UniformDHKeypair, UniformDHError>
uniform_dh_keygen() {
    BnCtx ctx;
    if (!ctx.ctx) return std::unexpected(UniformDHError::OpenSSLError);

    // Parse the prime
    Bn p;
    if (!BN_hex2bn(&p.bn, GROUP5_PRIME_HEX)) {
        return std::unexpected(UniformDHError::OpenSSLError);
    }

    // Generator g = 2
    Bn g;
    BN_set_word(g, GROUP5_GENERATOR);

    // Generate private key: random in [1, p-2]
    Bn priv;
    Bn p_minus_2;
    BN_copy(p_minus_2, p);
    BN_sub_word(p_minus_2, 2);

    // Generate random private key uniformly in [1, p-2]
    if (!BN_rand_range(priv, p_minus_2)) {
        return std::unexpected(UniformDHError::KeygenFailed);
    }
    BN_add_word(priv, 1);  // shift from [0, p-3] to [1, p-2]

    // Compute public key: g^priv mod p
    Bn pub;
    if (!BN_mod_exp(pub, g, priv, p, ctx)) {
        return std::unexpected(UniformDHError::KeygenFailed);
    }

    UniformDHKeypair kp{};
    bn_to_padded(kp.public_key, pub);
    bn_to_padded(kp.private_key, priv);

    return kp;
}

std::expected<std::array<uint8_t, UNIFORM_DH_KEY_LEN>, UniformDHError>
uniform_dh_shared_secret(std::span<const uint8_t, UNIFORM_DH_KEY_LEN> private_key,
                         std::span<const uint8_t, UNIFORM_DH_KEY_LEN> public_key) {
    BnCtx ctx;
    if (!ctx.ctx) return std::unexpected(UniformDHError::OpenSSLError);

    // Parse prime
    Bn p;
    if (!BN_hex2bn(&p.bn, GROUP5_PRIME_HEX)) {
        return std::unexpected(UniformDHError::OpenSSLError);
    }

    // Parse peer public key
    Bn peer_pub(BN_bin2bn(public_key.data(), UNIFORM_DH_KEY_LEN, nullptr));
    if (!peer_pub.bn) {
        return std::unexpected(UniformDHError::InvalidPublicKey);
    }

    // Validate: 2 <= peer_pub <= p-2
    if (BN_cmp(peer_pub, BN_value_one()) <= 0) {
        return std::unexpected(UniformDHError::InvalidPublicKey);
    }
    Bn p_minus_1;
    BN_copy(p_minus_1, p);
    BN_sub_word(p_minus_1, 1);
    if (BN_cmp(peer_pub, p_minus_1) >= 0) {
        return std::unexpected(UniformDHError::InvalidPublicKey);
    }

    // Parse local private key
    Bn priv(BN_bin2bn(private_key.data(), UNIFORM_DH_KEY_LEN, nullptr));
    if (!priv.bn) {
        return std::unexpected(UniformDHError::SharedSecretFailed);
    }

    // Compute shared secret: peer_pub^priv mod p
    Bn secret;
    if (!BN_mod_exp(secret, peer_pub, priv, p, ctx)) {
        return std::unexpected(UniformDHError::SharedSecretFailed);
    }

    std::array<uint8_t, UNIFORM_DH_KEY_LEN> result{};
    bn_to_padded(result, secret);
    return result;
}

}  // namespace obfs4::common
