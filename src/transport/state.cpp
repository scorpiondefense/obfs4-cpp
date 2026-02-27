#include "obfs4/transport/state.hpp"
#include "obfs4/crypto/hash.hpp"
#include <cstring>
#include <fstream>
#include <sstream>

namespace obfs4::transport {

// Base64 URL encoding (no padding)
static const char B64URL_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode_nopad(std::span<const uint8_t> data) {
    std::string result;
    result.reserve((data.size() * 4 + 2) / 3);

    size_t i = 0;
    while (i + 2 < data.size()) {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8) |
                     static_cast<uint32_t>(data[i + 2]);
        result += B64URL_CHARS[(n >> 18) & 63];
        result += B64URL_CHARS[(n >> 12) & 63];
        result += B64URL_CHARS[(n >> 6) & 63];
        result += B64URL_CHARS[n & 63];
        i += 3;
    }

    if (i + 1 == data.size()) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        result += B64URL_CHARS[(n >> 18) & 63];
        result += B64URL_CHARS[(n >> 12) & 63];
    } else if (i + 2 == data.size()) {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8);
        result += B64URL_CHARS[(n >> 18) & 63];
        result += B64URL_CHARS[(n >> 12) & 63];
        result += B64URL_CHARS[(n >> 6) & 63];
    }

    return result;
}

static int b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static std::expected<std::vector<uint8_t>, StateError>
base64_decode_nopad(const std::string& encoded) {
    std::string padded = encoded;
    while (padded.size() % 4 != 0) padded += '=';

    std::vector<uint8_t> result;
    result.reserve(padded.size() * 3 / 4);

    for (size_t i = 0; i < padded.size(); i += 4) {
        int a = (padded[i] == '=') ? 0 : b64_decode_char(padded[i]);
        int b = (padded[i + 1] == '=') ? 0 : b64_decode_char(padded[i + 1]);
        int c = (padded[i + 2] == '=') ? 0 : b64_decode_char(padded[i + 2]);
        int d = (padded[i + 3] == '=') ? 0 : b64_decode_char(padded[i + 3]);

        if (a < 0 || b < 0 || c < 0 || d < 0)
            return std::unexpected(StateError::InvalidCert);

        uint32_t n = (static_cast<uint32_t>(a) << 18) |
                     (static_cast<uint32_t>(b) << 12) |
                     (static_cast<uint32_t>(c) << 6) |
                     static_cast<uint32_t>(d);

        result.push_back(static_cast<uint8_t>((n >> 16) & 0xff));
        if (padded[i + 2] != '=') result.push_back(static_cast<uint8_t>((n >> 8) & 0xff));
        if (padded[i + 3] != '=') result.push_back(static_cast<uint8_t>(n & 0xff));
    }

    return result;
}

std::string encode_cert(const common::NodeID& node_id, const crypto::PublicKey& pub) {
    std::array<uint8_t, 52> raw{};
    std::memcpy(raw.data(), node_id.data(), 20);
    std::memcpy(raw.data() + 20, pub.data(), 32);
    return base64_encode_nopad(raw);
}

std::expected<std::pair<common::NodeID, crypto::PublicKey>, StateError>
decode_cert(const std::string& cert) {
    auto decoded = base64_decode_nopad(cert);
    if (!decoded || decoded->size() != 52) {
        return std::unexpected(StateError::InvalidCert);
    }

    common::NodeID node_id{};
    crypto::PublicKey pub{};
    std::memcpy(node_id.data(), decoded->data(), 20);
    std::memcpy(pub.data(), decoded->data() + 20, 32);

    return std::make_pair(node_id, pub);
}

// Simple JSON-like serialization (no dependency on JSON library)
std::expected<void, StateError> save_state(const std::string& path, const ServerState& state) {
    std::ofstream file(path);
    if (!file) return std::unexpected(StateError::IOError);

    auto node_id_hex = crypto::to_hex(state.node_id);
    auto priv_hex = crypto::to_hex(state.identity.private_key);
    auto pub_hex = crypto::to_hex(state.identity.public_key);
    auto seed_hex = crypto::to_hex(state.drbg_seed);

    file << "{\n";
    file << "  \"node-id\": \"" << node_id_hex << "\",\n";
    file << "  \"private-key\": \"" << priv_hex << "\",\n";
    file << "  \"public-key\": \"" << pub_hex << "\",\n";
    file << "  \"drbg-seed\": \"" << seed_hex << "\",\n";
    file << "  \"iat-mode\": " << static_cast<int>(state.iat_mode) << "\n";
    file << "}\n";

    return {};
}

std::expected<ServerState, StateError> load_state(const std::string& path) {
    std::ifstream file(path);
    if (!file) return std::unexpected(StateError::IOError);

    std::stringstream ss;
    ss << file.rdbuf();
    std::string content = ss.str();

    // Simple parser: extract hex values between quotes after known keys
    auto extract_hex = [&](const std::string& key) -> std::string {
        auto pos = content.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        pos = content.find('"', pos + key.size() + 2);
        if (pos == std::string::npos) return "";
        pos++;
        auto end = content.find('"', pos);
        if (end == std::string::npos) return "";
        return content.substr(pos, end - pos);
    };

    auto extract_int = [&](const std::string& key) -> int {
        auto pos = content.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0;
        pos = content.find(':', pos);
        if (pos == std::string::npos) return 0;
        pos++;
        while (pos < content.size() && content[pos] == ' ') pos++;
        return std::atoi(content.c_str() + pos);
    };

    ServerState state;

    auto nid_hex = extract_hex("node-id");
    auto priv_hex = extract_hex("private-key");
    auto pub_hex = extract_hex("public-key");
    auto seed_hex = extract_hex("drbg-seed");

    auto nid = crypto::from_hex(nid_hex);
    auto priv = crypto::from_hex(priv_hex);
    auto pub = crypto::from_hex(pub_hex);
    auto seed = crypto::from_hex(seed_hex);

    if (!nid || nid->size() != 20 || !priv || priv->size() != 32 ||
        !pub || pub->size() != 32 || !seed || seed->size() != 24) {
        return std::unexpected(StateError::InvalidStateFile);
    }

    std::memcpy(state.node_id.data(), nid->data(), 20);
    std::memcpy(state.identity.private_key.data(), priv->data(), 32);
    std::memcpy(state.identity.public_key.data(), pub->data(), 32);
    std::memcpy(state.drbg_seed.data(), seed->data(), 24);
    state.iat_mode = static_cast<IATMode>(extract_int("iat-mode"));

    return state;
}

std::string state_error_message(StateError err) {
    switch (err) {
        case StateError::InvalidCert: return "Invalid cert";
        case StateError::InvalidStateFile: return "Invalid state file";
        case StateError::IOError: return "I/O error";
        default: return "Unknown state error";
    }
}

}  // namespace obfs4::transport
