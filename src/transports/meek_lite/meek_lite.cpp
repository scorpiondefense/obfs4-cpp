#include "obfs4/transports/meek_lite/meek_lite.hpp"

#ifdef OBFS4_ENABLE_MEEK

#include "obfs4/common/csrand.hpp"
#include "obfs4/crypto/hash.hpp"
#include <cstring>

// cpp-httplib for HTTP client (FetchContent in CMake)
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#else
#include <httplib.h>
#endif

namespace obfs4::transports::meek_lite {

void MeekLiteConn::generate_session_id() {
    auto random = common::random_bytes(32);
    auto hash = crypto::sha256(random).value();
    // Use first 16 bytes as session ID (hex-encoded = 32 chars)
    session_id_.clear();
    session_id_.reserve(32);
    static constexpr char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 16; ++i) {
        session_id_ += hex[hash[i] >> 4];
        session_id_ += hex[hash[i] & 0x0F];
    }
}

void MeekLiteConn::init(const std::string& url, const std::string& front) {
    url_ = url;
    front_ = front;
    generate_session_id();
}

std::expected<std::vector<uint8_t>, TransportError>
MeekLiteConn::round_trip(std::span<const uint8_t> data) {
    // Parse URL to get host and path
    std::string scheme, host, path;
    auto scheme_end = url_.find("://");
    if (scheme_end == std::string::npos) {
        return std::unexpected(TransportError::InvalidArgs);
    }
    scheme = url_.substr(0, scheme_end);
    auto rest = url_.substr(scheme_end + 3);
    auto path_start = rest.find('/');
    if (path_start == std::string::npos) {
        host = rest;
        path = "/";
    } else {
        host = rest.substr(0, path_start);
        path = rest.substr(path_start);
    }

    // Create HTTP client
    auto base_url = scheme + "://" + host;
    httplib::Client cli(base_url);
    cli.set_connection_timeout(30);
    cli.set_read_timeout(30);

    // Set headers
    httplib::Headers headers;
    headers.emplace("X-Session-Id", session_id_);
    if (!front_.empty()) {
        headers.emplace("Host", front_);
    }

    // POST data
    std::string body(reinterpret_cast<const char*>(data.data()), data.size());
    auto result = cli.Post(path, headers, body, "application/octet-stream");

    if (!result || result->status != 200) {
        return std::unexpected(TransportError::ConnectionClosed);
    }

    return std::vector<uint8_t>(result->body.begin(), result->body.end());
}

std::vector<uint8_t> MeekLiteConn::write(std::span<const uint8_t> data) {
    std::lock_guard lock(mutex_);
    send_buf_.insert(send_buf_.end(), data.begin(), data.end());
    return {};  // meek_lite doesn't produce wire data locally
}

std::expected<ReadResult, TransportError>
MeekLiteConn::read(std::span<const uint8_t> data) {
    std::lock_guard lock(mutex_);
    ReadResult result;

    // In meek_lite, "reading" means performing a round trip
    // Send any pending data, receive response
    std::vector<uint8_t> to_send;
    std::swap(to_send, send_buf_);

    // Include any incoming data
    if (!data.empty()) {
        to_send.insert(to_send.end(), data.begin(), data.end());
    }

    auto response = round_trip(to_send);
    if (!response) {
        return std::unexpected(response.error());
    }

    result.plaintext = std::move(*response);
    result.consumed = data.size();
    return result;
}

// Factory
std::expected<void, TransportError>
MeekLiteClientFactory::parse_args(const Args& args) {
    auto url_it = args.find("url");
    if (url_it == args.end()) {
        return std::unexpected(TransportError::InvalidArgs);
    }
    url_ = url_it->second;

    auto front_it = args.find("front");
    if (front_it != args.end()) {
        front_ = front_it->second;
    }

    return {};
}

MeekLiteConn MeekLiteClientFactory::create() const {
    MeekLiteConn conn;
    conn.init(url_, front_);
    return conn;
}

}  // namespace obfs4::transports::meek_lite

#endif  // OBFS4_ENABLE_MEEK
