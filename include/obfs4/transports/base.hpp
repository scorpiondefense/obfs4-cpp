#pragma once

#include <concepts>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace obfs4::transports {

// Transport argument map (key=value pairs from PT protocol)
using Args = std::unordered_map<std::string, std::string>;

enum class TransportError {
    HandshakeFailed,
    HandshakeTimeout,
    ConnectionClosed,
    EncodeFailed,
    DecodeFailed,
    InvalidArgs,
    NotSupported,
    InternalError,
};

[[nodiscard]] std::string transport_error_message(TransportError err);

// Result of a read operation
struct ReadResult {
    std::vector<uint8_t> plaintext;
    size_t consumed = 0;
};

// C++20 concept for a transport connection.
// A transport connection handles encoding/decoding data
// after the handshake has been completed.
template<typename T>
concept TransportConn = requires(T t,
                                 std::span<const uint8_t> data,
                                 std::span<uint8_t> buf) {
    // Encode plaintext to wire format
    { t.write(data) } -> std::same_as<std::vector<uint8_t>>;

    // Decode wire format to plaintext
    { t.read(data) } -> std::same_as<std::expected<ReadResult, TransportError>>;

    // Transport name
    { T::transport_name() } -> std::convertible_to<std::string_view>;
};

// C++20 concept for a client-side transport factory.
// Creates client connections given transport arguments.
template<typename T>
concept ClientFactory = requires(T t, const Args& args) {
    // Transport name
    { T::transport_name() } -> std::convertible_to<std::string_view>;

    // Parse and validate arguments
    { t.parse_args(args) } -> std::same_as<std::expected<void, TransportError>>;
};

// C++20 concept for a server-side transport factory.
// Creates server connections given transport arguments.
template<typename T>
concept ServerFactory = requires(T t, const Args& args) {
    // Transport name
    { T::transport_name() } -> std::convertible_to<std::string_view>;

    // Parse and validate arguments
    { t.parse_args(args) } -> std::same_as<std::expected<void, TransportError>>;
};

}  // namespace obfs4::transports
