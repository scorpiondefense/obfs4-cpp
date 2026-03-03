#pragma once

#include <expected>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace obfs4::proxy {

enum class PtEnvError {
    MissingVariable,
    InvalidFormat,
    UnsupportedVersion,
};

[[nodiscard]] std::string pt_env_error_message(PtEnvError err);

// Parsed PT environment configuration
struct PtConfig {
    // Common
    std::string state_location;                       // TOR_PT_STATE_LOCATION
    std::string managed_transport_ver;                // TOR_PT_MANAGED_TRANSPORT_VER
    bool exit_on_stdin_close = false;                 // TOR_PT_EXIT_ON_STDIN_CLOSE

    // Client mode
    bool is_client = false;
    std::vector<std::string> client_transports;       // TOR_PT_CLIENT_TRANSPORTS

    // Server mode
    bool is_server = false;
    std::vector<std::string> server_transports;       // TOR_PT_SERVER_TRANSPORTS
    std::string orport;                               // TOR_PT_ORPORT
    std::string extended_orport;                      // TOR_PT_EXTENDED_SERVER_PORT
    std::unordered_map<std::string, std::string> bind_addrs;  // TOR_PT_SERVER_BINDADDR
    std::string auth_cookie;                          // TOR_PT_AUTH_COOKIE_FILE

    // Upstream proxy
    std::optional<std::string> proxy;                 // TOR_PT_PROXY
};

// Parse PT environment variables
std::expected<PtConfig, PtEnvError> parse_pt_env();

}  // namespace obfs4::proxy
