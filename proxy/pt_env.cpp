#include "pt_env.hpp"
#include <cstdlib>
#include <sstream>

namespace obfs4::proxy {

std::string pt_env_error_message(PtEnvError err) {
    switch (err) {
        case PtEnvError::MissingVariable: return "missing required environment variable";
        case PtEnvError::InvalidFormat: return "invalid environment variable format";
        case PtEnvError::UnsupportedVersion: return "unsupported PT version";
    }
    return "unknown PT environment error";
}

static std::optional<std::string> getenv_opt(const char* name) {
    const char* val = std::getenv(name);
    if (!val) return std::nullopt;
    return std::string(val);
}

static std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> result;
    std::istringstream stream(s);
    std::string token;
    while (std::getline(stream, token, delim)) {
        if (!token.empty()) {
            result.push_back(token);
        }
    }
    return result;
}

std::expected<PtConfig, PtEnvError> parse_pt_env() {
    PtConfig config;

    // TOR_PT_MANAGED_TRANSPORT_VER (required)
    auto ver = getenv_opt("TOR_PT_MANAGED_TRANSPORT_VER");
    if (!ver) {
        return std::unexpected(PtEnvError::MissingVariable);
    }
    config.managed_transport_ver = *ver;

    // Check version support
    auto versions = split(*ver, ',');
    bool has_v1 = false;
    for (const auto& v : versions) {
        if (v == "1") { has_v1 = true; break; }
    }
    if (!has_v1) {
        return std::unexpected(PtEnvError::UnsupportedVersion);
    }

    // TOR_PT_STATE_LOCATION
    auto state = getenv_opt("TOR_PT_STATE_LOCATION");
    if (state) config.state_location = *state;

    // TOR_PT_EXIT_ON_STDIN_CLOSE
    auto exit_stdin = getenv_opt("TOR_PT_EXIT_ON_STDIN_CLOSE");
    config.exit_on_stdin_close = exit_stdin && *exit_stdin == "1";

    // Determine client or server mode
    auto client_transports = getenv_opt("TOR_PT_CLIENT_TRANSPORTS");
    auto server_transports = getenv_opt("TOR_PT_SERVER_TRANSPORTS");

    if (client_transports) {
        config.is_client = true;
        config.client_transports = split(*client_transports, ',');
    }

    if (server_transports) {
        config.is_server = true;
        config.server_transports = split(*server_transports, ',');

        // TOR_PT_ORPORT (required for server)
        auto orport = getenv_opt("TOR_PT_ORPORT");
        if (!orport) {
            return std::unexpected(PtEnvError::MissingVariable);
        }
        config.orport = *orport;

        // TOR_PT_EXTENDED_SERVER_PORT
        auto ext_port = getenv_opt("TOR_PT_EXTENDED_SERVER_PORT");
        if (ext_port) config.extended_orport = *ext_port;

        // TOR_PT_SERVER_BINDADDR: "transport-addr,transport-addr"
        auto bind_addrs = getenv_opt("TOR_PT_SERVER_BINDADDR");
        if (bind_addrs) {
            auto pairs = split(*bind_addrs, ',');
            for (const auto& pair : pairs) {
                auto dash = pair.find('-');
                if (dash != std::string::npos) {
                    auto name = pair.substr(0, dash);
                    auto addr = pair.substr(dash + 1);
                    config.bind_addrs[name] = addr;
                }
            }
        }

        // TOR_PT_AUTH_COOKIE_FILE
        auto cookie = getenv_opt("TOR_PT_AUTH_COOKIE_FILE");
        if (cookie) config.auth_cookie = *cookie;
    }

    // TOR_PT_PROXY
    auto proxy = getenv_opt("TOR_PT_PROXY");
    if (proxy && !proxy->empty()) {
        config.proxy = *proxy;
    }

    if (!config.is_client && !config.is_server) {
        return std::unexpected(PtEnvError::MissingVariable);
    }

    return config;
}

}  // namespace obfs4::proxy
