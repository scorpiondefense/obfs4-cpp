#include "obfs4/common/log.hpp"
#include <algorithm>
#include <cctype>
#include <iostream>

namespace obfs4::common {

namespace {
    std::mutex g_log_mutex;
    LogSink g_log_sink;
    LogLevel g_log_level = LogLevel::Warn;
    bool g_unsafe_logging = false;
}

std::string_view log_level_string(LogLevel level) {
    switch (level) {
        case LogLevel::Error: return "ERROR";
        case LogLevel::Warn: return "WARN";
        case LogLevel::Info: return "INFO";
        case LogLevel::Debug: return "DEBUG";
    }
    return "UNKNOWN";
}

LogLevel parse_log_level(std::string_view s) {
    std::string lower(s);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (lower == "error") return LogLevel::Error;
    if (lower == "warn" || lower == "warning") return LogLevel::Warn;
    if (lower == "info") return LogLevel::Info;
    if (lower == "debug") return LogLevel::Debug;
    return LogLevel::Warn;
}

void set_log_sink(LogSink sink) {
    std::lock_guard lock(g_log_mutex);
    g_log_sink = std::move(sink);
}

void set_log_level(LogLevel level) {
    std::lock_guard lock(g_log_mutex);
    g_log_level = level;
}

LogLevel get_log_level() {
    std::lock_guard lock(g_log_mutex);
    return g_log_level;
}

void log(LogLevel level, std::string_view message) {
    std::lock_guard lock(g_log_mutex);
    if (static_cast<int>(level) > static_cast<int>(g_log_level)) {
        return;
    }
    if (g_log_sink) {
        g_log_sink(level, message);
    } else {
        std::cerr << "[" << log_level_string(level) << "] " << message << "\n";
    }
}

void log_error(std::string_view message) { log(LogLevel::Error, message); }
void log_warn(std::string_view message) { log(LogLevel::Warn, message); }
void log_info(std::string_view message) { log(LogLevel::Info, message); }
void log_debug(std::string_view message) { log(LogLevel::Debug, message); }

std::string elide_address(std::string_view addr) {
    if (g_unsafe_logging) {
        return std::string(addr);
    }

    // Find port separator
    // IPv6: [addr]:port or addr:port
    // IPv4: addr:port
    if (addr.empty()) return "[scrubbed]";

    std::string_view port;
    if (addr.front() == '[') {
        // IPv6 bracket notation: [addr]:port
        auto bracket_end = addr.find(']');
        if (bracket_end != std::string_view::npos && bracket_end + 1 < addr.size() && addr[bracket_end + 1] == ':') {
            port = addr.substr(bracket_end + 1);  // includes ':'
        }
    } else {
        // IPv4 or hostname: find last ':'
        auto colon = addr.rfind(':');
        if (colon != std::string_view::npos) {
            port = addr.substr(colon);  // includes ':'
        }
    }

    if (port.empty()) {
        return "[scrubbed]";
    }
    return std::string("[scrubbed]") + std::string(port);
}

void set_unsafe_logging(bool unsafe) {
    g_unsafe_logging = unsafe;
}

bool get_unsafe_logging() {
    return g_unsafe_logging;
}

}  // namespace obfs4::common
