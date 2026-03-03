#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>

namespace obfs4::common {

enum class LogLevel : int {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
};

// Convert log level to string
[[nodiscard]] std::string_view log_level_string(LogLevel level);

// Parse log level from string (case-insensitive)
[[nodiscard]] LogLevel parse_log_level(std::string_view s);

// Callback for log messages
using LogSink = std::function<void(LogLevel level, std::string_view message)>;

// Global log configuration
void set_log_sink(LogSink sink);
void set_log_level(LogLevel level);
LogLevel get_log_level();

// Log a message at the given level
void log(LogLevel level, std::string_view message);
void log_error(std::string_view message);
void log_warn(std::string_view message);
void log_info(std::string_view message);
void log_debug(std::string_view message);

// Elide IP addresses for privacy.
// "192.168.1.1:9001" -> "[scrubbed]:9001"
// "[2001:db8::1]:9001" -> "[scrubbed]:9001"
// If unsafe_logging is enabled, returns the address unchanged.
[[nodiscard]] std::string elide_address(std::string_view addr);

// Control whether addresses are elided (default: true = elide)
void set_unsafe_logging(bool unsafe);
bool get_unsafe_logging();

}  // namespace obfs4::common
