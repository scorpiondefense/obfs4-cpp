#include <catch2/catch_test_macros.hpp>
#include "obfs4/common/log.hpp"
#include <string>
#include <vector>

using namespace obfs4::common;

TEST_CASE("Log level string conversion", "[log]") {
    REQUIRE(log_level_string(LogLevel::Error) == "ERROR");
    REQUIRE(log_level_string(LogLevel::Warn) == "WARN");
    REQUIRE(log_level_string(LogLevel::Info) == "INFO");
    REQUIRE(log_level_string(LogLevel::Debug) == "DEBUG");
}

TEST_CASE("Parse log level", "[log]") {
    REQUIRE(parse_log_level("error") == LogLevel::Error);
    REQUIRE(parse_log_level("ERROR") == LogLevel::Error);
    REQUIRE(parse_log_level("warn") == LogLevel::Warn);
    REQUIRE(parse_log_level("warning") == LogLevel::Warn);
    REQUIRE(parse_log_level("info") == LogLevel::Info);
    REQUIRE(parse_log_level("debug") == LogLevel::Debug);
    REQUIRE(parse_log_level("unknown") == LogLevel::Warn);  // default
}

TEST_CASE("Log sink receives messages", "[log]") {
    std::vector<std::pair<LogLevel, std::string>> messages;

    set_log_level(LogLevel::Debug);
    set_log_sink([&](LogLevel level, std::string_view msg) {
        messages.emplace_back(level, std::string(msg));
    });

    log_error("test error");
    log_warn("test warn");
    log_info("test info");
    log_debug("test debug");

    REQUIRE(messages.size() == 4);
    REQUIRE(messages[0].first == LogLevel::Error);
    REQUIRE(messages[0].second == "test error");
    REQUIRE(messages[3].first == LogLevel::Debug);

    // Reset
    set_log_sink(nullptr);
    set_log_level(LogLevel::Warn);
}

TEST_CASE("Log level filtering", "[log]") {
    std::vector<std::string> messages;

    set_log_level(LogLevel::Warn);
    set_log_sink([&](LogLevel, std::string_view msg) {
        messages.emplace_back(msg);
    });

    log_error("err");
    log_warn("warn");
    log_info("info");   // should be filtered
    log_debug("debug"); // should be filtered

    REQUIRE(messages.size() == 2);

    set_log_sink(nullptr);
    set_log_level(LogLevel::Warn);
}

TEST_CASE("Elide IPv4 address", "[log]") {
    set_unsafe_logging(false);
    REQUIRE(elide_address("192.168.1.1:9001") == "[scrubbed]:9001");
    REQUIRE(elide_address("10.0.0.1:443") == "[scrubbed]:443");
}

TEST_CASE("Elide IPv6 address", "[log]") {
    set_unsafe_logging(false);
    REQUIRE(elide_address("[2001:db8::1]:9001") == "[scrubbed]:9001");
    REQUIRE(elide_address("[::1]:80") == "[scrubbed]:80");
}

TEST_CASE("Unsafe logging preserves address", "[log]") {
    set_unsafe_logging(true);
    REQUIRE(elide_address("192.168.1.1:9001") == "192.168.1.1:9001");
    set_unsafe_logging(false);
}
