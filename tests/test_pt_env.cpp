#include <catch2/catch_test_macros.hpp>
#include <cstdlib>

// We can't easily include the proxy headers from tests without
// adjusting include paths, so we test the PT env module indirectly.
// The main test here validates that the PtArgs parser works correctly
// via the SOCKS5 module which is in the library.
#include "obfs4/proxy/socks5.hpp"

using namespace obfs4::proxy;

TEST_CASE("PT args empty string", "[pt_env]") {
    auto result = PtArgs::parse("");
    REQUIRE(result.has_value());
    REQUIRE(result->args.empty());
}

TEST_CASE("PT args single pair", "[pt_env]") {
    auto result = PtArgs::parse("cert=AAAA");
    REQUIRE(result.has_value());
    REQUIRE(result->args.size() == 1);
    REQUIRE(result->get("cert").value() == "AAAA");
}

TEST_CASE("PT args multiple pairs", "[pt_env]") {
    auto result = PtArgs::parse("cert=AAAA;iat-mode=1;key=value");
    REQUIRE(result.has_value());
    REQUIRE(result->args.size() == 3);
    REQUIRE(result->get("cert").value() == "AAAA");
    REQUIRE(result->get("iat-mode").value() == "1");
    REQUIRE(result->get("key").value() == "value");
}

TEST_CASE("PT args backslash escaping", "[pt_env]") {
    auto result = PtArgs::parse("key=val\\;ue;other=te\\=st");
    REQUIRE(result.has_value());
    REQUIRE(result->get("key").value() == "val;ue");
    REQUIRE(result->get("other").value() == "te=st");
}
