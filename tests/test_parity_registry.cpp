#include <catch2/catch_test_macros.hpp>
#include "obfs4/transports/registry.hpp"
#include <algorithm>

using namespace obfs4::transports;

TEST_CASE("registry parity: all Go transports registered", "[registry][parity]") {
    TransportRegistry reg;
    auto names = reg.transport_names();

    REQUIRE(reg.has_transport("obfs2"));
    REQUIRE(reg.has_transport("obfs3"));
    REQUIRE(reg.has_transport("obfs4"));
    REQUIRE(reg.has_transport("scramblesuit"));
}

TEST_CASE("registry parity: server support matches Go", "[registry][parity]") {
    TransportRegistry reg;

    // Go: obfs2, obfs3, obfs4 have server support
    REQUIRE(reg.has_server("obfs2"));
    REQUIRE(reg.has_server("obfs3"));
    REQUIRE(reg.has_server("obfs4"));

    // Go: scramblesuit is client-only
    REQUIRE(!reg.has_server("scramblesuit"));
}

TEST_CASE("registry parity: nonexistent transport returns nullopt", "[registry][parity]") {
    TransportRegistry reg;

    REQUIRE(!reg.has_transport("nonexistent"));
    REQUIRE(!reg.has_server("nonexistent"));
    REQUIRE(!reg.client_factory("nonexistent").has_value());
    REQUIRE(!reg.server_factory("nonexistent").has_value());
}

TEST_CASE("registry parity: client factory for each transport", "[registry][parity]") {
    TransportRegistry reg;

    for (auto& name : {"obfs2", "obfs3", "obfs4", "scramblesuit"}) {
        auto factory = reg.client_factory(name);
        REQUIRE(factory.has_value());
    }
}

TEST_CASE("registry parity: server factory for server transports", "[registry][parity]") {
    TransportRegistry reg;

    for (auto& name : {"obfs2", "obfs3", "obfs4"}) {
        auto factory = reg.server_factory(name);
        REQUIRE(factory.has_value());
    }

    // scramblesuit should not have a server factory
    REQUIRE(!reg.server_factory("scramblesuit").has_value());
}

TEST_CASE("registry parity: transport names list", "[registry][parity]") {
    TransportRegistry reg;
    auto names = reg.transport_names();

    // At least 4 transports
    REQUIRE(names.size() >= 4);

    // All expected names present
    auto has = [&](const std::string& n) {
        return std::find(names.begin(), names.end(), n) != names.end();
    };
    REQUIRE(has("obfs2"));
    REQUIRE(has("obfs3"));
    REQUIRE(has("obfs4"));
    REQUIRE(has("scramblesuit"));
}

TEST_CASE("registry parity: server transport names list", "[registry][parity]") {
    TransportRegistry reg;
    auto names = reg.server_transport_names();

    // At least 3 server transports
    REQUIRE(names.size() >= 3);

    auto has = [&](const std::string& n) {
        return std::find(names.begin(), names.end(), n) != names.end();
    };
    REQUIRE(has("obfs2"));
    REQUIRE(has("obfs3"));
    REQUIRE(has("obfs4"));

    // scramblesuit should NOT be in server names
    REQUIRE(!has("scramblesuit"));
}

TEST_CASE("registry parity: obfs2 factory round-trip via registry", "[registry][parity]") {
    TransportRegistry reg;

    auto cf = reg.client_factory("obfs2");
    REQUIRE(cf.has_value());

    auto sf = reg.server_factory("obfs2");
    REQUIRE(sf.has_value());
}

TEST_CASE("registry parity: obfs4 factory round-trip via registry", "[registry][parity]") {
    TransportRegistry reg;

    auto cf = reg.client_factory("obfs4");
    REQUIRE(cf.has_value());

    auto sf = reg.server_factory("obfs4");
    REQUIRE(sf.has_value());
}
