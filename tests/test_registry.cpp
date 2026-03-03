#include <catch2/catch_test_macros.hpp>
#include "obfs4/transports/registry.hpp"
#include <algorithm>

using namespace obfs4::transports;

TEST_CASE("Registry has all transports", "[registry]") {
    TransportRegistry reg;

    REQUIRE(reg.has_transport("obfs2"));
    REQUIRE(reg.has_transport("obfs3"));
    REQUIRE(reg.has_transport("obfs4"));
    REQUIRE(reg.has_transport("scramblesuit"));
    REQUIRE(!reg.has_transport("nonexistent"));
}

TEST_CASE("Registry server support", "[registry]") {
    TransportRegistry reg;

    REQUIRE(reg.has_server("obfs2"));
    REQUIRE(reg.has_server("obfs3"));
    REQUIRE(reg.has_server("obfs4"));
    REQUIRE(!reg.has_server("scramblesuit"));  // client-only
}

TEST_CASE("Registry lists transport names", "[registry]") {
    TransportRegistry reg;

    auto names = reg.transport_names();
    REQUIRE(names.size() >= 4);
    REQUIRE(std::find(names.begin(), names.end(), "obfs2") != names.end());
    REQUIRE(std::find(names.begin(), names.end(), "obfs4") != names.end());
}

TEST_CASE("Registry lists server transport names", "[registry]") {
    TransportRegistry reg;

    auto names = reg.server_transport_names();
    REQUIRE(names.size() >= 3);  // obfs2, obfs3, obfs4
    REQUIRE(std::find(names.begin(), names.end(), "scramblesuit") == names.end());
}

TEST_CASE("Registry returns client factories", "[registry]") {
    TransportRegistry reg;

    auto obfs2_factory = reg.client_factory("obfs2");
    REQUIRE(obfs2_factory.has_value());

    auto obfs4_factory = reg.client_factory("obfs4");
    REQUIRE(obfs4_factory.has_value());

    auto none = reg.client_factory("invalid");
    REQUIRE(!none.has_value());
}

TEST_CASE("Registry returns server factories", "[registry]") {
    TransportRegistry reg;

    auto obfs4_server = reg.server_factory("obfs4");
    REQUIRE(obfs4_server.has_value());

    auto scramble_server = reg.server_factory("scramblesuit");
    REQUIRE(!scramble_server.has_value());
}
