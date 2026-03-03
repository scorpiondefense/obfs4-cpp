#pragma once

#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>
#include "obfs4/transports/base.hpp"
#include "obfs4/transports/obfs2/obfs2.hpp"
#include "obfs4/transports/obfs3/obfs3.hpp"
#include "obfs4/transports/obfs4/obfs4.hpp"
#include "obfs4/transports/scramblesuit/scramblesuit.hpp"

namespace obfs4::transports {

// Type-erased client factory variant
using AnyClientFactory = std::variant<
    obfs2::Obfs2ClientFactory,
    obfs3::Obfs3ClientFactory,
    obfs4_transport::Obfs4ClientFactory,
    scramblesuit::ScrambleSuitClientFactory
>;

// Type-erased server factory variant (only protocols with server support)
using AnyServerFactory = std::variant<
    obfs2::Obfs2ServerFactory,
    obfs3::Obfs3ServerFactory,
    obfs4_transport::Obfs4ServerFactory
>;

// Type-erased connection variant
using AnyConn = std::variant<
    obfs2::Obfs2Conn,
    obfs3::Obfs3Conn,
    obfs4_transport::Obfs4TransportConn,
    scramblesuit::ScrambleSuitConn
>;

// Transport registry: lookup transports by name
class TransportRegistry {
public:
    TransportRegistry();

    // Get a client factory by transport name
    std::optional<AnyClientFactory> client_factory(std::string_view name) const;

    // Get a server factory by transport name (returns nullopt if server not supported)
    std::optional<AnyServerFactory> server_factory(std::string_view name) const;

    // List all registered transport names
    std::vector<std::string> transport_names() const;

    // List transport names that support server mode
    std::vector<std::string> server_transport_names() const;

    // Check if a transport exists
    bool has_transport(std::string_view name) const;

    // Check if a transport supports server mode
    bool has_server(std::string_view name) const;

private:
    struct TransportEntry {
        std::string name;
        AnyClientFactory client;
        std::optional<AnyServerFactory> server;
    };

    std::vector<TransportEntry> transports_;
};

}  // namespace obfs4::transports
