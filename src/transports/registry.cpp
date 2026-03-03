#include "obfs4/transports/registry.hpp"

namespace obfs4::transports {

TransportRegistry::TransportRegistry() {
    // Register obfs2 (client + server)
    transports_.push_back({
        "obfs2",
        obfs2::Obfs2ClientFactory{},
        AnyServerFactory{obfs2::Obfs2ServerFactory{}}
    });

    // Register obfs3 (client + server)
    transports_.push_back({
        "obfs3",
        obfs3::Obfs3ClientFactory{},
        AnyServerFactory{obfs3::Obfs3ServerFactory{}}
    });

    // Register obfs4 (client + server)
    transports_.push_back({
        "obfs4",
        obfs4_transport::Obfs4ClientFactory{},
        AnyServerFactory{obfs4_transport::Obfs4ServerFactory{}}
    });

    // Register scramblesuit (client only)
    transports_.push_back({
        "scramblesuit",
        scramblesuit::ScrambleSuitClientFactory{},
        std::nullopt
    });
}

std::optional<AnyClientFactory>
TransportRegistry::client_factory(std::string_view name) const {
    for (const auto& entry : transports_) {
        if (entry.name == name) {
            return entry.client;
        }
    }
    return std::nullopt;
}

std::optional<AnyServerFactory>
TransportRegistry::server_factory(std::string_view name) const {
    for (const auto& entry : transports_) {
        if (entry.name == name) {
            return entry.server;
        }
    }
    return std::nullopt;
}

std::vector<std::string> TransportRegistry::transport_names() const {
    std::vector<std::string> names;
    names.reserve(transports_.size());
    for (const auto& entry : transports_) {
        names.push_back(entry.name);
    }
    return names;
}

std::vector<std::string> TransportRegistry::server_transport_names() const {
    std::vector<std::string> names;
    for (const auto& entry : transports_) {
        if (entry.server.has_value()) {
            names.push_back(entry.name);
        }
    }
    return names;
}

bool TransportRegistry::has_transport(std::string_view name) const {
    for (const auto& entry : transports_) {
        if (entry.name == name) return true;
    }
    return false;
}

bool TransportRegistry::has_server(std::string_view name) const {
    for (const auto& entry : transports_) {
        if (entry.name == name) {
            return entry.server.has_value();
        }
    }
    return false;
}

}  // namespace obfs4::transports
