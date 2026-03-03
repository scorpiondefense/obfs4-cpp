#include "pt_protocol.hpp"
#include "pt_env.hpp"
#include "socks5_server.hpp"
#include "client_handler.hpp"
#include "server_handler.hpp"
#include "term_monitor.hpp"
#include "obfs4/common/log.hpp"
#include "obfs4/transports/registry.hpp"

#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

struct Options {
    bool version = false;
    std::string log_level = "warn";
    bool enable_logging = false;
    bool unsafe_logging = false;
};

Options parse_args(int argc, char* argv[]) {
    Options opts;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0 || std::strcmp(argv[i], "-v") == 0) {
            opts.version = true;
        } else if (std::strcmp(argv[i], "--logLevel") == 0 && i + 1 < argc) {
            opts.log_level = argv[++i];
        } else if (std::strcmp(argv[i], "--enableLogging") == 0) {
            opts.enable_logging = true;
        } else if (std::strcmp(argv[i], "--unsafeLogging") == 0) {
            opts.unsafe_logging = true;
        }
    }
    return opts;
}

int run_client(obfs4::transports::TransportRegistry& registry,
               const obfs4::proxy::PtConfig& config,
               obfs4::proxy::PtProtocol& pt) {
    auto dialer_result = obfs4::proxy::create_dialer(
        config.proxy ? *config.proxy : "");
    if (!dialer_result) {
        pt.env_error("failed to create dialer");
        return 1;
    }

    auto dialer = std::shared_ptr<obfs4::proxy::Dialer>(
        std::move(*dialer_result));
    auto handler = std::make_shared<obfs4::proxy::ClientHandler>(registry, dialer);

    for (const auto& transport : config.client_transports) {
        if (transport == "*") {
            // All transports
            for (const auto& name : registry.transport_names()) {
                obfs4::proxy::Socks5Server server;
                auto addr = server.start(
                    [handler, name](int fd, const std::string& host,
                                     uint16_t port, const std::string& args) {
                        handler->handle(fd, host, port, name, args);
                    });
                if (addr.empty()) {
                    pt.cmethod_error(name, "failed to start SOCKS5 listener");
                } else {
                    pt.cmethod(name, "socks5", addr);
                }
            }
        } else if (registry.has_transport(transport)) {
            obfs4::proxy::Socks5Server server;
            auto name = transport;
            auto addr = server.start(
                [handler, name](int fd, const std::string& host,
                                 uint16_t port, const std::string& args) {
                    handler->handle(fd, host, port, name, args);
                });
            if (addr.empty()) {
                pt.cmethod_error(transport, "failed to start SOCKS5 listener");
            } else {
                pt.cmethod(transport, "socks5", addr);
            }
        } else {
            pt.cmethod_error(transport, "unknown transport");
        }
    }

    pt.cmethods_done();
    return 0;
}

int run_server(obfs4::transports::TransportRegistry& registry,
               const obfs4::proxy::PtConfig& config,
               obfs4::proxy::PtProtocol& pt) {
    for (const auto& transport : config.server_transports) {
        if (!registry.has_server(transport) && transport != "*") {
            pt.smethod_error(transport, "no server support");
            continue;
        }

        auto bind_it = config.bind_addrs.find(transport);
        std::string bind_addr = "0.0.0.0:0";
        if (bind_it != config.bind_addrs.end()) {
            bind_addr = bind_it->second;
        }

        obfs4::proxy::ServerHandler handler(registry, config.orport);
        obfs4::transports::Args args;
        auto actual_addr = handler.start(transport, bind_addr, args);

        if (actual_addr.empty()) {
            pt.smethod_error(transport, "failed to start listener");
        } else {
            pt.smethod(transport, actual_addr);
        }
    }

    pt.smethods_done();
    return 0;
}

}  // anonymous namespace

int main(int argc, char* argv[]) {
    auto opts = parse_args(argc, argv);

    if (opts.version) {
        std::cout << "obfs4proxy-cpp 0.1.0" << std::endl;
        return 0;
    }

    // Setup logging
    if (opts.enable_logging) {
        obfs4::common::set_log_level(obfs4::common::parse_log_level(opts.log_level));
    } else {
        obfs4::common::set_log_level(obfs4::common::LogLevel::Error);
    }
    obfs4::common::set_unsafe_logging(opts.unsafe_logging);

    // Parse PT environment
    auto config = obfs4::proxy::parse_pt_env();
    if (!config) {
        std::cerr << "ENV-ERROR " << obfs4::proxy::pt_env_error_message(config.error()) << std::endl;
        return 1;
    }

    // Initialize transport registry
    obfs4::transports::TransportRegistry registry;
    obfs4::proxy::PtProtocol pt;

    // Report supported version
    pt.version("1");

    // Setup termination monitor
    obfs4::proxy::TermMonitor monitor;
    monitor.start([]() {
        obfs4::common::log_info("shutdown requested");
    }, config->exit_on_stdin_close);

    int result = 0;
    if (config->is_client) {
        result = run_client(registry, *config, pt);
    } else if (config->is_server) {
        result = run_server(registry, *config, pt);
    }

    if (result != 0) return result;

    // Block until shutdown
    while (!monitor.should_shutdown()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
