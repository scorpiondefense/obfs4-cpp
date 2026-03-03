#pragma once

#include <mutex>
#include <string>
#include <string_view>

namespace obfs4::proxy {

// PT (Pluggable Transport) protocol v1 stdout communication.
// All output is line-oriented, written under a mutex for thread safety.
class PtProtocol {
public:
    PtProtocol() = default;

    // Managed transport protocol version
    void version(std::string_view ver = "1");

    // Client-mode methods
    void cmethod(std::string_view name, std::string_view socks_ver,
                 std::string_view addr_port);
    void cmethod_error(std::string_view name, std::string_view msg);
    void cmethods_done();

    // Server-mode methods
    void smethod(std::string_view name, std::string_view addr_port,
                 std::string_view args = "");
    void smethod_error(std::string_view name, std::string_view msg);
    void smethods_done();

    // General
    void env_error(std::string_view msg);
    void status(std::string_view name, std::string_view msg);
    void log_msg(std::string_view severity, std::string_view msg);

private:
    std::mutex mutex_;
    void write_line(const std::string& line);
};

}  // namespace obfs4::proxy
