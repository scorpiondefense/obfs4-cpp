#include "pt_protocol.hpp"
#include <iostream>

namespace obfs4::proxy {

void PtProtocol::write_line(const std::string& line) {
    std::lock_guard lock(mutex_);
    std::cout << line << std::endl;
}

void PtProtocol::version(std::string_view ver) {
    write_line("VERSION " + std::string(ver));
}

void PtProtocol::cmethod(std::string_view name, std::string_view socks_ver,
                          std::string_view addr_port) {
    write_line("CMETHOD " + std::string(name) + " " +
               std::string(socks_ver) + " " + std::string(addr_port));
}

void PtProtocol::cmethod_error(std::string_view name, std::string_view msg) {
    write_line("CMETHOD-ERROR " + std::string(name) + " " + std::string(msg));
}

void PtProtocol::cmethods_done() {
    write_line("CMETHODS DONE");
}

void PtProtocol::smethod(std::string_view name, std::string_view addr_port,
                          std::string_view args) {
    std::string line = "SMETHOD " + std::string(name) + " " + std::string(addr_port);
    if (!args.empty()) {
        line += " ARGS:" + std::string(args);
    }
    write_line(line);
}

void PtProtocol::smethod_error(std::string_view name, std::string_view msg) {
    write_line("SMETHOD-ERROR " + std::string(name) + " " + std::string(msg));
}

void PtProtocol::smethods_done() {
    write_line("SMETHODS DONE");
}

void PtProtocol::env_error(std::string_view msg) {
    write_line("ENV-ERROR " + std::string(msg));
}

void PtProtocol::status(std::string_view name, std::string_view msg) {
    write_line("STATUS TRANSPORT=" + std::string(name) + " " + std::string(msg));
}

void PtProtocol::log_msg(std::string_view severity, std::string_view msg) {
    write_line("LOG SEVERITY=" + std::string(severity) +
               " MESSAGE=" + std::string(msg));
}

}  // namespace obfs4::proxy
